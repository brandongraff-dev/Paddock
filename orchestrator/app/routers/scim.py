"""SCIM 2.0 service provider at ``/scim/v2`` (RFC 7643 / 7644; schema 020).

Authenticated ONLY by a SCIM bearer token (``pscim_...``, admin-created,
sha256 at rest). The governance middleware resolves it to a principal whose
sole capability is ``scim``: the token is useless on every other route, and
no other credential (API key, JWT, dev admin) can call SCIM.

Resources: Users, Groups (list + ``filter=attr eq "v"``, get, create,
replace, patch, delete), plus ServiceProviderConfig, ResourceTypes, Schemas.

* ``DELETE /Users/{id}`` deactivates (the row is kept for the audit trail),
  hides the user from SCIM and frees the userName for re-creation.
* Deactivation (DELETE or ``active: false``) immediately revokes the user's
  sessions (JWT watermark) and API keys.
* Group membership drives role + clearance through the SCIM role mappings
  in identity settings (first match wins).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute

from .. import audit
from .. import auth as auth_svc
from ..auth import current_principal, require_scope
from ..db import get_pool
from ..identity import scim_logic as sl
from ..identity.scim_logic import ScimError

logger = logging.getLogger(__name__)

SCIM_MEDIA = "application/scim+json"


def scim_json(body: Any, status_code: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status_code, media_type=SCIM_MEDIA, headers=headers)


class ScimRoute(APIRoute):
    """Render every error in the SCIM error schema (RFC 7644 §3.12)."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                return await original(request)
            except ScimError as exc:
                return scim_json(exc.body(), exc.status)
            except RequestValidationError:
                return scim_json(ScimError(400, "invalid request", "invalidSyntax").body(), 400)
            except HTTPException as exc:
                return scim_json(ScimError(exc.status_code, str(exc.detail)).body(), exc.status_code)

        return handler


router = APIRouter(
    prefix="/scim/v2",
    tags=["scim"],
    route_class=ScimRoute,
    dependencies=[Depends(require_scope("scim"))],
)

USER_COLS = (
    "id, username, external_id, given_name, family_name, display_name, email, active, "
    "role, clearance, created_at, updated_at, provisioned_by"
)
_USER_FILTERS = {
    "username": "username", "externalid": "external_id", "emails.value": "email",
    "emails": "email", "id": "id", "displayname": "display_name", "active": "active",
}
_GROUP_FILTERS = {"displayname": "display_name", "externalid": "external_id", "id": "id"}


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > 1_000_000:
        raise ScimError(413, "request too large")
    try:
        data = json.loads(raw or b"{}")
    except ValueError as exc:
        raise ScimError(400, "body is not valid JSON", "invalidSyntax") from exc
    if not isinstance(data, dict):
        raise ScimError(400, "body must be a JSON object", "invalidSyntax")
    return data


def _uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        return None


async def _audit(request: Request, *, action: str, rtype: str, rid: str | None, status: int, details: dict):
    p = current_principal(request)
    try:
        await audit.record(
            request.app.state.pool,
            action=action, actor=p.actor, actor_role=p.role, resource_type=rtype, resource_id=rid,
            method=request.method, path=request.url.path, status=status,
            ip=auth_svc.client_ip(request), request_id=getattr(request.state, "request_id", None),
            details=details,
        )
    except Exception:  # noqa: BLE001
        logger.exception("scim_audit_failed")


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def _visible(alias: str = "u", param: int = 1) -> str:
    return f"{sl.managed_sql(alias)} AND NOT (lower({alias}.username) = ANY(${param}::text[]))"


async def _get_user(con, uid: UUID | None):
    if uid is None:
        return None
    return await con.fetchrow(
        f"SELECT {USER_COLS} FROM app_users u WHERE id = $2 AND {_visible()}",
        await sl.break_glass(con), uid,
    )


async def _user_groups(con, user_ids: list) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {str(u): [] for u in user_ids}
    if not user_ids:
        return out
    rows = await con.fetch(
        "SELECT m.user_id, g.id, g.display_name FROM scim_group_members m "
        "JOIN scim_groups g ON g.id = m.group_id WHERE m.user_id = ANY($1::uuid[]) ORDER BY g.display_name",
        user_ids,
    )
    for r in rows:
        out[str(r["user_id"])].append((str(r["id"]), r["display_name"]))
    return out


async def _render_user(con, uid) -> dict[str, Any]:
    row = await con.fetchrow(f"SELECT {USER_COLS} FROM app_users WHERE id = $1", uid)
    groups = await _user_groups(con, [uid])
    return sl.user_resource(row, groups[str(uid)])


@router.get("/Users")
async def list_users(
    filter: str | None = Query(None, max_length=1024),  # noqa: A002 -- SCIM's name
    startIndex: int = Query(1),  # noqa: N803
    count: int = Query(100),
    pool=Depends(get_pool),
):
    conds = sl.parse_filter(filter, _USER_FILTERS)
    start = max(1, startIndex)
    count = max(0, min(count, sl.MAX_COUNT))
    async with pool.acquire() as con:
        args: list[Any] = [await sl.break_glass(con)]
        where = [_visible()]
        for col, val in conds:
            args.append(val)
            n = len(args)
            if col in ("username", "email"):
                where.append(f"lower(u.{col}) = lower(${n}::text)")
            elif col == "id":
                where.append(f"u.id::text = ${n}::text")
            elif col == "active":
                where.append(f"u.active = ${n}::boolean")
            else:
                where.append(f"u.{col} = ${n}::text")
        w = " AND ".join(where)
        total = await con.fetchval(f"SELECT count(*) FROM app_users u WHERE {w}", *args)
        rows = []
        if count:
            rows = await con.fetch(
                f"SELECT {USER_COLS} FROM app_users u WHERE {w} ORDER BY u.created_at, u.id "
                f"OFFSET {start - 1} LIMIT {count}",
                *args,
            )
        groups = await _user_groups(con, [r["id"] for r in rows])
    return scim_json(sl.list_response([sl.user_resource(r, groups[str(r["id"])]) for r in rows], total, start))


@router.get("/Users/{user_id}")
async def get_user(user_id: str, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await _get_user(con, _uuid(user_id))
        if row is None:
            raise ScimError(404, "user not found")
        return scim_json(await _render_user(con, row["id"]))


@router.post("/Users")
async def create_user(request: Request, pool=Depends(get_pool)):
    f = sl.user_fields_from_resource(await _body(request))
    async with pool.acquire() as con:
        async with con.transaction():
            s = await sl.get_settings(con)
            if f["username"].lower() in [u.lower() for u in s["break_glass_users"] or []]:
                raise ScimError(409, "userName is reserved", "uniqueness")
            existing = await con.fetchrow(
                "SELECT id, provisioned_by FROM app_users WHERE lower(username) = lower($1)", f["username"],
            )
            if existing is not None and existing["provisioned_by"] != sl.SCIM_DELETED:
                raise ScimError(409, "a user with this userName already exists", "uniqueness")
            if existing is not None:
                uid = existing["id"]  # re-create after a SCIM delete: revive the row
                await con.execute(
                    """
                    UPDATE app_users SET username = $2, external_id = $3, given_name = $4, family_name = $5,
                           display_name = $6, email = $7, active = $8, provisioned_by = 'scim',
                           role = $9, clearance = $10, updated_at = NOW()
                     WHERE id = $1
                    """,
                    uid, f["username"], f["external_id"], f["given_name"], f["family_name"],
                    f["display_name"], f["email"], f["active"], s["scim_default_role"], s["scim_default_clearance"],
                )
            else:
                uid = await con.fetchval(
                    """
                    INSERT INTO app_users (username, external_id, given_name, family_name, display_name,
                                           email, active, role, clearance, provisioned_by)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scim')
                    RETURNING id
                    """,
                    f["username"], f["external_id"], f["given_name"], f["family_name"], f["display_name"],
                    f["email"], f["active"], s["scim_default_role"], s["scim_default_clearance"],
                )
            await sl.recompute_roles(con, [uid])
            res = await _render_user(con, uid)
    await _audit(request, action="create", rtype="scim_user", rid=str(uid), status=201,
                 details={"userName": f["username"], "active": f["active"], "revived": existing is not None})
    return scim_json(res, 201, headers={"Location": res["meta"]["location"]})


def _cur_user_fields(row) -> dict[str, Any]:
    return {k: row[k] for k in (
        "username", "external_id", "given_name", "family_name", "display_name", "email", "active",
    )}


async def _persist_user(request: Request, con, row, new: dict[str, Any]) -> dict[str, Any]:
    cur = _cur_user_fields(row)
    if new["username"].lower() != cur["username"].lower():
        s = await sl.get_settings(con)
        if new["username"].lower() in [u.lower() for u in s["break_glass_users"] or []]:
            raise ScimError(409, "userName is reserved", "uniqueness")
        clash = await con.fetchval(
            "SELECT 1 FROM app_users WHERE lower(username) = lower($1) AND id <> $2", new["username"], row["id"],
        )
        if clash:
            raise ScimError(409, "a user with this userName already exists", "uniqueness")
    await con.execute(
        """
        UPDATE app_users SET username = $2, external_id = $3, given_name = $4, family_name = $5,
               display_name = $6, email = $7, active = $8, provisioned_by = 'scim', updated_at = NOW()
         WHERE id = $1
        """,
        row["id"], new["username"], new["external_id"], new["given_name"], new["family_name"],
        new["display_name"], new["email"], new["active"],
    )
    if cur["active"] and not new["active"]:
        await sl.deactivate(con, row["id"])
    if row["provisioned_by"] != "scim":
        await sl.recompute_roles(con, [row["id"]])  # adopted SSO user: SCIM now owns the role
    return {k: new[k] for k in new if new[k] != cur[k]}


@router.put("/Users/{user_id}")
async def replace_user(user_id: str, request: Request, pool=Depends(get_pool)):
    f = sl.user_fields_from_resource(await _body(request))
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_user(con, _uuid(user_id))
            if row is None:
                raise ScimError(404, "user not found")
            changes = await _persist_user(request, con, row, f)
            res = await _render_user(con, row["id"])
    await _audit(request, action="update", rtype="scim_user", rid=str(row["id"]), status=200,
                 details={"userName": f["username"], "changed": sorted(changes), "active": f["active"]})
    return scim_json(res)


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request, pool=Depends(get_pool)):
    body = await _body(request)
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_user(con, _uuid(user_id))
            if row is None:
                raise ScimError(404, "user not found")
            new = sl.apply_user_patch(_cur_user_fields(row), body.get("Operations"))
            changes = await _persist_user(request, con, row, new)
            res = await _render_user(con, row["id"])
    await _audit(request, action="update", rtype="scim_user", rid=str(row["id"]), status=200,
                 details={"userName": new["username"], "changed": sorted(changes), "active": new["active"]})
    return scim_json(res)


@router.delete("/Users/{user_id}")
async def delete_user(user_id: str, request: Request, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_user(con, _uuid(user_id))
            if row is None:
                raise ScimError(404, "user not found")
            await sl.deactivate(con, row["id"])
            await con.execute("DELETE FROM scim_group_members WHERE user_id = $1", row["id"])
            await con.execute("DELETE FROM user_identities WHERE user_id = $1", row["id"])
            await con.execute(
                "UPDATE app_users SET provisioned_by = $2, external_id = NULL WHERE id = $1",
                row["id"], sl.SCIM_DELETED,
            )
    await _audit(request, action="delete", rtype="scim_user", rid=str(row["id"]), status=204,
                 details={"userName": row["username"], "effect": "deactivated"})
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Groups
# --------------------------------------------------------------------------- #

GROUP_COLS = "id, display_name, external_id, created_at, updated_at"


async def _group_members(con, gid) -> list[tuple[str, str]]:
    rows = await con.fetch(
        "SELECT u.id, u.username FROM scim_group_members m JOIN app_users u ON u.id = m.user_id "
        "WHERE m.group_id = $1 ORDER BY u.username",
        gid,
    )
    return [(str(r["id"]), r["username"]) for r in rows]


async def _set_members(con, gid, wanted: set[str]) -> set:
    """Replace a group's membership with the visible users in ``wanted``.
    Returns every user id whose membership changed."""
    old = {r["user_id"] for r in await con.fetch("SELECT user_id FROM scim_group_members WHERE group_id = $1", gid)}
    ids = [u for u in (_uuid(w) for w in wanted) if u is not None]
    valid: set = set()
    if ids:
        rows = await con.fetch(
            f"SELECT u.id FROM app_users u WHERE u.id = ANY($2::uuid[]) AND {_visible()}",
            await sl.break_glass(con), ids,
        )
        valid = {r["id"] for r in rows}
    if len(valid) < len(wanted):
        logger.info("scim_group_unknown_members_ignored", extra={"group": str(gid), "n": len(wanted) - len(valid)})
    remove, add = old - valid, valid - old
    if remove:
        await con.execute(
            "DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = ANY($2::uuid[])", gid, list(remove),
        )
    for uid in add:
        await con.execute(
            "INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", gid, uid,
        )
    return remove | add


def _wants_members(excluded: str | None, attributes: str | None) -> bool:
    if excluded and "members" in [a.strip().lower() for a in excluded.split(",")]:
        return False
    if attributes and "members" not in [a.strip().lower() for a in attributes.split(",")]:
        return False
    return True


@router.get("/Groups")
async def list_groups(
    filter: str | None = Query(None, max_length=1024),  # noqa: A002
    startIndex: int = Query(1),  # noqa: N803
    count: int = Query(100),
    excludedAttributes: str | None = Query(None),  # noqa: N803
    attributes: str | None = Query(None),
    pool=Depends(get_pool),
):
    conds = sl.parse_filter(filter, _GROUP_FILTERS)
    start = max(1, startIndex)
    count = max(0, min(count, sl.MAX_COUNT))
    where, args = ["TRUE"], []
    for col, val in conds:
        args.append(val)
        n = len(args)
        if col == "display_name":
            where.append(f"lower(display_name) = lower(${n}::text)")
        elif col == "id":
            where.append(f"id::text = ${n}::text")
        else:
            where.append(f"{col} = ${n}::text")
    w = " AND ".join(where)
    with_members = _wants_members(excludedAttributes, attributes)
    async with pool.acquire() as con:
        total = await con.fetchval(f"SELECT count(*) FROM scim_groups WHERE {w}", *args)
        rows = []
        if count:
            rows = await con.fetch(
                f"SELECT {GROUP_COLS} FROM scim_groups WHERE {w} ORDER BY created_at, id "
                f"OFFSET {start - 1} LIMIT {count}",
                *args,
            )
        res = [sl.group_resource(r, await _group_members(con, r["id"]) if with_members else None) for r in rows]
    return scim_json(sl.list_response(res, total, start))


async def _get_group(con, gid: UUID | None):
    if gid is None:
        return None
    return await con.fetchrow(f"SELECT {GROUP_COLS} FROM scim_groups WHERE id = $1", gid)


@router.get("/Groups/{group_id}")
async def get_group(
    group_id: str,
    excludedAttributes: str | None = Query(None),  # noqa: N803
    attributes: str | None = Query(None),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        row = await _get_group(con, _uuid(group_id))
        if row is None:
            raise ScimError(404, "group not found")
        members = await _group_members(con, row["id"]) if _wants_members(excludedAttributes, attributes) else None
    return scim_json(sl.group_resource(row, members))


def _group_fields(body: dict[str, Any]) -> tuple[str, str | None, set[str]]:
    name = body.get("displayName")
    if not isinstance(name, str) or not name.strip():
        raise ScimError(400, "displayName is required", "invalidValue")
    return name.strip(), sl._opt_str(body.get("externalId")), set(sl._member_ids(body.get("members")))


async def _name_clash(con, name: str, gid=None) -> None:
    clash = await con.fetchval(
        "SELECT 1 FROM scim_groups WHERE lower(display_name) = lower($1) AND ($2::uuid IS NULL OR id <> $2)",
        name, gid,
    )
    if clash:
        raise ScimError(409, "a group with this displayName already exists", "uniqueness")


@router.post("/Groups")
async def create_group(request: Request, pool=Depends(get_pool)):
    name, ext, members = _group_fields(await _body(request))
    async with pool.acquire() as con:
        async with con.transaction():
            await _name_clash(con, name)
            gid = await con.fetchval(
                "INSERT INTO scim_groups (display_name, external_id) VALUES ($1, $2) RETURNING id", name, ext,
            )
            touched = await _set_members(con, gid, members)
            changed = await sl.recompute_roles(con, list(touched))
            row = await _get_group(con, gid)
            res = sl.group_resource(row, await _group_members(con, gid))
    await _audit(request, action="create", rtype="scim_group", rid=str(gid), status=201,
                 details={"displayName": name, "members": len(res["members"]), "roles_changed": changed})
    return scim_json(res, 201, headers={"Location": res["meta"]["location"]})


@router.put("/Groups/{group_id}")
async def replace_group(group_id: str, request: Request, pool=Depends(get_pool)):
    name, ext, members = _group_fields(await _body(request))
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_group(con, _uuid(group_id))
            if row is None:
                raise ScimError(404, "group not found")
            await _name_clash(con, name, row["id"])
            await con.execute(
                "UPDATE scim_groups SET display_name = $2, external_id = $3, updated_at = NOW() WHERE id = $1",
                row["id"], name, ext,
            )
            touched = await _set_members(con, row["id"], members)
            # a rename can change which mapping matches for every member
            if name != row["display_name"]:
                touched |= {r["user_id"] for r in await con.fetch(
                    "SELECT user_id FROM scim_group_members WHERE group_id = $1", row["id"])}
            changed = await sl.recompute_roles(con, list(touched))
            res = sl.group_resource(await _get_group(con, row["id"]), await _group_members(con, row["id"]))
    await _audit(request, action="update", rtype="scim_group", rid=str(row["id"]), status=200,
                 details={"displayName": name, "members": len(res["members"]), "roles_changed": changed})
    return scim_json(res)


@router.patch("/Groups/{group_id}")
async def patch_group(group_id: str, request: Request, pool=Depends(get_pool)):
    body = await _body(request)
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_group(con, _uuid(group_id))
            if row is None:
                raise ScimError(404, "group not found")
            cur_members = {m for m, _ in await _group_members(con, row["id"])}
            cur = {"display_name": row["display_name"], "external_id": row["external_id"]}
            new, members = sl.apply_group_patch(cur, cur_members, body.get("Operations"))
            if new["display_name"] != cur["display_name"]:
                await _name_clash(con, new["display_name"], row["id"])
            await con.execute(
                "UPDATE scim_groups SET display_name = $2, external_id = $3, updated_at = NOW() WHERE id = $1",
                row["id"], new["display_name"], new["external_id"],
            )
            touched = await _set_members(con, row["id"], members)
            if new["display_name"] != cur["display_name"]:
                touched |= {r["user_id"] for r in await con.fetch(
                    "SELECT user_id FROM scim_group_members WHERE group_id = $1", row["id"])}
            changed = await sl.recompute_roles(con, list(touched))
            members_now = await _group_members(con, row["id"])
    await _audit(request, action="update", rtype="scim_group", rid=str(row["id"]), status=200,
                 details={"displayName": new["display_name"], "members": len(members_now), "roles_changed": changed})
    # Entra accepts 204; Okta wants the resource. Returning it satisfies both.
    async with pool.acquire() as con:
        return scim_json(sl.group_resource(await _get_group(con, row["id"]), members_now))


@router.delete("/Groups/{group_id}")
async def delete_group(group_id: str, request: Request, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        async with con.transaction():
            row = await _get_group(con, _uuid(group_id))
            if row is None:
                raise ScimError(404, "group not found")
            members = [r["user_id"] for r in await con.fetch(
                "SELECT user_id FROM scim_group_members WHERE group_id = $1", row["id"])]
            await con.execute("DELETE FROM scim_groups WHERE id = $1", row["id"])
            changed = await sl.recompute_roles(con, members)
    await _audit(request, action="delete", rtype="scim_group", rid=str(row["id"]), status=204,
                 details={"displayName": row["display_name"], "roles_changed": changed})
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Discovery: ServiceProviderConfig, ResourceTypes, Schemas
# --------------------------------------------------------------------------- #

def _spc() -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/brandongraff-dev/Paddock/blob/main/docs/SSO.md",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": sl.MAX_COUNT},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Paddock SCIM token (Settings -> Identity -> SCIM), sent as Authorization: Bearer",
            "primary": True,
        }],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{sl.base_url()}/ServiceProviderConfig"},
    }


def _resource_types() -> list[dict[str, Any]]:
    return [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users", "description": "Paddock user account",
            "schema": sl.USER_SCHEMA,
            "schemaExtensions": [{"schema": sl.ENTERPRISE_SCHEMA, "required": False}],
            "meta": {"resourceType": "ResourceType", "location": f"{sl.base_url()}/ResourceTypes/User"},
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group", "name": "Group", "endpoint": "/Groups", "description": "Group (drives Paddock role)",
            "schema": sl.GROUP_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": f"{sl.base_url()}/ResourceTypes/Group"},
        },
    ]


def _attr(name: str, typ: str = "string", *, required: bool = False, multi: bool = False,
          mutability: str = "readWrite", uniqueness: str = "none", sub: list | None = None,
          case_exact: bool = False, returned: str = "default") -> dict[str, Any]:
    a: dict[str, Any] = {
        "name": name, "type": typ, "multiValued": multi, "description": name, "required": required,
        "caseExact": case_exact, "mutability": mutability, "returned": returned, "uniqueness": uniqueness,
    }
    if sub:
        a["subAttributes"] = sub
    return a


def _schemas() -> list[dict[str, Any]]:
    user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": sl.USER_SCHEMA, "name": "User", "description": "User Account",
        "attributes": [
            _attr("userName", required=True, uniqueness="server"),
            _attr("name", "complex", sub=[_attr("givenName"), _attr("familyName"), _attr("formatted")]),
            _attr("displayName"),
            _attr("emails", "complex", multi=True, sub=[_attr("value"), _attr("type"), _attr("primary", "boolean")]),
            _attr("active", "boolean"),
            _attr("groups", "complex", multi=True, mutability="readOnly",
                  sub=[_attr("value", mutability="readOnly"), _attr("display", mutability="readOnly"),
                       _attr("$ref", "reference", mutability="readOnly")]),
            _attr("roles", "complex", multi=True, mutability="readOnly",
                  sub=[_attr("value", mutability="readOnly"), _attr("primary", "boolean", mutability="readOnly")]),
        ],
        "meta": {"resourceType": "Schema", "location": f"{sl.base_url()}/Schemas/{sl.USER_SCHEMA}"},
    }
    group = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": sl.GROUP_SCHEMA, "name": "Group", "description": "Group",
        "attributes": [
            _attr("displayName", required=True, uniqueness="server"),
            _attr("members", "complex", multi=True,
                  sub=[_attr("value", mutability="immutable"), _attr("display", mutability="readOnly"),
                       _attr("$ref", "reference", mutability="immutable")]),
        ],
        "meta": {"resourceType": "Schema", "location": f"{sl.base_url()}/Schemas/{sl.GROUP_SCHEMA}"},
    }
    return [user, group]


@router.get("/ServiceProviderConfig")
async def service_provider_config():
    return scim_json(_spc())


@router.get("/ResourceTypes")
async def resource_types():
    rts = _resource_types()
    return scim_json(sl.list_response(rts, len(rts), 1))


@router.get("/ResourceTypes/{name}")
async def resource_type(name: str):
    for rt in _resource_types():
        if rt["id"].lower() == name.lower():
            return scim_json(rt)
    raise ScimError(404, "resource type not found")


@router.get("/Schemas")
async def schemas():
    s = _schemas()
    return scim_json(sl.list_response(s, len(s), 1))


@router.get("/Schemas/{schema_id}")
async def schema(schema_id: str):
    for s in _schemas():
        if s["id"] == schema_id:
            return scim_json(s)
    raise ScimError(404, "schema not found")
