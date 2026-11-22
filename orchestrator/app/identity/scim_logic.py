"""SCIM 2.0 (RFC 7643 / 7644) resource mapping, filters and PATCH semantics.

Kept free of FastAPI so it can be unit-tested directly. The router
(``routers/scim.py``) owns HTTP + transactions.

Which users SCIM may see / change: users it created (``provisioned_by =
'scim'``) and SSO-JIT users (``sso:<slug>``, adopted on first write). Local
password users -- and every break-glass user -- are invisible to SCIM, so a
leaked SCIM token can never deactivate the break-glass admin.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any

from ..config import settings
from . import mapping
from .scim_filter import Col, Exists, FilterError, Spec, compile_filter
from .store import get_settings, revoke_user_sessions

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

SCIM_DELETED = "scim-deleted"
MAX_COUNT = 200


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def body(self) -> dict[str, Any]:
        b: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            b["scimType"] = self.scim_type
        return b


def base_url() -> str:
    return settings.sso_base_url.rstrip("/") + "/scim/v2"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


# --------------------------------------------------------------------------- #
# Visibility
# --------------------------------------------------------------------------- #

def managed_sql(alias: str = "u") -> str:
    """SQL predicate: users SCIM may see. Break-glass names are excluded
    separately by the router (``routers.scim._visible``)."""
    return (
        f"({alias}.provisioned_by = 'scim' OR {alias}.provisioned_by LIKE 'sso:%')"
    )


async def break_glass(con) -> list[str]:
    s = await get_settings(con)
    return [u.lower() for u in s["break_glass_users"] or []]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def user_version(row, groups: list[tuple[str, str]] | None = None) -> str:
    return version_of("user", row["id"], row["updated_at"], row["role"], row["clearance"],
                      sorted(g for g, _ in (groups or [])))


def group_version(row, members: list[tuple[str, str]] | None = None) -> str:
    return version_of("group", row["id"], row["updated_at"], sorted(m for m, _ in (members or [])))


def user_resource(row, groups: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    uid = str(row["id"])
    res: dict[str, Any] = {
        "schemas": [USER_SCHEMA],
        "id": uid,
        "userName": row["username"],
        "active": bool(row["active"]),
        "meta": {
            "resourceType": "User",
            "created": _iso(row["created_at"]),
            "lastModified": _iso(row["updated_at"]),
            "location": f"{base_url()}/Users/{uid}",
            "version": user_version(row, groups),
        },
    }
    if row["external_id"]:
        res["externalId"] = row["external_id"]
    name = {k: v for k, v in (("givenName", row["given_name"]), ("familyName", row["family_name"])) if v}
    if name:
        name["formatted"] = " ".join(v for v in (row["given_name"], row["family_name"]) if v)
        res["name"] = name
    if row["display_name"]:
        res["displayName"] = row["display_name"]
    if row["email"]:
        res["emails"] = [{"value": row["email"], "type": "work", "primary": True}]
    # read-only view of the Paddock role the group mapping produced
    res["roles"] = [{"value": row["role"], "primary": True}]
    if groups is not None:
        res["groups"] = [
            {"value": gid, "display": name, "$ref": f"{base_url()}/Groups/{gid}"} for gid, name in groups
        ]
    return res


def group_resource(row, members: list[tuple[str, str]] | None) -> dict[str, Any]:
    gid = str(row["id"])
    res: dict[str, Any] = {
        "schemas": [GROUP_SCHEMA],
        "id": gid,
        "displayName": row["display_name"],
        "meta": {
            "resourceType": "Group",
            "created": _iso(row["created_at"]),
            "lastModified": _iso(row["updated_at"]),
            "location": f"{base_url()}/Groups/{gid}",
            "version": group_version(row, members),
        },
    }
    if row["external_id"]:
        res["externalId"] = row["external_id"]
    if members is not None:
        res["members"] = [
            {"value": uid, "display": uname, "$ref": f"{base_url()}/Users/{uid}"} for uid, uname in members
        ]
    return res


def list_response(resources: list[dict[str, Any]], total: int, start: int) -> dict[str, Any]:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


# --------------------------------------------------------------------------- #
# Filters (RFC 7644 3.4.2.2): see scim_filter.py
# --------------------------------------------------------------------------- #

USER_SPEC: Spec = {
    "username": Col("u.username"),
    "externalid": Col("u.external_id", ci=False),
    "displayname": Col("u.display_name"),
    "name.givenname": Col("u.given_name"),
    "name.familyname": Col("u.family_name"),
    "name.formatted": Col("concat_ws(' ', u.given_name, u.family_name)"),
    "emails": Col("u.email"),
    "emails.value": Col("u.email"),
    "emails.type": Col("(CASE WHEN u.email IS NULL THEN NULL ELSE 'work' END)"),
    "emails.primary": Col("(CASE WHEN u.email IS NULL THEN NULL ELSE TRUE END)", "bool"),
    "active": Col("u.active", "bool"),
    "id": Col("u.id::text", ci=False),
    "roles.value": Col("u.role"),
    "meta.lastmodified": Col("u.updated_at", "datetime"),
    "meta.created": Col("u.created_at", "datetime"),
    "groups.value": Exists(
        "EXISTS (SELECT 1 FROM scim_group_members gm WHERE gm.user_id = u.id AND lower(gm.group_id::text) = {p})",
        "EXISTS (SELECT 1 FROM scim_group_members gm WHERE gm.user_id = u.id)",
    ),
}
GROUP_SPEC: Spec = {
    "displayname": Col("g.display_name"),
    "externalid": Col("g.external_id", ci=False),
    "id": Col("g.id::text", ci=False),
    "meta.lastmodified": Col("g.updated_at", "datetime"),
    "meta.created": Col("g.created_at", "datetime"),
    "members.value": Exists(
        "EXISTS (SELECT 1 FROM scim_group_members gm WHERE gm.group_id = g.id AND lower(gm.user_id::text) = {p})",
        "EXISTS (SELECT 1 FROM scim_group_members gm WHERE gm.group_id = g.id)",
    ),
}


def filter_sql(expr: str | None, spec: Spec, args: list[Any]) -> str | None:
    """Compile a SCIM ``filter`` to SQL (bind values appended to ``args``);
    any problem is a 400 ``invalidFilter``."""
    try:
        return compile_filter(expr, spec, args)
    except FilterError as exc:
        raise ScimError(400, f"unsupported filter: {exc}", "invalidFilter") from exc


def project(res: dict[str, Any], attributes: str | None, excluded: str | None) -> dict[str, Any]:
    """RFC 7644 3.4.2.5 ``attributes`` / ``excludedAttributes`` (top-level
    names or dotted sub-attributes; ``id`` and ``schemas`` always stay)."""
    keep = {a.strip().lower().split(".")[0] for a in (attributes or "").split(",") if a.strip()}
    drop = {a.strip().lower() for a in (excluded or "").split(",") if a.strip()}
    if not keep and not drop:
        return res
    out = {}
    for k, v in res.items():
        low = k.lower()
        if low in ("id", "schemas"):
            out[k] = v
        elif keep and low not in keep:
            continue
        elif low in drop:
            continue
        else:
            out[k] = v
    return out


def version_of(*parts: Any) -> str:
    """Weak ETag over whatever makes a representation change."""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:20]
    return f'W/"{h}"'


def _strip_urn(path: str) -> str:
    for urn in (USER_SCHEMA, GROUP_SCHEMA, ENTERPRISE_SCHEMA):
        if path.lower().startswith(urn.lower() + ":"):
            return path[len(urn) + 1:]
    return path


# --------------------------------------------------------------------------- #
# Users: payload -> fields, PATCH
# --------------------------------------------------------------------------- #

def to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"  # Entra sends "True"/"False"
    raise ScimError(400, f"expected a boolean, got {v!r}", "invalidValue")


def _primary_email(emails: Any) -> str | None:
    if not isinstance(emails, list):
        return None
    vals = [e for e in emails if isinstance(e, dict) and e.get("value")]
    for e in vals:
        if e.get("primary") in (True, "true", "True"):
            return str(e["value"])
    for e in vals:
        if (e.get("type") or "").lower() == "work":
            return str(e["value"])
    return str(vals[0]["value"]) if vals else None


def user_fields_from_resource(body: dict[str, Any]) -> dict[str, Any]:
    """Full representation (POST / PUT) -> our columns."""
    if not isinstance(body, dict):
        raise ScimError(400, "body must be a JSON object", "invalidSyntax")
    user_name = body.get("userName")
    if not isinstance(user_name, str) or not user_name.strip():
        raise ScimError(400, "userName is required", "invalidValue")
    name = body.get("name") if isinstance(body.get("name"), dict) else {}
    return {
        "username": user_name.strip(),
        "external_id": _opt_str(body.get("externalId")),
        "given_name": _opt_str(name.get("givenName")),
        "family_name": _opt_str(name.get("familyName")),
        "display_name": _opt_str(body.get("displayName")) or _opt_str(name.get("formatted")),
        "email": (_primary_email(body.get("emails")) or None),
        "active": to_bool(body["active"]) if "active" in body else True,
    }


def _opt_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


_USER_ATTRS = {
    "username": "username",
    "externalid": "external_id",
    "displayname": "display_name",
    "active": "active",
    "name.givenname": "given_name",
    "name.familyname": "family_name",
}
_EMAIL_PATH = re.compile(r'^emails(\[[^\]]*\])?(\.value)?$', re.I)


def apply_user_patch(cur: dict[str, Any], operations: Any) -> dict[str, Any]:
    """Apply RFC 7644 §3.5.2 operations (Okta + Entra shapes) to ``cur``.

    Unknown attributes (enterprise extension, phoneNumbers, ...) are accepted
    and ignored, which is what both Okta and Entra expect.
    """
    if not isinstance(operations, list) or not operations:
        raise ScimError(400, "Operations must be a non-empty array", "invalidSyntax")
    new = dict(cur)
    for op in operations:
        if not isinstance(op, dict):
            raise ScimError(400, "each operation must be an object", "invalidSyntax")
        kind = str(op.get("op", "")).lower()
        if kind not in ("add", "replace", "remove"):
            raise ScimError(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
        path = op.get("path")
        value = op.get("value")
        if path is None:
            if kind == "remove":
                raise ScimError(400, "remove requires a path", "noTarget")
            if not isinstance(value, dict):
                raise ScimError(400, "op without path needs an object value", "invalidValue")
            for k, v in _flatten(value).items():
                _set_user_attr(new, kind, k, v)
        else:
            _set_user_attr(new, kind, str(path), value)
    return new


def _flatten(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in value.items():
        key = _strip_urn(f"{prefix}{k}")
        if key.lower() == "name" and isinstance(v, dict):
            out.update(_flatten(v, "name."))
        elif isinstance(v, dict) and k.lower().startswith("urn:"):
            continue  # extension block, e.g. enterprise user: ignored
        else:
            out[key] = v
    return out


def _set_user_attr(new: dict[str, Any], kind: str, path: str, value: Any) -> None:
    p = _strip_urn(path).strip()
    low = p.lower()
    if low == "name" and isinstance(value, dict):
        for k, v in value.items():
            _set_user_attr(new, kind, f"name.{k}", v)
        return
    if _EMAIL_PATH.match(p):
        if kind == "remove":
            new["email"] = None
        elif isinstance(value, list):
            new["email"] = _primary_email(value)
        elif value is not None:
            new["email"] = _opt_str(value)
        return
    col = _USER_ATTRS.get(low)
    if col is None:
        return  # unsupported attribute: ignore
    if kind == "remove":
        if col in ("username", "active"):
            raise ScimError(400, f"{p} cannot be removed", "mutability")
        new[col] = None
        return
    if col == "active":
        new[col] = to_bool(value)
    elif col == "username":
        if not isinstance(value, str) or not value.strip():
            raise ScimError(400, "userName must be a non-empty string", "invalidValue")
        new[col] = value.strip()
    else:
        new[col] = _opt_str(value)


# --------------------------------------------------------------------------- #
# Groups: PATCH
# --------------------------------------------------------------------------- #

_MEMBER_FILTER = re.compile(r'^members\[\s*value\s+eq\s+"([^"]+)"\s*\](\.value)?$', re.I)


def apply_group_patch(
    cur: dict[str, Any], members: set[str], operations: Any,
) -> tuple[dict[str, Any], set[str]]:
    """Return (new group fields, new member id set)."""
    if not isinstance(operations, list) or not operations:
        raise ScimError(400, "Operations must be a non-empty array", "invalidSyntax")
    new = dict(cur)
    mem = set(members)
    for op in operations:
        if not isinstance(op, dict):
            raise ScimError(400, "each operation must be an object", "invalidSyntax")
        kind = str(op.get("op", "")).lower()
        if kind not in ("add", "replace", "remove"):
            raise ScimError(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
        path = op.get("path")
        value = op.get("value")
        if path is None:
            if not isinstance(value, dict):
                raise ScimError(400, "op without path needs an object value", "invalidValue")
            for k, v in value.items():
                _group_attr(new, mem, kind, _strip_urn(k), v)
            continue
        p = _strip_urn(str(path)).strip()
        m = _MEMBER_FILTER.match(p)
        if m:
            if kind != "remove":
                raise ScimError(400, "only remove is supported with a member filter", "invalidPath")
            mem.discard(m.group(1).lower())
            continue
        _group_attr(new, mem, kind, p, value)
    return new, mem


def _member_ids(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("value"):
            out.append(str(it["value"]).lower())
        elif isinstance(it, str) and it:
            out.append(it.lower())
    return out


def _group_attr(new: dict[str, Any], mem: set[str], kind: str, path: str, value: Any) -> None:
    low = path.lower()
    if low == "members":
        ids = _member_ids(value)
        if kind == "add":
            mem.update(ids)
        elif kind == "replace":
            mem.clear()
            mem.update(ids)
        else:  # remove: with a value list (Entra) or everything
            if ids:
                mem.difference_update(ids)
            else:
                mem.clear()
        return
    if low == "displayname":
        if kind == "remove" or not isinstance(value, str) or not value.strip():
            raise ScimError(400, "displayName must be a non-empty string", "invalidValue")
        new["display_name"] = value.strip()
    elif low == "externalid":
        new["external_id"] = None if kind == "remove" else _opt_str(value)
    # id / meta / unknown: ignored


# --------------------------------------------------------------------------- #
# Group membership -> role
# --------------------------------------------------------------------------- #

async def recompute_roles(con, user_ids: list | None) -> int:
    """Re-derive role/clearance for SCIM-managed users from their groups.

    No-op when no SCIM role mappings are configured. Break-glass users are
    never touched. Returns the number of users whose role changed.
    """
    s = await get_settings(con)
    mappings = s["scim_role_mappings"] or []
    if not mappings:
        return 0
    bg = [u.lower() for u in s["break_glass_users"] or []]
    sql = (
        "SELECT u.id, u.username, u.role, u.clearance, "
        "       COALESCE(array_agg(g.display_name) FILTER (WHERE g.id IS NOT NULL), '{}') AS groups "
        "  FROM app_users u "
        "  LEFT JOIN scim_group_members m ON m.user_id = u.id "
        "  LEFT JOIN scim_groups g ON g.id = m.group_id "
        " WHERE u.provisioned_by = 'scim' AND NOT (lower(u.username) = ANY($1::text[]))"
    )
    args: list[Any] = [bg]
    if user_ids is not None:
        if not user_ids:
            return 0
        sql += " AND u.id = ANY($2::uuid[])"
        args.append(list(user_ids))
    sql += " GROUP BY u.id"
    changed = 0
    for r in await con.fetch(sql, *args):
        d = mapping.resolve_role(
            r["groups"], mappings,
            default_role=s["scim_default_role"], default_clearance=s["scim_default_clearance"],
        )
        if (d.role, d.clearance) != (r["role"], r["clearance"]):
            await con.execute(
                "UPDATE app_users SET role = $2, clearance = $3, updated_at = NOW() WHERE id = $1",
                r["id"], d.role, d.clearance,
            )
            changed += 1
    return changed


async def deactivate(con, user_id) -> None:
    await con.execute("UPDATE app_users SET active = FALSE, updated_at = NOW() WHERE id = $1", user_id)
    await revoke_user_sessions(con, user_id, revoke_api_keys=True)
