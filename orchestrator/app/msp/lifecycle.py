"""MSP lifecycle: provision / suspend / reactivate customers, onboarding
invites, grants, and templates applied to many customers.

Every step that writes INSIDE a customer (invite row, template objects) runs
under ``tenancy.tenant_context(customer)`` after a LIVE grant check
(``resolve_delegation``), and is audited in both the customer's and the MSP's
chain with the acting MSP user. Creating / suspending a tenant itself goes
through the two SECURITY DEFINER functions of schema 033 (the app role cannot
write ``tenants``).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import types
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
from fastapi import HTTPException

from .. import auth as auth_svc
from .. import tenancy
from ..config import settings
from . import core
from .core import DelegationError, audit_both, msp_settings

logger = logging.getLogger(__name__)

SLUG_RE = r"^[a-z0-9][a-z0-9-]{1,62}$"


# --------------------------------------------------------------------------- #
# Provision / suspend / reactivate
# --------------------------------------------------------------------------- #

async def create_customer(
    pool, ctx: core.MspContext, *, slug: str, name: str, request_id: str | None, ip: str | None,
    invite_label: str | None = None,
) -> dict[str, Any]:
    """Create the customer tenant, give the creator an admin grant on it, and
    issue the one-time onboarding invite for the customer's first admin."""
    actor = ctx.username
    try:
        with tenancy.tenant_context(ctx.msp_tenant_id):
            async with pool.acquire() as con:
                child_id = str(await con.fetchval(
                    "SELECT msp_create_child_tenant($1, $2, $3)", slug, name.strip(), actor
                ))
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="a tenant with that slug already exists") from None
    except asyncpg.InsufficientPrivilegeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except asyncpg.PostgresError as exc:
        if getattr(exc, "sqlstate", "") == "53400":
            raise HTTPException(status_code=409, detail="customer limit reached for this MSP") from None
        if getattr(exc, "sqlstate", "") == "23514":
            raise HTTPException(status_code=422, detail="invalid slug (a-z, 0-9, '-', 2-63 chars)") from None
        raise
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            await con.execute(
                "INSERT INTO msp_grants (tenant_id, user_id, child_tenant_id, role, clearance, granted_by) "
                "VALUES ($1, $2, $3, 'admin', 'internal', $4) "
                "ON CONFLICT (user_id, child_tenant_id) WHERE child_tenant_id IS NOT NULL DO NOTHING",
                ctx.msp_tenant_id, ctx.user_id, child_id, actor,
            )
    msp_slug = await _msp_slug(pool, ctx.msp_tenant_id)
    child_actor = f"msp:{msp_slug}/{actor}"
    await audit_both(
        pool, msp_tid=ctx.msp_tenant_id, child_tid=child_id, action="msp.customer_created",
        actor=actor, actor_role=ctx.role, child_actor=child_actor,
        resource_type="tenant", resource_id=child_id, request_id=request_id, ip=ip,
        msp_details={"slug": slug, "name": name},
        child_details={"slug": slug, "name": name, "provisioned_by": actor},
    )
    invite = await create_invite(
        pool, msp_tid=ctx.msp_tenant_id, child_id=child_id, created_by=child_actor, msp_user=actor,
        actor_role=ctx.role, label=invite_label, request_id=request_id, ip=ip,
    )
    return {"id": child_id, "slug": slug, "name": name, "status": "active", "invite": invite}


async def _msp_slug(pool, msp_tid: str) -> str:
    async with pool.acquire() as con:
        return str(await con.fetchval("SELECT slug FROM tenants WHERE id = $1", msp_tid))


async def set_customer_status(
    pool, ctx: core.MspContext, child_id: str, status: str, *, request_id: str | None, ip: str | None,
) -> dict[str, Any]:
    """Suspend / reactivate. Needs an admin grant on that customer."""
    facts = await require_grant(pool, ctx, child_id, "admin", allow_suspended=True)
    try:
        with tenancy.tenant_context(ctx.msp_tenant_id):
            async with pool.acquire() as con:
                await con.fetchval("SELECT msp_set_child_status($1, $2)", child_id, status)
    except asyncpg.InsufficientPrivilegeError:
        raise HTTPException(status_code=403, detail="not a customer of this MSP") from None
    await audit_both(
        pool, msp_tid=ctx.msp_tenant_id, child_tid=child_id,
        action="msp.customer_suspended" if status == "suspended" else "msp.customer_reactivated",
        actor=ctx.username, actor_role=ctx.role,
        child_actor=f"msp:{facts['msp_slug']}/{ctx.username}",
        resource_type="tenant", resource_id=child_id, request_id=request_id, ip=ip,
        msp_details={"slug": facts["child_slug"], "status": status},
    )
    return {"id": child_id, "slug": facts["child_slug"], "status": status}


async def require_grant(
    pool, ctx: core.MspContext, child_id: str, need: str, *, allow_suspended: bool = False
) -> dict[str, Any]:
    """Live grant check for a management action on a customer. ``need`` is the
    minimum grant role. Same refusal for "no such customer" and "no grant"."""
    rank = {"viewer": 0, "analyst": 1, "admin": 2}
    try:
        facts = await core.resolve_delegation(pool, ctx.msp_tenant_id, ctx.user_id, child_id)
    except DelegationError as exc:
        if allow_suspended and exc.status == 409:
            # resolve_delegation refuses suspended customers; for reactivation
            # re-read the grant without the status gate.
            facts = await _facts_ignoring_status(pool, ctx, child_id)
        else:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from None
    if rank[facts["role"]] < rank[need]:
        raise HTTPException(status_code=403, detail=f"requires an {need} grant on this customer")
    return facts


async def _facts_ignoring_status(pool, ctx: core.MspContext, child_id: str) -> dict[str, Any]:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                core.GRANTED_CHILDREN_SQL + " AND c.child_tenant_id = $2", ctx.user_id, child_id
            )
            msp_slug = await con.fetchval("SELECT slug FROM tenants WHERE id = $1", ctx.msp_tenant_id)
    if row is None:
        raise HTTPException(status_code=403, detail="no access grant for this customer")
    return {
        "msp_slug": msp_slug, "child_slug": row["slug"], "child_name": row["name"],
        "role": row["role"], "child_tenant_id": str(row["child_tenant_id"]),
    }


# --------------------------------------------------------------------------- #
# Onboarding invite (customer admin)
# --------------------------------------------------------------------------- #

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_invite(
    pool, *, msp_tid: str, child_id: str, created_by: str, msp_user: str, actor_role: str | None,
    label: str | None, request_id: str | None, ip: str | None,
) -> dict[str, Any]:
    """One-time invite for the customer's first admin. The raw token is
    returned once and never stored (only its sha256)."""
    token = f"{child_id}.{secrets.token_urlsafe(32)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=max(1, msp_settings.invite_ttl_hours))
    with tenancy.tenant_context(child_id):
        async with pool.acquire() as con:
            invite_id = await con.fetchval(
                "INSERT INTO msp_invites (tenant_id, msp_tenant_id, token_hash, label, created_by, expires_at) "
                "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                child_id, msp_tid, _hash_token(token), label, created_by, expires,
            )
    await audit_both(
        pool, msp_tid=msp_tid, child_tid=child_id, action="msp.invite_created",
        actor=msp_user, actor_role=actor_role, child_actor=created_by,
        resource_type="invite", resource_id=str(invite_id), request_id=request_id, ip=ip,
        msp_details={"child_tenant_id": child_id, "expires_at": expires.isoformat()},
        child_details={"expires_at": expires.isoformat()},
    )
    return {"id": str(invite_id), "token": token, "expires_at": expires, "redeem_path": "/v1/msp/invites/redeem"}


async def redeem_invite(
    pool, *, token: str, username: str, password: str, email: str | None, display_name: str | None,
    request_id: str | None, ip: str | None,
) -> dict[str, Any]:
    """Public: turn a valid invite into the customer's first admin user."""
    bad = HTTPException(status_code=400, detail="invalid or expired invitation")
    child_id, _, secret = (token or "").partition(".")
    try:
        child_id = tenancy._norm(child_id) or ""
    except ValueError:
        raise bad from None
    if not child_id or not secret:
        raise bad
    status = await core.tenant_status(pool, child_id)
    if status != "active":
        raise bad
    pw_hash = await asyncio.get_running_loop().run_in_executor(None, auth_svc.hash_password, password)
    try:
        with tenancy.tenant_context(child_id):
            async with pool.acquire() as con:
                async with con.transaction():
                    inv = await con.fetchrow(
                        "UPDATE msp_invites SET used_at = NOW(), used_by = $2 "
                        " WHERE token_hash = $1 AND tenant_id = $3 AND used_at IS NULL AND expires_at > NOW() "
                        "RETURNING id, created_by, msp_tenant_id",
                        _hash_token(token), username, child_id,
                    )
                    if inv is None:
                        raise bad
                    await con.execute(
                        "INSERT INTO app_users (username, email, display_name, role, clearance, pw_hash, tenant_id) "
                        "VALUES ($1, $2, $3, 'admin', 'confidential', $4, $5)",
                        username, email, display_name, pw_hash, child_id,
                    )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="that username is not available") from None
    await _audit_redeem(pool, child_id, username, str(inv["id"]), inv["msp_tenant_id"], request_id, ip)
    return {"tenant_id": child_id, "username": username, "role": "admin"}


async def _audit_redeem(pool, child_id: str, username: str, invite_id: str, msp_tid, request_id, ip) -> None:
    from .. import audit

    await audit.record(
        pool, tenant_id=child_id, action="msp.invite_redeemed", actor=username, actor_role="admin",
        resource_type="invite", resource_id=invite_id, request_id=request_id, ip=ip,
        details={"first_admin": username},
    )
    # Tell the MSP its customer's admin exists (MSP-side record, no customer data).
    if msp_tid:
        try:
            await audit.record(
                pool, tenant_id=str(msp_tid), action="msp.invite_redeemed", actor=username,
                resource_type="tenant", resource_id=child_id, request_id=request_id, ip=ip,
                details={"child_tenant_id": child_id},
            )
        except Exception:  # noqa: BLE001 -- best effort; the customer-side row is the record
            logger.exception("msp_redeem_mirror_failed")


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #

def _split_template(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(spec without secrets, {integration name: {field: secret}})."""
    from ..routers import changes as changes_router
    from ..routers.integrations import _cls, _validate_events, _validate_filters, _validate_severity
    from ..routers.scope import _validate_entry_value

    spec: dict[str, Any] = {"alert_rules": [], "integrations": [], "scope_suggestions": []}
    secrets_by_name: dict[str, dict[str, str]] = {}
    for r in body.get("alert_rules") or []:
        changes_router._validate_channel_target(r["channel"], r.get("target"))
        spec["alert_rules"].append({
            "name": r["name"], "match": r.get("match") or {}, "channel": r["channel"],
            "target": r.get("target"), "enabled": bool(r.get("enabled", True)),
        })
    seen: set[tuple[str, str]] = set()
    for i in body.get("integrations") or []:
        cls = _cls(i["kind"])
        if (i["kind"], i["name"]) in seen:
            raise HTTPException(status_code=422, detail=f"duplicate integration {i['kind']}/{i['name']}")
        seen.add((i["kind"], i["name"]))
        sec = {k: v for k, v in (i.get("secrets") or {}).items() if v}
        unknown = [k for k in sec if k not in cls.secret_fields]
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown secret field(s) for {i['kind']}: {unknown}")
        if sec:
            secrets_by_name[f"{i['kind']}/{i['name']}"] = sec
        spec["integrations"].append({
            "kind": i["kind"], "name": i["name"], "enabled": bool(i.get("enabled", True)),
            "config": i.get("config") or {},
            "events": _validate_events(i.get("events") or []),
            "min_severity": _validate_severity(i.get("min_severity") or "low"),
            "filters": _validate_filters(i.get("filters") or {}),
            "allow_private": bool(i.get("allow_private", False)),
        })
    for s in body.get("scope_suggestions") or []:
        canon = _validate_entry_value(s["kind"], s["value"])
        spec["scope_suggestions"].append({"kind": s["kind"], "value": canon, "notes": s.get("notes")})
    return spec, secrets_by_name


def _encrypt_template_secrets(secrets_by_name: dict[str, dict[str, str]]) -> str | None:
    from ..integrations import secrets as secrets_mod

    if not secrets_by_name:
        return None
    if settings.auth_mode == "enforce" and not secrets_mod.has_persistent_key():
        raise HTTPException(status_code=503, detail="PADDOCK_SECRET_KEY is not configured; refusing to store credentials")
    return secrets_mod.encrypt_secrets({"by_name": secrets_by_name})  # type: ignore[dict-item]


def template_out(row, *, with_secret_names: bool = True) -> dict[str, Any]:
    from ..integrations import secrets as secrets_mod

    d = dict(row)
    spec = d["spec"] if isinstance(d["spec"], dict) else json.loads(d["spec"] or "{}")
    spec = json.loads(json.dumps(spec))
    present: dict[str, list[str]] = {}
    if d.get("secrets"):
        try:
            present = {k: sorted(v) for k, v in secrets_mod.decrypt_secrets(d["secrets"]).get("by_name", {}).items()}
        except Exception:  # noqa: BLE001
            present = {}
    for i in spec.get("integrations", []):
        i["secrets"] = {f: "********" for f in present.get(f"{i['kind']}/{i['name']}", [])}
    return {
        "id": str(d["id"]), "name": d["name"], "description": d["description"], "spec": spec,
        "created_by": d["created_by"], "created_at": d["created_at"], "updated_at": d["updated_at"],
    }


async def save_template(
    pool, ctx: core.MspContext, *, template_id: str | None, body: dict[str, Any]
) -> dict[str, Any]:
    spec, sec = _split_template(body)
    blob = _encrypt_template_secrets(sec)
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            try:
                if template_id is None:
                    row = await con.fetchrow(
                        "INSERT INTO msp_templates (tenant_id, name, description, spec, secrets, created_by) "
                        "VALUES ($1,$2,$3,$4::jsonb,$5,$6) RETURNING *",
                        ctx.msp_tenant_id, body["name"].strip(), body.get("description"), json.dumps(spec),
                        blob, ctx.username,
                    )
                else:
                    # Keep stored secrets for integrations whose secrets were not re-sent.
                    old = await con.fetchrow("SELECT secrets FROM msp_templates WHERE id = $1", template_id)
                    if old is None:
                        raise HTTPException(status_code=404, detail="template not found")
                    row = await con.fetchrow(
                        "UPDATE msp_templates SET name=$2, description=$3, spec=$4::jsonb, secrets=$5, "
                        "updated_at=NOW() WHERE id=$1 RETURNING *",
                        template_id, body["name"].strip(), body.get("description"), json.dumps(spec),
                        _merge_secret_blobs(old["secrets"], sec, spec),
                    )
            except asyncpg.UniqueViolationError:
                raise HTTPException(status_code=409, detail="a template with that name exists") from None
    return template_out(row)


def _merge_secret_blobs(old_blob: str | None, new: dict[str, dict[str, str]], spec: dict[str, Any]) -> str | None:
    from ..integrations import secrets as secrets_mod

    keep: dict[str, dict[str, str]] = {}
    if old_blob:
        try:
            keep = secrets_mod.decrypt_secrets(old_blob).get("by_name", {})  # type: ignore[assignment]
        except Exception:  # noqa: BLE001
            keep = {}
    live = {f"{i['kind']}/{i['name']}" for i in spec.get("integrations", [])}
    merged = {k: v for k, v in keep.items() if k in live}
    for k, v in new.items():
        merged[k] = {**merged.get(k, {}), **v}
    return _encrypt_template_secrets(merged)


async def apply_template(
    pool, request_app, ctx: core.MspContext, template_id: str, child_ids: list[str], *,
    request_id: str | None, ip: str | None,
) -> dict[str, Any]:
    from ..integrations import secrets as secrets_mod

    child_ids = list(dict.fromkeys(child_ids))
    if len(child_ids) > msp_settings.max_apply_batch:
        raise HTTPException(status_code=422, detail=f"at most {msp_settings.max_apply_batch} customers per call")
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            tpl = await con.fetchrow("SELECT * FROM msp_templates WHERE id = $1", template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="template not found")
    spec = tpl["spec"] if isinstance(tpl["spec"], dict) else json.loads(tpl["spec"])
    tpl_secrets: dict[str, dict[str, str]] = {}
    if tpl["secrets"]:
        tpl_secrets = secrets_mod.decrypt_secrets(tpl["secrets"]).get("by_name", {})  # type: ignore[assignment]

    results: list[dict[str, Any]] = []
    for cid in child_ids:
        res: dict[str, Any] = {"customer_id": cid, "status": "failed", "created": {}, "skipped": {}, "errors": []}
        try:
            facts = await core.resolve_delegation(pool, ctx.msp_tenant_id, ctx.user_id, cid)
            if facts["role"] != "admin":
                raise DelegationError(403, "requires an admin grant on this customer")
        except DelegationError as exc:
            res["errors"].append(exc.detail)
            results.append(res)
            await _record_application(pool, ctx, template_id, cid, "failed", res)
            continue
        principal = core.principal_from_facts(facts)
        shim = types.SimpleNamespace(
            state=types.SimpleNamespace(principal=principal), app=request_app, headers={},
        )
        try:
            with tenancy.tenant_context(cid):
                await _apply_into_customer(pool, shim, spec, tpl_secrets, principal, tpl["name"], res)
        except Exception as exc:  # noqa: BLE001 -- one customer's failure must not stop the batch
            logger.exception("msp_template_apply_failed", extra={"child": cid})
            res["errors"].append(f"unexpected error: {type(exc).__name__}")
        made = sum(res["created"].values())
        if res["errors"]:
            res["status"] = "partial" if made else "failed"
        else:
            res["status"] = "applied" if made else "skipped"
        results.append(res)
        await _record_application(pool, ctx, template_id, cid, res["status"], res)
        await audit_both(
            pool, msp_tid=ctx.msp_tenant_id, child_tid=cid, action="msp.template_applied",
            actor=ctx.username, actor_role=ctx.role, child_actor=principal.actor,
            resource_type="template", resource_id=template_id, request_id=request_id, ip=ip,
            msp_details={"template": tpl["name"], "customer": facts["child_slug"], "status": res["status"],
                         "created": res["created"], "errors": res["errors"]},
            child_details={"template": tpl["name"], "status": res["status"], "created": res["created"],
                           "errors": res["errors"]},
        )
    return {
        "template_id": template_id, "template": tpl["name"], "results": results,
        "applied": sum(1 for r in results if r["status"] == "applied"),
        "failed": sum(1 for r in results if r["status"] in ("failed", "partial")),
    }


async def _record_application(pool, ctx, template_id, cid, status, res) -> None:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            await con.execute(
                "INSERT INTO msp_template_applications (tenant_id, template_id, child_tenant_id, status, detail, applied_by) "
                "VALUES ($1,$2,$3,$4,$5::jsonb,$6)",
                ctx.msp_tenant_id, template_id, cid, status, json.dumps(res, default=str), ctx.username,
            )


async def _apply_into_customer(pool, shim, spec, tpl_secrets, principal, tpl_name: str, res) -> None:
    """Create the template's objects in the CURRENT tenant context (the
    customer). Idempotent: existing objects (same name / key) are skipped."""
    from ..routers import integrations as integ_router
    from ..routers.changes import _validate_channel_target

    def bump(kind: str, field: str) -> None:
        res[field][kind] = res[field].get(kind, 0) + 1

    for r in spec.get("alert_rules", []):
        try:
            _validate_channel_target(r["channel"], r.get("target"))
            async with pool.acquire() as con:
                exists = await con.fetchval("SELECT 1 FROM alert_rules WHERE name = $1", r["name"])
                if exists:
                    bump("alert_rules", "skipped")
                    continue
                await con.execute(
                    "INSERT INTO alert_rules (name, enabled, match, channel, target) VALUES ($1,$2,$3::jsonb,$4,$5)",
                    r["name"], r.get("enabled", True), json.dumps(r.get("match") or {}), r["channel"], r.get("target"),
                )
            bump("alert_rules", "created")
        except HTTPException as exc:
            res["errors"].append(f"alert rule {r['name']!r}: {exc.detail}")

    for i in spec.get("integrations", []):
        try:
            async with pool.acquire() as con:
                exists = await con.fetchval(
                    "SELECT 1 FROM integrations WHERE kind = $1 AND name = $2", i["kind"], i["name"]
                )
            if exists:
                bump("integrations", "skipped")
                continue
            body = integ_router.IntegrationIn(
                kind=i["kind"], name=i["name"], enabled=i.get("enabled", True), config=i.get("config") or {},
                secrets=dict(tpl_secrets.get(f"{i['kind']}/{i['name']}", {})), events=i.get("events") or [],
                min_severity=i.get("min_severity", "low"), filters=i.get("filters") or {},
                allow_private=bool(i.get("allow_private", False)),
            )
            await integ_router.create_integration(body, shim, pool)
            bump("integrations", "created")
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else (exc.detail or {})
            if isinstance(detail, dict):
                detail = detail.get("detail") or detail.get("message") or "invalid"
            res["errors"].append(f"integration {i['kind']}/{i['name']}: {detail}")

    for s in spec.get("scope_suggestions", []):
        # Suggestions only: stored INACTIVE. They authorise nothing until the
        # customer's own admin activates them (and, where REQUIRE_SCOPE_PROOF is
        # on, proves control). A template can never widen a customer's scope.
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "INSERT INTO scope_entries (kind, value, added_by, notes, active, metadata) "
                "VALUES ($1,$2,$3,$4,FALSE,$5::jsonb) ON CONFLICT (tenant_id, kind, value) DO NOTHING RETURNING id",
                s["kind"], s["value"], f"msp-template:{tpl_name}",
                (s.get("notes") or "") + " [suggested by MSP template; inactive until the customer activates it]",
                json.dumps({"msp_template": tpl_name}),
            )
        bump("scope_suggestions", "created" if row else "skipped")


# --------------------------------------------------------------------------- #
# Grants
# --------------------------------------------------------------------------- #

async def set_grant(
    pool, ctx: core.MspContext, *, user_id: str, child_id: str | None, role: str, clearance: str,
    request_id: str | None, ip: str | None,
) -> dict[str, Any]:
    """Create or replace a grant. The user must belong to the MSP tenant
    (app_users is tenant-scoped, so a foreign user id is simply not found) and
    ``child_id`` must be one of its customers."""
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            user = await con.fetchrow("SELECT id, username FROM app_users WHERE id = $1 AND active", user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="no such active user in this MSP")
            child = None
            if child_id is not None:
                child = await con.fetchrow(
                    "SELECT child_tenant_id, slug FROM msp_children WHERE child_tenant_id = $1", child_id
                )
                if child is None:
                    raise HTTPException(status_code=404, detail="no such customer")
            if child_id is None:
                await con.execute("DELETE FROM msp_grants WHERE user_id = $1 AND child_tenant_id IS NULL", user_id)
            else:
                await con.execute("DELETE FROM msp_grants WHERE user_id = $1 AND child_tenant_id = $2", user_id, child_id)
            row = await con.fetchrow(
                "INSERT INTO msp_grants (tenant_id, user_id, child_tenant_id, role, clearance, granted_by) "
                "VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, user_id, child_tenant_id, role, clearance, granted_by, granted_at",
                ctx.msp_tenant_id, user_id, child_id, role, clearance, ctx.username,
            )
    await audit_both(
        pool, msp_tid=ctx.msp_tenant_id, child_tid=child_id, action="msp.grant_set", actor=ctx.username,
        actor_role=ctx.role, resource_type="grant", resource_id=str(row["id"]), request_id=request_id, ip=ip,
        msp_details={"user": user["username"], "customer": child["slug"] if child else "*",
                     "role": role, "clearance": clearance},
        child_details={"user": user["username"], "role": role},
    )
    return _grant_out(row, user["username"], child["slug"] if child else None)


def _grant_out(row, username: str | None, slug: str | None) -> dict[str, Any]:
    return {
        "id": str(row["id"]), "user_id": str(row["user_id"]), "username": username,
        "customer_id": str(row["child_tenant_id"]) if row["child_tenant_id"] else None,
        "customer_slug": slug, "all_customers": row["child_tenant_id"] is None,
        "role": row["role"], "clearance": row["clearance"], "granted_by": row["granted_by"],
        "granted_at": row["granted_at"],
    }


async def list_grants(pool, ctx: core.MspContext, *, user_id: str | None = None) -> list[dict[str, Any]]:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            rows = await con.fetch(
                "SELECT g.*, u.username, c.slug AS child_slug FROM msp_grants g "
                "  JOIN app_users u ON u.id = g.user_id "
                "  LEFT JOIN msp_children c ON c.child_tenant_id = g.child_tenant_id "
                " WHERE ($1::uuid IS NULL OR g.user_id = $1) ORDER BY u.username, c.slug NULLS FIRST",
                user_id,
            )
    return [_grant_out(r, r["username"], r["child_slug"]) for r in rows]


async def revoke_grant(
    pool, ctx: core.MspContext, grant_id: str, *, request_id: str | None, ip: str | None
) -> dict[str, Any]:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "DELETE FROM msp_grants g USING app_users u WHERE g.id = $1 AND u.id = g.user_id "
                "RETURNING g.id, g.user_id, g.child_tenant_id, g.role, g.clearance, g.granted_by, g.granted_at, u.username",
                grant_id,
            )
    if row is None:
        raise HTTPException(status_code=404, detail="grant not found")
    await audit_both(
        pool, msp_tid=ctx.msp_tenant_id, child_tid=row["child_tenant_id"] and str(row["child_tenant_id"]),
        action="msp.grant_revoked", actor=ctx.username, actor_role=ctx.role, resource_type="grant",
        resource_id=str(row["id"]), request_id=request_id, ip=ip,
        msp_details={"user": row["username"], "customer": str(row["child_tenant_id"]) if row["child_tenant_id"] else "*"},
        child_details={"user": row["username"]},
    )
    return {"revoked": True, "id": str(row["id"])}
