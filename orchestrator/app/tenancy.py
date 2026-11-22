"""Multi-tenancy: request-scoped tenant context -> Postgres RLS.

How isolation works (see schema/099_tenancy.sql and docs/trust/TENANCY.md):

* Every tenant-scoped table carries ``tenant_id`` and a FORCEd row-level
  security policy ``tenant_id = paddock_current_tenant()``, where
  ``paddock_current_tenant()`` reads the session GUC ``app.tenant_id``.
* The orchestrator connects as the non-superuser ``paddock_app`` role (RLS is
  bypassed by superusers and BYPASSRLS roles -- ``db.warn_if_privileged``
  shouts about that at startup).
* The tenant of the current request lives in a ``ContextVar`` set by the
  governance middleware from the resolved principal. ``db.create_pool``
  installs :func:`setup_connection` as the pool's ``setup`` hook, so EVERY
  ``pool.acquire()`` stamps ``app.tenant_id`` onto the connection before the
  caller sees it. asyncpg's release-time reset (``RESET ALL``) clears it again,
  so a pooled connection never carries a previous request's tenant.

Because the scoping happens at acquire time, existing queries need no
``WHERE tenant_id = ...`` clause and INSERTs need no tenant column: the column
default reads the same GUC and the policy's WITH CHECK rejects anything else.

Code with no tenant in context (startup, background loops, tests that build
their own pool) runs in the default tenant -- unless ``TENANCY_STRICT=true``,
in which case it runs with NO tenant and sees nothing / can write nothing.
"""
from __future__ import annotations

import contextlib
import contextvars
import logging
import uuid
from typing import Any, Iterator

from .config import settings

logger = logging.getLogger(__name__)

#: The tenant every pre-tenancy row belongs to (and single-tenant installs use).
DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"

#: Header a *service* principal (SERVICE_API_KEY) uses to pick its tenant.
TENANT_HEADER = "x-paddock-tenant"

_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "paddock_tenant_id", default=None
)
_auth_lookup: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "paddock_auth_lookup", default=False
)


def _norm(tenant_id: Any) -> str | None:
    if tenant_id is None or tenant_id == "":
        return None
    return str(uuid.UUID(str(tenant_id)))  # validates; raises ValueError


#: Public name for the validator (raises ValueError on a malformed id).
norm = _norm


def current_tenant_id() -> str | None:
    """The tenant queries in this context run as (None = no tenant).

    No explicit tenant falls back to the default tenant, except in strict mode.
    """
    t = _tenant.get()
    if t is not None:
        return t
    return None if settings.tenancy_strict else DEFAULT_TENANT_ID


def current_tenant_key() -> str:
    """A cache key for per-tenant in-process caches."""
    return current_tenant_id() or "-"


def event_visible_to(payload: dict, caller_tenant: str | None) -> bool:
    """May ``caller_tenant`` see this stream event? Events are stamped with a
    ``tenant_id`` by ``queue.publish_event``; an unstamped (legacy) event
    belongs to the default tenant, and in strict mode to nobody."""
    if caller_tenant is None:
        return False
    ev = payload.get("tenant_id")
    if ev in (None, ""):
        return not settings.tenancy_strict and caller_tenant == DEFAULT_TENANT_ID
    try:
        return _norm(ev) == caller_tenant
    except ValueError:
        return False


def set_tenant(tenant_id: Any) -> contextvars.Token:
    """Bind ``tenant_id`` to the current context. Pair with :func:`reset_tenant`."""
    return _tenant.set(_norm(tenant_id))


def reset_tenant(token: contextvars.Token) -> None:
    _tenant.reset(token)


@contextlib.contextmanager
def tenant_context(tenant_id: Any) -> Iterator[str | None]:
    """Run a block as ``tenant_id`` (e.g. a background job for one tenant)."""
    token = set_tenant(tenant_id)
    try:
        yield _tenant.get()
    finally:
        _tenant.reset(token)


@contextlib.contextmanager
def auth_lookup() -> Iterator[None]:
    """Credential resolution: the tenant is not known until the key/user row is
    read, so app_users/api_keys are readable across tenants inside this block
    (their RLS policy honours ``app.auth_lookup``). No other table is."""
    token = _auth_lookup.set(True)
    try:
        yield
    finally:
        _auth_lookup.reset(token)


async def setup_connection(con) -> None:
    """asyncpg pool ``setup`` hook: stamp the context's tenant on the session.

    ``set_config(..., false)`` is session-scoped; asyncpg's release reset
    (``RESET ALL``) returns it to the role default, so nothing leaks between
    acquisitions. In auth-lookup mode no tenant is set at all.
    """
    if _auth_lookup.get():
        tenant, lookup = "", "on"
    else:
        tenant, lookup = (current_tenant_id() or ""), "off"
    await con.execute(
        "SELECT set_config('app.tenant_id', $1, false), set_config('app.auth_lookup', $2, false)",
        tenant,
        lookup,
    )


async def list_tenant_ids(pool, *, active_only: bool = True) -> list[str]:
    """All tenant ids (the app role may read the tenants catalogue).

    Falls back to ``[DEFAULT_TENANT_ID]`` when the tenants table is absent so
    background loops keep working on a not-yet-migrated database.
    """
    sql = "SELECT id FROM tenants" + (" WHERE status = 'active'" if active_only else "") + " ORDER BY created_at, id"
    try:
        async with pool.acquire() as con:
            rows = await con.fetch(sql)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tenant_list_failed", extra={"error": str(exc)})
        return [DEFAULT_TENANT_ID]
    return [str(r["id"]) for r in rows] or [DEFAULT_TENANT_ID]


async def resolve_tenant_ref(pool, ref: str) -> str | None:
    """Map a tenant id or slug (from ``X-Paddock-Tenant``) to an active tenant id."""
    ref = (ref or "").strip()
    if not ref:
        return None
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id FROM tenants WHERE (id::text = $1 OR slug = $1) AND status = 'active'",
            ref.lower(),
        )
    return str(row["id"]) if row else None


async def create_tenant(owner_pool, *, slug: str, name: str, tenant_id: str | None = None) -> str:
    """Create a tenant. Needs the schema OWNER (the app role may not write
    ``tenants``). Returns the new tenant id. Seeds nothing else: users are
    created inside the tenant afterwards (see ``python -m app.tenancy``)."""
    async with owner_pool.acquire() as con:
        row = await con.fetchrow(
            "INSERT INTO tenants (id, slug, name) VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, $3) "
            "RETURNING id",
            tenant_id,
            slug,
            name,
        )
    return str(row["id"])


# --------------------------------------------------------------------------- #
# Database roles (schema/100_app_role.sh + 101_service_roles.sh, or this CLI)
# --------------------------------------------------------------------------- #

#: Compute services that connect as their own least-privilege role
#: ``paddock_svc_<name>`` (schema/029_service_tenancy.sql).
SERVICE_ROLE_NAMES = (
    "intel", "correlation", "mlrisk", "triage", "ontology", "threatintel",
    "otdiscovery", "changewatch", "brain", "remediation", "sca", "codeanalysis",
    "graphsync",
)


def role_password(role: str, env: dict[str, str] | None = None) -> str | None:
    """Password for a DB role from the environment, first match wins:
    ``PADDOCK_SVC_<NAME>_DB_PASSWORD`` (service roles) -> ``PADDOCK_SERVICES_DB_PASSWORD``
    (service roles) -> ``PADDOCK_APP_DB_PASSWORD`` -> ``POSTGRES_PASSWORD``."""
    import os

    e = os.environ if env is None else env
    names: list[str] = []
    if role.startswith("paddock_svc_"):
        names += [f"PADDOCK_SVC_{role[len('paddock_svc_'):].upper()}_DB_PASSWORD", "PADDOCK_SERVICES_DB_PASSWORD"]
    names += ["PADDOCK_APP_DB_PASSWORD", "POSTGRES_PASSWORD"]
    for n in names:
        if e.get(n):
            return e[n]
    return None


async def provision_roles(con, env: dict[str, str] | None = None) -> dict[str, str]:
    """Give ``paddock_app`` and every ``paddock_svc_*`` role LOGIN + a password
    (needs the schema owner). Roles with no configured password stay NOLOGIN.
    Idempotent. Returns ``{role: "login" | "nologin" | "missing"}``."""
    out: dict[str, str] = {}
    for role in ("paddock_app", *(f"paddock_svc_{n}" for n in SERVICE_ROLE_NAMES)):
        if not await con.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role):
            out[role] = "missing"
            continue
        pw = role_password(role, env)
        if not pw:
            out[role] = "nologin"
            continue
        stmt = await con.fetchval("SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', $1::text, $2::text)", role, pw)
        await con.execute(stmt)
        out[role] = "login"
    return out


# --------------------------------------------------------------------------- #
# Operator CLI:  python -m app.tenancy create <slug> "<name>" [--admin USER]
#                python -m app.tenancy provision-roles
# Run with OWNER_DATABASE_URL (the schema owner / migration role).
# --------------------------------------------------------------------------- #

async def _cli(argv: list[str]) -> int:
    import argparse
    import os
    import secrets

    import asyncpg

    from .auth import hash_password
    from .db import _coerce_dsn

    p = argparse.ArgumentParser(prog="python -m app.tenancy")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="create a tenant (+ optional admin user)")
    c.add_argument("slug")
    c.add_argument("name")
    c.add_argument("--admin", help="username of the tenant's first admin")
    sub.add_parser("list", help="list tenants")
    sub.add_parser("provision-roles", help="set LOGIN + passwords on paddock_app and the paddock_svc_* roles")
    args = p.parse_args(argv)

    dsn = os.environ.get("OWNER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        print("set OWNER_DATABASE_URL (schema owner) first")
        return 2
    con = await asyncpg.connect(_coerce_dsn(dsn))
    try:
        if args.cmd == "provision-roles":
            for role, state in (await provision_roles(con)).items():
                print(f"{role:<28} {state}")
            return 0
        if args.cmd == "list":
            for r in await con.fetch("SELECT id, slug, name, status FROM tenants ORDER BY created_at"):
                print(f"{r['id']}  {r['slug']:<24} {r['status']:<10} {r['name']}")
            return 0
        tid = await con.fetchval(
            "INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING id", args.slug, args.name
        )
        print(f"tenant {args.slug}: {tid}")
        if args.admin:
            pw = secrets.token_urlsafe(18)
            async with con.transaction():
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", str(tid))
                await con.execute(
                    "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
                    "VALUES ($1, 'admin', 'restricted', $2, $3)",
                    args.admin,
                    hash_password(pw),
                    tid,
                )
            print(f"admin user {args.admin!r} password (shown once): {pw}")
        return 0
    finally:
        await con.close()


if __name__ == "__main__":  # pragma: no cover
    import asyncio
    import sys

    raise SystemExit(asyncio.run(_cli(sys.argv[1:])))
