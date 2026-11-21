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
# Operator CLI:  python -m app.tenancy create <slug> "<name>" [--admin USER]
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
    args = p.parse_args(argv)

    dsn = os.environ.get("OWNER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        print("set OWNER_DATABASE_URL (schema owner) first")
        return 2
    con = await asyncpg.connect(_coerce_dsn(dsn))
    try:
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
