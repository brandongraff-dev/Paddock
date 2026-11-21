"""Shared test kit: a real Postgres, the real schema, two tenants, service roles.

Used by each compute service's ``tests/test_tenancy.py`` (and the orchestrator's
service-role audit) to prove, against Postgres row-level security, that tenant
A's job cannot read or write tenant B's rows when connected as the service's own
``paddock_svc_*`` role.

    TENANCY_TEST_PG=host:port[:user]   default 127.0.0.1:55470:postgres
                                       (ORCH_TEST_PG is honoured too)

The schema is applied ONCE per process into a template database (every
``schema/*.sql`` in order -- 029 before 099, as production does) and cloned per
test. Nothing here talks to anything but that Postgres.
"""
from __future__ import annotations

import atexit
import asyncio
import os
import uuid
from pathlib import Path

import asyncpg

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schema"

TENANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"

_template: dict[str, str] = {}


def pg_target() -> tuple[str, int, str]:
    raw = os.environ.get("TENANCY_TEST_PG") or os.environ.get("ORCH_TEST_PG") or "127.0.0.1:55470:postgres"
    host, port, *user = raw.split(":")
    return host, int(port), (user[0] if user else "postgres")


def _base() -> str:
    host, port, user = pg_target()
    return f"postgresql://{user}@{host}:{port}"


def _fix(sql: str) -> str:
    # 003_findings.sql declares an unquoted reserved word PG16 rejects; the
    # orchestrator's tests quote it the same way.
    return sql.replace("  references    TEXT[]", '  "references"    TEXT[]')


async def _ensure_template() -> str:
    if _template.get("name"):
        return _template["name"]
    name = f"tmpl_svc_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(f"{_base()}/postgres")
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    con = await asyncpg.connect(f"{_base()}/{name}")
    try:
        for path in sorted(SCHEMA_DIR.glob("*.sql")):
            await con.execute(_fix(path.read_text()))
    finally:
        await con.close()
    _template["name"] = name
    atexit.register(_drop_template, name)
    return name


def _drop_template(name: str) -> None:
    async def _go() -> None:
        admin = await asyncpg.connect(f"{_base()}/postgres")
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            await admin.close()

    try:
        asyncio.run(_go())
    except Exception:  # noqa: BLE001 - best effort
        pass


class TestDB:
    """A cloned database with the full schema. ``owner`` is the superuser DSN."""

    __test__ = False  # not a pytest class

    def __init__(self, name: str) -> None:
        self.name = name
        self.owner_dsn = f"{_base()}/{name}"

    def role_dsn(self, role: str) -> str:
        host, port, _ = pg_target()
        return f"postgresql://{role}@{host}:{port}/{self.name}"

    async def owner(self) -> asyncpg.Connection:
        return await asyncpg.connect(self.owner_dsn)

    async def seed_tenants(self) -> None:
        con = await self.owner()
        try:
            await con.execute(
                "INSERT INTO tenants (id, slug, name) VALUES ($1,'tenant-a','A'), ($2,'tenant-b','B') "
                "ON CONFLICT DO NOTHING",
                TENANT_A, TENANT_B,
            )
        finally:
            await con.close()

    async def allow_login(self, role: str) -> None:
        con = await self.owner()
        try:
            await con.execute(f'ALTER ROLE "{role}" LOGIN')
        finally:
            await con.close()

    async def as_tenant(self, tenant: str, sql: str, *args):
        """Run ``sql`` through the owner role with RLS forced on (SET ROLE paddock_app)."""
        con = await self.owner()
        try:
            async with con.transaction():
                await con.execute("SET LOCAL ROLE paddock_app")
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
                return await con.fetch(sql, *args)
        finally:
            await con.close()

    async def raw(self, sql: str, *args):
        """Superuser (bypasses RLS) -- for seeding / assertions only."""
        con = await self.owner()
        try:
            return await con.fetch(sql, *args)
        finally:
            await con.close()

    async def drop(self) -> None:
        admin = await asyncpg.connect(f"{_base()}/postgres")
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')
        finally:
            await admin.close()


async def make_db(*, roles: tuple[str, ...] = ()) -> TestDB:
    """Clone the template; two tenants (A, B) seeded; ``roles`` may log in."""
    tmpl = await _ensure_template()
    name = f"t_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(f"{_base()}/postgres")
    try:
        await admin.execute(f'CREATE DATABASE "{name}" TEMPLATE "{tmpl}"')
    finally:
        await admin.close()
    db = TestDB(name)
    await db.seed_tenants()
    for r in roles:
        await db.allow_login(r)
    return db


# --------------------------------------------------------------------------- #
# Seeding (superuser; explicit tenant_id) + shared assertions
# --------------------------------------------------------------------------- #

async def seed_asset(db: TestDB, tenant: str, value: str, kind: str = "domain",
                     metadata: str = "{}") -> str:
    rows = await db.raw(
        "INSERT INTO assets (kind, value, canonical, source, metadata, tenant_id) "
        "VALUES ($1, $2, $2, 'test', $3::jsonb, $4) RETURNING id::text",
        kind, value, metadata, tenant,
    )
    return rows[0][0]


async def seed_finding(db: TestDB, tenant: str, asset_id: str, rule: str = "r1",
                       severity: str = "high") -> str:
    rows = await db.raw(
        "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, tenant_id) "
        "VALUES ($1::uuid, $2, 'manual', $3, 'T '||$2, 'd', $4) RETURNING id::text",
        asset_id, rule, severity, tenant,
    )
    return rows[0][0]


async def role_info(dsn: str) -> dict:
    con = await asyncpg.connect(dsn)
    try:
        r = await con.fetchrow(
            "SELECT current_user AS u, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        return dict(r)
    finally:
        await con.close()


async def expect_denied(coro, *, what: str = "statement") -> Exception:
    """Await ``coro`` and require a privilege / RLS rejection."""
    import asyncpg.exceptions as ax

    try:
        await coro
    except (ax.InsufficientPrivilegeError, ax.UndefinedTableError) as exc:
        return exc
    except asyncpg.PostgresError as exc:  # pragma: no cover - surfaced for debugging
        raise AssertionError(f"{what}: expected a privilege/RLS rejection, got {exc!r}") from exc
    raise AssertionError(f"{what}: was ALLOWED but must be rejected")


async def session_tenant_after_release(database) -> str | None:
    """The ``app.tenant_id`` a *fresh* acquire on the service pool sees BEFORE any
    scoping: must be empty (SET LOCAL never leaks through the pool)."""
    async with database.pool.acquire() as con:
        return await con.fetchval("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
