"""Test fixtures.

- Real Postgres via pytest-postgresql (fast startup, one proc per session,
  one disposable DB per test).
- fakeredis for Redis (so we don't need a real server).
- An asyncpg pool attached to app.state.pool; the FastAPI app is driven
  by httpx.AsyncClient against the in-memory ASGI transport.

Scope and DNS caches are reset per test so inter-test state can't leak.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import asyncpg
import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pytest_postgresql import factories

# Make the pg16 binaries discoverable (where pytest-postgresql looks).
PG_BIN = "/usr/lib/postgresql/16/bin"
if Path(PG_BIN).is_dir() and PG_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = PG_BIN + os.pathsep + os.environ.get("PATH", "")

# Make the app import-able regardless of pytest cwd.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA_DIR = ROOT.parent / "schema"


postgresql_my_proc = factories.postgresql_proc(
    executable=str(Path(PG_BIN) / "pg_ctl"),
    port=None,
)


@pytest_asyncio.fixture
async def db_pool(postgresql_my_proc):
    """Fresh database per test, schema applied."""
    host = postgresql_my_proc.host
    port = postgresql_my_proc.port
    user = postgresql_my_proc.user
    password = postgresql_my_proc.password
    auth = f"{user}:{password}" if password else user
    admin_dsn = f"postgresql://{auth}@{host}:{port}/postgres"

    dbname = f"test_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(admin_dsn)
    await admin.execute(f'CREATE DATABASE "{dbname}"')
    await admin.close()

    dsn = f"postgresql://{auth}@{host}:{port}/{dbname}"
    pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=4)
    async with pool.acquire() as con:
        for f in sorted(SCHEMA_DIR.glob("*.sql")):
            sql_text = f.read_text()
            # Contract defect workaround: schema/003_findings.sql declares a
            # column named `references` without quotes, which Postgres 16
            # rejects as a reserved keyword. We quote it for our tests; the
            # orchestrator's SQL already uses the quoted form.
            sql_text = sql_text.replace(
                "  references    TEXT[]", '  "references"    TEXT[]'
            )
            await con.execute(sql_text)

    try:
        yield pool
    finally:
        await pool.close()
        admin = await asyncpg.connect(admin_dsn)
        # Terminate any lingering connections, then drop.
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = $1 AND pid <> pg_backend_pid()",
            dbname,
        )
        await admin.execute(f'DROP DATABASE "{dbname}"')
        await admin.close()


@pytest_asyncio.fixture
async def fake_redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    try:
        yield r
    finally:
        await r.aclose()


@pytest.fixture(autouse=True)
def reset_scope_caches():
    from app import scope as scope_svc

    scope_svc.scope_cache.invalidate()
    scope_svc.dns_cache._by_host.clear()
    yield
    scope_svc.scope_cache.invalidate()
    scope_svc.dns_cache._by_host.clear()


@pytest_asyncio.fixture
async def app(db_pool, fake_redis):
    """FastAPI app with lifespan bypassed; we attach pool/redis directly."""
    from app.main import create_app
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _noop_lifespan(app):
        yield

    # Build the app without running the lifespan (which would try real conns).
    from app import main as main_mod

    original_lifespan = main_mod.lifespan
    main_mod.lifespan = _noop_lifespan
    try:
        app_obj = create_app()
    finally:
        main_mod.lifespan = original_lifespan

    app_obj.state.pool = db_pool
    app_obj.state.redis = fake_redis
    return app_obj


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
