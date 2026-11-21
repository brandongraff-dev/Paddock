"""graphsync is single-tenant by design (one Neo4j graph, no per-tenant
isolation in Neo4j Community): prove it can never mirror or serve another
tenant's data, against real Postgres RLS (``paddock_svc_graphsync``)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import GraphSyncService  # noqa: E402

ROLE = "paddock_svc_graphsync"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    d = await kit.seed_asset(tdb, kit.DEFAULT_TENANT, "platform.example.com")
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    await kit.seed_finding(tdb, kit.TENANT_A, a)
    try:
        yield tdb, db, d, a, b
    finally:
        await db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, db, *_ = env
    info = await tenancy.check_role(db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_sync_reads_never_include_another_tenant_whatever_the_context(env):
    _, db, d, a, b = env
    for ctx in (kit.TENANT_A, kit.TENANT_B, None):
        if ctx is None:
            rows = await db.fetch_assets(None)
        else:
            with tenancy.tenant_context(ctx):  # a bug binding a tenant cannot widen or redirect it
                rows = await db.fetch_assets(None)
        assert {r["id"] for r in rows} == {d}
        assert await db.fetch_open_findings(since=None) == []


async def test_cursor_lives_in_the_tenant_scoped_table_not_the_global_one(env):
    tdb, db, *_ = env
    await db.set_cursor(stats={"nodes": 3})
    rows = await tdb.raw("SELECT tenant_id::text, service FROM service_cursors")
    assert [tuple(r) for r in rows] == [(kit.DEFAULT_TENANT, "graphsync")]
    assert (await db.get_cursor())["stats"] == {"nodes": 3}


async def test_other_tenants_get_the_unavailable_degrade_not_the_platform_graph(env, monkeypatch):
    _, db, *_ = env
    svc = GraphSyncService(config_module.load())
    svc.db = db
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    client = TestClient(TestServer(svc._make_app()))
    await client.start_server()
    try:
        key = {"X-API-Key": "svc-key"}
        for path in ("/paths", "/blast/x", "/neighborhood/x", "/stats"):
            r = await client.get(path, headers={**key, tenancy.TENANT_HEADER: kit.TENANT_A})
            body = await r.json()
            assert r.status == 200 and body["available"] is False and "single-tenant" in body["reason"], path
        r = await client.post("/resync", headers={**key, tenancy.TENANT_HEADER: kit.TENANT_B})
        assert (await r.json())["available"] is False
        # selecting a tenant without the service key is refused outright
        r = await client.get("/paths", headers={tenancy.TENANT_HEADER: kit.TENANT_A})
        assert r.status == 403
    finally:
        await client.close()
