"""Tenant isolation for threatintel against real Postgres RLS
(``paddock_svc_threatintel``): the IOC catalogue is global and platform-written;
matches are per-tenant rows."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import ThreatIntelService  # noqa: E402

ROLE = "paddock_svc_threatintel"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = ThreatIntelService(config_module.load())
    svc.db = Database(tdb.role_dsn(ROLE))
    await svc.db.connect()
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    try:
        yield tdb, svc, a, b
    finally:
        await svc.db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_indicators_are_global_written_by_the_platform_even_from_a_tenant_job(env):
    tdb, svc, a, b = env
    with tenancy.tenant_context(kit.TENANT_A):
        res = await svc.db.upsert_indicator({"type": "domain", "value": "evil.example", "labels": []})
        assert res["inserted"]
    cols = await tdb.raw("SELECT 1 FROM information_schema.columns WHERE table_name='ti_indicators' AND column_name='tenant_id'")
    assert cols == []  # a global catalogue: no tenant column to stamp with A's id
    assert (await tdb.raw("SELECT count(*) FROM ti_indicators"))[0][0] == 1
    with tenancy.tenant_context(kit.TENANT_B):
        assert await svc.db.count_indicators() == 1  # everyone reads the catalogue
        async with svc.db.acquire() as con:  # ...but a tenant cannot write it directly
            await kit.expect_denied(con.execute(
                "INSERT INTO ti_indicators (type, value) VALUES ('domain','x.example')"), what="tenant IOC write")


async def test_non_platform_tenant_cannot_register_feeds_or_ingest(env):
    _, svc, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        denied = svc._platform_only(make_mocked_request("POST", "/feeds"))
        assert denied is not None and denied.status == 403
    with tenancy.platform_context():
        assert svc._platform_only(make_mocked_request("POST", "/feeds")) is None


async def test_matches_are_per_tenant(env):
    tdb, svc, a, b = env
    ind = (await svc.db.upsert_indicator({"type": "domain", "value": "a.example.com", "labels": []}))["id"]
    with tenancy.tenant_context(kit.TENANT_A):
        assert await svc.db.upsert_match(
            indicator_id=ind, subject_type="asset", subject_id=a, matched_value="a.example.com", severity="high")
    with tenancy.tenant_context(kit.TENANT_B):
        assert await svc.db.count_matches() == 0  # A's match is invisible to B
        assert [x["id"] for x in await svc.db.list_match_assets(kinds=["domain"])] == [b]  # B only sees B's assets
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO ti_matches (indicator_id, subject_type, subject_id, matched_value, tenant_id) "
                "VALUES ($1::uuid, 'asset', $2::uuid, 'x', $3)", ind, a, kit.TENANT_A), what="match for A written as B")
    with tenancy.tenant_context(kit.TENANT_A):
        assert await svc.db.count_matches() == 1
