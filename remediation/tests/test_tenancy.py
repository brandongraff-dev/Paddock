"""Tenant isolation for remediation against real Postgres RLS
(``paddock_svc_remediation``)."""
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
from app.main import RemediationService  # noqa: E402

ROLE = "paddock_svc_remediation"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = RemediationService(config_module.load())
    svc.db = Database(tdb.role_dsn(ROLE))
    svc.pipeline.db = svc.db
    await svc.db.connect()
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    fa = await kit.seed_finding(tdb, kit.TENANT_A, a)
    fb = await kit.seed_finding(tdb, kit.TENANT_B, b)
    try:
        yield tdb, svc, fa, fb
    finally:
        await svc.db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_a_job_cannot_see_or_remediate_another_tenants_finding(env):
    _, svc, fa, fb = env
    with tenancy.tenant_context(kit.TENANT_A):
        assert (await svc.db.get_finding(fa)) is not None
        assert (await svc.db.get_finding(fb)) is None  # B's finding id is simply not there
    with tenancy.tenant_context(kit.TENANT_B):
        assert (await svc.db.get_finding(fa)) is None


async def test_remediation_rows_are_per_tenant(env):
    tdb, svc, fa, fb = env
    with tenancy.tenant_context(kit.TENANT_A):
        await svc.db.insert_remediation({"finding_id": fa, "kind": "dependency_bump", "summary": "A fix"})
    with tenancy.tenant_context(kit.TENANT_B):
        assert (await svc.db.list_remediations())[1] == 0
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO remediations (finding_id, kind, summary, tenant_id) "
                "VALUES ($1::uuid, 'dependency_bump', 'x', $2)", fa, kit.TENANT_A), what="remediation for A written as B")
    rows = await tdb.raw("SELECT tenant_id::text FROM remediations")
    assert [r[0] for r in rows] == [kit.TENANT_A]


async def test_http_tenant_selection_needs_the_service_key(env, monkeypatch):
    _, svc, fa, fb = env
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    client = TestClient(TestServer(svc._make_app()))
    await client.start_server()
    try:
        hdr = {tenancy.TENANT_HEADER: kit.TENANT_A}
        r = await client.post("/propose", json={"finding_id": fa}, headers=hdr)  # no key
        assert r.status == 403
        r = await client.post("/propose", json={"finding_id": fb},
                              headers={**hdr, "X-API-Key": "svc-key"})  # B's finding, A's context
        assert r.status == 404 and (await r.json())["error"] == "finding_not_found"
    finally:
        await client.close()
