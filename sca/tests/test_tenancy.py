"""Tenant isolation for the SCA service against real Postgres RLS
(``paddock_svc_sca``)."""
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
from app.main import ScaService  # noqa: E402

ROLE = "paddock_svc_sca"
pytestmark = pytest.mark.asyncio

_COMP = {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "direct": True, "depth": 0}
_VULN = {"osv_id": "GHSA-xxxx", "cve_id": "CVE-2099-9", "severity": "high", "fixed_version": "1.0.1"}


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    try:
        yield tdb, db
    finally:
        await db.close()
        await tdb.drop()


async def _scan(db, tenant, name="shop"):
    with tenancy.tenant_context(tenant):
        p = await db.upsert_project(name, "repo", ["npm"])
        c = await db.upsert_component(p["id"], _COMP)
        await db.upsert_vuln(c["id"], _VULN)
        await db.upsert_risk(p["id"], c["id"], {"risk_type": "unpinned", "summary": "s"})
        return p["id"], c["id"]


async def test_least_privilege_role(env):
    _, db = env
    info = await tenancy.check_role(db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_same_project_name_in_two_tenants_never_collides_or_leaks(env):
    tdb, db = env
    pa, ca = await _scan(db, kit.TENANT_A)
    pb, cb = await _scan(db, kit.TENANT_B)  # same project NAME "shop": per-tenant key
    assert pa != pb and ca != cb
    with tenancy.tenant_context(kit.TENANT_A):
        assert [r["id"] for r in await db.fetch("SELECT id::text AS id FROM sca_projects")] == [pa]
        assert (await db.stats())["projects"] == 1
    with tenancy.tenant_context(kit.TENANT_B):
        assert [r["id"] for r in await db.fetch("SELECT id::text AS id FROM sbom_components")] == [cb]
    rows = await tdb.raw("SELECT tenant_id::text FROM sca_projects ORDER BY tenant_id")
    assert [r[0] for r in rows] == [kit.TENANT_A, kit.TENANT_B]


async def test_a_job_cannot_write_into_another_tenants_project(env):
    _, db = env
    pa, _ = await _scan(db, kit.TENANT_A)
    with tenancy.tenant_context(kit.TENANT_B):
        async with db.acquire() as con:  # attach a component to A's project while acting as B
            await kit.expect_denied(con.execute(
                "INSERT INTO sbom_components (project_id, ecosystem, name, version, tenant_id) "
                "VALUES ($1::uuid, 'npm', 'x', '1', $2)", pa, kit.TENANT_A), what="component in A's partition")
        assert await db.execute("UPDATE sca_projects SET source_ref = 'pwned'") == "UPDATE 0"
        assert await db.execute("DELETE FROM sbom_components") == "DELETE 0"


async def test_scan_dir_is_platform_only_and_tenant_header_needs_the_key(env, monkeypatch):
    _, db = env
    svc = ScaService(config_module.load())
    svc.db = db
    monkeypatch.setenv("SERVICE_API_KEY", "svc-key")
    client = TestClient(TestServer(svc._make_app()))
    await client.start_server()
    try:
        hdr = {tenancy.TENANT_HEADER: kit.TENANT_A}
        assert (await client.post("/scan-dir", json={"path": "/tmp"}, headers=hdr)).status == 403  # no key
        r = await client.post("/scan-dir", json={"path": "/tmp"}, headers={**hdr, "X-API-Key": "svc-key"})
        assert r.status == 403 and "platform" in (await r.json())["error"]
    finally:
        await client.close()
