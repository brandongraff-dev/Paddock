"""Tenant isolation for codeanalysis against real Postgres RLS
(``paddock_svc_codeanalysis``)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402

ROLE = "paddock_svc_codeanalysis"
pytestmark = pytest.mark.asyncio


async def _seed_project(tdb, tenant: str, name: str = "shop") -> tuple[str, str]:
    pid = (await tdb.raw(
        "INSERT INTO sca_projects (name, tenant_id) VALUES ($1, $2) RETURNING id::text", name, tenant))[0][0]
    cid = (await tdb.raw(
        "INSERT INTO sbom_components (project_id, ecosystem, name, version, tenant_id) "
        "VALUES ($1::uuid, 'npm', 'left-pad', '1.0.0', $2) RETURNING id::text", pid, tenant))[0][0]
    vid = (await tdb.raw(
        "INSERT INTO sbom_component_vulns (component_id, osv_id, severity, tenant_id) "
        "VALUES ($1::uuid, 'GHSA-1', 'high', $2) RETURNING id::text", cid, tenant))[0][0]
    return pid, vid


def _finding(pid: str) -> dict:
    return dict(project_id=pid, asset_id=None, engine="semgrep", rule="r", message="m",
                severity="high", file="a.py", start_line=1, end_line=2, source=None, sink=None,
                dataflow=[], cwe=None, metadata={})


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    pa, va = await _seed_project(tdb, kit.TENANT_A)
    pb, vb = await _seed_project(tdb, kit.TENANT_B)  # same project name in both tenants
    try:
        yield tdb, db, (pa, va), (pb, vb)
    finally:
        await db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, db, *_ = env
    info = await tenancy.check_role(db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_project_lookup_and_vulns_are_tenant_scoped(env):
    _, db, (pa, va), (pb, vb) = env
    with tenancy.tenant_context(kit.TENANT_A):
        assert (await db.get_project("shop"))["id"] == pa
        assert [v["vuln_id"] for v in await db.fetch_project_vulns("shop")] == [va]
    with tenancy.tenant_context(kit.TENANT_B):
        assert (await db.get_project("shop"))["id"] == pb
        assert [v["vuln_id"] for v in await db.fetch_project_vulns("shop")] == [vb]


async def test_reachability_update_cannot_touch_another_tenants_vuln(env):
    tdb, db, (pa, va), (pb, vb) = env
    with tenancy.tenant_context(kit.TENANT_A):
        assert await db.update_reachability(vb, "reachable", "sym", []) is False  # B's vuln id: invisible
        assert await db.update_reachability(va, "reachable", "sym", []) is True
    rows = await tdb.raw("SELECT tenant_id::text, reachability FROM sbom_component_vulns ORDER BY tenant_id")
    assert [r[0] for r in rows if r[1] == "reachable"] == [kit.TENANT_A]


async def test_sast_findings_land_only_in_the_callers_tenant(env):
    tdb, db, (pa, va), (pb, vb) = env
    with tenancy.tenant_context(kit.TENANT_A):
        await db.upsert_code_finding(**_finding(pa))
        with pytest.raises(Exception) as exc:  # a finding attached to B's project, written as A
            async with db.acquire() as con:
                await con.execute(
                    "INSERT INTO code_findings (project_id, engine, rule, message, severity, file, tenant_id) "
                    "VALUES ($1::uuid, 'semgrep', 'r', 'm', 'high', 'f', $2)", pb, kit.TENANT_B)
        assert "row-level security" in str(exc.value)
    rows = await tdb.raw("SELECT tenant_id::text FROM code_findings")
    assert [r[0] for r in rows] == [kit.TENANT_A]
    with tenancy.tenant_context(kit.TENANT_B):
        assert (await db.stats())["code_findings"] == 0
