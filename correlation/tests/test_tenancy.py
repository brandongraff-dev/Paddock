"""Tenant isolation for the correlation service against real Postgres RLS
(connected as ``paddock_svc_correlation``)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.engine.attackpath import AttackPathEngine  # noqa: E402

ROLE = "paddock_svc_correlation"
pytestmark = pytest.mark.asyncio


def _path(a: str, b: str, fp: str) -> dict:
    return {
        "source_asset_id": a, "target_asset_id": b, "hops": [], "length": 1,
        "total_cost": 1.0, "exploitability": 50.0, "severity": "high",
        "title": f"path {fp}", "narrative": None, "kev_on_path": False,
        "fingerprint": fp, "metadata": {},
    }


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    a1 = await kit.seed_asset(tdb, kit.TENANT_A, "a1.example.com")
    a2 = await kit.seed_asset(tdb, kit.TENANT_A, "a2.example.com")
    b1 = await kit.seed_asset(tdb, kit.TENANT_B, "b1.example.com")
    b2 = await kit.seed_asset(tdb, kit.TENANT_B, "b2.example.com")
    try:
        yield tdb, db, (a1, a2), (b1, b2)
    finally:
        await db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    tdb, db, *_ = env
    info = await tenancy.check_role(db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]
    async with db.acquire() as con:
        await kit.expect_denied(con.fetch("SELECT * FROM audit_log"), what="audit_log")


async def test_attack_path_jobs_are_isolated_including_prune(env):
    tdb, db, (a1, a2), (b1, b2) = env
    eng = AttackPathEngine(db)
    with tenancy.tenant_context(kit.TENANT_A):
        assert len(await eng._persist([_path(a1, a2, "fp-shared")])) == 1
    with tenancy.tenant_context(kit.TENANT_B):
        # same natural key (fingerprint) in another tenant: no collision, no leak
        assert len(await eng._persist([_path(b1, b2, "fp-shared")])) == 1
    with tenancy.tenant_context(kit.TENANT_A):
        # tenant A's run saw nothing this time -> prunes ITS paths only
        await eng._persist([])
        assert await db.fetch("SELECT 1 FROM attack_paths") == []
    with tenancy.tenant_context(kit.TENANT_B):
        rows = await db.fetch("SELECT source_asset_id::text AS s FROM attack_paths")
        assert [r["s"] for r in rows] == [b1]
    # superuser view: B's row survived with B's tenant id
    raw = await tdb.raw("SELECT tenant_id::text FROM attack_paths")
    assert [r[0] for r in raw] == [kit.TENANT_B]


async def test_cannot_write_other_tenants_rows(env):
    tdb, db, (a1, a2), (b1, b2) = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO finding_chains (chain_rule_id, severity, title, description, finding_ids, tenant_id) "
                "VALUES ('r','high','t','d','{}', $1)", kit.TENANT_B), what="insert into B")


async def test_attack_catalogue_is_platform_write_only(env):
    tdb, db, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO attack_technique_map (technique_id, technique, tactic) "
                "VALUES ('T0','n','t')"), what="tenant write to the global ATT&CK map")
    with tenancy.platform_context():
        async with db.acquire() as con:
            await con.execute(
                "INSERT INTO attack_technique_map (technique_id, technique, tactic) "
                "VALUES ('T0','n','t')")


async def test_events_must_name_a_tenant_in_strict_mode(monkeypatch):
    monkeypatch.setenv("TENANCY_STRICT", "true")
    with pytest.raises(tenancy.TenantError):
        with tenancy.bind_event({"event": "finding_opened"}):
            pass
    with tenancy.bind_event({"event": "finding_opened", "tenant_id": kit.TENANT_A}):
        assert tenancy.current_tenant_id() == kit.TENANT_A
    ev = tenancy.stamp_event({"event": "x"})
    assert "tenant_id" not in ev  # strict + unbound: nothing to stamp
