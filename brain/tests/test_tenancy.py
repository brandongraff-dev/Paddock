"""Tenant isolation for brain (NL-query SQL executes here!) against real
Postgres RLS as ``paddock_svc_brain``."""
from __future__ import annotations

import sys
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import BrainService  # noqa: E402

ROLE = "paddock_svc_brain"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    await kit.seed_finding(tdb, kit.TENANT_A, a, "rule-a")
    await kit.seed_finding(tdb, kit.TENANT_B, b, "rule-b")
    try:
        yield tdb, db
    finally:
        await db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, db = env
    info = await tenancy.check_role(db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_nl_query_sql_only_ever_sees_the_callers_tenant(env):
    _, db = env
    with tenancy.tenant_context(kit.TENANT_A):
        cols, rows = await db.run_readonly_select("SELECT rule_id FROM ask_findings", 5000, 100)
        assert [r[0] for r in rows] == ["rule-a"]
        # even a hostile "give me everything" query is pinned by RLS
        _, rows = await db.run_readonly_select("SELECT value FROM ask_assets", 5000, 100)
        assert [r[0] for r in rows] == ["a.example.com"]
    with tenancy.tenant_context(kit.TENANT_B):
        _, rows = await db.run_readonly_select("SELECT rule_id FROM ask_findings", 5000, 100)
        assert [r[0] for r in rows] == ["rule-b"]


async def test_nl_query_sql_cannot_escape_its_tenant_or_write_or_reach_secrets(env):
    _, db = env
    with tenancy.tenant_context(kit.TENANT_A):
        # Even if the validator were bypassed, moving the tenant GUC mid-statement
        # must not return another tenant's rows (the DB layer discards them)...
        for evil in (
            f"WITH s AS (SELECT set_config('app.tenant_id','{kit.TENANT_B}',true)) "
            "SELECT rule_id FROM s, ask_findings",
            f"SELECT set_config('app.tenant_id','{kit.TENANT_B}',true), rule_id FROM ask_findings",
        ):
            with pytest.raises(PermissionError):
                await db.run_readonly_select(evil, 5000, 100)
        # ...and the validator itself refuses set_config in the first place.
        from app import guard
        assert not guard.validate(
            f"WITH s AS (SELECT set_config('app.tenant_id','{kit.TENANT_B}',true)) SELECT rule_id FROM s, ask_findings")[0]
        _, rows = await db.run_readonly_select("SELECT rule_id FROM ask_findings", 5000, 100)
        assert [r[0] for r in rows] == ["rule-a"]
        for evil in ("DELETE FROM findings", "UPDATE findings SET severity = 'low'",
                     "INSERT INTO nl_queries (question) VALUES ('x')"):
            with pytest.raises(asyncpg.PostgresError):
                await db.run_readonly_select(evil, 5000, 100)
        with pytest.raises(asyncpg.PostgresError):
            await db.run_readonly_select("SELECT * FROM app_users", 5000, 100)
        with pytest.raises(asyncpg.PostgresError):
            await db.run_readonly_select("SELECT * FROM audit_log", 5000, 100)
    # nothing was changed by any of that
    with tenancy.tenant_context(kit.TENANT_B):
        _, rows = await db.run_readonly_select("SELECT severity FROM ask_findings", 5000, 100)
        assert [r[0] for r in rows] == ["high"]


async def test_nl_query_refuses_to_run_without_a_tenant(env, monkeypatch):
    _, db = env
    monkeypatch.setenv("TENANCY_STRICT", "true")
    with pytest.raises(PermissionError):
        await db.run_readonly_select("SELECT 1", 5000, 100)


async def test_clusters_and_query_log_are_per_tenant(env):
    tdb, db = env
    svc = BrainService(config_module.load())
    svc.db = db
    with tenancy.tenant_context(kit.TENANT_A):
        await db.replace_clusters([{"label": "A cluster", "summary": "s", "severity": "high",
                                    "finding_ids": [], "metadata": {}}], "template")
    with tenancy.tenant_context(kit.TENANT_B):
        await db.replace_clusters([], "template")  # B's replace must not delete A's
    with tenancy.tenant_context(kit.TENANT_A):
        assert [c["label"] for c in await db.list_clusters()] == ["A cluster"]
    with tenancy.tenant_context(kit.TENANT_B):
        assert await db.list_clusters() == []
    out = await svc.triage()  # all tenants, each clustered on its own findings
    assert out["failed"] == 0 and out["tenants"] >= 2
