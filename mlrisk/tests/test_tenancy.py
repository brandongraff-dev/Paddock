"""Tenant isolation for mlrisk against real Postgres RLS (``paddock_svc_mlrisk``)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import MlRiskService  # noqa: E402

ROLE = "paddock_svc_mlrisk"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = MlRiskService(config_module.Config())
    svc.db = Database(tdb.role_dsn(ROLE))
    await svc.db.connect()
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com", kind="subdomain")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com", kind="subdomain")
    fa = await kit.seed_finding(tdb, kit.TENANT_A, a)
    fb = await kit.seed_finding(tdb, kit.TENANT_B, b)
    try:
        yield tdb, svc, (a, fa), (b, fb)
    finally:
        await svc.db.close()
        await tdb.drop()


async def test_runs_as_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_scoring_job_for_tenant_a_only_touches_tenant_a(env):
    tdb, svc, (a, fa), (b, fb) = env
    with tenancy.tenant_context(kit.TENANT_A):
        assert (await svc.retrain_and_score())["scored"] == 1
    rows = await tdb.raw("SELECT finding_id::text, tenant_id::text FROM ml_risk_scores")
    assert [tuple(r) for r in rows] == [(fa, kit.TENANT_A)]
    with tenancy.tenant_context(kit.TENANT_B):
        assert await svc.db.fetch_open_feature_rows() != []  # B sees its own...
        ids = {str(r["finding_id"]) if "finding_id" in r else str(r.get("id")) for r in await svc.db.fetch_open_feature_rows()}
        assert fa not in ids  # ...never A's
        assert await svc.db.fetch_host_subject_rows() is not None


async def test_scheduled_pass_covers_every_tenant_with_independent_model_versions(env):
    tdb, svc, *_ = env
    out = await svc.run_once_scoped()  # no request tenant -> all active tenants
    assert {kit.TENANT_A, kit.TENANT_B} <= set(out)
    models = await tdb.raw(
        "SELECT tenant_id::text, kind, version FROM ml_models WHERE kind = 'risk_ranker' ORDER BY tenant_id")
    # the same (kind, version) exists once PER tenant: the key is tenant-scoped
    per_tenant = {r[0]: r[2] for r in models}
    assert per_tenant[kit.TENANT_A] == per_tenant[kit.TENANT_B] == 1
    scores = await tdb.raw("SELECT count(*) FROM ml_risk_scores")
    assert scores[0][0] == 2
    # a B-context reader cannot see A's model or scores
    with tenancy.tenant_context(kit.TENANT_B):
        async with svc.db.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM ml_risk_scores") == 1
            assert await con.fetchval("SELECT count(*) FROM ml_models WHERE tenant_id = $1", kit.TENANT_A) == 0


async def test_cannot_write_into_another_tenant(env):
    _, svc, (a, fa), (b, fb) = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO ml_risk_scores (finding_id, ml_risk, model_version, tenant_id) "
                "VALUES ($1::uuid, 1, 1, $2)", fb, kit.TENANT_B), what="score for B")
