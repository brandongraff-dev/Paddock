"""Tenant isolation for triage against real Postgres RLS (``paddock_svc_triage``)."""
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
from app.main import TriageService  # noqa: E402

ROLE = "paddock_svc_triage"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = TriageService(config_module.load())
    svc.db = Database(tdb.role_dsn(ROLE))
    await svc.db.connect()
    from app.tickets import TicketManager

    svc.manager = TicketManager(svc.db, svc.cfg, svc.dispatcher, publish=svc._publish)
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    fa = await kit.seed_finding(tdb, kit.TENANT_A, a, severity="critical")
    fb = await kit.seed_finding(tdb, kit.TENANT_B, b, severity="critical")
    try:
        yield tdb, svc, fa, fb
    finally:
        await svc.db.close()
        await tdb.drop()


async def test_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_event_driven_pass_for_tenant_a_never_touches_b(env):
    tdb, svc, fa, fb = env
    await svc._on_event({"event": "finding_opened", "finding_id": fa, "tenant_id": kit.TENANT_A})
    rows = await tdb.raw("SELECT finding_id::text, tenant_id::text FROM tickets")
    assert [tuple(r) for r in rows] == [(fa, kit.TENANT_A)]  # B's finding was NOT ticketed
    with tenancy.tenant_context(kit.TENANT_B):
        assert await svc.db.open_findings_without_ticket(["critical"]) != []  # still pending in B


async def test_scheduled_pass_ticket_each_tenant_in_its_own_partition(env):
    tdb, svc, fa, fb = env
    out = await svc.run_pass()  # no tenant named: every active tenant
    assert out["failed"] == 0 and out["tenants"] >= 2
    rows = await tdb.raw("SELECT finding_id::text, tenant_id::text FROM tickets ORDER BY tenant_id")
    assert {tuple(r) for r in rows} == {(fa, kit.TENANT_A), (fb, kit.TENANT_B)}
    with tenancy.tenant_context(kit.TENANT_A):
        assert [str(r["finding_id"]) for r in await svc.db.fetch("SELECT finding_id FROM tickets")] == [fa]


async def test_unnamed_event_is_dropped_in_strict_mode(env, monkeypatch):
    tdb, svc, fa, fb = env
    monkeypatch.setenv("TENANCY_STRICT", "true")
    await svc._on_event({"event": "finding_opened", "finding_id": fa})  # no tenant_id
    assert await tdb.raw("SELECT 1 FROM tickets") == []


async def test_cannot_write_into_another_tenant(env):
    _, svc, fa, fb = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO tickets (finding_id, title, severity, tenant_id) "
                "VALUES ($1::uuid, 'x', 'high', $2)", fb, kit.TENANT_B), what="ticket in B")
        async with svc.db.acquire() as con:
            assert await con.execute("UPDATE tickets SET status = 'closed'") == "UPDATE 0"
