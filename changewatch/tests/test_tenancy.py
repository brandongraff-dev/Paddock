"""Tenant isolation for changewatch against real Postgres RLS
(``paddock_svc_changewatch``); per-tenant cursors live in ``service_cursors``,
never in the global ``intel_cursors``."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.alerts import AlertDispatcher  # noqa: E402
from app.db import Database  # noqa: E402
from app.detect import ChangeDetector  # noqa: E402
from app.main import ChangewatchService  # noqa: E402

ROLE = "paddock_svc_changewatch"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = ChangewatchService(config_module.load())
    svc.db = Database(tdb.role_dsn(ROLE))
    await svc.db.connect()
    svc.detector = ChangeDetector(svc.db, svc.cfg)
    svc.dispatcher = AlertDispatcher(svc.db, svc.cfg)
    a = await kit.seed_asset(tdb, kit.TENANT_A, "new-a.example.com", kind="subdomain")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "new-b.example.com", kind="subdomain")
    try:
        yield tdb, svc, a, b
    finally:
        await svc.db.close()
        await tdb.drop()


async def _changes(tdb):
    return {(r[0], r[1]) for r in await tdb.raw("SELECT tenant_id::text, asset_value FROM surface_changes")}


async def test_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_event_for_tenant_a_detects_only_tenant_a_and_moves_only_a_cursor(env):
    tdb, svc, a, b = env
    await svc._on_event({"event": "finding_opened", "tenant_id": kit.TENANT_A})
    assert await _changes(tdb) == {(kit.TENANT_A, "new-a.example.com")}
    cur = await tdb.raw("SELECT tenant_id::text, service, key FROM service_cursors")
    assert [tuple(r) for r in cur] == [(kit.TENANT_A, "changewatch", "changewatch")]
    # the GLOBAL cursor table never receives a tenant's state
    legacy = await tdb.raw("SELECT stats::text FROM intel_cursors WHERE source = 'changewatch'")
    assert all(r[0] in ("{}", None) for r in legacy)  # the old seed row is untouched


async def test_scheduled_pass_runs_every_tenant_with_independent_cursors(env):
    tdb, svc, a, b = env
    out = await svc.run_pass()
    assert out["failed"] == 0 and out["tenants"] >= 2
    assert await _changes(tdb) == {
        (kit.TENANT_A, "new-a.example.com"), (kit.TENANT_B, "new-b.example.com")}
    with tenancy.tenant_context(kit.TENANT_A):
        assert (await svc.db.get_cursor("changewatch")) is not None
        assert [r["asset_value"] for r in await svc.db.fetch("SELECT asset_value FROM surface_changes")] == ["new-a.example.com"]
    with tenancy.tenant_context(kit.TENANT_B):
        assert [r["asset_value"] for r in await svc.db.fetch("SELECT asset_value FROM surface_changes")] == ["new-b.example.com"]


async def test_cannot_write_another_tenants_changes_or_rules(env):
    _, svc, a, b = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO surface_changes (change_type, summary, tenant_id) "
                "VALUES ('ip_discovered', 'x', $1)", kit.TENANT_B), what="change in B")
        async with svc.db.acquire() as con:
            assert await con.execute("UPDATE alert_rules SET enabled = FALSE") == "UPDATE 0"


async def test_global_cursor_table_is_not_writable_by_the_service_role(env):
    _, svc, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO intel_cursors (source) VALUES ('changewatch')"), what="intel_cursors")


async def test_unnamed_event_dropped_in_strict_mode(env, monkeypatch):
    tdb, svc, *_ = env
    monkeypatch.setenv("TENANCY_STRICT", "true")
    await svc._on_event({"event": "finding_opened"})
    assert await _changes(tdb) == set()
