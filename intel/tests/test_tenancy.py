"""Tenant isolation for the intel service, against real Postgres RLS.

Connected as ``paddock_svc_intel`` (non-superuser, NOBYPASSRLS), tenant A's work
cannot read or write tenant B's rows; the global CVE catalogue is written only
from the platform context; no tenant context = no rows.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402

ROLE = "paddock_svc_intel"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    db = Database(tdb.role_dsn(ROLE))
    await db.connect()
    a1 = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com")
    b1 = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com")
    try:
        yield tdb, db, a1, b1
    finally:
        await db.close()
        await tdb.drop()


async def test_runs_as_a_non_privileged_role(env):
    tdb, db, *_ = env
    info = await kit.role_info(tdb.role_dsn(ROLE))
    assert info["u"] == ROLE and not info["rolsuper"] and not info["rolbypassrls"]
    assert (await tenancy.check_role(db.pool, require=True))["role"] == ROLE


async def test_tenant_a_cannot_read_or_write_tenant_b(env):
    tdb, db, a1, b1 = env
    await db.upsert_cve({"id": "CVE-2099-0001", "cvss_v3": 9.0})  # global, any tenant ctx
    with tenancy.tenant_context(kit.TENANT_A):
        assert await db.upsert_match("CVE-2099-0001", a1, 80, "cpe")
    with tenancy.tenant_context(kit.TENANT_B):
        assert await db.upsert_match("CVE-2099-0001", b1, 70, "cpe")

    with tenancy.tenant_context(kit.TENANT_A):
        rows = await db.matches_for_cve("CVE-2099-0001")
        assert [str(r["asset_id"]) for r in rows] == [a1]
        async with db.acquire() as con:
            # write into B's partition: rejected by WITH CHECK
            await kit.expect_denied(con.execute(
                "INSERT INTO cve_matches (cve_id, asset_id, confidence, matcher, tenant_id) "
                "VALUES ('CVE-2099-0001', $1::uuid, 1, 'x', $2)", b1, kit.TENANT_B), what="cross-tenant insert")
        async with db.acquire() as con:
            # update / delete B's row: invisible, so zero rows
            assert (await con.execute("UPDATE cve_matches SET confidence = 1 WHERE asset_id = $1::uuid", b1)) == "UPDATE 0"
            assert (await con.execute("DELETE FROM cve_matches WHERE asset_id = $1::uuid", b1)) == "DELETE 0"
    with tenancy.tenant_context(kit.TENANT_B):
        rows = await db.matches_for_cve("CVE-2099-0001")
        assert [(str(r["asset_id"]), r["confidence"]) for r in rows] == [(b1, 70)]


async def test_global_catalogue_is_platform_write_only(env):
    tdb, db, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        async with db.acquire() as con:  # a tenant context may NOT write the CVE feed
            await kit.expect_denied(con.execute("INSERT INTO cves (id) VALUES ('CVE-2099-0002')"), what="tenant write to cves")
        await db.mark_kev("CVE-2099-0002", None)  # no row yet: no-op, but allowed path
        await db.upsert_cve({"id": "CVE-2099-0003"})  # the service's own path uses the platform context
        assert (await db.get_cve("CVE-2099-0003")) is not None
    with tenancy.tenant_context(kit.TENANT_B):
        assert (await db.get_cve("CVE-2099-0003")) is not None  # global: readable by everyone


async def test_no_tenant_means_no_rows_and_nothing_leaks_through_the_pool(env, monkeypatch):
    tdb, db, a1, b1 = env
    await db.upsert_cve({"id": "CVE-2099-0004"})
    with tenancy.tenant_context(kit.TENANT_A):
        await db.upsert_match("CVE-2099-0004", a1, 50, "cpe")
    monkeypatch.setenv("TENANCY_STRICT", "true")
    assert tenancy.current_tenant_id() is None
    assert await db.matches_for_cve("CVE-2099-0004") == []  # strict + unbound: sees nothing
    with tenancy.tenant_context(kit.TENANT_A):
        assert len(await db.matches_for_cve("CVE-2099-0004")) == 1
    assert await kit.session_tenant_after_release(db) is None  # SET LOCAL did not leak


async def test_service_role_cannot_reach_audit_or_credentials(env):
    _, db, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        for tbl in ("audit_log", "app_users", "api_keys", "integrations"):
            async with db.acquire() as con:  # a rejected statement aborts its transaction
                await kit.expect_denied(con.fetch(f"SELECT * FROM {tbl}"), what=tbl)


async def test_events_carry_the_tenant():
    with tenancy.bind_event({"event": "asset_added", "tenant_id": kit.TENANT_B}):
        assert tenancy.current_tenant_id() == kit.TENANT_B
    with pytest.raises(tenancy.TenantError):
        tenancy.event_tenant({"tenant_id": "not-a-uuid"})
