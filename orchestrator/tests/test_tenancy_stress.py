"""Concurrency leakage: interleaved requests + background loops across tenants.

Six identities hammer one app instance concurrently (a tenant key for A and B,
an MSP user's own session, an MSP switch token into a customer, and the fleet
service key naming A / B via X-Paddock-Tenant) against a 4-connection pool, so
connections are reused across tenants constantly. Every response must hold only
the caller's marker, every row written must land in the caller's tenant, and no
connection may come back from the pool still carrying a tenant.
"""
from __future__ import annotations

import asyncio
import random
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import retention, tenancy
from app import sensors as sensors_svc
from app.config import settings

from . import stress_world as sw


@pytest.fixture
def stress_settings(monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", sw.SERVICE_KEY)
    yield


def _identities(w: sw.World):
    svc = lambda tid: {"X-API-Key": sw.SERVICE_KEY, "X-Paddock-Tenant": tid}  # noqa: E731
    # name -> (headers, own tenant name)
    return {
        "a-key": (w["a"].headers(), "a"),
        "b-key": (w["b"].headers(), "b"),
        "m-session": (w["m"].headers(), "m"),
        "c1-switched": (w["c1"].headers(), "c1"),
        "svc-a": (svc(sw.T_A), "a"),
        "svc-b": (svc(sw.T_B), "b"),
    }


READS = ["/v1/findings", "/v1/findings/list?limit=50", "/v1/assets", "/v1/scope", "/v1/suppliers",
         "/v1/reports/executive", "/v1/audit?limit=20", "/v1/tickets", "/v1/scans", "/v1/usage",
         "/v1/trust-links", "/v1/ingest/sources", "/v1/sensors/tokens", "/v1/timeline", "/v1/onboarding"]


async def test_interleaved_requests_never_cross_tenants(stress_settings, app, app_pool, db_pool, client):
    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client, generic=False)
    ids = _identities(w)
    marks = {n: t.marker for n, t in w.t.items()}
    rnd = random.Random(1234)
    leaks: list[str] = []
    bad_status: list[str] = []
    written: dict[str, int] = {n: 0 for n in marks}
    sem = asyncio.Semaphore(24)
    stop = asyncio.Event()

    async def one(i: int):
        name = rnd.choice(list(ids))
        hdr, own = ids[name]
        m = marks[own]
        others = [mk for n, mk in marks.items() if n != own]
        kind = rnd.choice(("read", "read", "read", "write_findings", "write_assets", "patch", "detail"))
        async with sem:
            if kind == "read":
                url = rnd.choice(READS)
                if own == "m" and rnd.random() < 0.15:
                    url = "/v1/msp/summary"
                r = await client.get(url, headers=hdr)
            elif kind == "write_findings":
                r = await client.post("/v1/findings/bulk", headers=hdr, json={"items": [{
                    "asset_value": f"{m}.example", "asset_kind": "domain", "rule_id": f"{m}-conc-{i}",
                    "rule_source": "policy", "severity": "low", "title": f"{m} concurrent {i}",
                    "description": m}]})
                if r.status_code in (200, 201):
                    written[own] += 1
            elif kind == "write_assets":
                r = await client.post("/v1/assets/bulk", headers=hdr, json={"items": [
                    {"kind": "domain", "value": f"c{i}.{m}.example", "source": "test"}]})
                if r.status_code in (200, 201):
                    written[own] += 1
            elif kind == "patch":
                fid = rnd.choice(w[own].api["findings"])
                r = await client.patch(f"/v1/findings/{fid}", headers=hdr, json={"status": "acknowledged"})
            else:
                fid = rnd.choice(w[own].api["findings"])
                r = await client.get(f"/v1/findings/{fid}", headers=hdr)
                if r.status_code != 200:
                    bad_status.append(f"{name} own finding -> {r.status_code}")
        low = r.text.lower()
        for mk in others:
            if mk in low:
                # the MSP parent legitimately lists its customer by NAME/slug, never the data marker
                leaks.append(f"{name} {kind} {r.request.url.path} leaked {mk}")
        if r.status_code >= 500:
            bad_status.append(f"{name} {kind} {r.request.url.path} -> {r.status_code} {r.text[:120]}")

    async def background():
        """Tenant-iterating loops running WHILE requests are in flight."""
        while not stop.is_set():
            await sensors_svc.sweep_all_tenants(app_pool)
            await retention.run_retention(app_pool)
            await asyncio.sleep(0)

    bg = asyncio.create_task(background())
    await asyncio.gather(*(one(i) for i in range(900)))
    stop.set()
    await bg

    assert not leaks, "\n".join(leaks[:30])
    assert not bad_status, "\n".join(bad_status[:30])
    assert sum(written.values()) > 100

    # Every row written landed in its writer's tenant (checked behind RLS).
    async with db_pool.acquire() as con:
        for n, t in w.t.items():
            for table, col in (("findings", "title"), ("assets", "value")):
                wrong = await con.fetchval(
                    f"SELECT count(*) FROM {table} WHERE {col} ILIKE $1 AND tenant_id <> $2::uuid",
                    f"%{t.marker}%", t.id)
                assert wrong == 0, f"{table}: {wrong} rows of {n} landed in another tenant"
        # Service-key calls named A / B: their writes stayed in those tenants.
        for n in ("a", "b"):
            cnt = await con.fetchval("SELECT count(*) FROM findings WHERE tenant_id = $1::uuid", w[n].id)
            assert cnt >= 4

    # Pooled connections come back clean.
    with tenancy.tenant_context(sw.T_A):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT current_setting('app.tenant_id', true)") == sw.T_A
    async with app_pool.acquire() as con:   # no context -> default tenant, never A's or B's
        got = await con.fetchval("SELECT current_setting('app.tenant_id', true)")
        assert got == tenancy.DEFAULT_TENANT_ID


async def test_strict_mode_pool_reuse_never_inherits_a_tenant(stress_settings, app, app_pool, db_pool, client,
                                                              monkeypatch):
    """Under TENANCY_STRICT a context-less acquire must see NOTHING, even right
    after other tenants used the very same pooled connections."""
    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client, generic=False)
    monkeypatch.setattr(settings, "tenancy_strict", True)
    hdrs = [w["a"].headers(), w["b"].headers()]
    await asyncio.gather(*(client.get("/v1/findings", headers=hdrs[i % 2]) for i in range(60)))
    for _ in range(12):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT current_setting('app.tenant_id', true)") in ("", None)
            assert await con.fetchval("SELECT count(*) FROM findings") == 0
            assert await con.fetchval("SELECT count(*) FROM assets") == 0


async def test_context_does_not_survive_a_background_task_boundary(app_pool, db_pool):
    """A task created inside tenant_context inherits it (documented asyncio
    semantics) -- loops that spawn tasks must re-bind. A task created OUTSIDE
    any context never sees a sibling's tenant."""
    for tid in (sw.T_A, sw.T_B):
        await tenancy.create_tenant(db_pool, slug=f"ctx-{tid[-2:]}", name="ctx", tenant_id=tid)

    async def who():
        async with app_pool.acquire() as con:
            return await con.fetchval("SELECT current_setting('app.tenant_id', true)")

    async def a_then_sleep():
        with tenancy.tenant_context(sw.T_A):
            await asyncio.sleep(0.01)
            return await who()

    async def b_then_sleep():
        with tenancy.tenant_context(sw.T_B):
            await asyncio.sleep(0.005)
            return await who()

    outs = await asyncio.gather(*(f() for _ in range(40) for f in (a_then_sleep, b_then_sleep, who)))
    assert outs[0::3] == [sw.T_A] * 40
    assert outs[1::3] == [sw.T_B] * 40
    assert set(outs[2::3]) == {tenancy.DEFAULT_TENANT_ID}


# --------------------------------------------------------------------------- #
# Scheduler / background loops act in the right tenant
# --------------------------------------------------------------------------- #

async def _two_tenants(db_pool):
    for slug, tid in (("loop-a", sw.T_A), ("loop-b", sw.T_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def test_source_sync_sweep_covers_every_tenant(app_pool, db_pool):
    """Regression: the sweep task inherited the FIRST tenant's context and a
    single-flight guard stopped the others, so only one tenant was ever synced."""
    from app.integrations import runtime

    await _two_tenants(db_pool)
    seen: list[str | None] = []

    async def runner(pool, redis):
        seen.append(tenancy.current_tenant_id())
        return 0

    runtime._sweep = None
    with tenancy.tenant_context(sw.T_B):      # the scheduler iteration that happens to kick first
        assert runtime.kick_source_syncs(app_pool, None, runner=runner) is True
    await runtime._sweep
    assert set(seen) >= {sw.T_A, sw.T_B, tenancy.DEFAULT_TENANT_ID}
    assert len(seen) == len(set(seen))


async def test_retention_purges_every_tenant(app_pool, db_pool):
    """Regression: retention ran in the default tenant only."""
    await _two_tenants(db_pool)
    old = datetime.now(timezone.utc) - timedelta(days=4000)
    async with db_pool.acquire() as con:
        for tid in (sw.T_A, sw.T_B, tenancy.DEFAULT_TENANT_ID):
            await con.execute(
                "INSERT INTO scope_decisions (target, normalized, decision, worker, decided_at, tenant_id) "
                "VALUES ('x.example', 'x.example', 'allow', 'w', $1, $2)", old, tid)
            await con.execute(
                "INSERT INTO scope_decisions (target, normalized, decision, worker, tenant_id) "
                "VALUES ('keep.example', 'keep.example', 'allow', 'w', $1)", tid)
    counts = await retention.run_retention(app_pool, [retention.Policy("scope_decisions", "decided_at", 30)])
    assert counts == {"scope_decisions": 3}
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT tenant_id::text AS t, target FROM scope_decisions ORDER BY 1")
    assert {(r["t"], r["target"]) for r in rows} == {
        (t, "keep.example") for t in (sw.T_A, sw.T_B, tenancy.DEFAULT_TENANT_ID)}


async def test_weekly_digest_runs_per_tenant(app_pool, db_pool, monkeypatch):
    """Regression: only the default tenant got a weekly digest (and the slot
    claim was globally unique, so a second tenant could never claim one)."""
    from app.reports import digest

    await _two_tenants(db_pool)
    monkeypatch.setattr(digest, "emit_digest", lambda pool, ev: _ok())
    monkeypatch.setattr(digest.report_settings, "digest_enabled", True)
    now = datetime.now(timezone.utc)
    res = await digest.run_due_digests(app_pool, now=digest.current_slot(now) + timedelta(minutes=5))
    assert len(res) == 3
    async with db_pool.acquire() as con:
        got = {r["t"] for r in await con.fetch("SELECT tenant_id::text AS t FROM report_digests")}
    assert got == {sw.T_A, sw.T_B, tenancy.DEFAULT_TENANT_ID}
    # idempotent per tenant+slot
    again = await digest.run_due_digests(app_pool, now=digest.current_slot(now) + timedelta(minutes=6))
    assert again == []


async def _ok():
    return "emitted", None


async def test_all_scheduler_hooks_iterate_tenants_not_one():
    """Static guard: every periodic hook the scheduler/lifespan starts must
    iterate ``tenancy.list_tenant_ids`` (or be explicitly platform-wide)."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "app"
    expect = {
        "scheduler.py": "list_tenant_ids",
        "sensors.py": "list_tenant_ids",
        "billing/metering.py": "list_tenant_ids",
        "growth/suppliers.py": "list_tenant_ids",
        "integrations/worker.py": "list_tenant_ids",
        "integrations/runtime.py": "list_tenant_ids",
        "retention.py": "list_tenant_ids",
        "reports/digest.py": "list_tenant_ids",
        "audit.py": "list_tenant_ids",
    }
    for rel, needle in expect.items():
        assert re.search(needle, (root / rel).read_text()), f"{rel} no longer iterates tenants"
