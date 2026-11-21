"""Supplier monitoring: validation, scheduling, diffing, events, tenancy."""
from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio

from app import tenancy
from app.config import settings
from app.growth import clients, engine, exposure, suppliers
from app.growth.config import growth_settings
from app.growth.runner import growth_loop
from app.integrations.base import EVENT_TYPES
from tests.growth_fakes import FakeCT, FakeResolver, cert, healthy_zone
from tests.test_growth_trust import TENANT_A, TENANT_B, _admin

S = "vendor-co.com"
EVENTS = ["supplier.grade_changed", "supplier.dangling_dns", "supplier.cert_expiring"]


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


class World:
    """A mutable fake internet the supplier lives in."""

    def __init__(self):
        self.resolver = healthy_zone(S)
        self.ct = FakeCT([cert([S, f"www.{S}"])])
        clients.set_client_factory(lambda: (self.resolver, self.ct))

    def break_it(self):
        """DMARC gone, a dangling heroku CNAME, and a certificate about to lapse."""
        self.resolver.zone.pop((f"_dmarc.{S}", "TXT"), None)
        self.resolver.add(f"old.{S}", "CNAME", "vendor-old.herokuapp.com")
        self.ct.rows = [cert([S, f"old.{S}"], serial="a", days_left=60),
                        cert([f"www.{S}"], serial="b", days_left=1, age_days=89)]

    def fix_it(self):
        self.resolver.add(f"_dmarc.{S}", "TXT", f"v=DMARC1; p=reject; rua=mailto:d@{S}")
        self.resolver.zone.pop((f"old.{S}", "CNAME"), None)
        self.ct.rows = [cert([S, f"www.{S}"])]


@pytest.fixture
def world():
    w = World()
    saved = growth_settings.supplier_batch
    yield w
    clients.set_client_factory(None)
    growth_settings.supplier_batch = saved


@pytest_asyncio.fixture
async def env(enforce, app, app_pool, db_pool, client):
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    return {
        "pool": app_pool,
        "a": await _admin(db_pool, TENANT_A, "alice"),
        "b": await _admin(db_pool, TENANT_B, "bob"),
        "viewer": await _admin(db_pool, TENANT_B, "vera", role="viewer"),
    }


async def add(client, hdr, domain=S, **kw):
    r = await client.post("/v1/suppliers", headers=hdr, json={"domain": domain, "name": "Vendor Co", **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def webhook_for(pool, tenant, events=EVENTS):
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            return await con.fetchval(
                "INSERT INTO integrations (kind, name, events, min_severity) "
                "VALUES ('webhook', 'hook', $1, 'info') RETURNING id", events)


async def deliveries(db_pool, tenant=TENANT_B):
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT event_type, payload FROM integration_deliveries WHERE tenant_id = $1 ORDER BY id", tenant)
    return [(r["event_type"], json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"]) for r in rows]


async def make_due(db_pool):
    async with db_pool.acquire() as con:
        await con.execute("UPDATE suppliers SET next_run_at = NOW() - interval '1 minute'")


# --------------------------------------------------------------------------- #
# catalogue + pure diff
# --------------------------------------------------------------------------- #

def test_events_are_in_the_catalogue():
    for e in EVENTS:
        assert e in EVENT_TYPES and EVENT_TYPES[e]


async def test_events_visible_in_the_integrations_catalog(env, client):
    r = await client.get("/v1/integrations/catalog", headers=env["b"])
    assert r.status_code == 200
    types = {e["type"] for e in r.json()["events"]}
    assert set(EVENTS) <= types


def test_diff_assessments():
    def f(i, rule="r", sev="low", host=None):
        return {"id": i, "rule": rule, "severity": sev, "title": f"t{i}", "host": host}

    d = suppliers.diff_assessments(None, None, "B", 88, None, [f("1")])
    assert d["first"] and d["grade_direction"] == "none" and [x["id"] for x in d["new"]] == ["1"]
    d = suppliers.diff_assessments("B", [f("1"), f("2")], "D", 60, 88,
                                   [f("2"), f("3", "dangling_cname", "medium", "x"), f("4", "cert_expiring", "high")])
    assert d["grade_direction"] == "drop" and d["score_delta"] == -28
    assert [x["id"] for x in d["resolved"]] == ["1"]
    assert [x["id"] for x in d["new_dangling"]] == ["3"] and [x["id"] for x in d["new_cert_expiring"]] == ["4"]
    assert suppliers.diff_assessments("D", [], "B", 85, 60, [])["grade_direction"] == "improve"
    assert suppliers.diff_assessments("B", [], "B", 85, 85, [])["grade_direction"] == "none"


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad,code", [
    ("10.0.0.1", "ip_literal"), ("localhost", "internal_name"), ("www.vendor-co.com", "not_registrable"),
    ("vendor.corp", "internal_name"), ("https://vendor-co.com", "invalid_chars"),
])
async def test_supplier_domain_validation(env, client, bad, code):
    r = await client.post("/v1/suppliers", headers=env["b"], json={"domain": bad})
    assert r.status_code == 422 and r.json()["detail"]["code"] == code


async def test_overlong_supplier_domain_is_422(env, client):
    r = await client.post("/v1/suppliers", headers=env["b"], json={"domain": "a" * 400 + ".com"})
    assert r.status_code == 422


async def test_crud_and_permissions(env, client):
    s = await add(client, env["b"], criticality="high", interval_hours=24)
    assert s["domain"] == S and s["criticality"] == "high" and s["last_grade"] is None
    dup = await client.post("/v1/suppliers", headers=env["b"], json={"domain": S.upper()})
    assert dup.status_code == 409
    # viewers can read but not write
    assert (await client.get("/v1/suppliers", headers=env["viewer"])).status_code == 200
    assert (await client.post("/v1/suppliers", headers=env["viewer"], json={"domain": "x-corp.com"})).status_code == 403
    assert (await client.delete(f"/v1/suppliers/{s['id']}", headers=env["viewer"])).status_code == 403
    p = await client.patch(f"/v1/suppliers/{s['id']}", headers=env["b"], json={"enabled": False, "name": "V2"})
    assert p.status_code == 200 and p.json()["enabled"] is False and p.json()["name"] == "V2"
    assert (await client.patch(f"/v1/suppliers/{s['id']}", headers=env["b"], json={})).status_code == 422
    assert (await client.delete(f"/v1/suppliers/{s['id']}", headers=env["b"])).status_code == 204
    assert (await client.get(f"/v1/suppliers/{s['id']}", headers=env["b"])).status_code == 404


async def test_same_domain_in_two_tenants_and_isolation(env, client):
    sa = await add(client, env["a"])
    sb = await add(client, env["b"])
    assert sa["id"] != sb["id"]
    assert [x["id"] for x in (await client.get("/v1/suppliers", headers=env["a"])).json()] == [sa["id"]]
    assert (await client.get(f"/v1/suppliers/{sa['id']}", headers=env["b"])).status_code == 404
    assert (await client.delete(f"/v1/suppliers/{sa['id']}", headers=env["b"])).status_code == 404
    assert (await client.post(f"/v1/suppliers/{sa['id']}/assess", headers=env["b"])).status_code == 404


# --------------------------------------------------------------------------- #
# scheduling
# --------------------------------------------------------------------------- #

async def test_first_assessment_stores_grade_and_schedules_next(env, client, world, db_pool):
    s = await add(client, env["b"], interval_hours=24)
    res = await suppliers.run_due(env["pool"])
    assert len(res) == 1 and res[0]["ok"] and res[0]["tenant_id"] == TENANT_B and res[0]["grade"] == "A"
    d = (await client.get(f"/v1/suppliers/{s['id']}", headers=env["b"])).json()
    assert d["last_grade"] == "A" and d["last_score"] >= 90 and d["last_assessed_at"] and d["last_error"] is None
    assert len(d["history"]) == 1 and d["history"][0]["changes"]["first"] is True
    assert d["summary"]["grade"] == "A"
    async with db_pool.acquire() as con:
        nxt = await con.fetchval("SELECT next_run_at - NOW() FROM suppliers")
    assert 23 * 3600 < nxt.total_seconds() <= 24 * 3600
    # not due again until the interval passes
    assert await suppliers.run_due(env["pool"]) == []


async def test_disabled_and_future_suppliers_are_skipped_and_assess_now_requeues(env, client, world, db_pool):
    s = await add(client, env["b"])
    await client.patch(f"/v1/suppliers/{s['id']}", headers=env["b"], json={"enabled": False})
    assert await suppliers.run_due(env["pool"]) == []
    r = await client.post(f"/v1/suppliers/{s['id']}/assess", headers=env["b"])
    assert r.status_code == 202 and r.json()["enabled"] is True
    assert len(await suppliers.run_due(env["pool"])) == 1


async def test_claim_is_a_lease_so_replicas_do_not_double_run(env, client, world):
    await add(client, env["b"])
    with tenancy.tenant_context(TENANT_B):
        a = await suppliers.claim_due(env["pool"], 5)
        b = await suppliers.claim_due(env["pool"], 5)
    assert len(a) == 1 and b == []


async def test_batch_size_limits_one_tick(env, client, world):
    for i in range(4):
        await add(client, env["b"], f"vendor-{i}.com")
    res = await suppliers.run_due(env["pool"], limit=3)
    assert len(res) == 3
    assert len(await suppliers.run_due(env["pool"], limit=3)) == 1


async def test_failures_back_off_and_keep_the_last_good_grade(env, client, world, db_pool):
    s = await add(client, env["b"])
    await suppliers.run_due(env["pool"])
    await make_due(db_pool)
    world.resolver.nx.add(S)  # the supplier's domain stops existing
    res = await suppliers.run_due(env["pool"])
    assert res[0]["ok"] is False
    d = (await client.get(f"/v1/suppliers/{s['id']}", headers=env["b"])).json()
    assert d["last_error"] == "domain does not resolve" and d["last_grade"] == "A"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT consecutive_failures, next_run_at - NOW() AS wait FROM suppliers")
    assert row["consecutive_failures"] == 1 and row["wait"].total_seconds() > 3000
    await make_due(db_pool)
    await suppliers.run_due(env["pool"])
    async with db_pool.acquire() as con:
        w = await con.fetchval("SELECT next_run_at - NOW() FROM suppliers")
        assert await con.fetchval("SELECT consecutive_failures FROM suppliers") == 2
    assert w.total_seconds() > 1.9 * 3600  # exponential
    # recovery resets the counter
    world.resolver.nx.discard(S)
    await make_due(db_pool)
    assert (await suppliers.run_due(env["pool"]))[0]["ok"]
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT consecutive_failures FROM suppliers") == 0


async def test_history_is_bounded(env, client, world, db_pool):
    s = await add(client, env["b"])
    with tenancy.tenant_context(TENANT_B):
        sup = (await suppliers.claim_due(env["pool"], 1))[0]
        for _ in range(125):
            await suppliers.assess_supplier(env["pool"], sup)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM supplier_assessments WHERE supplier_id = $1", s["id"]) == 120


# --------------------------------------------------------------------------- #
# changes over time -> events
# --------------------------------------------------------------------------- #

async def test_grade_drop_dangling_and_cert_alerts(env, client, world, db_pool):
    await webhook_for(env["pool"], TENANT_B)
    await add(client, env["b"], criticality="high")
    await suppliers.run_due(env["pool"])
    assert await deliveries(db_pool) == []  # clean first run: nothing to say

    world.break_it()
    await make_due(db_pool)
    res = (await suppliers.run_due(env["pool"]))[0]
    assert res["changes"]["grade_direction"] == "drop"
    assert set(res["events"]) == set(EVENTS)

    got = {t: p for t, p in await deliveries(db_pool)}
    assert set(got) == set(EVENTS)
    gc = got["supplier.grade_changed"]
    assert gc["severity"] == "high"  # a drop on a high-criticality supplier
    assert gc["data"]["grade_from"] == "A" and gc["data"]["direction"] == "drop"
    assert gc["data"]["supplier"] == "Vendor Co" and gc["tenant_id"] == TENANT_B
    dd = got["supplier.dangling_dns"]
    assert dd["severity"] == "high" and dd["data"]["hosts"] == [f"old.{S}"]
    ce = got["supplier.cert_expiring"]
    assert ce["data"]["count"] == 1 and ce["severity"] == "high"

    # nothing new -> nothing more (the same problems are not re-announced)
    before = len(await deliveries(db_pool))
    await make_due(db_pool)
    again = (await suppliers.run_due(env["pool"]))[0]
    assert again["events"] == [] and len(await deliveries(db_pool)) == before


async def test_improvement_emits_info_only_and_records_resolved(env, client, world, db_pool):
    await webhook_for(env["pool"], TENANT_B)
    s = await add(client, env["b"])
    world.break_it()
    await suppliers.run_due(env["pool"])
    first = [t for t, _ in await deliveries(db_pool)]
    assert "supplier.dangling_dns" in first and "supplier.grade_changed" not in first  # first run: no grade event

    world.fix_it()
    await make_due(db_pool)
    res = (await suppliers.run_due(env["pool"]))[0]
    assert res["changes"]["grade_direction"] == "improve" and res["events"] == ["supplier.grade_changed"]
    last = (await deliveries(db_pool))[-1][1]
    assert last["severity"] == "info" and "improved" in last["title"]
    d = (await client.get(f"/v1/suppliers/{s['id']}", headers=env["b"])).json()
    assert len(d["history"]) == 2
    assert {x["rule"] for x in d["history"][0]["changes"]["resolved"]} >= {"dangling_cname_takeover", "dmarc_missing"}


async def test_events_reach_only_the_owning_tenants_integrations(env, client, world, db_pool):
    await webhook_for(env["pool"], TENANT_A)
    await webhook_for(env["pool"], TENANT_B)
    await add(client, env["b"])
    world.break_it()
    await suppliers.run_due(env["pool"])
    assert await deliveries(db_pool, TENANT_A) == []
    assert await deliveries(db_pool, TENANT_B)


async def test_event_ids_are_idempotent(env, client, world, db_pool):
    await webhook_for(env["pool"], TENANT_B)
    await add(client, env["b"])
    world.break_it()
    with tenancy.tenant_context(TENANT_B):
        sup = (await suppliers.claim_due(env["pool"], 1))[0]
        res = await suppliers.assess_supplier(env["pool"], sup)
        n = len(await deliveries(db_pool))
        await suppliers.emit_events(env["pool"], sup, res["assessment_id"], res["changes"], TENANT_B)
    assert len(await deliveries(db_pool)) == n


async def test_integration_not_subscribed_receives_nothing(env, client, world, db_pool):
    await webhook_for(env["pool"], TENANT_B, events=["scan.completed"])
    await add(client, env["b"])
    world.break_it()
    await suppliers.run_due(env["pool"])
    assert await deliveries(db_pool) == []


async def test_assessment_only_asks_dns_and_ct(env, client, world):
    await add(client, env["b"])
    world.break_it()
    await suppliers.run_due(env["pool"])
    assert world.ct.calls == [S]
    assert {t for _, t in world.resolver.calls} <= {"NS", "A", "AAAA", "MX", "TXT", "CAA", "DS", "CNAME"}


# --------------------------------------------------------------------------- #
# the runner loop drives both features
# --------------------------------------------------------------------------- #

async def test_runner_loop_processes_exposure_and_suppliers(env, client, world, app, monkeypatch):
    monkeypatch.setattr(growth_settings, "runner_interval_sec", 0.02)
    monkeypatch.setattr(growth_settings, "supplier_interval_sec", 0.0)
    await add(client, env["b"])
    rid = (await client.post("/v1/public/exposure-report", json={"domain": S})).json()["id"]
    task = asyncio.create_task(growth_loop(app))
    try:
        for _ in range(100):
            await asyncio.sleep(0.05)
            r = (await client.get(f"/v1/public/exposure-report/{rid}")).json()
            s = (await client.get("/v1/suppliers", headers=env["b"])).json()
            if r["status"] == "done" and s[0]["last_grade"]:
                break
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert r["status"] == "done" and s[0]["last_grade"] == "A"


async def test_runner_survives_a_bad_tick(env, world, app, monkeypatch):
    monkeypatch.setattr(growth_settings, "runner_interval_sec", 0.01)
    calls = []

    async def boom(pool, *a, **k):
        calls.append(1)
        raise RuntimeError("db hiccup")

    monkeypatch.setattr(exposure, "run_pending", boom)
    task = asyncio.create_task(growth_loop(app))
    await asyncio.sleep(0.15)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(calls) >= 3
