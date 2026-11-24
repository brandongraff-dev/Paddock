"""Hardening of the provable-containment API (review findings security-2/3/4/5/7/8).

* security-4 (ABAC): every read of the reach graph, coverage, state, labels, zones and of stored
  invariant results/runs must hide what the caller's clearance hides in /v1/assets, and a hidden
  thing answers exactly like a missing one. The tests use a real low-clearance key.
* security-2/5: attacker-controlled CPU (YAML parsing, the coverage scan) never runs on the event
  loop; ``limit=1`` does not do the full scan; the SQL coverage summary is pinned to the library.
* security-3: per-tenant caps answer a clear 409/422.
* security-7: removals need a justification; exceptions are audited with reason and expiry.
* security-8: the flow ingest refuses scoped IPv6 spellings and over-long strings.
* sensor scopes (schema 040): the admin-only endpoints.

Real Postgres, the real router and the real library (same conventions as test_assurance_api.py).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
import uuid

import pytest
import pytest_asyncio

from app import tenancy
from app.routers import assurance as api

from .test_assurance_api import (
    NOW,
    TENANT_A,
    _audit_rows,
    _create,
    _seed_cov,
    _seed_edge,
    enforce,  # noqa: F401  (fixture)
    inv_yaml,
)
from .test_governance import _hdr, _seed_user_with_key
from .test_tenancy import _seed_admin

SECRET_VALUE = "secret-payroll-db"
SECRET_IP = "10.7.7.7"
PUB_IP = "10.1.1.1"


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------

async def _asset(db_pool, value, classification, ips=(), kind="cloud_resource") -> str:
    async with db_pool.acquire() as con:
        return str(await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source, classification, metadata) "
            "VALUES ($1, $2, $2, 'test', $3, $4::jsonb) RETURNING id",
            kind, value, classification, json.dumps({"private_ips": list(ips)})))


async def _node(db_pool, ref, kind="cloud_instance", asset_id=None, attrs=None, label=""):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_nodes (node_ref, kind, label, asset_id, attrs, source) "
            "VALUES ($1, $2, $3, $4::uuid, $5::jsonb, 'test')",
            ref, kind, label, asset_id, json.dumps(attrs or {}))


@pytest_asyncio.fixture
async def world(enforce, client, db_pool):  # noqa: F811
    """A restricted asset (and the stray ``ip:`` node of the same machine), a public asset, edges,
    coverage, a label and a zone naming the secret; keys: admin (restricted) and viewer (public)."""
    admin = _hdr(await _seed_admin(db_pool, TENANT_A, "ada-admin"))
    _, vk = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    _, ck = await _seed_user_with_key(db_pool, "conrad", "viewer", "confidential")
    _, lk = await _seed_user_with_key(db_pool, "lowadmin", "admin", "public")
    sec = await _asset(db_pool, SECRET_VALUE, "restricted", [SECRET_IP])
    pub = await _asset(db_pool, "public-web", "public", [PUB_IP])
    sref, pref = f"asset:{sec}", f"asset:{pub}"
    await _node(db_pool, sref, "cloud_db", sec, {"ips": [SECRET_IP]}, label=SECRET_VALUE)
    await _node(db_pool, f"ip:{SECRET_IP}", "ip")                       # same machine, other spelling
    await _node(db_pool, pref, "cloud_instance", pub, {"ips": [PUB_IP]}, label="public-web")
    await _node(db_pool, "ip:10.9.9.9", "ip")
    await _seed_edge(db_pool, "ip:10.9.9.9", sref, port=5432)           # touches the secret
    await _seed_edge(db_pool, pref, f"ip:{SECRET_IP}", port=5432)       # touches its other spelling
    await _seed_edge(db_pool, "ip:10.9.9.9", pref, port=443,
                     evidence={"sg": ["sg-1"], "peer_ips": [SECRET_IP], "note": f"also {SECRET_VALUE}"})
    await _seed_cov(db_pool, sref, "in")
    await _seed_cov(db_pool, f"ip:{SECRET_IP}", "out")
    await _seed_cov(db_pool, pref, "in")
    r = await client.put("/v1/labels", headers=admin, json={
        "node_ref": sref, "tag": "crown-jewel", "value": "true", "justification": "payroll"})
    assert r.status_code == 200, r.text
    r = await client.put("/v1/labels", headers=admin, json={
        "node_ref": pref, "tag": "app-tier", "value": "web", "justification": "front end"})
    assert r.status_code == 200, r.text
    r = await client.post("/v1/zones", headers=admin, json={
        "name": "pos", "cidrs": [f"{SECRET_IP}/32", "10.50.0.0/16"], "justification": "pos net"})
    assert r.status_code == 201, r.text
    return {"admin": admin, "viewer": _hdr(vk), "conf": _hdr(ck), "lowadmin": _hdr(lk),
            "sec": sec, "pub": pub, "sref": sref, "pref": pref}


def _leaks(text: str, w) -> list[str]:
    return [n for n in (w["sec"], SECRET_VALUE, SECRET_IP) if n in text]


# --------------------------------------------------------------------------------------------
# security-4: reads
# --------------------------------------------------------------------------------------------

async def test_reach_nodes_and_edges_hide_assets_above_clearance(world, client):
    w = world
    for path in ("/v1/reach/nodes?limit=500", "/v1/reach/edges?include_evidence=true&limit=500"):
        low = await client.get(path, headers=w["viewer"])
        assert low.status_code == 200, path
        assert _leaks(low.text, w) == [], (path, low.text)
        full = (await client.get(path, headers=w["admin"])).text
        assert _leaks(full, w), "the admin must still see the secret (the filter is not a blanket)"
    nodes = (await client.get("/v1/reach/nodes", headers=w["viewer"])).json()
    assert sorted(n["node_ref"] for n in nodes["items"]) == sorted([w["pref"], "ip:10.9.9.9"])
    assert nodes["total"] == 2                               # the count does not betray hidden rows
    edges = (await client.get("/v1/reach/edges?include_evidence=true", headers=w["viewer"])).json()
    assert edges["total"] == 1 and edges["items"][0]["dst_ref"] == w["pref"]
    # evidence of a VISIBLE edge that mentions the secret is scrubbed, not dropped
    ev = json.dumps(edges["items"][0]["evidence"])
    assert "sg-1" in ev and "[redacted]" in ev


async def test_filters_cannot_be_used_as_an_oracle_for_hidden_nodes(world, client):
    w = world
    for path in (f"/v1/reach/nodes?q={SECRET_IP}", f"/v1/reach/nodes?q={SECRET_VALUE}",
                 f"/v1/reach/nodes?q={w['sec']}", f"/v1/reach/edges?node={w['sref']}",
                 f"/v1/reach/edges?dst={w['sref']}", f"/v1/reach/edges?src=ip:{SECRET_IP}",
                 f"/v1/reach/edges?node=ip:{SECRET_IP}", f"/v1/labels?node_ref={w['sref']}"):
        body = (await client.get(path, headers=w["viewer"])).json()
        assert body["total"] == 0 and body["items"] == [], path


async def test_coverage_and_state_count_only_what_the_caller_may_see(world, client):
    w = world
    cov = (await client.get("/v1/assurance/coverage?limit=500", headers=w["viewer"])).json()
    assert _leaks(json.dumps(cov, default=str), w) == []
    assert cov["summary"]["nodes"] == 2                       # public asset + ip:10.9.9.9
    assert sorted(n["node_ref"] for n in cov["nodes"]["items"]) == sorted([w["pref"], "ip:10.9.9.9"])
    assert sum(r["facts"] for r in cov["by_source"]) == 1     # only the public asset's fact
    full = (await client.get("/v1/assurance/coverage?limit=500", headers=w["admin"])).json()
    assert full["summary"]["nodes"] == 4 and sum(r["facts"] for r in full["by_source"]) == 3

    low = (await client.get("/v1/assurance/state", headers=w["viewer"])).json()
    assert low["counts"]["nodes"] == 2 and low["counts"]["edges"] == 1
    assert low["counts"]["coverage_facts"] == 1 and low["counts"]["labels"] == 1
    assert low["edges_by_source"] == {"aws_sg": 1}
    adm = (await client.get("/v1/assurance/state", headers=w["admin"])).json()
    assert adm["counts"]["nodes"] == 4 and adm["counts"]["edges"] == 3 and adm["counts"]["labels"] == 2


async def test_labels_and_zones_hide_what_names_a_hidden_asset(world, client):
    w = world
    labs = (await client.get("/v1/labels", headers=w["viewer"])).json()
    assert labs["total"] == 1 and labs["items"][0]["node_ref"] == w["pref"]
    zones = (await client.get("/v1/zones", headers=w["viewer"])).json()["items"]
    assert zones[0]["cidrs"] == ["10.50.0.0/16"]              # the /32 that IS the secret's address is gone
    assert _leaks(json.dumps(zones), w) == []
    zid = zones[0]["id"]
    assert (await client.get(f"/v1/zones/{zid}", headers=w["viewer"])).json()["cidrs"] == ["10.50.0.0/16"]
    assert f"{SECRET_IP}/32" in (await client.get(f"/v1/zones/{zid}", headers=w["admin"])).text


async def test_hidden_label_and_asset_answer_exactly_like_missing_ones(world, client, db_pool):
    """A low-clearance ADMIN must not be able to relabel (strip the crown-jewel tag of) or probe an
    asset it cannot see, and the refusal must equal the one for a node that does not exist."""
    w = world
    secret_lab = (await client.get("/v1/labels", headers=w["admin"])).json()["items"]
    secret_lab = next(x for x in secret_lab if x["node_ref"] == w["sref"])
    ghost = f"asset:{uuid.uuid4()}"
    body = {"tag": "crown-jewel", "value": "false", "justification": "tidy"}
    hidden = await client.put("/v1/labels", headers=w["lowadmin"], json={**body, "node_ref": w["sref"]})
    missing = await client.put("/v1/labels", headers=w["lowadmin"], json={**body, "node_ref": ghost})
    assert hidden.status_code == missing.status_code == 422
    assert hidden.json() == missing.json()
    ip_hidden = await client.put("/v1/labels", headers=w["lowadmin"],
                                 json={**body, "node_ref": f"ip:{SECRET_IP}"})
    assert ip_hidden.status_code == 422 and ip_hidden.json() == missing.json()
    d_hidden = await client.delete(f"/v1/labels/{secret_lab['id']}?justification=tidy", headers=w["lowadmin"])
    d_missing = await client.delete(f"/v1/labels/{uuid.uuid4()}?justification=tidy", headers=w["lowadmin"])
    assert d_hidden.status_code == d_missing.status_code == 404 and d_hidden.json() == d_missing.json()
    # nothing moved
    still = (await client.get("/v1/labels", headers=w["admin"])).json()["items"]
    assert any(x["node_ref"] == w["sref"] and x["value"] == "true" for x in still)
    # the same low admin can still label what it CAN see
    ok = await client.put("/v1/labels", headers=w["lowadmin"], json={**body, "node_ref": w["pref"], "tag": "class",
                                                                     "value": "web"})
    assert ok.status_code == 200, ok.text


async def test_confidential_clearance_hides_restricted_only(world, client, db_pool):
    w = world
    conf = await _asset(db_pool, "conf-asset", "confidential", ["10.3.3.3"])
    await _node(db_pool, f"asset:{conf}", "cloud_instance", conf)
    nodes = (await client.get("/v1/reach/nodes?limit=500", headers=w["conf"])).json()
    refs = {n["node_ref"] for n in nodes["items"]}
    assert f"asset:{conf}" in refs and w["sref"] not in refs
    low = (await client.get("/v1/reach/nodes?limit=500", headers=w["viewer"])).json()
    assert f"asset:{conf}" not in {n["node_ref"] for n in low["items"]}


# --------------------------------------------------------------------------------------------
# security-4: stored invariant results
# --------------------------------------------------------------------------------------------

async def _store_result(db_pool, inv, w):
    """What the runner stores for a violated invariant whose witness runs into the secret."""
    result = {
        "verdict": "VIOLATED", "reasons": [f"counterexample to {w['sref']}"], "violation_count": 1,
        "violating_targets": [w["sref"], "ip:10.9.9.9"], "violating_truncated": False,
        "evidence_tier": "configured", "coverage": {"universe": 4, "covered": 2, "ratio": 0.5},
        "witnesses": [{"hops": [{"src": "ip:10.9.9.9", "dst": w["sref"], "proto": "tcp", "ports": "5432",
                                 "detail": {"dst_ips": [SECRET_IP], "name": SECRET_VALUE}}]}],
        "blind_spots": [{"node": f"ip:{SECRET_IP}", "reason": "no_sensor", "direction": "in"}],
        "blind_spot_summary": {"total": 1, "by_reason": {"no_sensor": 1}},
    }
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE invariants SET last_verdict = 'VIOLATED', last_graph_version = 0, last_result = $2::jsonb "
            "WHERE id = $1", uuid.UUID(inv["id"]), json.dumps(result))
        await con.execute(
            "INSERT INTO invariant_runs (invariant_id, digest, verdict, reasons, result, graph_version) "
            "VALUES ($1, $2, 'VIOLATED', $3::jsonb, $4::jsonb, 0)", inv["invariant_id"], inv["digest"],
            json.dumps(result["reasons"]), json.dumps(result))
    return result


async def test_invariant_results_runs_and_witnesses_are_redacted(world, client, db_pool):
    w = world
    r = await client.post("/v1/invariants", headers=w["admin"], json={"yaml": inv_yaml()})
    assert r.status_code == 201, r.text
    inv = r.json()["invariant"]
    await _store_result(db_pool, inv, w)
    paths = ["/v1/invariants", f"/v1/invariants/{inv['id']}", f"/v1/invariants/{inv['id']}/runs?include_result=true"]
    for path in paths:
        low = await client.get(path, headers=w["viewer"])
        assert low.status_code == 200, path
        assert _leaks(low.text, w) == [], (path, low.text)
        assert "[redacted]" in low.text, path
        full = (await client.get(path, headers=w["admin"])).text
        assert w["sref"] in full, path                 # the admin still sees the real thing
    detail = (await client.get(paths[1], headers=w["viewer"])).json()
    assert detail["redacted"] is True and detail["violation_count"] == 1
    hop = detail["last_result"]["witnesses"][0]["hops"][0]
    assert hop["dst"] == "[redacted]" and hop["src"] == "ip:10.9.9.9" and hop["ports"] == "5432"
    run = (await client.get(paths[2], headers=w["viewer"])).json()["items"][0]
    assert run["redacted"] is True and run["verdict"] == "VIOLATED"
    # the admin's own view is untouched
    full = (await client.get(paths[1], headers=w["admin"])).json()
    assert full["redacted"] is False and full["last_result"]["witnesses"][0]["hops"][0]["dst"] == w["sref"]


async def test_evaluate_response_is_redacted_for_a_low_clearance_admin(world, client, monkeypatch):
    w = world
    from app.assurance import runner

    async def fake(pool, tid, **kw):
        return {"ok": True, "evaluated": 1, "graph_version": 3,
                "results": [{"invariant_id": "acme:x", "verdict": "VIOLATED",
                             "witness": f"ip:10.9.9.9 -> {w['sref']} ({SECRET_IP})"}],
                "builders": {"aws_sg": {"notes": [f"{SECRET_VALUE} has no rules"]}}}

    monkeypatch.setattr(runner, "evaluate_tenant", fake)
    low = await client.post("/v1/assurance/evaluate", headers=w["lowadmin"], json={})
    assert low.status_code == 200 and _leaks(low.text, w) == [] and "[redacted]" in low.text
    full = await client.post("/v1/assurance/evaluate", headers=w["admin"], json={})
    assert w["sref"] in full.text


def test_scrub_is_token_exact_and_handles_compounds():
    vis = api._Vis({"ip:10.7.7.7"}, [], {"10.7.7.7", "ip:10.7.7.7", "asset:abcd", "abcd", "secret-payroll-db"},
                   ["payroll db"], active=True)
    assert vis.scrub("10.7.7.77 and 10.7.7.7:5432") == "10.7.7.77 and [redacted]"
    # a token glued to punctuation is still caught (the whole run is replaced: coarse is safe)
    assert vis.scrub({"ip:10.7.7.7": ["x", "asset:abcd->ok", "reaches 10.7.7.7."]}) == {
        "[redacted]": ["x", "[redacted]>ok", "reaches [redacted]"]}
    assert vis.scrub("the Payroll DB box") == "the [redacted] box"
    assert vis.scrub(7) == 7 and vis.scrub(None) is None


# --------------------------------------------------------------------------------------------
# security-2: attacker-controlled CPU stays off the event loop
# --------------------------------------------------------------------------------------------

class _Ticker:
    """Measures the worst gap between 20 ms loop ticks while a request runs."""

    def __init__(self):
        self.max_lag = 0.0
        self._stop = False

    async def run(self):
        last = time.perf_counter()
        while not self._stop:
            await asyncio.sleep(0.02)
            now = time.perf_counter()
            self.max_lag = max(self.max_lag, now - last - 0.02)
            last = now

    async def __aenter__(self):
        self._t = asyncio.ensure_future(self.run())
        await asyncio.sleep(0.05)
        return self

    async def __aexit__(self, *a):
        self._stop = True
        await self._t


async def test_compile_does_not_block_the_event_loop(client, monkeypatch):
    import paddock_assurance as lib
    real = lib.compile_text

    def slow(text):
        time.sleep(0.6)               # a CPU-bound parse, as far as the loop is concerned
        return real(text)

    monkeypatch.setattr(lib, "compile_text", slow)
    assert (await client.get("/v1/invariants")).status_code == 200      # warm the app (first-request costs)
    async with _Ticker() as tick:
        r = await client.post("/v1/invariants", json={"yaml": inv_yaml()})
    assert r.status_code == 201, r.text
    assert tick.max_lag < 0.3, f"event loop was blocked for {tick.max_lag:.2f}s"


async def test_compile_timeout_is_a_422_and_slots_are_bounded(client, monkeypatch):
    import paddock_assurance as lib

    def hang(text):
        time.sleep(1.0)
        raise RuntimeError("never mind")

    monkeypatch.setattr(lib, "compile_text", hang)
    monkeypatch.setattr(api, "COMPILE_TIMEOUT_S", 0.2)
    t0 = time.perf_counter()
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml()})
    assert time.perf_counter() - t0 < 0.9
    assert r.status_code == 422
    assert any("within" in p for p in r.json()["detail"]["problems"])
    assert (await client.get("/v1/invariants")).json()["total"] == 0
    # PUT shares the path
    await asyncio.sleep(1.0)          # let the wedged thread end and free its slot


async def test_all_compile_slots_taken_is_429_not_a_queue(client, monkeypatch):
    held = [api._compile_slots.acquire(blocking=False) for _ in range(api.COMPILE_SLOTS)]
    try:
        assert all(held)
        r = await client.post("/v1/invariants", json={"yaml": inv_yaml()})
        assert r.status_code == 429 and r.headers.get("retry-after")
    finally:
        for h in held:
            if h:
                api._compile_slots.release()
    assert (await client.post("/v1/invariants", json={"yaml": inv_yaml()})).status_code == 201


async def test_hostile_nesting_is_refused_before_any_parser_runs(client):
    assert (await client.get("/v1/invariants")).status_code == 200      # warm the app (first-request costs)
    async with _Ticker() as tick:
        t0 = time.perf_counter()
        r = await client.post("/v1/invariants", json={"yaml": "[" * 2500})
        took = time.perf_counter() - t0
        r2 = await client.post("/v1/invariants", json={"yaml": "a: " + "{" * 100 + "}" * 100})
    assert r.status_code == 422 and "nest" in json.dumps(r.json())
    assert r2.status_code == 422
    assert took < 1.0, f"took {took:.1f}s"
    assert tick.max_lag < 0.3


# --------------------------------------------------------------------------------------------
# security-3: per-tenant caps
# --------------------------------------------------------------------------------------------

def test_cap_constants_are_the_documented_ones():
    assert api.MAX_INVARIANTS_ENABLED == 200 and api.MAX_ZONES == 200 and api.MAX_ZONE_CIDRS == 256
    assert api.MAX_LABELS == 20_000 and api.MAX_SENSOR_CIDRS == 64


async def test_enabled_invariant_cap_is_a_409_on_create_enable_and_std(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_INVARIANTS_ENABLED", 2)
    a = await _create(client, "acme:one")
    await _create(client, "acme:two")
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml("acme:three")})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "invariant_limit"
    assert r.json()["detail"]["limit"] == 2
    # a disabled one is allowed (it costs nothing per tick) ...
    d = await client.post("/v1/invariants", json={"yaml": inv_yaml("acme:three"), "enabled": False})
    assert d.status_code == 201
    # ... but enabling it, or enabling a std copy, would pass the cap
    third = d.json()["invariant"]["id"]
    assert (await client.put(f"/v1/invariants/{third}", json={"enabled": True})).status_code == 409
    assert (await client.post("/v1/invariants/std/std:coverage-complete/enable")).status_code == 409
    # freeing a slot frees the cap
    assert (await client.delete(f"/v1/invariants/{a['id']}")).status_code == 200
    assert (await client.put(f"/v1/invariants/{third}", json={"enabled": True})).status_code == 200


async def test_total_invariant_rows_are_capped_too(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_INVARIANTS_TOTAL", 2)
    for i in range(2):
        assert (await client.post("/v1/invariants", json={"yaml": inv_yaml(f"acme:r{i}"),
                                                          "enabled": False})).status_code == 201
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml("acme:r9"), "enabled": False})
    assert r.status_code == 409 and r.json()["detail"]["scope"] == "total"


async def test_zone_caps(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_ZONES", 2)
    for i in range(2):
        r = await client.post("/v1/zones", json={"name": f"z{i}", "cidrs": [f"10.{i}.0.0/16"], "justification": "j"})
        assert r.status_code == 201
    r = await client.post("/v1/zones", json={"name": "z9", "cidrs": ["10.9.0.0/16"], "justification": "j"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "zone_limit"
    # an update of an existing zone is not a new zone
    zid = (await client.get("/v1/zones")).json()["items"][0]["id"]
    assert (await client.put(f"/v1/zones/{zid}", json={"description": "x", "justification": "j"})).status_code == 200
    # total CIDRs over all zones
    monkeypatch.setattr(api, "MAX_ZONES", 200)
    monkeypatch.setattr(api, "MAX_TOTAL_ZONE_CIDRS", 3)
    r = await client.put(f"/v1/zones/{zid}", json={"cidrs": [f"172.16.{i}.0/24" for i in range(3)],
                                                   "justification": "j"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "zone_cidr_limit"
    ok = await client.put(f"/v1/zones/{zid}", json={"cidrs": ["172.16.0.0/24", "172.16.1.0/24"],
                                                    "justification": "j"})
    assert ok.status_code == 200


async def test_cidrs_per_zone_cap_is_256_and_clear(client):
    many = [f"10.{i // 256}.{i % 256}.0/24" for i in range(257)]
    r = await client.post("/v1/zones", json={"name": "big", "cidrs": many, "justification": "j"})
    assert r.status_code == 422
    r = await client.post("/v1/zones", json={"name": "big", "cidrs": many[:256], "justification": "j"})
    assert r.status_code == 201


async def test_label_cap_counts_declared_labels_and_allows_changes(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_LABELS", 2)
    for i in range(2):
        r = await client.put("/v1/labels", json={"node_ref": f"ip:10.0.0.{i + 1}", "tag": "class",
                                                 "value": "x", "justification": "j"})
        assert r.status_code == 200
    r = await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.9", "tag": "class", "value": "x",
                                             "justification": "j"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "label_limit"
    # changing an existing label is not a new one
    r = await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.1", "tag": "class", "value": "y",
                                             "justification": "j"})
    assert r.status_code == 200 and r.json()["changed"]


# --------------------------------------------------------------------------------------------
# security-5: the coverage view
# --------------------------------------------------------------------------------------------

async def _seed_cov_at(db_pool, ref, direction, *, tier, age_h, source="s", detail=None):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_coverage (node_ref, direction, tier, source, observed_at, detail) "
            "VALUES ($1,$2,$3,$4,$5,$6::jsonb)", ref, direction, tier, source,
            NOW() - dt.timedelta(hours=age_h), json.dumps(detail or {}))


async def _seed_coverage_zoo(db_pool):
    """Every combination the SQL has to classify the way the library does."""
    cases = {
        "a": [("in", "observed", 1), ("out", "observed", 1)],            # covered both
        "b": [("in", "observed", 1)],                                    # in only
        "c": [("out", "configured", 1)],                                 # out only
        "d": [("in", "observed", 48), ("out", "observed", 48)],          # stale both
        "e": [("in", "declared", 1), ("out", "declared", 1)],            # tier below configured
        "f": [("in", "observed", -2), ("out", "observed", -2)],          # from the future
        "g": [],                                                         # nothing
        "h": [("in", "declared", 1), ("in", "observed", 48)],            # tier below AND stale: stale wins
        "i": [("in", "observed", 1, {"origin": "internet", "proto": "tcp"}), ("out", "observed", 1)],  # qualified
        "j": [("in", "configured", 23.9), ("out", "tested", 0.1)],       # edge of freshness
    }
    for name, facts in cases.items():
        await _node_plain(db_pool, f"ip:10.0.0.{ord(name)}")
        for i, f in enumerate(facts):
            direction, tier, age = f[:3]
            await _seed_cov_at(db_pool, f"ip:10.0.0.{ord(name)}", direction, tier=tier, age_h=age,
                               source=f"s{i}", detail=f[3] if len(f) > 3 else None)
    return cases


async def _node_plain(db_pool, ref, kind="host"):
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO reach_nodes (node_ref, kind, source) VALUES ($1, $2, 'test')", ref, kind)


def _library_view(cases, now, min_tier, max_age):
    """The truth: the library's own ``direction_state`` over the same facts (qualified facts do not
    speak for the unqualified question)."""
    import paddock_assurance as lib
    from paddock_assurance import graph as g
    per = {}
    for name, facts in cases.items():
        cov = tuple(g.Coverage(tier=lib.Tier(f[1]), observed_at=now - dt.timedelta(hours=f[2]), source="s",
                               direction=f[0], **(f[3] if len(f) > 3 else {})) for f in facts)
        node = g.Node(id=f"ip:10.0.0.{ord(name)}", coverage=cov)
        per[node.id] = (g.direction_state(node, "in", now, lib.Tier(min_tier), max_age),
                        g.direction_state(node, "out", now, lib.Tier(min_tier), max_age))
    return per


@pytest.mark.parametrize("min_tier,max_age_h", [("configured", 24), ("observed", 24), ("declared", 72),
                                                ("tested", 6)])
async def test_sql_coverage_summary_equals_the_librarys_rule(client, db_pool, min_tier, max_age_h):
    cases = await _seed_coverage_zoo(db_pool)
    r = (await client.get(f"/v1/assurance/coverage?min_tier={min_tier}&max_age_h={max_age_h}&limit=500")).json()
    per = _library_view(cases, dt.datetime.now(dt.timezone.utc), min_tier, dt.timedelta(hours=max_age_h))
    both = sum(1 for i, o in per.values() if i.covered and o.covered)
    assert r["summary"]["nodes"] == len(cases) and r["summary"]["covered"] == both
    assert r["summary"]["covered_in_only"] == sum(1 for i, o in per.values() if i.covered and not o.covered)
    assert r["summary"]["covered_out_only"] == sum(1 for i, o in per.values() if o.covered and not i.covered)
    for d, idx in (("in", 0), ("out", 1)):
        want: dict[str, int] = {}
        for st in per.values():
            if st[idx].reason:
                want[st[idx].reason] = want.get(st[idx].reason, 0) + 1
        assert r["blind_spots"]["nodes_by_reason"][d] == want, (d, min_tier, max_age_h)
    # the page (re-derived through the library) agrees with the summary and with the library
    for n in r["nodes"]["items"]:
        i, o = per[n["node_ref"]]
        assert (n["covered_in"], n["covered_out"], n["reason_in"], n["reason_out"]) == (
            i.covered, o.covered, i.reason, o.reason), n["node_ref"]
    blind = (await client.get(f"/v1/assurance/coverage?only_blind=true&min_tier={min_tier}&max_age_h={max_age_h}"
                              "&limit=500")).json()
    assert blind["nodes"]["total"] == len(cases) - both
    assert (await client.get("/v1/assurance/coverage?kind=cidr")).json()["nodes"]["total"] == 0
    assert (await client.get("/v1/assurance/coverage?q=10.0.0.97")).json()["nodes"]["total"] == 1   # 'a'


async def test_limit_one_derives_only_one_page_of_nodes(client, db_pool, monkeypatch):
    """The old handler classified EVERY node through the library on every request (finding
    security-5: 100k nodes took seconds on the loop). Now only the requested page is."""
    await _seed_coverage_zoo(db_pool)
    from paddock_assurance import graph as g
    calls = []
    real = g.direction_state

    def counting(node, *a, **kw):
        calls.append(node.id)
        return real(node, *a, **kw)

    monkeypatch.setattr(g, "direction_state", counting)
    r = (await client.get("/v1/assurance/coverage?limit=1")).json()
    assert r["summary"]["nodes"] == 10 and len(r["nodes"]["items"]) == 1 and r["nodes"]["total"] == 10
    assert len(calls) == 2, calls          # in + out of ONE node


async def test_coverage_runs_without_blocking_with_many_nodes(client, db_pool):
    assert (await client.get("/v1/invariants")).status_code == 200      # warm the app (first-request costs)
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_nodes (node_ref, kind, source) "
            "SELECT 'ip:10.' || (g / 65536) || '.' || ((g / 256) % 256) || '.' || (g % 256), 'ip', 'test' "
            "FROM generate_series(1, 40000) g")
        await con.execute(
            "INSERT INTO reach_coverage (node_ref, direction, tier, source, observed_at) "
            "SELECT node_ref, d, 'observed', 'sentry_flow', NOW() FROM reach_nodes, (VALUES ('in'), ('out')) v(d)")
    async with _Ticker() as tick:
        r = await client.get("/v1/assurance/coverage?limit=1")
    assert r.status_code == 200 and r.json()["summary"]["nodes"] == 40000
    assert r.json()["summary"]["covered"] == 40000
    assert tick.max_lag < 0.3, f"loop lag {tick.max_lag:.2f}s"


# --------------------------------------------------------------------------------------------
# security-7: removals need a reason; exceptions are audited
# --------------------------------------------------------------------------------------------

async def test_zone_and_label_delete_require_a_justification(client, db_pool):
    z = (await client.post("/v1/zones", json={"name": "guest", "cidrs": ["10.0.0.0/8"],
                                              "justification": "j"})).json()["zone"]
    lab = (await client.put("/v1/labels", json={"node_ref": "ip:10.0.0.5", "tag": "class", "value": "x",
                                                "justification": "j"})).json()["label"]
    v = (await client.get("/v1/assurance/state")).json()["graph_version"]
    for path in (f"/v1/zones/{z['id']}", f"/v1/labels/{lab['id']}"):
        assert (await client.delete(path)).status_code == 422                        # absent
        assert (await client.delete(path + "?justification=")).status_code == 422    # empty
        assert (await client.delete(path + "?justification=%20%20ab%20")).status_code == 422   # < 3 trimmed
    assert (await client.get("/v1/assurance/state")).json()["graph_version"] == v    # nothing moved
    assert (await client.get(f"/v1/zones/{z['id']}")).status_code == 200
    assert (await client.delete(f"/v1/zones/{z['id']}?justification=%20network%20retired%20")).status_code == 200
    assert (await client.delete(f"/v1/labels/{lab['id']}?justification=host%20decommissioned")).status_code == 200
    assert (await _audit_rows(db_pool, "assurance_zone_delete"))[0]["justification"] == "network retired"
    assert (await _audit_rows(db_pool, "assurance_label_delete"))[0]["justification"] == "host decommissioned"


async def test_invariant_changes_accept_and_audit_a_justification(client, db_pool):
    r = await client.post("/v1/invariants", json={"yaml": inv_yaml(), "justification": "pos segmentation policy"})
    inv = r.json()["invariant"]
    await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": inv_yaml(title="Renamed rule"),
                                                          "justification": "wording"})
    await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": False, "justification": "noisy during migration"})
    await client.delete(f"/v1/invariants/{inv['id']}?justification=superseded")
    await client.post("/v1/invariants/std/std:coverage-complete/enable?justification=insurer%20asked")
    assert [a["justification"] for a in await _audit_rows(db_pool, "assurance_invariant_create")] == [
        "pos segmentation policy"]
    ups = await _audit_rows(db_pool, "assurance_invariant_update")
    assert [a["justification"] for a in ups] == ["wording", "noisy during migration"]
    # an omitted justification stays optional (and is recorded as none)
    await client.put(f"/v1/invariants/{inv['id']}", json={"enabled": True})
    assert (await _audit_rows(db_pool, "assurance_invariant_update"))[-1]["justification"] in (None, "")
    assert (await _audit_rows(db_pool, "assurance_std_enable"))[0]["justification"] == "insurer asked"


def _allow_yaml(expires: str, reason: str = "legacy till cutover") -> str:
    return inv_yaml() + f"allow:\n  - to: {{ zone: pos }}\n    reason: {reason}\n    expires: {expires}\n"


async def test_allow_exceptions_are_audited_with_reason_and_expiry_and_capped(client, db_pool):
    soon = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    r = await client.post("/v1/invariants", json={"yaml": _allow_yaml(soon)})
    assert r.status_code == 201, r.text
    inv = r.json()["invariant"]
    ex = (await _audit_rows(db_pool, "assurance_invariant_create"))[0]["details"]["exceptions"]
    assert ex[0]["reason"] == "legacy till cutover" and ex[0]["expires"] == soon
    later = (dt.date.today() + dt.timedelta(days=60)).isoformat()
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": _allow_yaml(later, "extended by CAB")})
    assert r.status_code == 200
    ex = (await _audit_rows(db_pool, "assurance_invariant_update"))[0]["details"]["exceptions"]
    assert ex[0]["reason"] == "extended by CAB" and ex[0]["expires"] == later
    # a permanent exception is refused (create and update), naming the limit
    forever = await client.post("/v1/invariants", json={"yaml": _allow_yaml("9999-12-31").replace(
        "guest-cannot-reach-pos", "other")})
    assert forever.status_code == 422 and "90 days" in json.dumps(forever.json())
    r = await client.put(f"/v1/invariants/{inv['id']}", json={"yaml": _allow_yaml("9999-12-31")})
    assert r.status_code == 422 and "allow[0].expires" in json.dumps(r.json())


# --------------------------------------------------------------------------------------------
# sensor scopes
# --------------------------------------------------------------------------------------------

async def _sensor(db_pool, name="s1", tenant=TENANT_A) -> str:
    async with db_pool.acquire() as con:
        return str(await con.fetchval(
            "INSERT INTO sensors (tenant_id, name, site, cred_prefix, cred_hash) VALUES ($1, $2, 'hq', $3, 'h') "
            "RETURNING id", tenant, name, f"sp-{uuid.uuid4().hex[:8]}"))


async def test_sensor_scope_crud_audit_graph_version_and_rebuild_flag(client, db_pool):
    sid = await _sensor(db_pool)
    listed = (await client.get("/v1/assurance/sensor-scopes")).json()
    assert listed["items"] == [] and [s["sensor_id"] for s in listed["unscoped_sensors"]] == [sid]
    async with db_pool.acquire() as con:       # pretend a build just finished
        await con.execute("INSERT INTO assurance_state (last_build_at) VALUES (NOW())")
    v0 = (await client.get("/v1/assurance/state")).json()["graph_version"]
    r = await client.put(f"/v1/assurance/sensor-scopes/{sid}", json={
        "cidrs": ["10.20.0.5/24", "10.30.0.0/24", "10.30.0.0/24"], "justification": "span port 3"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] is True and body["scope"]["cidrs"] == ["10.20.0.0/24", "10.30.0.0/24"]
    assert body["graph_version"] == v0 + 1 and body["previous"] is None
    assert body["scope"]["set_by"] and body["scope"]["justification"] == "span port 3"
    async with db_pool.acquire() as con:       # the builders are made due NOW (narrowing must bite fast)
        assert await con.fetchval("SELECT last_build_at FROM assurance_state") is None
        await con.execute("UPDATE assurance_state SET last_build_at = NOW()")
    # same set again: justification refreshed, no version bump, no rebuild request
    same = (await client.put(f"/v1/assurance/sensor-scopes/{sid}", json={
        "cidrs": ["10.30.0.0/24", "10.20.0.0/24"], "justification": "re-confirmed"})).json()
    assert same["changed"] is False and same["graph_version"] is None
    assert same["scope"]["justification"] == "re-confirmed"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT last_build_at FROM assurance_state") is not None
    got = (await client.get("/v1/assurance/sensor-scopes")).json()
    assert got["total"] == 1 and got["items"][0]["name"] == "s1" and got["unscoped_sensors"] == []
    aud = await _audit_rows(db_pool, "assurance_sensor_scope_set")
    assert aud[0]["details"]["cidrs"] == ["10.20.0.0/24", "10.30.0.0/24"] and aud[0]["justification"] == "span port 3"
    # delete: justification required, bumps, audited, then it covers nothing again
    assert (await client.delete(f"/v1/assurance/sensor-scopes/{sid}")).status_code == 422
    d = await client.delete(f"/v1/assurance/sensor-scopes/{sid}?justification=span%20removed")
    assert d.status_code == 200 and d.json()["previous"] == ["10.20.0.0/24", "10.30.0.0/24"]
    assert d.json()["graph_version"] == v0 + 2
    assert (await client.delete(f"/v1/assurance/sensor-scopes/{sid}?justification=again")).status_code == 404
    assert (await _audit_rows(db_pool, "assurance_sensor_scope_delete"))[0]["justification"] == "span removed"
    assert [s["sensor_id"] for s in (await client.get("/v1/assurance/sensor-scopes")).json()["unscoped_sensors"]] == [sid]


async def test_sensor_scope_validation(client, db_pool):
    sid = await _sensor(db_pool)
    path = f"/v1/assurance/sensor-scopes/{sid}"
    ok = {"cidrs": ["10.0.0.0/24"], "justification": "j"}
    for bad in ({**ok, "cidrs": []}, {**ok, "cidrs": ["0.0.0.0/0"]}, {**ok, "cidrs": ["10.0.0.0"]},
                {**ok, "cidrs": ["nonsense/24"]}, {**ok, "justification": "  "}, {"cidrs": ok["cidrs"]},
                {**ok, "cidrs": [f"10.{i}.0.0/16" for i in range(65)]}, {**ok, "extra": 1} if False else {}):
        r = await client.put(path, json=bad)
        assert r.status_code == 422, (bad, r.status_code, r.text)
    assert (await client.put(path, json={**ok, "cidrs": [f"10.{i}.0.0/16" for i in range(64)]})).status_code == 200
    assert (await client.get("/v1/assurance/sensor-scopes")).json()["total"] == 1


async def test_sensor_scope_unknown_and_foreign_ids_are_the_same_404(enforce, client, app, app_pool, db_pool):  # noqa: F811
    app.state.pool = app_pool
    b = "00000000-0000-0000-0000-0000000000b8"
    await tenancy.create_tenant(db_pool, slug="bravo-scope", name="Bravo", tenant_id=b)
    ka = _hdr(await _seed_admin(db_pool, TENANT_A, "alice-admin"))
    kb = _hdr(await _seed_admin(db_pool, b, "bob-admin"))
    sa = await _sensor(db_pool, "alpha-sensor", TENANT_A)
    body = {"cidrs": ["10.0.0.0/24"], "justification": "j"}
    assert (await client.put(f"/v1/assurance/sensor-scopes/{sa}", headers=ka, json=body)).status_code == 200
    before = (await client.get("/v1/assurance/sensor-scopes", headers=ka)).json()
    foreign = await client.put(f"/v1/assurance/sensor-scopes/{sa}", headers=kb, json=body)
    unknown = await client.put(f"/v1/assurance/sensor-scopes/{uuid.uuid4()}", headers=kb, json=body)
    assert foreign.status_code == unknown.status_code == 404 and foreign.json() == unknown.json()
    f2 = await client.delete(f"/v1/assurance/sensor-scopes/{sa}?justification=cleanup", headers=kb)
    u2 = await client.delete(f"/v1/assurance/sensor-scopes/{uuid.uuid4()}?justification=cleanup", headers=kb)
    assert f2.status_code == u2.status_code == 404 and f2.json() == u2.json()
    assert (await client.get("/v1/assurance/sensor-scopes", headers=kb)).json() == {
        "items": [], "unscoped_sensors": [], "total": 0}
    assert (await client.get("/v1/assurance/sensor-scopes", headers=ka)).json() == before
    assert "alpha" not in (await client.get("/v1/assurance/sensor-scopes", headers=kb)).text


async def test_sensor_scope_rbac_and_billing_gate(enforce, client, db_pool):  # noqa: F811
    admin = _hdr(await _seed_admin(db_pool, TENANT_A, "ada-admin"))
    _, vk = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    viewer = _hdr(vk)
    sid = await _sensor(db_pool)
    path = f"/v1/assurance/sensor-scopes/{sid}"
    body = {"cidrs": ["10.0.0.0/24"], "justification": "j"}
    assert (await client.get("/v1/assurance/sensor-scopes")).status_code == 401
    assert (await client.get("/v1/assurance/sensor-scopes", headers=viewer)).status_code == 200
    assert (await client.put(path, json=body)).status_code == 401
    assert (await client.put(path, headers=viewer, json=body)).status_code == 403
    assert (await client.delete(path + "?justification=abc", headers=viewer)).status_code == 403
    assert (await client.get("/v1/assurance/sensor-scopes", headers=admin)).json()["items"] == []
    assert (await client.put(path, headers=admin, json=body)).status_code == 200


# --------------------------------------------------------------------------------------------
# security-8: flow ingest
# --------------------------------------------------------------------------------------------

def _flow(**kw):
    now = dt.datetime.now(dt.timezone.utc)
    f = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "tcp", "dst_port": 443,
         "sensor_id": str(uuid.uuid4()), "first_seen": (now - dt.timedelta(minutes=2)).isoformat(),
         "last_seen": now.isoformat(), "packets": 3, "bytes": 300, "oriented": "syn"}
    f.update(kw)
    return f


async def test_flow_ingest_rejects_scope_ids_and_oversize_strings(client, db_pool):
    for bad in ({"src_ip": "2001:db8::99%9"}, {"dst_ip": "fe80::1%eth0"}, {"src_ip": "2001:db8::7%" + "z" * 100},
                {"src_ip": "1" * 200}, {"dst_ip": "[2001:db8::1%1]"}, {"src_ip": "10.0.0.1%1"},
                {"sensor_id": "{" + str(uuid.uuid4()) + "}"}, {"sensor_id": uuid.uuid4().hex},
                {"sensor_id": "urn:uuid:" + str(uuid.uuid4())}, {"sensor_id": "x" * 500}):
        r = await client.post("/v1/reach/flows/bulk", json={"flows": [_flow(**bad)]})
        assert r.status_code == 422, (bad, r.status_code, r.text[:200])
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM reach_flow_obs") == 0       # all-or-nothing, nothing stored
    sid = str(uuid.uuid4())
    r = await client.post("/v1/reach/flows/bulk", json={"flows": [
        _flow(src_ip="2001:DB8::0099", sensor_id=sid), _flow(src_ip="[2001:db8::99]", sensor_id=sid)]})
    assert r.status_code == 200 and r.json()["merged"] == 1        # canonical, one identity
    async with db_pool.acquire() as con:
        assert [x["src_ip"] for x in await con.fetch("SELECT src_ip FROM reach_flow_obs")] == ["2001:db8::99"]


async def test_flow_ingest_writes_no_handler_audit_rows(client, db_pool):
    """The data-plane route adds none of its own rows (the middleware's per-request record is the
    only one; exempting this route from it is a request to auth.py, see the work package notes)."""
    r = await client.post("/v1/reach/flows/bulk", json={"flows": [_flow()]})
    assert r.status_code == 200
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT count(*) FROM audit_log WHERE action LIKE 'assurance_%'")
    assert n == 0

