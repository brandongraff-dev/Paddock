"""Sentry flows -> reach graph (docs/ASSURANCE_P1.md section 4.3).

Three layers:

* pure ``build`` tests (no database),
* the ingest route ``POST /v1/reach/flows/bulk`` (validation, upsert semantics, clamping, RBAC and
  tenant isolation; served through the non-superuser pool so RLS is real),
* the loader on Postgres, plus soundness checks that feed the builder's output to the real
  ``paddock_assurance`` evaluator: a node must never be reported covered by a silent sensor.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import random
import uuid

import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.assurance.builders import _ipmap
from app.assurance.builders import sentry_flows as sen
from app.config import settings

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
H = dt.timedelta(hours=1)
S1 = "5e5e5e5e-0000-0000-0000-000000000001"
S2 = "5e5e5e5e-0000-0000-0000-000000000002"
S3 = "5e5e5e5e-0000-0000-0000-000000000003"
CAM = "10.1.0.10"
NVR = "10.1.0.20"
POS = "10.2.0.5"
UP = NOW - dt.timedelta(minutes=2)


def flow(src, dst, port=443, *, proto="tcp", sensor=S1, oriented="syn", last=NOW - dt.timedelta(minutes=1),
         first=None, packets=3, nbytes=300):
    return {"src_ip": src, "dst_ip": dst, "proto": proto, "dst_port": port, "sensor_id": sensor,
            "first_seen": first or last - dt.timedelta(minutes=5), "last_seen": last,
            "packets": packets, "bytes": nbytes, "oriented": oriented}


def sensor(sid=S1, *, status="active", online=True, up=UP):
    return {"id": sid, "name": f"s-{sid[-1]}", "status": status, "online": online, "last_upload_at": up}


def device(ips, aid=None, kind="iot_device"):
    return {"id": aid or str(uuid.uuid4()), "kind": kind, "value": "dev", "canonical": "dev",
            "metadata": {"ips": list(ips)}}


# Coverage needs a declared sensor scope (review finding builders-3, schema 040 ``sensor_scopes``):
# these tests are about everything *except* scoping, so by default every test sensor mirrors the
# private ranges the fixtures use. tests/test_assurance_sensor_scope.py covers scoping itself.
DEFAULT_SCOPE = ("10.0.0.0/8", "2001:db8::/32")


def rows(flows=(), sensors=(sensor(),), assets=(), truncated=False, scopes=None):
    if scopes is None:
        scopes = [{"sensor_id": s["id"], "cidrs": list(DEFAULT_SCOPE)} for s in sensors]
    return {"flows": list(flows), "sensors": list(sensors), "assets": list(assets), "truncated": truncated,
            "scopes": scopes}


def covered(out):
    return {(c.node_ref, c.direction) for c in out.coverage}


# --------------------------------------------------------------------------- #
# Pure builder: edges
# --------------------------------------------------------------------------- #

def test_flow_becomes_an_observed_edge_with_the_contract_shape():
    out = sen.build(rows([flow(CAM, NVR, 554)]), NOW)
    assert (out.source, out.mode, out.window) == ("sentry_flow", "window", dt.timedelta(hours=24))
    (e,) = out.edges
    assert (e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi) == (f"ip:{CAM}", f"ip:{NVR}", "tcp", 554, 554)
    assert (e.basis, e.source, e.confidence) == ("observed", "sentry_flow", 100)
    assert e.evidence["oriented"] == "syn" and e.evidence["sensors"] == [S1]
    assert {n.ref for n in out.nodes} == {f"ip:{CAM}", f"ip:{NVR}"}


def test_guessed_orientation_lowers_confidence_and_says_so():
    out = sen.build(rows([flow(CAM, NVR, 5000, oriented="heuristic")]), NOW)
    e = next(e for e in out.edges if e.src_ref == f"ip:{CAM}")
    assert e.confidence == 50 and "assumption" in e.evidence
    assert (e.port_lo, e.port_hi) == (5000, 5000)
    assert any("guessed direction" in n for n in out.notes)


def test_a_guessed_orientation_also_emits_the_reverse_edge_on_every_port():
    """If the guess is backwards the real edge is NVR -> CAM; leaving it out would be a false HOLDS."""
    out = sen.build(rows([flow(CAM, NVR, 5000, oriented="heuristic")]), NOW)
    by = {(e.src_ref, e.dst_ref): e for e in out.edges}
    assert set(by) == {(f"ip:{CAM}", f"ip:{NVR}"), (f"ip:{NVR}", f"ip:{CAM}")}
    r = by[(f"ip:{NVR}", f"ip:{CAM}")]
    assert (r.proto, r.port_lo, r.port_hi, r.basis, r.confidence) == ("tcp", 1, 65535, "observed", 50)
    assert r.evidence["assumed_all_ports"] == "reverse_of_guessed_orientation"
    assert "assumption" in r.evidence


def test_a_syn_confirmed_edge_has_no_reverse_and_icmp_reverse_has_no_ports():
    out = sen.build(rows([flow(CAM, NVR, 554, oriented="syn")]), NOW)
    assert [(e.src_ref, e.dst_ref) for e in out.edges] == [(f"ip:{CAM}", f"ip:{NVR}")]
    out = sen.build(rows([flow(CAM, NVR, 0, proto="icmp", oriented="heuristic")]), NOW)
    rev = next(e for e in out.edges if e.src_ref == f"ip:{NVR}")
    assert (rev.proto, rev.port_lo, rev.port_hi) == ("icmp", 0, 0)


def test_every_edge_the_builder_emits_is_accepted_by_the_store():
    """Pure check of the store's own rule: nothing the builder emits would be skipped."""
    from app.assurance import store

    out = sen.build(rows([flow(CAM, NVR, 0, proto="any"), flow(CAM, POS, 0, proto="udp"),
                          flow(CAM, "10.1.0.30", 0, proto="icmp"),
                          flow(NVR, POS, 5000, oriented="heuristic")]), NOW)
    assert out.edges and all(store._edge_issue(e, out.source) is None for e in out.edges)


def test_a_syn_observation_of_the_same_edge_restores_confidence():
    out = sen.build(rows([flow(CAM, NVR, 80, oriented="heuristic", sensor=S1),
                          flow(CAM, NVR, 80, oriented="syn", sensor=S2)],
                         sensors=[sensor(S1), sensor(S2)]), NOW)
    (e,) = out.edges
    assert e.confidence == 100 and e.evidence["sensors"] == [S1, S2]


def test_flows_from_several_sensors_merge_into_one_edge_with_summed_counters():
    out = sen.build(rows([flow(CAM, NVR, packets=3, nbytes=10, last=NOW - H, sensor=S1),
                          flow(CAM, NVR, packets=4, nbytes=20, last=NOW - 2 * H, sensor=S2)],
                         sensors=[sensor(S1), sensor(S2)]), NOW)
    (e,) = out.edges
    assert (e.evidence["packets"], e.evidence["bytes"]) == (7, 30)
    assert e.last_seen == NOW - H and e.first_seen == NOW - 2 * H - dt.timedelta(minutes=5)


def test_known_device_ips_resolve_to_the_asset_node_and_kind():
    cam = device([CAM], aid=str(uuid.uuid4()))
    out = sen.build(rows([flow(CAM, NVR)], assets=[cam]), NOW)
    (e,) = out.edges
    assert e.src_ref == f"asset:{cam['id']}" and e.dst_ref == f"ip:{NVR}"
    kinds = {n.ref: (n.kind, n.asset_id) for n in out.nodes}
    assert kinds[e.src_ref] == ("device", cam["id"]) and kinds[e.dst_ref][0] == "ip"


def test_the_same_machine_is_one_node_whatever_ip_spelling_the_flow_used():
    cam = device(["2001:db8::1"])
    out = sen.build(rows([flow("2001:0DB8:0:0:0:0:0:1", NVR), flow("::ffff:10.1.0.20", "2001:db8::1")],
                         assets=[cam]), NOW)
    refs = {(e.src_ref, e.dst_ref) for e in out.edges}
    assert refs == {(f"asset:{cam['id']}", f"ip:{NVR}"), (f"ip:{NVR}", f"asset:{cam['id']}")}


def test_ambiguous_address_is_over_approximated_to_every_candidate_and_gets_no_coverage():
    a, b = device([CAM]), device([CAM])
    out = sen.build(rows([flow(CAM, NVR)], assets=[a, b]), NOW)
    srcs = {e.src_ref for e in out.edges}
    assert srcs == {f"asset:{a['id']}", f"asset:{b['id']}", f"ip:{CAM}"}
    assert all(e.evidence["ambiguous_identity"] for e in out.edges)
    assert not any(c.node_ref in srcs for c in out.coverage)        # never guess an owner
    assert (f"ip:{NVR}", "in") in covered(out)                      # the unambiguous end is fine


def test_unknown_protocol_and_missing_port_are_widened_not_pinned_to_zero():
    out = sen.build(rows([flow(CAM, NVR, 0, proto="any"), flow(CAM, POS, 0, proto="udp"),
                          flow(CAM, "10.1.0.30", 0, proto="icmp")]), NOW)
    by = {e.dst_ref: e for e in out.edges}
    # 1-65535, not 0-65535: port 0 is not a TCP/UDP port and the store refuses it (an edge the store
    # skips is an edge the evaluator never sees, i.e. an under-approximation)
    assert (by[f"ip:{NVR}"].port_lo, by[f"ip:{NVR}"].port_hi) == (1, 65535)
    assert (by[f"ip:{POS}"].port_lo, by[f"ip:{POS}"].port_hi) == (1, 65535)
    assert by[f"ip:{POS}"].evidence["assumed_all_ports"] == "no_port"
    assert (by["ip:10.1.0.30"].port_lo, by["ip:10.1.0.30"].port_hi) == (0, 0)


def test_window_excludes_old_flows_and_future_timestamps_are_clamped():
    far = NOW + dt.timedelta(days=30)
    out = sen.build(rows([flow(CAM, NVR, 80, last=NOW - dt.timedelta(hours=25)),
                          flow(CAM, POS, 81, last=NOW - dt.timedelta(hours=23)),
                          flow(NVR, POS, 82, last=far, first=far)]), NOW)
    assert {e.port_lo for e in out.edges} == {81, 82}
    future = next(e for e in out.edges if e.port_lo == 82)
    assert future.last_seen <= NOW + sen.CLOCK_SLACK and future.first_seen <= future.last_seen
    out2 = sen.build(rows([flow(CAM, NVR, 80, last=NOW - dt.timedelta(hours=3))]), NOW, window=2 * H)
    assert out2.edges == [] and out2.window == 2 * H


def test_self_loops_and_garbage_rows_are_dropped_with_a_note_not_a_crash():
    bad = [{"src_ip": "nope", "dst_ip": NVR, "proto": "tcp", "dst_port": 1, "last_seen": NOW},
           {"src_ip": CAM, "dst_ip": NVR, "proto": "gre", "dst_port": 1, "last_seen": NOW},
           {"src_ip": CAM, "dst_ip": NVR, "proto": "tcp", "dst_port": 70000, "last_seen": NOW},
           {"src_ip": CAM, "dst_ip": NVR, "proto": "tcp", "dst_port": 1, "last_seen": None}]
    dev = device([CAM, "10.1.0.11"])
    out = sen.build(rows(bad + [flow(CAM, "10.1.0.11")], assets=[dev]), NOW)
    assert out.edges == []
    assert any("4 flow record(s) skipped" in n for n in out.notes)
    assert any("same node" in n for n in out.notes)


def test_output_is_deterministic_and_sorted_whatever_the_row_order():
    fl = [flow(f"10.0.0.{i}", f"10.0.1.{i % 5}", 1000 + i % 7, sensor=S1 if i % 2 else S2) for i in range(40)]
    ss = [sensor(S1), sensor(S2, up=UP - H)]
    base = sen.build(rows(fl, ss), NOW)
    for seed in range(5):
        f2, s2 = fl[:], ss[:]
        random.Random(seed).shuffle(f2)
        random.Random(seed).shuffle(s2)
        assert sen.build(rows(f2, s2), NOW) == base
    keys = [(e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi) for e in base.edges]
    assert keys == sorted(keys) and [n.ref for n in base.nodes] == sorted(n.ref for n in base.nodes)
    assert [(c.node_ref, c.direction) for c in base.coverage] == sorted(
        (c.node_ref, c.direction) for c in base.coverage)


def test_build_does_not_mutate_its_input():
    r = rows([flow(CAM, NVR)], assets=[device([CAM])])
    before = copy.deepcopy(r)
    sen.build(r, NOW)
    assert r == before


# --------------------------------------------------------------------------- #
# Pure builder: coverage (the soundness-critical part)
# --------------------------------------------------------------------------- #

def test_seen_nodes_of_an_online_active_sensor_are_covered_both_ways_at_observed():
    out = sen.build(rows([flow(CAM, NVR)]), NOW)
    assert covered(out) == {(f"ip:{CAM}", "in"), (f"ip:{CAM}", "out"), (f"ip:{NVR}", "in"), (f"ip:{NVR}", "out")}
    assert all(c.tier == "observed" and c.source == "sentry_flow" and c.observed_at == UP for c in out.coverage)


@pytest.mark.parametrize("sens", [
    sensor(online=False), sensor(status="revoked"), sensor(up=None),
    sensor(online=None), sensor(sid="not-a-uuid"),
], ids=["offline", "revoked", "never-uploaded", "online-unknown", "bad-id"])
def test_a_silent_or_unusable_sensor_gives_no_coverage_but_its_edges_stay(sens):
    out = sen.build(rows([flow(CAM, NVR)], sensors=[sens]), NOW)
    assert out.coverage == [] and len(out.edges) == 1


def test_a_sensor_missing_from_the_table_gives_no_coverage():
    out = sen.build(rows([flow(CAM, NVR, sensor=S3)], sensors=[sensor(S1)]), NOW)
    assert out.coverage == [] and len(out.edges) == 1


def test_only_ips_the_sensor_actually_saw_are_covered():
    out = sen.build(rows([flow(CAM, NVR)], assets=[device([POS])]), NOW)
    assert not any(POS in c.node_ref or "asset:" in c.node_ref for c in out.coverage)
    assert not any(c.node_ref == f"ip:{POS}" for c in out.coverage)


def test_nothing_is_inferred_without_flows():
    assert sen.build(rows([]), NOW).coverage == []
    assert sen.build(rows([], sensors=[]), NOW).edges == []


def test_flow_outside_the_window_does_not_earn_coverage():
    out = sen.build(rows([flow(CAM, NVR, last=NOW - dt.timedelta(hours=30))]), NOW)
    assert out.coverage == []


def test_observed_at_is_the_oldest_vantage_point_and_never_in_the_future():
    out = sen.build(rows([flow(CAM, NVR, sensor=S1), flow(CAM, NVR, sensor=S2)],
                         [sensor(S1, up=NOW - dt.timedelta(minutes=1)), sensor(S2, up=NOW - 3 * H)]), NOW)
    assert {c.observed_at for c in out.coverage} == {NOW - 3 * H}
    skew = sen.build(rows([flow(CAM, NVR)], [sensor(up=NOW + 10 * H)]), NOW)
    assert {c.observed_at for c in skew.coverage} == {NOW}


def test_a_stale_second_sensor_cannot_borrow_the_fresh_ones_coverage():
    """CAM is seen by S1 (fresh) and S2 (offline): only S1's vantage point counts, S2's is ignored,
    but NVR is seen by S2 alone and stays blind."""
    out = sen.build(rows([flow(CAM, "10.9.9.9", sensor=S1), flow(CAM, NVR, sensor=S2)],
                         [sensor(S1), sensor(S2, online=False)]), NOW)
    assert (f"ip:{CAM}", "in") in covered(out) and (f"ip:{NVR}", "in") not in covered(out)


def test_a_multi_homed_asset_seen_on_one_address_only_stays_blind():
    dev = device([CAM, "10.1.0.11"])
    ref = f"asset:{dev['id']}"
    out = sen.build(rows([flow(CAM, NVR)], assets=[dev]), NOW)
    assert (ref, "in") not in covered(out) and any("some of their addresses" in n for n in out.notes)
    out = sen.build(rows([flow(CAM, NVR), flow("10.1.0.11", NVR)], assets=[dev]), NOW)
    assert {(ref, "in"), (ref, "out")} <= covered(out)


def test_truncated_read_is_reported():
    out = sen.build(rows([flow(CAM, NVR)], truncated=True), NOW)
    assert any("row cap" in n for n in out.notes)


# --------------------------------------------------------------------------- #
# Soundness against the real evaluator (the claim that matters)
# --------------------------------------------------------------------------- #

def _graph_doc(out, zones):
    cov: dict[str, list] = {}
    for c in out.coverage:
        cov.setdefault(c.node_ref, []).append({"direction": c.direction, "tier": c.tier,
                                               "observed_at": c.observed_at.isoformat(), "source": c.source})
    refs = sorted({*zones, *cov, *(e.src_ref for e in out.edges), *(e.dst_ref for e in out.edges)})
    nodes = [{"id": ref, "kind": "host", "zone": zones.get(ref), "coverage": cov.get(ref, [])} for ref in refs]
    edges = [{"src": e.src_ref, "dst": e.dst_ref, "proto": e.proto,
              "ports": "-".join(map(str, sorted({e.port_lo, e.port_hi}))) if e.proto != "icmp" else "",
              "basis": e.basis, "source": e.source, "last_seen": e.last_seen.isoformat()} for e in out.edges]
    return {"version": 1, "now": NOW.isoformat(), "nodes": nodes, "edges": edges}


def _verdict(out, zones):
    from paddock_assurance import ReachGraph, compile_text, evaluate
    plan = compile_text(
        "apiVersion: paddock.dev/invariant/v1\nid: acme:guest-no-pos\ntitle: guest never reaches pos\nseverity: high\n"
        "subjects: {from: {zone: guest}, to: {zone: pos}}\nassert: unreachable\n"
        "evidence: {min_tier: observed, max_age: 24h}\n")
    return evaluate(plan, ReachGraph.from_dict(_graph_doc(out, zones)), NOW)


ZONES = {f"ip:{CAM}": "guest", f"ip:{POS}": "pos"}


def test_silent_sensor_never_yields_holds_but_a_live_one_does():
    live = sen.build(rows([flow(CAM, "10.1.0.99", 443), flow(POS, "10.2.0.99", 443)]), NOW)
    assert _verdict(live, ZONES).verdict.value == "HOLDS"
    for dead in (sensor(online=False), sensor(status="revoked"), sensor(up=None)):
        silent = sen.build(rows([flow(CAM, "10.1.0.99", 443), flow(POS, "10.2.0.99", 443)], [dead]), NOW)
        assert _verdict(silent, ZONES).verdict.value == "UNKNOWN"


def test_an_observed_guest_to_pos_flow_is_a_violation_with_that_witness():
    out = sen.build(rows([flow(CAM, POS, 443)]), NOW)
    res = _verdict(out, ZONES)
    assert res.verdict.value == "VIOLATED"
    hop = res.witnesses[0].hops[0]
    assert (hop.src, hop.dst, hop.source) == (f"ip:{CAM}", f"ip:{POS}", "sentry_flow")


def test_a_sensor_that_saw_neither_guest_nor_pos_proves_nothing_about_them():
    """The sensor is healthy but only ever saw two unrelated hosts: nothing is inferred for CAM or POS,
    so the possible CAM -> POS edge stays and the verdict is UNKNOWN, never HOLDS."""
    both_blind = sen.build(rows([flow("10.7.7.7", "10.7.7.8")]), NOW)
    assert _verdict(both_blind, ZONES).verdict.value == "UNKNOWN"


# --------------------------------------------------------------------------- #
# Ingest route
# --------------------------------------------------------------------------- #

SVC_KEY = "svc-sentry-flows-key-1"
TENANT_B = "00000000-0000-0000-0000-0000000000b3"


def rec(src=CAM, dst=NVR, port=443, **kw):
    now = dt.datetime.now(UTC)
    base = {"src_ip": src, "dst_ip": dst, "proto": "tcp", "dst_port": port, "sensor_id": S1,
            "first_seen": (now - dt.timedelta(minutes=5)).isoformat(), "last_seen": now.isoformat(),
            "packets": 3, "bytes": 300, "oriented": "syn"}
    base.update(kw)
    return base


async def _user_key(db_pool, name, role):
    full, prefix, h = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash) VALUES ($1,$2,'restricted',NULL) RETURNING id",
            name, role)
        await con.execute("INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1,$2,$3,$4,$5::text[])",
                          uid, f"k-{prefix}", prefix, h, sorted(auth_svc.ROLE_CAPABILITIES.get(role, {"read"})))
    return {"Authorization": f"Bearer {full}"}


@pytest_asyncio.fixture
async def env(app, app_pool, db_pool, client, monkeypatch):
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    monkeypatch.setattr(settings, "service_api_key", SVC_KEY)
    app.state.pool = app_pool          # RLS is only real for the non-superuser pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    try:
        yield client
    finally:
        settings.auth_mode = prev


A = {"X-API-Key": SVC_KEY, "X-Paddock-Tenant": tenancy.DEFAULT_TENANT_ID}
B = {"X-API-Key": SVC_KEY, "X-Paddock-Tenant": TENANT_B}


async def _post(client, flows, headers=A):
    return await client.post("/v1/reach/flows/bulk", headers=headers, json={"flows": flows})


async def _rows(db_pool, tenant=tenancy.DEFAULT_TENANT_ID):
    async with db_pool.acquire() as con:
        return [dict(r) for r in await con.fetch(
            "SELECT * FROM reach_flow_obs WHERE tenant_id = $1 ORDER BY src_ip, dst_ip, dst_port", uuid.UUID(tenant))]


async def test_post_inserts_then_upserts_with_the_contract_semantics(env, db_pool):
    t0 = dt.datetime.now(UTC) - dt.timedelta(hours=2)
    first = rec(first_seen=t0.isoformat(), last_seen=(t0 + dt.timedelta(minutes=1)).isoformat(),
                packets=3, bytes=100, oriented="heuristic")
    r = await _post(env, [first])
    assert r.status_code == 200 and r.json() == {"received": 1, "merged": 1, "inserted": 1, "updated": 0}
    later = rec(first_seen=(t0 + dt.timedelta(hours=1)).isoformat(),
                last_seen=(t0 + dt.timedelta(hours=1, minutes=1)).isoformat(), packets=4, bytes=50, oriented="syn")
    r = await _post(env, [later])
    assert r.json() == {"received": 1, "merged": 1, "inserted": 0, "updated": 1}
    (row,) = await _rows(db_pool)
    assert row["first_seen"] == dt.datetime.fromisoformat(first["first_seen"])            # LEAST
    assert row["last_seen"] == dt.datetime.fromisoformat(later["last_seen"])              # GREATEST
    assert (row["packets"], row["bytes"], row["oriented"]) == (7, 150, "syn")             # counters add, syn wins
    older = rec(first_seen=(t0 - H).isoformat(), last_seen=(t0 - H).isoformat(), oriented="heuristic")
    await _post(env, [older])
    (row,) = await _rows(db_pool)
    assert row["first_seen"] == dt.datetime.fromisoformat(older["first_seen"])
    assert row["last_seen"] == dt.datetime.fromisoformat(later["last_seen"]) and row["oriented"] == "syn"


async def test_replaying_a_batch_never_creates_rows_or_moves_timestamps(env, db_pool):
    batch = [rec(port=p) for p in (22, 80, 443)]
    for _ in range(3):
        assert (await _post(env, batch)).status_code == 200
    rows_ = await _rows(db_pool)
    assert len(rows_) == 3
    want = {b["dst_port"]: dt.datetime.fromisoformat(b["last_seen"]) for b in batch}
    assert {r["dst_port"]: r["last_seen"] for r in rows_} == want


async def test_duplicate_keys_inside_one_batch_are_folded_not_rejected(env, db_pool):
    r = await _post(env, [rec(packets=1), rec(packets=2, oriented="heuristic"), rec(port=80)])
    assert r.status_code == 200 and r.json()["received"] == 3 and r.json()["merged"] == 2
    got = {x["dst_port"]: x for x in await _rows(db_pool)}
    assert got[443]["packets"] == 3 and got[443]["oriented"] == "syn"


async def test_timestamps_are_clamped_to_now_plus_five_minutes(env, db_pool):
    far = (dt.datetime.now(UTC) + dt.timedelta(days=365)).isoformat()
    assert (await _post(env, [rec(first_seen=far, last_seen=far)])).status_code == 200
    (row,) = await _rows(db_pool)
    limit = dt.datetime.now(UTC) + dt.timedelta(minutes=5, seconds=5)
    assert row["last_seen"] <= limit and row["first_seen"] <= row["last_seen"]


async def test_naive_and_epoch_timestamps_are_read_as_utc(env, db_pool):
    now = dt.datetime.now(UTC)
    naive = (now - H).replace(tzinfo=None).isoformat()
    assert (await _post(env, [rec(first_seen=naive, last_seen=naive),
                              rec(port=80, first_seen=1000.0, last_seen=1001.0)])).status_code == 200
    got = {x["dst_port"]: x for x in await _rows(db_pool)}
    assert got[443]["last_seen"] == (now - H).replace(microsecond=(now - H).microsecond)
    assert got[80]["last_seen"] == dt.datetime.fromtimestamp(1001, UTC)


async def test_ips_are_canonicalised_before_storage(env, db_pool):
    assert (await _post(env, [rec(src="2001:0DB8:0:0:0:0:0:1", dst="::ffff:10.1.0.20")])).status_code == 200
    (row,) = await _rows(db_pool)
    assert (row["src_ip"], row["dst_ip"]) == ("2001:db8::1", NVR)


@pytest.mark.parametrize("bad", [
    {"src_ip": "not-an-ip"}, {"dst_ip": "10.0.0.256"}, {"src_ip": "10.0.0.0/8"}, {"dst_ip": ""},
    {"dst_port": 65536}, {"dst_port": -1}, {"dst_port": "http"}, {"proto": "sctp"}, {"proto": "TCP "},
    {"packets": -1}, {"bytes": -5}, {"packets": 10**16}, {"oriented": "maybe"},
    {"sensor_id": "not-a-uuid"}, {"sensor_id": None}, {"extra": 1},
    {"first_seen": "yesterday"}, {"last_seen": None},
], ids=lambda b: json.dumps(b)[:40])
async def test_a_bad_record_rejects_the_whole_batch_and_writes_nothing(env, db_pool, bad):
    r = await _post(env, [rec(port=80), {**rec(), **bad}])
    assert r.status_code == 422
    assert await _rows(db_pool) == []


async def test_first_after_last_is_rejected(env, db_pool):
    now = dt.datetime.now(UTC)
    r = await _post(env, [rec(first_seen=now.isoformat(), last_seen=(now - H).isoformat())])
    assert r.status_code == 422 and await _rows(db_pool) == []


async def test_batch_size_is_capped_at_1000(env, db_pool):
    ok = [rec(port=1 + i % 60000, src=f"10.{i // 250}.{i % 250}.1") for i in range(1000)]
    assert (await _post(env, ok)).status_code == 200
    assert (await _post(env, ok + [rec(port=9)])).status_code == 422
    assert len(await _rows(db_pool)) == 1000
    assert (await _post(env, [])).json() == {"received": 0, "merged": 0, "inserted": 0, "updated": 0}


async def test_error_responses_share_one_shape_and_do_not_echo_internals(env):
    shapes = []
    for body in ({"flows": [{**rec(), "src_ip": "x"}]}, {"flows": "no"}, {"nope": []}, {}):
        r = await env.post("/v1/reach/flows/bulk", headers=A, json=body)
        assert r.status_code == 422 and list(r.json()) == ["detail"]
        shapes.append(type(r.json()["detail"]))
    assert set(shapes) == {list}


async def test_rbac_service_key_allowed_read_only_and_anonymous_refused(env, db_pool):
    viewer = await _user_key(db_pool, "viewer-1", "viewer")
    assert (await _post(env, [rec()], headers=A)).status_code == 200
    assert (await _post(env, [rec()], headers=viewer)).status_code == 403
    assert (await _post(env, [rec()], headers={})).status_code == 401
    assert (await _post(env, [rec()], headers={"X-API-Key": "wrong-key-123456789"})).status_code in (401, 403)
    assert len(await _rows(db_pool)) == 1                         # only the service-key write landed
    assert (await env.get("/v1/reach/flows/bulk", headers=A)).status_code in (404, 405)


async def test_tenants_are_isolated_in_storage_and_in_conflict_resolution(env, db_pool):
    same = rec(packets=5)
    assert (await _post(env, [same], headers=A)).json()["inserted"] == 1
    assert (await _post(env, [same], headers=B)).json()["inserted"] == 1     # same key, other tenant: insert
    assert (await _post(env, [same], headers=B)).json()["updated"] == 1
    (a,) = await _rows(db_pool)
    (b,) = await _rows(db_pool, TENANT_B)
    assert a["packets"] == 5 and b["packets"] == 10


async def test_tenant_b_cannot_see_tenant_a_flows_through_the_app_pool(env, app_pool):
    await _post(env, [rec()], headers=A)
    with tenancy.tenant_context(TENANT_B):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM reach_flow_obs") == 0
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM reach_flow_obs") == 1


# --------------------------------------------------------------------------- #
# Loader on Postgres
# --------------------------------------------------------------------------- #

async def _seed_sensor(db_pool, sid, tenant=tenancy.DEFAULT_TENANT_ID, *, online=True, status="active",
                       up=None):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensors (id, tenant_id, name, site, status, cred_prefix, cred_hash, online, last_upload_at) "
            "VALUES ($1,$2,$3,'site',$4,$5,'h',$6,$7)",
            uuid.UUID(sid), uuid.UUID(tenant), f"s-{sid[-1]}", status, f"pst_{sid[-8:]}{tenant[-2:]}", online, up)


async def _seed_scope(db_pool, sid, tenant=tenancy.DEFAULT_TENANT_ID, cidrs=("10.0.0.0/8", "2001:db8::/32")):
    """Coverage needs a declared scope (schema 040 sensor_scopes); these tests are not about scoping."""
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO sensor_scopes (tenant_id, sensor_id, cidrs, set_by, justification) VALUES ($1,$2,$3,'t','test')",
            uuid.UUID(tenant), uuid.UUID(sid), list(cidrs))


async def _seed_flow(db_pool, tenant, src, dst, port, sid, last):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO reach_flow_obs (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id, first_seen, last_seen) "
            "VALUES ($1,$2,$3,'tcp',$4,$5,$6,$6)", uuid.UUID(tenant), src, dst, port, uuid.UUID(sid), last)


async def test_loader_reads_the_tenants_flows_sensors_and_identity_then_builds(app_pool, db_pool):
    now = dt.datetime.now(UTC)
    dev_id = uuid.uuid4()
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO assets (id, kind, value, canonical, source, metadata) VALUES ($1,'iot_device','cam','cam','test',$2::jsonb)",
            dev_id, json.dumps({"ips": [CAM]}))
    await _seed_sensor(db_pool, S1, up=now - dt.timedelta(minutes=1))
    await _seed_sensor(db_pool, S2, online=False, up=now - dt.timedelta(minutes=1))
    await _seed_scope(db_pool, S1)
    await _seed_scope(db_pool, S2)
    await _seed_flow(db_pool, tenancy.DEFAULT_TENANT_ID, CAM, NVR, 554, S1, now - dt.timedelta(minutes=3))
    await _seed_flow(db_pool, tenancy.DEFAULT_TENANT_ID, POS, NVR, 80, S2, now - dt.timedelta(minutes=3))
    await _seed_flow(db_pool, tenancy.DEFAULT_TENANT_ID, CAM, POS, 22, S1, now - dt.timedelta(hours=30))  # aged out
    # another tenant's world must be invisible
    await tenancy.create_tenant(db_pool, slug="bravo", name="B", tenant_id=TENANT_B)
    await _seed_sensor(db_pool, S3, TENANT_B, up=now)
    await _seed_flow(db_pool, TENANT_B, "10.66.0.1", "10.66.0.2", 9, S3, now)
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            loaded = await sen.load(con, now)
    assert {f["dst_port"] for f in loaded["flows"]} == {554, 80} and not loaded["truncated"]
    assert {s["id"] for s in loaded["sensors"]} == {S1, S2}
    out = sen.build(loaded, now)
    assert {(e.src_ref, e.dst_ref, e.port_lo) for e in out.edges} == {
        (f"asset:{dev_id}", f"ip:{NVR}", 554), (f"ip:{POS}", f"ip:{NVR}", 80)}
    cov = {c.node_ref for c in out.coverage}
    assert f"asset:{dev_id}" in cov and f"ip:{NVR}" in cov          # seen by the online sensor S1
    assert f"ip:{POS}" not in cov                                   # seen only by offline S2
    assert not any("10.66" in e.src_ref for e in out.edges)
    # a window passed through opts is honoured by the SQL too
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            wide = await sen.load(con, now, window=dt.timedelta(hours=48))
    assert {f["dst_port"] for f in wide["flows"]} == {554, 80, 22}


async def test_route_to_builder_round_trip(env, app_pool, db_pool):
    """What the route stores is exactly what the builder understands (spelling, types, proto)."""
    now = dt.datetime.now(UTC)
    await _seed_sensor(db_pool, S1, up=now)
    await _seed_scope(db_pool, S1)
    assert (await _post(env, [rec("2001:DB8::1", NVR, 443), rec(NVR, POS, 0, proto="any", oriented="heuristic")])
            ).status_code == 200
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            out = sen.build(await sen.load(con, now), now)
    assert {(e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi, e.confidence) for e in out.edges} == {
        ("ip:2001:db8::1", f"ip:{NVR}", "tcp", 443, 443, 100), (f"ip:{NVR}", f"ip:{POS}", "any", 1, 65535, 50),
        (f"ip:{POS}", f"ip:{NVR}", "any", 1, 65535, 50)}      # + the possible reverse of a guess
    assert (f"ip:{NVR}", "out") in covered(out)


def test_ipmap_is_the_one_identity_source():
    assert sen._ipmap is _ipmap
