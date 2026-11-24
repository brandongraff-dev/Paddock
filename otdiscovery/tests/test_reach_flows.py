"""Flows reach the orchestrator's reach graph (docs/ASSURANCE_P1.md section 4.3).

The records posted here become edges (and, for a healthy sensor, coverage) in a security proof, so
the properties that matter are: the sensor id comes from the authenticated claim and never from the
payload, a failed post is retried and never lost, counters are not inflated by re-analysis, and one
malformed observation cannot wedge a sensor's uploads forever.
"""
from __future__ import annotations

import dataclasses
import math
from datetime import datetime, timezone

import pytest

from app.config import Config
from app.pipeline import DiscoveryEngine, ReachFlowBuffer, clean_sensor_id

from .test_sensor_ingest import CRED, TENANT_A, TENANT_B, _env, _flows, _h, env  # noqa: F401  (env is a fixture)

SID = "5e5e5e5e-0000-0000-0000-000000000001"
OTHER = "5e5e5e5e-0000-0000-0000-0000000000ff"


def _by_key(recs):
    return {(r["src_ip"], r["dst_ip"], r["proto"], r["dst_port"], r["sensor_id"]): r for r in recs}


async def test_managed_ingest_posts_the_expected_aggregate(env):  # noqa: F811
    svc, fake, client = env
    r = await client.post("/ingest", json=_env(_flows(3)), headers=_h())
    assert r.status == 200, await r.text()
    got = _by_key(fake.flows_posted)
    assert len(got) == 3
    rec = got[("10.9.0.10", "10.9.0.200", "tcp", 443, SID)]
    assert rec == {"src_ip": "10.9.0.10", "dst_ip": "10.9.0.200", "proto": "tcp", "dst_port": 443,
                   "sensor_id": SID, "packets": 3, "bytes": 300, "oriented": "syn",
                   "first_seen": datetime.fromtimestamp(1000.0, timezone.utc).isoformat(),
                   "last_seen": datetime.fromtimestamp(1001.0, timezone.utc).isoformat()}
    assert (await r.json())["orchestrator"]["flows"]["received"] == 3


async def test_sensor_id_comes_from_the_claim_not_the_payload(env):  # noqa: F811
    _, fake, client = env
    forged = [{**f, "sensor_id": OTHER} for f in _flows(2)]
    assert (await client.post("/ingest", json=_env(forged), headers=_h())).status == 200
    assert {r["sensor_id"] for r in fake.flows_posted} == {SID}


async def test_legacy_shared_token_flows_are_never_posted_even_with_a_forged_sensor_id(env):  # noqa: F811
    svc, fake, client = env
    svc.cfg = dataclasses.replace(svc.cfg, sentry_tokens=("legacy",))
    forged = [{**f, "sensor_id": SID} for f in _flows(2)]
    r = await client.post("/ingest", json=_env(forged), headers={"Authorization": "Bearer legacy"})
    assert r.status == 200 and fake.flows_posted == []


async def test_orientation_is_syn_only_for_a_tcp_handshake(env):  # noqa: F811
    _, fake, client = env
    obs = [{**_flows(1)[0], "tcp_syn": False, "dst_port": 8443},
           {**_flows(1)[0], "proto": "udp", "tcp_syn": True, "dst_port": 53},
           {**_flows(1)[0], "dst_port": 22}]
    assert (await client.post("/ingest", json=_env(obs), headers=_h())).status == 200
    got = {r["dst_port"]: r for r in fake.flows_posted}
    assert (got[8443]["oriented"], got[53]["oriented"], got[22]["oriented"]) == ("heuristic", "heuristic", "syn")
    assert got[53]["proto"] == "udp"


async def test_reanalysis_posts_only_the_difference_so_counters_are_not_inflated(env):  # noqa: F811
    svc, fake, client = env
    for i in range(3):
        assert (await client.post("/ingest", json=_env(_flows(2)), headers=_h(f"batch-in-{i:04d}"))).status == 200
    await svc.engines[TENANT_A].analyze()                                    # no new data
    per_key = {}
    for r in fake.flows_posted:
        per_key[(r["src_ip"], r["dst_port"])] = per_key.get((r["src_ip"], r["dst_port"]), 0) + r["packets"]
    assert per_key == {("10.9.0.10", 443): 9, ("10.9.0.11", 443): 9}         # 3 uploads x 3 packets, once
    assert len(fake.flows_posted) == 6                                       # nothing re-posted for /analyze


async def test_a_failed_post_answers_503_and_the_retry_delivers_everything(env):  # noqa: F811
    svc, fake, client = env
    fake.flow_error = True
    r = await client.post("/ingest", json=_env(_flows(4)), headers=_h())
    assert r.status == 503 and r.headers["Retry-After"]
    assert fake.flows_posted == [] and fake.done_calls == [("batch-0000001", False, 4)]
    fake.flow_error = False
    r = await client.post("/ingest", json=_env(_flows(4)), headers=_h())      # the sensor retries the batch id
    assert r.status == 200 and "duplicate" not in await r.json()
    assert {r["src_ip"] for r in fake.flows_posted} == {f"10.9.0.{10 + i}" for i in range(4)}
    first = svc.engines[TENANT_A]._reach.pending()
    assert first == []                                                       # fully delivered, nothing pending


async def test_one_malformed_observation_cannot_wedge_the_sensor(env):  # noqa: F811
    _, fake, client = env
    good = _flows(1)[0]
    poison = [
        {**good, "src_ip": "not-an-ip"}, {**good, "dst_ip": "10.0.0.999"}, {**good, "src_ip": None},
        {**good, "dst_port": 70000, "src_ip": "10.8.0.1"},
        {**good, "packets": -5, "bytes": -1, "src_ip": "10.8.0.3"},
        {**good, "first_seen": float("nan"), "last_seen": None, "src_ip": "10.8.0.4"},
        {**good, "proto": "gre", "src_ip": "10.8.0.5"},
    ]
    r = await client.post("/ingest", json=_env([good] + poison), headers=_h())
    assert r.status == 200, await r.text()
    got = _by_key(fake.flows_posted)
    assert ("10.9.0.10", "10.9.0.200", "tcp", 443, SID) in got
    assert not any(k[0] in ("not-an-ip", "None") for k in got)
    # damaged but real endpoints are kept, widened/zeroed rather than guessed
    assert got[("10.8.0.1", "10.9.0.200", "tcp", 0, SID)]["dst_port"] == 0
    assert got[("10.8.0.3", "10.9.0.200", "tcp", 443, SID)]["packets"] == 0
    assert got[("10.8.0.3", "10.9.0.200", "tcp", 443, SID)]["bytes"] == 0
    assert got[("10.8.0.5", "10.9.0.200", "any", 0, SID)]["proto"] == "any"
    rec = got[("10.8.0.4", "10.9.0.200", "tcp", 443, SID)]
    assert math.isfinite(datetime.fromisoformat(rec["last_seen"]).timestamp())
    assert datetime.fromisoformat(rec["first_seen"]) <= datetime.fromisoformat(rec["last_seen"])


async def test_every_posted_record_satisfies_the_orchestrator_schema(env):  # noqa: F811
    """The same checks routers/reach_flows.py applies, so a drift between the two shows up here."""
    import ipaddress
    _, fake, client = env
    obs = _flows(5) + [{**_flows(1)[0], "src_ip": "2001:DB8::1", "dst_ip": "::ffff:10.0.0.1", "proto": "ICMP"}]
    assert (await client.post("/ingest", json=_env(obs), headers=_h())).status == 200
    for r in fake.flows_posted:
        assert set(r) == {"src_ip", "dst_ip", "proto", "dst_port", "sensor_id", "first_seen", "last_seen",
                          "packets", "bytes", "oriented"}
        ipaddress.ip_address(r["src_ip"]), ipaddress.ip_address(r["dst_ip"])
        assert r["proto"] in ("icmp", "tcp", "udp", "any") and 0 <= r["dst_port"] <= 65535
        assert r["packets"] >= 0 and r["bytes"] >= 0 and r["oriented"] in ("syn", "heuristic")
        assert datetime.fromisoformat(r["first_seen"]).tzinfo is not None
    icmp = next(r for r in fake.flows_posted if r["proto"] == "icmp")
    assert (icmp["src_ip"], icmp["dst_ip"], icmp["dst_port"]) == ("2001:db8::1", "10.0.0.1", 0)


async def test_flows_differing_only_by_mac_are_one_record(env):  # noqa: F811
    _, fake, client = env
    a, b = _flows(1)[0], _flows(1)[0]
    b["src_mac"] = "02:ff:ff:ff:ff:ff"
    assert (await client.post("/ingest", json=_env([a, b]), headers=_h())).status == 200
    (rec,) = fake.flows_posted
    assert rec["packets"] == 6


async def test_two_sensors_report_the_same_peer_pair_as_two_rows_and_tenants_stay_apart(env):  # noqa: F811
    svc, fake, client = env
    await client.post("/ingest", json=_env(_flows(1)), headers=_h("batch-s1-0001"))
    fake.sensor = {**fake.sensor, "sensor_id": "5e5e5e5e-0000-0000-0000-000000000002", "name": "pi-2"}
    await client.post("/ingest", json=_env(_flows(1)), headers=_h("batch-s2-0001"))
    assert {r["sensor_id"] for r in fake.flows_posted} == {SID, "5e5e5e5e-0000-0000-0000-000000000002"}
    fake.sensor = {**fake.sensor, "tenant_id": TENANT_B, "sensor_id": "5e5e5e5e-0000-0000-0000-000000000003"}
    await client.post("/ingest", json=_env(_flows(1)), headers=_h("batch-b-00001"))
    assert len(svc.engines[TENANT_A]._reach) == 2 and len(svc.engines[TENANT_B]._reach) == 1


# -- engine level: batching, partial failure, deferred analysis ------------------------------- #

class _Orch:
    def __init__(self):
        self.calls: list[list[dict]] = []
        self.fail_on: set[int] = set()

    async def bulk_assets(self, a):
        return {"inserted": len(a)}

    async def bulk_edges(self, e):
        return {}

    async def bulk_findings(self, f):
        return {"inserted": len(f)}

    async def bulk_flows(self, flows):
        n = len(self.calls)
        self.calls.append(list(flows))
        return {"error": "down"} if n in self.fail_on else {"received": len(flows)}


def _many(n):
    return [{"kind": "flow", "proto": "tcp", "src_ip": f"10.{i // 250}.{i % 250}.1", "dst_ip": "10.200.0.1",
             "dst_port": 443, "packets": 1, "bytes": 10, "first_seen": 1000.0, "last_seen": 1001.0,
             "tcp_syn": True} for i in range(n)]


async def test_batches_never_exceed_1000_and_a_failed_chunk_keeps_earlier_ones_acknowledged():
    orch = _Orch()
    eng = DiscoveryEngine(dataclasses.replace(Config(), enable_db=False, analyze_interval_s=0.0), orch=orch)
    orch.fail_on = {1}                                                       # the second chunk fails
    res = await eng.ingest(observations=_many(2300), sensor_id=SID)
    assert [len(c) for c in orch.calls] == [1000, 1000]
    assert "error" in res["orchestrator"]["flows"] and res["orchestrator"]["flows"]["received"] == 1000
    orch.fail_on = set()
    orch.calls.clear()
    await eng.analyze()
    assert [len(c) for c in orch.calls] == [1000, 300]                       # chunk 1 is not re-sent
    sent = {r["src_ip"] for c in orch.calls for r in c}
    assert len(sent) == 1300 and len(eng._reach.pending()) == 0


async def test_deferred_analysis_retries_an_undelivered_flow_on_the_next_run():
    orch = _Orch()
    cfg = dataclasses.replace(Config(), enable_db=False, analyze_interval_s=0.0)
    eng = DiscoveryEngine(cfg, orch=orch)
    orch.fail_on = {0}
    assert "error" in (await eng.ingest(observations=_many(3), sensor_id=SID))["orchestrator"]["flows"]
    res = await eng.analyze()                                                # next scheduled run
    assert "error" not in res["orchestrator"]["flows"] and len(orch.calls[-1]) == 3
    assert (await eng.analyze())["orchestrator"].get("flows") is None        # nothing left to say


def test_buffer_never_evicts_an_undelivered_entry_and_counts_what_it_drops():
    buf = ReachFlowBuffer(max_entries=3)
    assert buf.add(_many(5), SID) == 3 and buf.dropped == 2 and len(buf) == 3
    for key, _, snap in buf.pending()[:2]:
        buf.mark_posted(key, snap)
    assert buf.add(_many(7)[5:], SID) == 2 and len(buf) == 3                 # room made from delivered ones
    assert len(buf.pending()) == 3


def test_buffer_ignores_a_missing_or_malformed_sensor_id():
    buf = ReachFlowBuffer()
    for bad in (None, "", "pi-1", "5e5e", 7):
        assert buf.add(_many(2), bad) == 0
    assert len(buf) == 0 and clean_sensor_id(SID.upper()) == SID


def test_syn_seen_later_is_delivered_even_if_nothing_else_changed():
    buf = ReachFlowBuffer()
    o = _many(1)[0]
    buf.add([{**o, "tcp_syn": False}], SID)
    (k, rec, snap), = buf.pending()
    assert rec["oriented"] == "heuristic"
    buf.mark_posted(k, snap)
    assert buf.pending() == []
    buf.add([{**o, "tcp_syn": True, "packets": 0, "bytes": 0, "last_seen": 1001.0}], SID)
    (k, rec, _), = buf.pending()
    assert rec["oriented"] == "syn" and rec["packets"] == 0
