"""P2.1 section 4.5 and 4.6 (WP4): the ``host_fw`` builder and ``_ipmap`` with an operator pairing and with
scan-conflict acknowledgements. Pure tests, no database (the database half is ``test_fleet_pairing_db.py``).

A pairing changes IDENTITY, never trust (D27): the host becomes ``asset:<uuid>`` with basis ``paired``, its facts
stay ``configured``, every P2 gate still applies, the node addresses are the asset's (never the host's claim), and the
peer address survives only as a negative detector (D28). An acknowledgement clears one conflict record for coverage
purposes and nothing else (D30).
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import uuid

import pytest

from app.assurance import refs
from app.assurance.builders import _ipmap
from app.assurance.builders import host_fw as hf

from .test_assurance_host_fw import (H, MIN, NOW, PUBLIC, acc, agent_row, aid, chain, cloud, covered, edges_of,
                                     fw_section, lis_section, listener, posture_row, ref1, rows_of, scan_edge,
                                     sections)

PRIV = "10.0.0.5"
MAX_AGE = dt.timedelta(hours=72)


def asset_ref(n=100):
    return refs.asset_ref(aid(n))


def prec(agent=1, asset=100, *, kind="cloud_resource", rtype="instance", priv=(PRIV,), pub=(PUBLIC,),
         last_seen=NOW - MIN, present=True):
    """A row as ``host_fw.PAIRINGS_SQL`` returns it (``md`` is the asset's address metadata)."""
    md = {"resource_type": rtype, "private_ips": list(priv), "public_ips": list(pub), "ips": None, "ip": None}
    return {"pairing_id": str(uuid.UUID(int=900 + agent)), "agent_id": aid(agent), "asset_id": aid(asset),
            "a_id": aid(asset) if present else None, "kind": kind if present else None,
            "last_seen": last_seen if present else None, "md": md if present else None}


def row_of(**kw) -> _ipmap.PairingRow:
    row = _ipmap.pairing_row(prec(**kw))
    assert row is not None
    return row


def claim(*, ips=(PRIV,), peer=PRIV, direct=True, agent="a"):
    return _ipmap.Claim(agent, tuple(ips), peer, direct=direct)


def decide(row, c=None, *, now=NOW, shared=False, max_age=MAX_AGE):
    return _ipmap.pairing_decision(c or claim(), row, now, max_age, shared)


def build(agents=None, *, pairings=(), acks=(), assets=(), scans=(), now=NOW, secs=None, **kw):
    agents = agents or [agent_row(peer=PRIV)]
    r = rows_of(*[(a, posture_row(secs)) for a in agents], assets=list(assets), scans=list(scans))
    r.pairings = list(pairings)
    r.acks = list(acks)
    return hf.build(r, now, **kw)


def host_agent(out, ref):
    (f,) = [f for f in out.facts if f.node_ref == ref]
    return f.facts["host_agent"]


# --------------------------------------------------------------------------- #
# _ipmap.pairing_decision: ONE pure function for ingest and builder
# --------------------------------------------------------------------------- #

def test_decision_has_basis_and_conflict_defaults_and_old_equality_is_kept():
    d = _ipmap.Decision(None, "x")
    assert d.basis == "claimed" and d.conflict == "" and d == _ipmap.Decision(None, "x")


def test_no_pairing_row_falls_through_to_corroboration():
    assert _ipmap.pairing_decision(claim(), None, NOW, MAX_AGE, False) == _ipmap.Decision(None, "")


def test_a_live_pairing_to_a_vm_decides_the_asset_with_basis_paired():
    d = decide(row_of())
    assert (d.ref, d.note, d.basis, d.conflict) == (asset_ref(), "", "paired", "")


@pytest.mark.parametrize("kw,why", [
    ({"rtype": "db_instance"}, "asset_not_vm"),
    ({"rtype": "load_balancer"}, "asset_not_vm"),
    ({"rtype": "bucket"}, "asset_not_vm"),
    ({"kind": "iot_device"}, "asset_not_vm"),            # a device row with VM-looking metadata is still no VM
    ({"kind": "domain"}, "asset_not_vm"),
    ({"present": False}, "asset_missing"),
    ({"last_seen": NOW - MAX_AGE - dt.timedelta(seconds=1)}, "asset_stale"),
    ({"last_seen": None}, "asset_stale"),                # an undated asset cannot prove freshness
    ({"last_seen": NOW + dt.timedelta(days=30)}, "asset_stale"),      # a future date would never age out
])
def test_every_inert_state_falls_back_with_its_note(kw, why):
    d = decide(row_of(**kw) if kw.get("present", True) else _ipmap.pairing_row(prec(**kw)))
    assert d.ref is None and d.note == f"pairing_inert:{why}" and d.basis == "claimed" and d.conflict == ""


def test_the_asset_age_limit_is_inclusive_and_naive_datetimes_are_read_as_utc():
    assert decide(row_of(last_seen=NOW - MAX_AGE)).ref == asset_ref()
    assert decide(row_of(last_seen=(NOW - MAX_AGE).replace(tzinfo=None))).ref == asset_ref()
    assert decide(row_of(last_seen=NOW - MAX_AGE - dt.timedelta(microseconds=1))).ref is None


def test_a_bad_row_never_pairs():
    assert _ipmap.pairing_row({"agent_id": "nope", "asset_id": aid(1)}) is None
    assert _ipmap.pairing_row({}) is None
    bad = prec()
    bad["asset_id"] = "not-a-uuid"
    assert _ipmap.pairing_row(bad) is None


@pytest.mark.parametrize("c,shared,conflict", [
    (claim(peer="10.9.9.9"), False, "paired_peer_mismatch"),         # direct, private, unshared, not the asset's
    (claim(peer="10.9.9.9", direct=False), False, ""),                # a proxy hop proves nothing
    (claim(peer="10.9.9.9"), True, ""),                               # shared egress proves nothing
    (claim(peer="93.184.216.34"), False, ""),                         # a public peer proves nothing (NAT)
    (claim(peer=None), False, ""),
    (claim(peer=PRIV), False, ""),                                    # the asset's own private address
    (claim(peer="10.9.9.9", ips=()), False, "paired_peer_mismatch"),  # the claim does not matter
])
def test_the_peer_is_only_a_negative_detector(c, shared, conflict):
    d = decide(row_of(), c, shared=shared)
    assert d.ref == asset_ref() and d.basis == "paired" and d.conflict == conflict


def test_a_peer_that_is_one_of_the_assets_public_addresses_is_no_mismatch():
    # a direct peer equal to an asset address of any kind is not a disagreement
    assert decide(row_of(priv=(PRIV, "10.0.0.6")), claim(peer="10.0.0.6")).conflict == ""


def test_the_decision_is_pure_and_deterministic():
    a, b = decide(row_of(), claim(peer="10.9.9.9")), decide(row_of(), claim(peer="10.9.9.9"))
    assert a == b


# --------------------------------------------------------------------------- #
# the builder with a pairing
# --------------------------------------------------------------------------- #

def test_a_paired_host_is_the_asset_node_with_its_facts_edges_and_coverage_on_it():
    out = build(pairings=[prec()])
    ref = asset_ref()
    assert [f.node_ref for f in out.facts] == [ref] and covered(out) == [ref]
    assert {e.dst_ref for e in out.edges} == {ref} and out.edges
    assert not any(n.ref in (ref, ref1()) for n in out.nodes)         # the asset node is its connector's; no agent node
    data = host_agent(out, ref)["data"]
    assert data["identity_basis"] == "paired" and "identity_note" not in data
    assert data["agent_id"] == aid(1)
    for name in ("sshd", "firewall", "listeners", "patch"):
        e = out.facts[0].facts[name]
        assert e["signed"] is True and out.facts[0].tier == "configured"   # facts stay configured (E2)
    (cov,) = out.coverage
    assert (cov.node_ref, cov.direction, cov.tier, cov.source) == (ref, "in", "configured", "host_fw")


def test_pairing_never_lifts_a_trust_gate():
    """Every P2 gate still applies to a paired host: an approximate firewall, a stale posture or a silent agent
    give no coverage and no facts, paired or not."""
    approx = sections(firewall=fw_section(confidence="approximate", conf="approximate"))
    assert build(pairings=[prec()], secs=approx).coverage == []
    stale = build(pairings=[prec()], now=NOW + 7 * H)
    assert stale.coverage == [] and set(stale.facts[0].facts) == {"host_agent"}
    silent = [agent_row(peer=PRIV, last_seen=NOW - 2 * H)]
    out = build(silent, pairings=[prec()])
    assert out.coverage == [] and set(out.facts[0].facts) == {"host_agent"}
    unsigned = rows_of((agent_row(peer=PRIV), posture_row(signed=False)))
    unsigned.pairings = [prec()]
    out = hf.build(unsigned, NOW)
    assert out.coverage == [] and out.facts[0].facts["host_agent"]["reason"] == "untrusted_posture"


def test_the_node_addresses_are_the_assets_never_the_hosts_claim():
    a = agent_row(ips=("10.0.0.5", "10.77.0.1"), peer=PRIV)           # claims an address the asset does not have
    rows = rows_of((a, posture_row()))
    rows.pairings = [prec(priv=(PRIV,), pub=())]
    idents = hf._resolve_identities([a], _ipmap.build_ip_map([]), rows.pairings, NOW, MAX_AGE)
    i = idents[aid(1)]
    assert i.ref == asset_ref() and i.basis == "paired"
    assert i.node_ips == [PRIV]                                       # NOT 10.77.0.1
    assert i.claimed == ["10.0.0.5", "10.77.0.1"]                     # kept for display only
    assert i.addressable is None                                      # no public asset address


def test_a_paired_host_is_addressable_when_the_asset_has_a_public_address():
    a = agent_row(ips=("10.0.0.5",), peer=PRIV)
    rows = rows_of((a, posture_row()))
    rows.pairings = [prec(pub=(PUBLIC,))]
    i = hf._resolve_identities([a], _ipmap.build_ip_map([]), rows.pairings, NOW, MAX_AGE)[aid(1)]
    assert i.addressable is True
    # ... and a CLAIMED public address does not make a paired host addressable
    b = agent_row(ips=(PUBLIC,), peer=PRIV)
    rows = rows_of((b, posture_row()))
    rows.pairings = [prec(pub=())]
    assert hf._resolve_identities([b], _ipmap.build_ip_map([]), rows.pairings, NOW, MAX_AGE)[aid(1)] \
        .addressable is None


@pytest.mark.parametrize("kw,why", [
    ({"rtype": "db_instance"}, "asset_not_vm"),
    ({"present": False}, "asset_missing"),
    ({"last_seen": NOW - 73 * H}, "asset_stale"),
])
def test_an_inert_pairing_falls_back_to_the_agent_node_with_a_visible_note(kw, why):
    out = build(pairings=[prec(**kw)])
    me = ref1()
    assert [f.node_ref for f in out.facts] == [me] and covered(out) == [me]
    assert [n.ref for n in out.nodes if n.ref == me] == [me]         # the agent node is back
    data = host_agent(out, me)["data"]
    assert data["identity_basis"] == "claimed" and data["identity_note"] == f"pairing_inert:{why}"
    assert out.facts[0].facts["sshd"]["signed"] is True
    assert all(e.dst_ref == me for e in out.edges)


def test_an_inert_pairing_is_never_a_pass_it_is_the_unpaired_p2_behaviour():
    # unpaired P2: the agent node alone carries facts; the asset node has none (reach invariants read UNKNOWN there)
    out = build(pairings=[prec(last_seen=NOW - 100 * H)])
    assert asset_ref() not in {f.node_ref for f in out.facts} and asset_ref() not in covered(out)


def test_the_peer_mismatch_conflict_withdraws_every_fact_and_the_coverage():
    a = agent_row(ips=("10.0.0.5",), peer="10.9.9.9")                  # direct private peer that is not the asset's
    out = build([a], pairings=[prec()])
    ref = asset_ref()
    want = {"kind": "paired_peer_mismatch", "proto": "any", "port": 0, "scan_seen_at": hf._iso(NOW - 2 * MIN)}
    f = out.facts[0].facts
    for name in ("sshd", "firewall", "listeners", "patch", "host_agent"):
        assert f[name]["conflict"] == [want], name
    assert out.coverage == [] and out.facts[0].node_ref == ref
    assert f["host_agent"]["data"]["coverage"]["blocked_by"] == ["conflict"]
    assert f["host_agent"]["data"]["conflicts"] == [want]
    assert f["host_agent"]["data"]["identity_basis"] == "paired"
    assert out.edges                                                    # edges are still drawn (over-approximation)


def test_a_peer_mismatch_is_not_acknowledgeable():
    a = agent_row(ips=("10.0.0.5",), peer="10.9.9.9")
    ack = {"id": str(uuid.UUID(int=1)), "agent_id": aid(1), "kind": "agent_closed_scan_open", "proto": "tcp",
           "port": 0, "through_seen_at": NOW, "expires_at": NOW + H, "acked_by": "x", "acked_at": NOW - H}
    out = build([a], pairings=[prec()], acks=[ack])
    assert out.coverage == []
    assert out.facts[0].facts["host_agent"]["data"]["conflicts"][0]["kind"] == "paired_peer_mismatch"
    assert "conflicts_acknowledged" not in out.facts[0].facts["host_agent"]["data"]


def test_a_shared_or_proxied_or_public_peer_raises_no_mismatch():
    for peer, direct in (("10.9.9.9", False), (PUBLIC, True)):
        a = agent_row(ips=("10.0.0.5",), peer=peer)
        a["identity"]["peer_proxied"] = not direct
        out = build([a], pairings=[prec()])
        assert covered(out) == [asset_ref()], (peer, direct)
    a1, a2 = agent_row(1, peer="10.9.9.9"), agent_row(2, peer="10.9.9.9", hostname="h2")
    out = build([a1, a2], pairings=[prec(1, 100)])
    assert asset_ref() in covered(out)                                  # the shared egress is no proof either way


def test_a_scan_that_contradicts_the_agent_is_compared_against_the_paired_asset_node():
    """Effect 4 of 4.5: ``_scan_conflicts`` 'mine' includes ``asset:X``, so the external scan's edge
    internet -> asset:X (the instance's public IP) is checked against the agent's own model."""
    out = build(pairings=[prec()], scans=[scan_edge(8080, dst=asset_ref())])
    f = out.facts[0].facts
    assert out.coverage == [] and f["firewall"]["conflict"][0] == {
        "kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080, "scan_seen_at": hf._iso(NOW - MIN)}
    # the same scan against an UNPAIRED agent (edge on the asset, agent not merged) is invisible to it: the gap
    unpaired = build(scans=[scan_edge(8080, dst=asset_ref())])
    assert len(unpaired.coverage) == 1 and "conflict" not in unpaired.facts[0].facts["firewall"]


def test_a_rogue_agent_that_only_claims_the_assets_addresses_stays_itself_and_does_not_demote_the_paired_one():
    paired = agent_row(1, ips=("10.0.0.5",), peer=PRIV)
    rogue = agent_row(2, ips=("10.0.0.5",), peer="10.0.0.99", hostname="rogue")
    out = build([paired, rogue], pairings=[prec(1, 100)], assets=[cloud(100, priv=[PRIV], pub=[PUBLIC])])
    assert sorted(f.node_ref for f in out.facts) == sorted([asset_ref(), ref1(2)])
    assert asset_ref() in covered(out)
    assert host_agent(out, ref1(2))["data"]["identity_basis"] == "claimed"


def test_two_pairings_onto_one_asset_keep_neither_fact_row():
    """The unique index makes it impossible; if the table is tampered with the builder fails closed."""
    a1, a2 = agent_row(1, peer=PRIV), agent_row(2, peer=PRIV, hostname="h2")
    out = build([a1, a2], pairings=[prec(1, 100), prec(2, 100)])
    assert asset_ref() not in {f.node_ref for f in out.facts} and asset_ref() not in covered(out)
    assert any("two agents resolved" in n for n in out.notes)


def test_two_active_rows_for_one_agent_are_inert_never_guessed():
    """``uq_pairing_active_agent`` makes it impossible; a tampered table must not pick one."""
    out = build(pairings=[prec(1, 100), prec(1, 101)])
    assert [f.node_ref for f in out.facts] == [ref1()]
    assert host_agent(out, ref1())["data"]["identity_note"] == "pairing_inert:pairing_ambiguous"
    assert asset_ref(100) not in covered(out) and asset_ref(101) not in covered(out)


def test_only_the_active_pairing_row_of_an_agent_counts_and_a_foreign_agent_row_is_ignored():
    out = build(pairings=[prec(agent=7, asset=100)])                   # a pairing for an agent that is not live here
    assert [f.node_ref for f in out.facts] == [ref1()]


def test_the_default_does_not_pair_without_a_row_and_corroboration_stays_off():
    out = build(assets=[cloud(100, priv=[PRIV], pub=[PUBLIC])])
    assert [f.node_ref for f in out.facts] == [ref1()]
    assert _ipmap.PRIVATE_PEER_IS_PROOF is False


def test_the_asset_age_limit_is_a_build_option():
    p = prec(last_seen=NOW - 10 * H)
    assert covered(build(pairings=[p], pairing_asset_max_age=dt.timedelta(hours=11))) == [asset_ref()]
    assert covered(build(pairings=[p], pairing_asset_max_age=dt.timedelta(hours=9))) == [ref1()]
    assert covered(build(pairings=[p], pairing_asset_max_age=dt.timedelta(0))) == [asset_ref()]   # invalid: the default


def test_a_paired_build_is_byte_identical_for_equal_inputs():
    def once():
        out = build([agent_row(1, peer=PRIV), agent_row(2, peer="10.0.0.9", hostname="b")],
                    pairings=[prec(1, 100)])
        return json.dumps([out.facts[i].facts for i in range(len(out.facts))], sort_keys=True, default=str) + \
            json.dumps(sorted((e.src_ref, e.dst_ref, e.port_lo) for e in out.edges)) + "|".join(out.notes)
    assert once() == once()


def test_the_pairings_sql_reads_active_rows_only_and_names_no_tenant():
    sql = hf.PAIRINGS_SQL
    assert "status = 'active'" in sql and "LEFT JOIN assets" in sql and "tenant_id" not in sql.lower()
    for word in ("INSERT", "UPDATE", "DELETE"):
        assert word not in sql.upper()
    asql = hf.ACKS_SQL
    assert "status = 'active'" in asql and "expires_at > $1" in asql and "tenant_id" not in asql.lower()


def test_a_missing_pairings_attribute_is_the_p2_behaviour():
    r = rows_of((agent_row(peer=PRIV), posture_row()))
    assert r.pairings == [] and r.acks == []
    assert [f.node_ref for f in hf.build(r, NOW).facts] == [ref1()]


# --------------------------------------------------------------------------- #
# 4.6: acknowledgement of agent_closed_scan_open
# --------------------------------------------------------------------------- #

def ack(*, port=8080, proto="tcp", through=NOW - MIN, expires=NOW + H, acked_at=NOW - H, agent=1, n=1,
        kind="agent_closed_scan_open", by="alice"):
    return {"id": str(uuid.UUID(int=500 + n)), "agent_id": aid(agent), "kind": kind, "proto": proto, "port": port,
            "through_seen_at": through, "expires_at": expires, "acked_by": by, "acked_at": acked_at}


def conflict(port=8080, proto="tcp", seen=NOW - MIN, kind="agent_closed_scan_open"):
    return {"kind": kind, "proto": proto, "port": port, "scan_seen_at": hf._iso(seen)}


def test_apply_acks_partitions_into_open_and_acknowledged():
    open_, acked = hf._apply_acks([conflict(8080), conflict(9090)], [ack(port=8080)], NOW)
    assert open_ == [conflict(9090)]
    assert acked == [{"kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080,
                      "scan_seen_at": hf._iso(NOW - MIN), "ack_id": str(uuid.UUID(int=501)), "acked_by": "alice",
                      "expires_at": hf._iso(NOW + H)}]


@pytest.mark.parametrize("what,a,c", [
    ("another port", ack(port=9091), conflict(8080)),
    ("another proto", ack(proto="udp"), conflict(8080, "tcp")),
    ("expired", ack(expires=NOW), conflict()),
    ("expired earlier", ack(expires=NOW - MIN), conflict()),
    ("a LATER observation", ack(through=NOW - 2 * MIN), conflict(seen=NOW - MIN)),
    ("a later observation, one second", ack(through=NOW - MIN - dt.timedelta(seconds=1)), conflict(seen=NOW - MIN)),
    ("another kind of ack", ack(kind="paired_peer_mismatch"), conflict()),
    ("lifetime over 720 h", ack(acked_at=NOW - 800 * H, expires=NOW + H), conflict()),
    ("no expiry", {**ack(), "expires_at": None}, conflict()),
    ("garbage time", {**ack(), "through_seen_at": "yesterday"}, conflict()),
])
def test_an_ack_covers_only_the_observation_it_was_made_for(what, a, c):
    open_, acked = hf._apply_acks([c], [a], NOW)
    assert open_ == [c] and acked == [], what


def test_an_ack_covers_the_observation_it_names_and_older_ones_but_never_a_newer_one():
    for seen in (NOW - MIN, NOW - 5 * MIN):
        open_, acked = hf._apply_acks([conflict(seen=seen)], [ack(through=NOW - MIN)], NOW)
        assert open_ == [] and len(acked) == 1
    open_, acked = hf._apply_acks([conflict(seen=NOW)], [ack(through=NOW - MIN)], NOW)
    assert len(open_) == 1 and acked == []
    assert open_[0]["scan_seen_at"] == hf._iso(NOW)                   # the conflict is re-raised with the NEW time


@pytest.mark.parametrize("kind", ["agent_scan_check_budget_exceeded", "paired_peer_mismatch", "anything"])
def test_only_agent_closed_scan_open_is_acknowledgeable(kind):
    c = conflict(kind=kind, port=0, proto="any")
    open_, acked = hf._apply_acks([c], [ack(port=0, proto="any", kind="agent_closed_scan_open")], NOW)
    assert open_ == [c] and acked == []


def test_an_ack_for_a_budget_conflict_does_not_clear_it_in_a_build():
    c = conflict(kind="agent_scan_check_budget_exceeded", port=0, proto="any")
    assert hf._apply_acks([c], [ack(port=0, proto="tcp")], NOW)[0] == [c]


def test_apply_acks_is_deterministic_and_picks_the_newest_covering_ack():
    a1, a2 = ack(n=1, through=NOW - 2 * MIN), ack(n=2, through=NOW)
    r1 = hf._apply_acks([conflict()], [a1, a2], NOW)
    r2 = hf._apply_acks([conflict()], [a2, a1], NOW)
    assert r1 == r2 and r1[1][0]["ack_id"] == str(uuid.UUID(int=502))


def test_an_ack_restores_coverage_discloses_itself_and_a_later_observation_re_raises():
    scans = [scan_edge(8080)]
    base = build(scans=scans)
    assert base.coverage == []
    acked = build(scans=scans, acks=[ack()])
    assert covered(acked) == [ref1()]
    (cov,) = acked.coverage
    assert cov.detail["acknowledged_conflicts"] == 1
    data = host_agent(acked, ref1())["data"]
    assert data["conflicts"] == [] and data["coverage"] == {"granted": True, "blocked_by": []}
    assert data["conflicts_acknowledged"] == [{
        "kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080, "scan_seen_at": hf._iso(NOW - MIN),
        "ack_id": str(uuid.UUID(int=501)), "acked_by": "alice", "expires_at": hf._iso(NOW + H)}]
    assert all("conflict" not in e for e in acked.facts[0].facts.values())
    later = build(scans=[scan_edge(8080, seen=NOW)], acks=[ack(through=NOW - MIN)])
    assert later.coverage == []
    assert later.facts[0].facts["firewall"]["conflict"][0]["scan_seen_at"] == hf._iso(NOW)


def test_an_ack_for_one_port_leaves_the_other_conflicts_open():
    out = build(scans=[scan_edge(8080), scan_edge(9090)], acks=[ack(port=8080)])
    assert out.coverage == []
    assert [c["port"] for c in out.facts[0].facts["firewall"]["conflict"]] == [9090]
    assert out.facts[0].facts["host_agent"]["data"]["conflicts_acknowledged"][0]["port"] == 8080


def test_an_ack_of_another_agent_covers_nothing():
    out = build(scans=[scan_edge(8080)], acks=[ack(agent=2)])
    assert out.coverage == []


def test_an_ack_covers_a_paired_host_too_and_a_scan_on_the_asset_node():
    out = build(pairings=[prec()], scans=[scan_edge(8080, dst=asset_ref())], acks=[ack()])
    assert covered(out) == [asset_ref()]
    assert out.coverage[0].detail["acknowledged_conflicts"] == 1


def test_acknowledged_conflicts_do_not_move_the_fact_digest_but_a_changed_ack_does():
    from app.assurance import store
    a = build(scans=[scan_edge(8080)], acks=[ack()])
    b = build(scans=[scan_edge(8080, seen=NOW - 2 * MIN)], acks=[ack(expires=NOW + 2 * H)])
    da = store.fact_row_digest("configured", a.facts[0].facts)
    db = store.fact_row_digest("configured", b.facts[0].facts)
    assert da == db                                                    # only *_at moved (the observation, the expiry)
    c = build(scans=[scan_edge(8080)], acks=[ack(n=2)])                # another ack row (another ack_id)
    assert store.fact_row_digest("configured", c.facts[0].facts) != da
    d = build(scans=[scan_edge(8080)])                                 # no ack at all: a different meaning
    assert store.fact_row_digest("configured", d.facts[0].facts) != da


def test_a_build_with_acks_is_byte_identical_for_equal_inputs():
    def once():
        out = build(scans=[scan_edge(8080), scan_edge(9090)], acks=[ack(port=8080), ack(port=9090, n=2)])
        return json.dumps(out.facts[0].facts, sort_keys=True, default=str)
    assert once() == once()


def test_ack_rows_are_never_mutated_by_a_build():
    a = ack()
    before = copy.deepcopy(a)
    build(scans=[scan_edge(8080)], acks=[a])
    assert a == before


# --------------------------------------------------------------------------- #
# 4.6: acknowledgements are applied BEFORE the display cap (verifier finding: truncation + acks cleared hidden ones)
# --------------------------------------------------------------------------- #

def _scans(lo, n):
    return [scan_edge(p) for p in range(lo, lo + n)]


def test_acking_every_visible_conflict_never_clears_the_ones_that_were_cut_off_the_list():
    scans = _scans(8001, 25)
    shown = host_agent(build(scans=scans), ref1())["data"]["conflicts"]
    assert [c["port"] for c in shown] == list(range(8001, 8021))          # only 20 are shown
    acks = [ack(n=i, port=p) for i, p in enumerate(range(8001, 8021), 1)]
    out = build(scans=scans, acks=acks)
    assert out.coverage == [] and covered(out) == []                       # five were never shown: still no coverage
    data = host_agent(out, ref1())["data"]
    assert [c["port"] for c in data["conflicts"]] == list(range(8021, 8026))     # they are now shown, open
    assert len(data["conflicts_acknowledged"]) == 20
    assert data["coverage"]["granted"] is False


def test_the_open_list_is_capped_but_acknowledged_ones_do_not_use_up_the_cap():
    scans = _scans(8001, 30)
    acks = [ack(n=i, port=p) for i, p in enumerate(range(8001, 8011), 1)]    # 10 acked, 20 left open
    data = host_agent(build(scans=scans, acks=acks), ref1())["data"]
    assert [c["port"] for c in data["conflicts"]] == list(range(8011, 8031))
    assert len(data["conflicts_acknowledged"]) == 10


def test_every_conflict_acked_gives_coverage_again_even_when_there_were_more_than_the_display_cap():
    scans = _scans(8001, 25)
    out = build(scans=scans, acks=[ack(n=i, port=p) for i, p in enumerate(range(8001, 8026), 1)])
    assert covered(out) == [ref1()]
    assert out.coverage[0].detail["acknowledged_conflicts"] == 25


def test_more_conflicts_than_can_be_enumerated_leave_an_unacknowledgeable_marker_and_no_coverage():
    n = hf.MAX_SCAN_CONFLICTS + 30
    scans = _scans(2001, n)
    acks = [ack(n=i, port=p) for i, p in enumerate(range(2001, 2001 + n), 1)]       # even an ack of every port
    out = build(scans=scans, acks=acks)
    assert out.coverage == [] and covered(out) == []
    data = host_agent(out, ref1())["data"]
    kinds = {c["kind"] for c in data["conflicts"]}
    assert "agent_scan_conflicts_truncated" in kinds and len(data["conflicts"]) <= hf.MAX_CONFLICTS
    assert len(data["conflicts_acknowledged"]) <= hf.MAX_SCAN_CONFLICTS


def test_the_truncation_marker_cannot_be_acknowledged():
    c = conflict(kind="agent_scan_conflicts_truncated", port=0, proto="any")
    assert hf._apply_acks([c], [ack(port=0, proto="any")], NOW)[0] == [c]


def test_exactly_the_enumeration_limit_is_not_truncated():
    scans = _scans(2001, hf.MAX_SCAN_CONFLICTS)
    data = host_agent(build(scans=scans), ref1())["data"]
    assert "agent_scan_conflicts_truncated" not in {c["kind"] for c in data["conflicts"]}
