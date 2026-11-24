import datetime as dt

import pytest

from paddock_assurance import Verdict, evaluate

from helpers import NOW, STALE, edge, graph, node, reach


def V(plan, g, now=NOW):
    return evaluate(plan, g, now)


def test_direct_path_is_violated_with_witness():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("a1", "b1", "445")])
    r = V(reach(), g)
    assert r.verdict is Verdict.VIOLATED
    assert [(h.src, h.dst, h.ports) for h in r.witnesses[0].hops] == [("a1", "b1", "445")]
    assert r.witnesses[0].confirmed and r.witnesses[0].weakest_basis == "observed"


def test_multi_hop_path_found_and_hops_ordered():
    g = graph([node("a1", "a"), node("m1", "m"), node("m2", "m"), node("b1", "b")],
              [edge("a1", "m1"), edge("m1", "m2"), edge("m2", "b1")])
    w = V(reach(), g).witnesses[0]
    assert [h.dst for h in w.hops] == ["m1", "m2", "b1"]


def test_edges_are_directed():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("b1", "a1")])
    assert V(reach(), g).verdict is Verdict.HOLDS


def test_max_hops_bounds_the_search():
    g = graph([node("a1", "a"), node("m", "m"), node("b1", "b")], [edge("a1", "m"), edge("m", "b1")])
    short = reach("via: { max_hops: 1 }\nevidence: { min_tier: observed }\ncoverage: { require: 0 }")
    assert V(short, g).verdict is Verdict.HOLDS
    assert V(reach(), g).verdict is Verdict.VIOLATED


def test_protocol_and_port_filters_ignore_other_edges():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("a1", "b1", "53", proto="udp")])
    tcp_only = reach("via: { protocols: [tcp] }\nevidence: { min_tier: observed }\ncoverage: { require: 0 }")
    assert V(tcp_only, g).verdict is Verdict.HOLDS
    ports = reach("via: { ports: '445' }\nevidence: { min_tier: observed }\ncoverage: { require: 0 }")
    assert V(ports, g).verdict is Verdict.HOLDS
    assert V(reach(), g).verdict is Verdict.VIOLATED


def test_any_proto_edge_matches_tcp_filter():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("a1", "b1", "1-65535", proto="any")])
    tcp_only = reach("via: { protocols: [tcp] }\nevidence: { min_tier: observed }\ncoverage: { require: 0 }")
    assert V(tcp_only, g).verdict is Verdict.VIOLATED


def test_weakest_basis_and_confirmed_flag():
    g = graph([node("a1", "a"), node("m", "m"), node("b1", "b")],
              [edge("a1", "m", basis="observed"), edge("m", "b1", basis="configured")])
    w = V(reach(), g).witnesses[0]
    assert w.weakest_basis == "configured" and not w.confirmed


def test_stronger_parallel_edge_preferred_for_witness():
    g = graph([node("a1", "a"), node("b1", "b")],
              [edge("a1", "b1", "22", basis="declared"), edge("a1", "b1", "22", basis="tested")])
    assert V(reach(), g).witnesses[0].weakest_basis == "tested"


def test_redundant_witnesses_collapse_to_root_cause():
    # b1 is the violation; b2 is only reachable through b1.
    g = graph([node("a1", "a"), node("b1", "b"), node("b2", "b")],
              [edge("a1", "b1"), edge("b1", "b2")])
    r = V(reach(), g)
    assert r.violation_count == 2 and len(r.witnesses) == 1
    assert r.witnesses[0].hops[-1].dst == "b1"


# ---- soundness: unknown is not safe ---------------------------------------------------------

def test_blind_endpoints_make_it_unknown_not_holds():
    g = graph([node("a1", "a", tier=None), node("b1", "b", tier=None)], [])
    r = V(reach(), g)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["possible_via_unknown_edges"]
    assert {b.node for b in r.blind_spots if b.relevant} == {"a1", "b1"}


def test_one_covered_endpoint_rules_the_edge_out():
    # A connection needs both ends to allow it; b1 is covered and shows no inbound edge.
    g = graph([node("a1", "a", tier=None), node("b1", "b")], [])
    assert V(reach(), g).verdict is Verdict.HOLDS


def test_blind_intermediate_bridges_two_blind_nodes_only():
    # a1 -> blind m -> ... b1 is blind too: an unknown m->b1 edge could exist.
    g = graph([node("a1", "a"), node("m", "m", tier=None), node("b1", "b", tier=None)],
              [edge("a1", "m")])
    r = V(reach(), g)
    assert r.verdict is Verdict.UNKNOWN
    assert [h.proto for h in r.witnesses[0].hops] == ["tcp", "unknown"]


def test_blind_node_off_every_path_does_not_matter():
    g = graph([node("a1", "a"), node("b1", "b"), node("island", "x", tier=None)], [])
    assert V(reach(), g).verdict is Verdict.HOLDS


def test_stale_evidence_is_blind():
    g = graph([node("a1", "a", seen=STALE), node("b1", "b", seen=STALE)], [])
    r = V(reach(), g)
    assert r.verdict is Verdict.UNKNOWN
    assert {b.reason for b in r.blind_spots} == {"stale"}


def test_future_timestamp_is_blind():
    g = graph([node("a1", "a", seen="2026-12-02T09:00:00Z"), node("b1", "b", seen="2026-12-02T09:00:00Z")], [])
    assert {b.reason for b in V(reach(), g).blind_spots} == {"future_timestamp"}


def test_evidence_tier_below_minimum_is_blind():
    g = graph([node("a1", "a", tier="configured"), node("b1", "b", tier="configured")], [])
    assert V(reach(), g).verdict is Verdict.UNKNOWN   # plan needs observed
    ok = reach("evidence: { min_tier: configured, max_age: 24h }\ncoverage: { require: 0 }")
    assert V(ok, g).verdict is Verdict.HOLDS


def test_violation_beats_blindness():
    g = graph([node("a1", "a"), node("b1", "b"), node("x", "x", tier=None)], [edge("a1", "b1")])
    assert V(reach(), g).verdict is Verdict.VIOLATED


def test_empty_selector_is_unknown_not_vacuously_true():
    g = graph([node("a1", "typo-zone"), node("b1", "b")], [])
    r = V(reach(), g)
    assert r.verdict is Verdict.UNKNOWN and r.reasons[0] == "empty_selector:from"
    g2 = graph([node("a1", "a")], [])
    assert V(reach(), g2).reasons[0] == "empty_selector:to"


def test_coverage_floor_turns_holds_into_unknown():
    g = graph([node("a1", "a"), node("b1", "b"), node("x", "x", tier=None), node("y", "y", tier=None)], [])
    strict = reach("evidence: { min_tier: observed }\ncoverage: { require: 0.9 }")
    r = V(strict, g)
    assert r.verdict is Verdict.UNKNOWN and "coverage_below_required" in r.reasons
    assert r.coverage_covered == 2 and r.coverage_universe == 4
    assert r.evidence_tier is None and r.valid_until is None
    lax = reach("evidence: { min_tier: observed }\ncoverage: { require: 0.5 }")
    assert V(lax, g).verdict is Verdict.HOLDS


# ---- freshness ------------------------------------------------------------------------------

def test_holds_carries_tier_and_valid_until_then_expires():
    g = graph([node("a1", "a", tier="tested"), node("b1", "b", tier="observed")], [])
    r = V(reach(), g)
    assert r.verdict is Verdict.HOLDS and r.evidence_tier.value == "observed"   # the weakest used
    assert r.valid_until == dt.datetime(2026, 12, 2, 8, 30, tzinfo=dt.timezone.utc)
    assert r.status_at(NOW) == "HOLDS"
    assert r.status_at(r.valid_until + dt.timedelta(seconds=1)) == "EXPIRED"


def test_naive_now_rejected():
    g = graph([node("a1", "a"), node("b1", "b")], [])
    with pytest.raises(ValueError):
        evaluate(reach(), g, dt.datetime(2026, 12, 1, 9, 0))


# ---- exceptions -----------------------------------------------------------------------------

def _allow(expires):
    return (f"allow:\n  - to: {{ id: b1 }}\n    reason: legacy reporting link\n    expires: {expires}\n"
            "evidence: { min_tier: observed }\ncoverage: { require: 0 }")


def test_active_exception_exempts_target_and_is_reported():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("a1", "b1")])
    r = V(reach(_allow("2026-12-31")), g)
    assert r.verdict is Verdict.HOLDS
    assert r.exceptions_used[0]["target"] == "b1" and r.exceptions_used[0]["expires"] == "2026-12-31"


def test_exception_valid_through_its_expiry_day_then_lapses():
    g = graph([node("a1", "a"), node("b1", "b")], [edge("a1", "b1")])
    plan = reach(_allow("2026-12-01"))
    assert V(plan, g, NOW).verdict is Verdict.HOLDS
    later = NOW + dt.timedelta(days=1)
    g2 = graph([node("a1", "a", seen="2026-12-02T08:30:00Z"), node("b1", "b", seen="2026-12-02T08:30:00Z")],
               [edge("a1", "b1")])
    r = V(plan, g2, later)
    assert r.verdict is Verdict.VIOLATED and len(r.expired_exceptions) == 1


def test_exception_does_not_cover_other_targets():
    g = graph([node("a1", "a"), node("b1", "b"), node("b2", "b")], [edge("a1", "b1"), edge("a1", "b2")])
    r = V(reach(_allow("2026-12-31")), g)
    assert r.verdict is Verdict.VIOLATED and r.witnesses[0].hops[-1].dst == "b2"


# ---- application boundary -------------------------------------------------------------------

BOUNDARY = ("via: { stop_at: { tag: app-tier } }\nevidence: { min_tier: observed }\n"
            "coverage: { require: 0 }")


def test_search_reaches_but_does_not_pass_a_boundary():
    g = graph([node("a1", "a"), node("app", "m", tags=("app-tier",)), node("b1", "b")],
              [edge("a1", "app"), edge("app", "b1")])
    r = V(reach(BOUNDARY), g)
    assert r.verdict is Verdict.HOLDS and r.boundaries_reached == ["app"]
    assert V(reach(), g).verdict is Verdict.VIOLATED       # without the boundary it is a path


def test_boundary_does_not_hide_a_direct_bypass():
    g = graph([node("a1", "a"), node("app", "m", tags=("app-tier",)), node("b1", "b")],
              [edge("a1", "app"), edge("app", "b1"), edge("a1", "b1", "5432")])
    assert V(reach(BOUNDARY), g).verdict is Verdict.VIOLATED


def test_boundary_node_can_be_a_source():
    g = graph([node("app", "a", tags=("app-tier",)), node("b1", "b")], [edge("app", "b1")])
    assert V(reach(BOUNDARY), g).verdict is Verdict.VIOLATED


def test_determinism_under_input_order():
    nodes = [node("a1", "a"), node("a2", "a"), node("m", "m"), node("b1", "b"), node("b2", "b")]
    edges = [edge("a1", "m"), edge("a2", "m"), edge("m", "b2"), edge("m", "b1")]
    r1 = evaluate(reach(), graph(nodes, edges), NOW).to_dict()
    r2 = evaluate(reach(), graph(list(reversed(nodes)), list(reversed(edges))), NOW).to_dict()
    assert r1 == r2
