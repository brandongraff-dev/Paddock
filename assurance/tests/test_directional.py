"""Directional, multi-source coverage (contract D3/D4, section 3).

A source covers a node only in the direction it can actually see. An unknown edge ``u -> v`` is
possible iff ``u`` is not covered outbound AND ``v`` is not covered inbound. Every test here fails
if that rule is replaced by the old clique or if direction is ignored.
"""
import datetime as dt

import pytest

from paddock_assurance import GraphError, ReachGraph, Verdict, compile_text, evaluate

from helpers import FRESH, NOW, STALE, dnode, edge, expose, fact, graph, node, reach

OBS = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"
CFG = "evidence: { min_tier: configured, max_age: 24h }\ncoverage: { require: 0 }"


def V(plan, g, now=NOW):
    return evaluate(plan, g, now)


# ---- the headline: inbound coverage cannot rule out an outbound edge -------------------------

def test_inbound_only_cover_cannot_rule_out_its_outbound_edge_to_a_blind_peer():
    # a1's security group says nothing about what a1 connects to; b1 is not covered at all.
    g = graph([dnode("a1", "a", fact("in")), dnode("b1", "b")], [])
    r = V(reach(CFG), g)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["possible_via_unknown_edges"]
    assert [(h.src, h.dst, h.proto) for h in r.witnesses[0].hops] == [("a1", "b1", "unknown")]


def test_the_same_node_covered_both_ways_does_rule_it_out():
    g = graph([dnode("a1", "a", fact("both")), dnode("b1", "b")], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS


def test_two_inbound_covered_nodes_hold():
    g = graph([dnode("a1", "a", fact("in")), dnode("b1", "b", fact("in"))], [])
    r = V(reach(CFG), g)
    assert r.verdict is Verdict.HOLDS
    # b1's inbound coverage is what rules a1 -> b1 out; the verdict must say it relied on it.
    assert r.evidence_tier.value == "observed"


def test_outbound_coverage_of_the_source_rules_the_edge_out():
    g = graph([dnode("a1", "a", fact("out")), dnode("b1", "b")], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS


def test_outbound_coverage_of_the_target_does_not_rule_out_an_inbound_edge():
    # b1 is watched for what it opens, not for what is opened to it; a1 is blind.
    g = graph([dnode("a1", "a"), dnode("b1", "b", fact("out"))], [])
    assert V(reach(CFG), g).verdict is Verdict.UNKNOWN


def test_direction_of_the_possible_edge_matters():
    # b1 -> a1 would need b1 blind outbound and a1 blind inbound; the invariant asks a -> b only.
    g = graph([dnode("a1", "a", fact("out")), dnode("b1", "b", fact("in"))], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS


def test_possible_edges_are_bipartite_not_a_clique():
    # Old clique: blind a1 and blind m reach each other and everything blind. Now a1 -> m needs
    # m blind inbound; m is covered inbound, so the chain a1 -> m -> b1 does not exist.
    g = graph([dnode("a1", "a"), dnode("m", "m", fact("in")), dnode("b1", "b", fact("in"))], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS
    # An inbound-covered middle that is blind outbound still cannot be entered...
    g2 = graph([dnode("a1", "a", fact("in")), dnode("m", "m"), dnode("b1", "b")], [])
    r = V(reach(CFG), g2)       # ...but here m is blind both ways, so a1 -> m -> b1 is possible
    assert r.verdict is Verdict.UNKNOWN


def test_chain_through_a_blind_intermediate_needs_each_hops_two_ends():
    # a1 (blind out) -> m (blind in, covered out): m cannot open anything unknown, so b1 (blind in)
    # is not reachable through m; a1 itself still reaches b1 directly, so use a covered-in b1.
    g = graph([dnode("a1", "a"), dnode("m", "m", fact("out")), dnode("b1", "b", fact("in"))], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS
    # Known edge m -> b1 turns the possible a1 -> m into a real counterexample candidate.
    g2 = graph([dnode("a1", "a"), dnode("m", "m", fact("out")), dnode("b1", "b", fact("in"))],
               [edge("m", "b1")])
    r = V(reach(CFG), g2)
    assert r.verdict is Verdict.UNKNOWN
    assert [h.proto for h in r.witnesses[0].hops] == ["unknown", "tcp"]


def test_the_realistic_aws_only_estate():
    """Security groups cover everything inbound; nothing is covered outbound; the internet is
    never covered. app (blind-out) could reach db only if db were blind inbound."""
    nodes = [dnode("internet", "internet", kind="internet"),
             dnode("app", "m", fact("in", "configured"), tags=("app-tier",)),
             dnode("db", "b", fact("in", "configured"), cls="data_store")]
    g = graph(nodes, [edge("internet", "app", "443", basis="configured")])
    yml = """
apiVersion: paddock.dev/invariant/v1
id: acme:no-internet-db
title: no internet path to a data store
subjects: { from: { zone: internet }, to: { class: data_store } }
assert: unreachable
via: { stop_at: { tag: app-tier } }
evidence: { min_tier: configured }
coverage: { require: 0 }
"""
    r = V(compile_text(yml), g)
    assert r.verdict is Verdict.HOLDS
    assert r.evidence_tier.value == "configured"
    # The same estate with an unmapped database (no SG data): app could open a connection to it.
    g2 = graph(nodes[:2] + [dnode("db", "b", cls="data_store")],
               [edge("internet", "app", "443", basis="configured")])
    assert V(compile_text(yml.replace("stop_at: { tag: app-tier }", "max_hops: 6")), g2
             ).verdict is Verdict.UNKNOWN


# ---- exposes-only ----------------------------------------------------------------------------

def _expose_graph(t_facts, s_facts=(), edges=()):
    return graph([dnode("internet", "internet", *s_facts, kind="internet"),
                  dnode("t1", "x", *t_facts)], list(edges))


def test_exposure_holds_when_targets_are_covered_inbound_even_if_internet_is_blind():
    assert V(expose(CFG), _expose_graph([fact("in")])).verdict is Verdict.HOLDS


def test_exposure_unknown_when_target_is_not_covered_inbound():
    assert V(expose(CFG), _expose_graph([])).verdict is Verdict.UNKNOWN
    assert V(expose(CFG), _expose_graph([fact("out")])).verdict is Verdict.UNKNOWN


def test_exposure_source_covered_outbound_rules_out_unknown_edges():
    assert V(expose(CFG), _expose_graph([], [fact("out")])).verdict is Verdict.HOLDS
    assert V(expose(CFG), _expose_graph([], [fact("in")])).verdict is Verdict.UNKNOWN


def test_exposure_violation_still_wins():
    g = _expose_graph([], edges=[edge("internet", "t1", "22")])
    assert V(expose(CFG), g).verdict is Verdict.VIOLATED


# ---- multi-source facts, tier and age per direction ------------------------------------------

def test_any_fresh_qualifying_fact_covers_so_a_stale_source_does_not_hurt():
    g = graph([dnode("a1", "a", fact("both", "observed", STALE), fact("both", "observed", FRESH)),
               dnode("b1", "b", fact("both"))], [])
    assert V(reach(OBS), g).verdict is Verdict.HOLDS


def test_two_sources_each_covering_one_direction_cover_both():
    a1 = dnode("a1", "a", fact("in", "configured", source="aws_sg"),
               fact("out", "observed", source="sentry"))
    g = graph([a1, dnode("b1", "b", fact("both", "configured"))], [])
    plan = reach(CFG)
    r = V(plan, g)
    assert r.verdict is Verdict.HOLDS and r.coverage_covered == 2 == r.coverage_universe


def test_a_fact_below_the_minimum_tier_does_not_count_but_another_may():
    g = graph([dnode("a1", "a", fact("both", "declared"), fact("out", "configured")),
               dnode("b1", "b", fact("in", "configured"))], [])
    assert V(reach(CFG), g).verdict is Verdict.HOLDS
    g2 = graph([dnode("a1", "a", fact("both", "declared")), dnode("b1", "b", fact("in", "declared"))], [])
    r = V(reach(CFG), g2)
    assert r.verdict is Verdict.UNKNOWN
    spots = {(b.node, b.direction, b.reason) for b in r.blind_spots}
    assert ("a1", "both", "tier_below_min") in spots and ("b1", "in", "tier_below_min") in spots


def test_evidence_tier_and_expiry_come_from_the_best_qualifying_fact_per_direction():
    shuffled = [fact("in", "configured", "2026-12-01T08:50:00Z"),
                fact("in", "observed", "2026-12-01T07:00:00Z"),
                fact("in", "observed", STALE)]            # stale: never used
    for facts in (shuffled, shuffled[::-1], shuffled[1:] + shuffled[:1]):
        g = graph([dnode("a1", "a", fact("out", "tested", "2026-12-01T08:30:00Z")),
                   dnode("b1", "b", *facts)], [])
        r = V(reach(CFG), g)
        assert r.verdict is Verdict.HOLDS
        # a1.out is tested@08:30, b1.in's best is observed@07:00: the weakest tier is observed,
        # the earliest expiry is 07:00 + 24h.
        assert r.evidence_tier.value == "observed"
        assert r.valid_until == dt.datetime(2026, 12, 2, 7, 0, tzinfo=dt.timezone.utc)


def test_expiry_is_per_direction_not_per_node():
    # a1's inbound fact is old but its outbound fact is fresh; only outbound is relied on.
    g = graph([dnode("a1", "a", fact("in", seen="2026-12-01T01:00:00Z"),
                     fact("out", seen="2026-12-01T08:30:00Z")),
               dnode("b1", "b", fact("both", seen="2026-12-01T08:00:00Z"))], [])
    r = V(reach(OBS), g)
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until == dt.datetime(2026, 12, 2, 8, 0, tzinfo=dt.timezone.utc)


def test_stale_in_one_direction_only_blinds_that_direction():
    g = graph([dnode("a1", "a", fact("in", seen=STALE), fact("out")), dnode("b1", "b")], [])
    r = V(reach(OBS), g)
    # a1 is covered outbound, so a1 -> b1 is ruled out; but a1 is blind inbound (stale).
    assert r.verdict is Verdict.HOLDS
    spots = {(b.node, b.direction, b.reason) for b in r.blind_spots}
    assert ("a1", "in", "stale") in spots and ("b1", "both", "no_sensor") in spots


def test_future_timestamp_fact_is_not_coverage():
    g = graph([dnode("a1", "a", fact("both", seen="2026-12-02T09:00:00Z")),
               dnode("b1", "b", fact("both", seen="2026-12-02T09:00:00Z"))], [])
    r = V(reach(OBS), g)
    assert r.verdict is Verdict.UNKNOWN and {b.reason for b in r.blind_spots} == {"future_timestamp"}


# ---- blind spots, counts ---------------------------------------------------------------------

def test_blind_spot_direction_is_in_the_serialised_result():
    g = graph([dnode("a1", "a", fact("in")), dnode("b1", "b")], [])
    d = V(reach(OBS), g).to_dict()
    rows = {(b["node"], b["direction"], b["reason"]) for b in d["blind_spots"]}
    assert rows == {("a1", "out", "no_sensor"), ("b1", "both", "no_sensor")}


def test_different_reasons_per_direction_give_separate_rows():
    g = graph([dnode("a1", "a", fact("in", seen=STALE)), dnode("b1", "b")], [])
    rows = {(b.node, b.direction, b.reason) for b in V(reach(OBS), g).blind_spots}
    assert {("a1", "in", "stale"), ("a1", "out", "no_sensor")} <= rows


def test_a_node_counts_as_covered_only_when_covered_both_ways():
    g = graph([dnode("a1", "a", fact("in")), dnode("b1", "b", fact("both")),
               dnode("c1", "x", fact("out")), dnode("d1", "y")], [])
    r = V(reach(OBS), g)
    assert (r.coverage_covered, r.coverage_universe) == (1, 4)


def test_coverage_floor_uses_both_direction_counts():
    g = graph([dnode("a1", "a", fact("in")), dnode("b1", "b", fact("in"))], [])
    strict = reach("evidence: { min_tier: observed }\ncoverage: { require: 0.5 }")
    r = V(strict, g)
    assert r.verdict is Verdict.UNKNOWN and "coverage_below_required" in r.reasons


# ---- a covered node off the found paths can still carry the verdict --------------------------

def test_expiry_accounts_for_covered_nodes_off_the_found_paths():
    """x is covered inbound, so blind a1 cannot reach it, and x has a known edge to b1. If x's
    coverage lapsed, a1 -> x -> b1 would appear, so the HOLDS must expire with x's evidence."""
    old = "2026-12-01T01:00:00Z"
    g = graph([dnode("a1", "a"), dnode("x", "m", fact("in", seen=old)),
               dnode("b1", "b", fact("in"))], [edge("x", "b1")])
    plan = reach(OBS)
    r = V(plan, g)
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until == dt.datetime(2026, 12, 2, 1, 0, tzinfo=dt.timezone.utc)
    later = dt.datetime(2026, 12, 2, 1, 0, 1, tzinfo=dt.timezone.utc)
    assert r.status_at(later) == "EXPIRED"
    g2 = ReachGraph.from_dict({"version": 1, "nodes": [
        dnode("a1", "a"),
        dnode("x", "m", fact("in", seen=old)),
        dnode("b1", "b", fact("in", seen="2026-12-02T01:00:00Z"))],
        "edges": [edge("x", "b1")]})
    assert evaluate(plan, g2, later).verdict is Verdict.UNKNOWN


# ---- parsing ---------------------------------------------------------------------------------

def test_p0_single_object_means_both_directions():
    g = graph([node("a1", "a"), node("b1", "b", tier=None)], [])
    n = g.nodes["a1"]
    assert len(n.coverage) == 1 and n.coverage[0].direction == "both"
    assert V(reach(OBS), g).verdict is Verdict.HOLDS      # a1 covered out, b1 blind in: ruled out


def test_single_object_equals_one_element_both_list():
    legacy = graph([node("a1", "a", tier=None), node("b1", "b")], [])
    listed = graph([dnode("a1", "a"), dnode("b1", "b", fact("both"))], [])
    assert V(reach(OBS), legacy).to_dict() | {"blind_spots": 0} == \
        V(reach(OBS), listed).to_dict() | {"blind_spots": 0}


@pytest.mark.parametrize("cov,needle", [
    ([{"tier": "observed", "observed_at": FRESH}], "direction"),                  # list item w/o direction
    ([{"direction": "sideways", "tier": "observed", "observed_at": FRESH}], "direction"),
    ([{"direction": "in", "tier": "great", "observed_at": FRESH}], "tier"),
    ([{"direction": "in", "tier": "observed", "observed_at": "2026-12-01T00:00:00"}], "timezone"),
    ([{"direction": "in", "tier": "observed"}], "timestamp"),
    (["in"], "object"),
    ("in", "object"),
    ([fact("in")] * 33, "too many"),
])
def test_bad_coverage_is_rejected_loudly(cov, needle):
    with pytest.raises(GraphError, match=needle):
        ReachGraph.from_dict({"nodes": [{"id": "a", "coverage": cov}]})


def test_empty_list_and_null_mean_blind():
    for cov in ([], None):
        g = ReachGraph.from_dict({"nodes": [{"id": "a", "coverage": cov}]})
        assert g.nodes["a"].coverage == ()


def test_fact_order_in_the_document_does_not_change_the_result():
    facts = [fact("in", "configured"), fact("out", "observed"), fact("both", "declared", STALE)]
    a = graph([dnode("a1", "a", *facts), dnode("b1", "b")], []).nodes["a1"]
    b = graph([dnode("a1", "a", *facts[::-1]), dnode("b1", "b")], []).nodes["a1"]
    assert a.coverage == b.coverage
