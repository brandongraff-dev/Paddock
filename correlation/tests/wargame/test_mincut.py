"""Tests for the minimum-cost fix set (weighted hitting set)."""
from __future__ import annotations

from app.engine.wargame import mincut
from app.engine.wargame.model import (
    DEFAULT_COST_CLASSES,
    EvidenceLabel,
    FixCandidate,
    Hop,
    ReachabilityResult,
    Route,
)


def _cand(cid: str, cost_class: str, overrides=None) -> FixCandidate:
    return FixCandidate(
        id=cid,
        kind="rule",
        cost_class=cost_class,
        description=f"change {cid}",
        cost=mincut.cost_for(cost_class, overrides),
    )


# ---------------------------------------------------------------------------
# cost_for
# ---------------------------------------------------------------------------

def test_cost_for_known_class():
    assert mincut.cost_for("network_rule") == DEFAULT_COST_CLASSES["network_rule"]
    assert mincut.cost_for("device_patch") == DEFAULT_COST_CLASSES["device_patch"]


def test_cost_for_unknown_class_uses_documented_default():
    assert mincut.cost_for("no_such_class") == mincut.DEFAULT_UNKNOWN_COST
    assert mincut.DEFAULT_UNKNOWN_COST == 5.0


def test_cost_for_overrides_win():
    assert mincut.cost_for("network_rule", {"network_rule": 0.25}) == 0.25
    # unknown class can be priced via overrides
    assert mincut.cost_for("custom", {"custom": 9.0}) == 9.0


# ---------------------------------------------------------------------------
# single route picks cheapest element
# ---------------------------------------------------------------------------

def test_single_route_picks_cheapest_element():
    candidates = {
        "a": _cand("a", "device_patch"),     # 50.0
        "b": _cand("b", "network_rule"),     # 1.0
        "c": _cand("c", "compensating"),     # 2.5
    }
    routes = [frozenset({"a", "b", "c"})]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.optimality == "exact"
    assert fs.selected == ["b"]
    assert fs.total_cost == 1.0
    assert fs.cuts_all is True
    assert fs.uncut_routes == []


def test_compensating_control_preferred_over_device_patch():
    # The compensating control (2.5) cuts the same route as the device_patch
    # (50.0); the optimiser must choose the cheaper compensating control.
    candidates = {
        "patch": _cand("patch", "device_patch"),
        "comp": _cand("comp", "compensating"),
    }
    routes = [frozenset({"patch", "comp"})]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.selected == ["comp"]
    assert fs.total_cost == DEFAULT_COST_CLASSES["compensating"]


# ---------------------------------------------------------------------------
# shared element covers multiple routes cheaply
# ---------------------------------------------------------------------------

def test_shared_element_covers_multiple_routes():
    # "shared" sits on both routes; picking it once (cost 1) beats picking the
    # two route-specific cheaper-looking elements separately.
    candidates = {
        "shared": _cand("shared", "network_rule"),   # 1.0
        "x": _cand("x", "credential"),               # 2.0
        "y": _cand("y", "credential"),               # 2.0
    }
    routes = [frozenset({"shared", "x"}), frozenset({"shared", "y"})]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.selected == ["shared"]
    assert fs.total_cost == 1.0
    assert fs.cuts_all is True


def test_two_disjoint_routes_need_two_fixes():
    candidates = {
        "a": _cand("a", "network_rule"),
        "b": _cand("b", "network_rule"),
    }
    routes = [frozenset({"a"}), frozenset({"b"})]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.selected == ["a", "b"]
    assert fs.total_cost == 2.0
    assert fs.cuts_all is True


# ---------------------------------------------------------------------------
# cost classes change the choice
# ---------------------------------------------------------------------------

def test_cost_classes_change_the_choice():
    # Same route topology, different pricing → different optimal pick.
    base = {
        "hub": _cand("hub", "network_rule"),     # 1.0
        "p": _cand("p", "network_rule"),         # 1.0
        "q": _cand("q", "network_rule"),         # 1.0
    }
    routes = [frozenset({"hub", "p"}), frozenset({"hub", "q"})]
    # With equal costs, the single shared hub (cost 1) beats two picks (cost 2).
    fs1 = mincut.min_cost_fix_set(routes, base)
    assert fs1.selected == ["hub"]
    assert fs1.total_cost == 1.0

    # Now make the hub very expensive; the two cheap endpoints win.
    overrides = {"network_rule": 1.0, "device_patch": 50.0}
    expensive = {
        "hub": _cand("hub", "device_patch", overrides),  # 50.0
        "p": _cand("p", "network_rule", overrides),      # 1.0
        "q": _cand("q", "network_rule", overrides),      # 1.0
    }
    fs2 = mincut.min_cost_fix_set(routes, expensive)
    assert fs2.selected == ["p", "q"]
    assert fs2.total_cost == 2.0


# ---------------------------------------------------------------------------
# empty route → uncut, cuts_all False, rest still covered
# ---------------------------------------------------------------------------

def test_empty_route_is_uncuttable_but_rest_covered():
    candidates = {"a": _cand("a", "network_rule")}
    routes = [
        frozenset({"a"}),   # index 0, cuttable
        frozenset(),        # index 1, no modelled control → uncuttable
        frozenset({"a"}),   # index 2, cuttable (shares "a")
    ]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.uncut_routes == [1]
    assert fs.cuts_all is False
    # the two real routes are still optimally covered by the one shared fix
    assert fs.selected == ["a"]
    assert fs.total_cost == 1.0


def test_all_routes_empty():
    fs = mincut.min_cost_fix_set([frozenset(), frozenset()], {})
    assert fs.selected == []
    assert fs.total_cost == 0.0
    assert fs.cuts_all is False
    assert fs.uncut_routes == [0, 1]


def test_no_routes_at_all():
    fs = mincut.min_cost_fix_set([], {})
    assert fs.selected == []
    assert fs.cuts_all is True
    assert fs.uncut_routes == []
    assert fs.optimality == "exact"


# ---------------------------------------------------------------------------
# exact vs greedy threshold
# ---------------------------------------------------------------------------

def test_small_instance_is_exact_with_known_optimum():
    # 4 distinct ids, well under the exact threshold. Known optimum: the two
    # cheap network rules "r1" and "r2" cover all three routes for cost 2,
    # beating the single pricey "big" (8.0) that also covers all three.
    candidates = {
        "big": _cand("big", "vendor_patch"),   # 8.0, on every route
        "r1": _cand("r1", "network_rule"),      # 1.0
        "r2": _cand("r2", "network_rule"),      # 1.0
        "r3": _cand("r3", "credential"),        # 2.0
    }
    routes = [
        frozenset({"big", "r1"}),
        frozenset({"big", "r1", "r3"}),
        frozenset({"big", "r2"}),
    ]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.optimality == "exact"
    assert fs.selected == ["r1", "r2"]
    assert fs.total_cost == 2.0
    assert fs.cuts_all is True


def test_exact_threshold_boundary_is_exact():
    # Exactly _EXACT_MAX_ELEMENTS distinct ids → still exact.
    n = mincut._EXACT_MAX_ELEMENTS
    ids = [f"c{i:02d}" for i in range(n)]
    candidates = {cid: _cand(cid, "network_rule") for cid in ids}
    routes = [frozenset({cid}) for cid in ids]  # each route forces its own id
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.optimality == "exact"
    assert fs.selected == sorted(ids)
    assert fs.total_cost == float(n)
    assert fs.cuts_all is True


def test_large_instance_falls_back_to_greedy():
    # More than _EXACT_MAX_ELEMENTS distinct ids → greedy, and it still cuts
    # every route.
    n = mincut._EXACT_MAX_ELEMENTS + 20
    ids = [f"c{i:03d}" for i in range(n)]
    candidates = {cid: _cand(cid, "network_rule") for cid in ids}
    routes = [frozenset({cid}) for cid in ids]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.optimality == "greedy"
    assert fs.cuts_all is True
    # every route had exactly one element, so all must be chosen
    assert set(fs.selected) == set(ids)


def test_greedy_prefers_high_coverage_per_cost():
    # Large instance (forces greedy). "hub" sits on many routes; greedy's
    # coverage/cost heuristic should take it.
    n = mincut._EXACT_MAX_ELEMENTS + 5
    tail_ids = [f"t{i:03d}" for i in range(n)]
    candidates = {t: _cand(t, "network_rule") for t in tail_ids}
    candidates["hub"] = _cand("hub", "network_rule")
    # many routes all contain "hub" plus a unique tail element
    routes = [frozenset({"hub", t}) for t in tail_ids]
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.optimality == "greedy"
    assert "hub" in fs.selected
    assert fs.cuts_all is True


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------

def test_determinism_same_input_same_output():
    candidates = {
        "a": _cand("a", "network_rule"),
        "b": _cand("b", "network_rule"),
        "c": _cand("c", "network_rule"),
    }
    routes = [frozenset({"a", "b"}), frozenset({"b", "c"}), frozenset({"a", "c"})]
    first = mincut.min_cost_fix_set(routes, candidates)
    for _ in range(5):
        again = mincut.min_cost_fix_set(routes, candidates)
        assert again.selected == first.selected
        assert again.total_cost == first.total_cost
        assert again.optimality == first.optimality


def test_determinism_insensitive_to_route_order():
    candidates = {
        "a": _cand("a", "network_rule"),
        "b": _cand("b", "credential"),
        "c": _cand("c", "network_rule"),
    }
    r = [frozenset({"a", "b"}), frozenset({"b", "c"}), frozenset({"a", "c"})]
    import itertools

    results = {
        tuple(sorted(mincut.min_cost_fix_set(list(p), candidates).selected))
        for p in itertools.permutations(r)
    }
    # optimum cost identical regardless of order
    costs = {
        mincut.min_cost_fix_set(list(p), candidates).total_cost
        for p in itertools.permutations(r)
    }
    assert len(costs) == 1
    assert len(results) == 1


def test_unknown_candidate_id_uses_default_cost():
    # route references an id with no FixCandidate → priced at the default.
    candidates = {"known": _cand("known", "device_patch")}  # 50.0
    routes = [frozenset({"known", "ghost"})]  # ghost unpriced → 5.0, cheaper
    fs = mincut.min_cost_fix_set(routes, candidates)
    assert fs.selected == ["ghost"]
    assert fs.total_cost == mincut.DEFAULT_UNKNOWN_COST


# ---------------------------------------------------------------------------
# fix_set_for over a ReachabilityResult
# ---------------------------------------------------------------------------

def _route(entry, jewel, elems) -> Route:
    hop = Hop(
        src=entry,
        dst=jewel,
        labels=frozenset({EvidenceLabel.PROVED_CONFIG}),
        fix_candidate_ids=frozenset(elems),
    )
    return Route(entry=entry, jewel=jewel, hops=[hop])


def test_fix_set_for_only_uses_open_pairs():
    candidates = {
        "open_fix": _cand("open_fix", "network_rule"),
        "closed_fix": _cand("closed_fix", "network_rule"),
    }
    open_route = _route("internet", "db", {"open_fix"})
    closed_route = _route("guest", "db", {"closed_fix"})
    result = ReachabilityResult(
        routes=[open_route, closed_route],
        open_pairs={("internet", "db")},
        closed_pairs={("guest", "db")},
    )
    fs = mincut.fix_set_for(result, candidates)
    # only the open pair's route is considered
    assert fs.selected == ["open_fix"]
    assert fs.cuts_all is True


# ---------------------------------------------------------------------------
# solver audit: tie-breaking, node limit, cost validation, exactness
# ---------------------------------------------------------------------------

import itertools
import random

import pytest

from app.engine.wargame.model import Edge, FixSet, Node, NodeRole


def _brute_force_cost(routes, costs):
    ids = sorted({c for r in routes for c in r})
    best = float("inf")
    for k in range(len(ids) + 1):
        for combo in itertools.combinations(ids, k):
            s = set(combo)
            if all(r & s for r in routes):
                best = min(best, sum(costs[c] for c in combo))
    return best


def test_greedy_tie_break_prefers_lower_id_even_for_prefixes():
    # The old max-key trick ranked "ab" above "a" (a prefix compares smaller
    # as a negated tuple), contradicting "lower id wins a tie".
    assert mincut._greedy([frozenset({"a", "ab"})], {"a": 1.0, "ab": 1.0}) == ["a"]
    # Through the public API on an instance large enough to force greedy.
    n = mincut._EXACT_MAX_ELEMENTS + 1
    routes = [frozenset({"a", "ab"})] + [frozenset({f"z{i:02d}"}) for i in range(n)]
    cands = {cid: _cand(cid, "network_rule") for r in routes for cid in r}
    fs = mincut.min_cost_fix_set(routes, cands)
    assert fs.optimality == "greedy"
    assert "a" in fs.selected and "ab" not in fs.selected


def test_branch_and_bound_matches_brute_force_on_random_instances():
    rng = random.Random(7)
    classes = ["network_rule", "credential", "compensating", "segment_move", "vendor_patch"]
    for _ in range(150):
        ids = [f"c{i}" for i in range(rng.randint(1, 9))]
        cands = {cid: _cand(cid, rng.choice(classes)) for cid in ids}
        routes = [frozenset(rng.sample(ids, rng.randint(1, len(ids)))) for _ in range(rng.randint(1, 8))]
        fs = mincut.min_cost_fix_set(routes, cands)
        costs = {c: cands[c].cost for c in ids}
        assert fs.optimality == "exact"
        assert fs.cuts_all
        assert fs.total_cost == pytest.approx(_brute_force_cost(routes, costs))


def test_lower_bound_is_admissible_on_random_instances():
    rng = random.Random(11)
    for _ in range(150):
        ids = [f"c{i}" for i in range(rng.randint(1, 8))]
        costs = {c: rng.choice([0.0, 1.0, 2.0, 2.5, 8.0, 50.0]) for c in ids}
        routes = [frozenset(rng.sample(ids, rng.randint(1, len(ids)))) for _ in range(rng.randint(1, 7))]
        bit = {c: i for i, c in enumerate(sorted(ids))}
        masks = [sum(1 << bit[c] for c in r) for r in routes]
        cost_vec = [costs[c] for c in sorted(ids)]
        assert mincut._lower_bound(masks, cost_vec) <= _brute_force_cost(routes, costs) + 1e-9


def test_node_limit_hit_is_not_labelled_exact(monkeypatch):
    monkeypatch.setattr(mincut, "_BNB_NODE_LIMIT", 2)
    ids = [f"c{i:02d}" for i in range(10)]
    cands = {cid: _cand(cid, "network_rule") for cid in ids}
    routes = [frozenset({a, b}) for a, b in zip(ids, ids[1:])]
    fs = mincut.min_cost_fix_set(routes, cands)
    assert fs.optimality == "greedy"     # search did not complete
    assert fs.cuts_all is True           # but the answer still cuts everything


def test_invalid_costs_are_rejected():
    bad = FixCandidate(id="x", kind="rule", cost_class="custom", description="", cost=-1.0)
    with pytest.raises(ValueError):
        mincut.min_cost_fix_set([frozenset({"x"})], {"x": bad})
    nan = FixCandidate(id="x", kind="rule", cost_class="custom", description="", cost=float("nan"))
    with pytest.raises(ValueError):
        mincut.min_cost_fix_set([frozenset({"x"})], {"x": nan})


def test_zero_cost_candidates_are_handled():
    cands = {
        "free": FixCandidate(id="free", kind="rule", cost_class="custom", description="", cost=0.0),
        "a": _cand("a", "network_rule"),
    }
    fs = mincut.min_cost_fix_set([frozenset({"free", "a"}), frozenset({"a"})], cands)
    assert fs.selected == ["a"] and fs.total_cost == 1.0 and fs.optimality == "exact"


def test_duplicate_routes_report_every_uncut_index():
    cands = {"a": _cand("a", "network_rule")}
    routes = [frozenset({"a"}), frozenset({"a"}), frozenset(), frozenset()]
    fs = mincut.min_cost_fix_set(routes, cands)
    assert fs.selected == ["a"]
    assert fs.uncut_routes == [2, 3]
    assert fs.cuts_all is False


def test_threshold_counts_reduced_routes():
    # 30 distinct ids, but superset routes reduce away to 3 → still exact.
    big = frozenset(f"x{i:02d}" for i in range(27))
    routes = [frozenset({"a"}), frozenset({"b"}), frozenset({"c"})] + [
        big | {"a"}, big | {"b"}, big | {"c"}
    ]
    cands = {cid: _cand(cid, "network_rule") for r in routes for cid in r}
    fs = mincut.min_cost_fix_set(routes, cands)
    assert fs.optimality == "exact"
    assert fs.selected == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# fix_set_for honesty over an incomplete listing
# ---------------------------------------------------------------------------

def test_fix_set_for_never_claims_cuts_all_over_incomplete_listing():
    candidates = {"f": _cand("f", "network_rule")}
    route = _route("internet", "db", {"f"})
    incomplete = ReachabilityResult(
        routes=[route],
        open_pairs={("internet", "db")},
        closed_pairs=set(),
        incomplete_pairs={("internet", "db")},
    )
    fs = mincut.fix_set_for(incomplete, candidates)
    assert fs.selected == ["f"]
    assert fs.cuts_all is False
    assert fs.optimality == "greedy"

    truncated = ReachabilityResult(
        routes=[], open_pairs={("internet", "db")}, closed_pairs=set(),
        truncated_pairs={("internet", "db")}, incomplete_pairs={("internet", "db")},
    )
    fs = mincut.fix_set_for(truncated, candidates)
    assert fs.cuts_all is False

    budget = ReachabilityResult(
        routes=[route], open_pairs={("internet", "db")}, closed_pairs=set(),
        budget_exhausted=True,
    )
    assert mincut.fix_set_for(budget, candidates).cuts_all is False


# ---------------------------------------------------------------------------
# verified_fix_set: solve → apply → re-check → add routes → re-solve
# ---------------------------------------------------------------------------

def _n(nid, role=NodeRole.INTERMEDIATE, i=0):
    return Node(id=nid, role=role, cidrs=(f"10.{i}.0.0/24",))


def _priced(ids, cls="network_rule", **over):
    out = {cid: _cand(cid, cls) for cid in ids}
    for cid, c in over.items():
        out[cid] = _cand(cid, c)
    return out


def test_parallel_edges_fix_set_cuts_both():
    # The old collapse kept one parallel edge's fix id: the solver cut A and
    # claimed cuts_all while B still carried the route.
    nodes = {"e": _n("e", NodeRole.ENTRY, 1), "m": _n("m", i=2), "j": _n("j", NodeRole.CROWN_JEWEL, 3)}
    edges = [
        Edge(src="e", dst="m", fix_candidate_id="A"),
        Edge(src="e", dst="m", fix_candidate_id="B"),
        Edge(src="m", dst="j", fix_candidate_id="X"),
    ]
    cands = _priced(["A", "B"], X="device_patch")
    from app.engine.wargame import reachability

    legacy = mincut.fix_set_for(reachability.backward_reachability(nodes, edges, {}), cands)
    assert legacy.selected == ["A", "B"] and legacy.cuts_all and legacy.optimality == "exact"

    fs = mincut.verified_fix_set(nodes, edges, {}, cands)
    assert isinstance(fs, mincut.VerifiedFixSet) and isinstance(fs, FixSet)
    assert fs.selected == ["A", "B"]
    assert fs.cuts_all and fs.verified and fs.optimality == "exact"
    assert fs.target_pairs == {("e", "j")} and fs.uncut_pairs == set()
    post = reachability.backward_reachability(nodes, mincut.apply_fix_set(edges, fs.selected), {})
    assert post.open_pairs == set()


def _long_chain_with_fixes(n_hops):
    names = ["e"] + [f"m{i}" for i in range(1, n_hops)] + ["j"]
    nodes = {nm: _n(nm, i=i) for i, nm in enumerate(names)}
    nodes["e"] = _n("e", NodeRole.ENTRY, 200)
    nodes["j"] = _n("j", NodeRole.CROWN_JEWEL, 201)
    edges = [Edge(src=a, dst=b, fix_candidate_id=f"cut-{a}-{b}") for a, b in zip(names, names[1:])]
    return nodes, edges


def test_verified_fix_set_cuts_route_beyond_hop_limit():
    nodes, edges = _long_chain_with_fixes(10)
    cands = _priced([e.fix_candidate_id for e in edges], "device_patch", **{"cut-m5-m6": "network_rule"})
    from app.engine.wargame import reachability

    rr = reachability.backward_reachability(nodes, edges, {})
    assert rr.routes == [] and rr.truncated_pairs == {("e", "j")}
    legacy = mincut.fix_set_for(rr, cands)
    assert legacy.cuts_all is False            # nothing listed: never claim it

    fs = mincut.verified_fix_set(nodes, edges, {}, cands)
    assert fs.selected == ["cut-m5-m6"]
    assert fs.cuts_all and fs.verified and fs.optimality == "exact"


def test_verified_fix_set_lazy_constraints_reach_true_optimum():
    # Three disjoint 2-hop routes e->mi->j; listing capped at one route, so
    # the first solve sees one route only. Verification must add the rest.
    nodes = {"e": _n("e", NodeRole.ENTRY, 100), "j": _n("j", NodeRole.CROWN_JEWEL, 101)}
    edges = []
    for i in range(3):
        nodes[f"m{i}"] = _n(f"m{i}", i=i)
        edges += [
            Edge(src="e", dst=f"m{i}", fix_candidate_id=f"in{i}"),
            Edge(src=f"m{i}", dst="j", fix_candidate_id=f"out{i}"),
        ]
    # cheapest is "jfw" which gates all three into the jewel... via a shared id
    for e in edges:
        if e.dst == "j":
            e.fix_candidate_id = "jfw"
    cands = _priced([f"in{i}" for i in range(3)], jfw="segment_move")  # 3 x 1.0 vs 3.0
    fs = mincut.verified_fix_set(nodes, edges, {}, cands, max_routes_per_pair=1)
    assert fs.cuts_all and fs.verified
    assert fs.iterations > 1
    assert fs.total_cost == 3.0
    assert fs.optimality == "exact"


def test_verified_fix_set_reports_uncuttable_pairs():
    nodes = {
        "e": _n("e", NodeRole.ENTRY, 1),
        "e2": _n("e2", NodeRole.ENTRY, 2),
        "j": _n("j", NodeRole.CROWN_JEWEL, 3),
    }
    edges = [
        Edge(src="e", dst="j", fix_candidate_id="A"),
        Edge(src="e2", dst="j"),                    # no modelled control
    ]
    fs = mincut.verified_fix_set(nodes, edges, {}, _priced(["A"]))
    assert fs.selected == ["A"]
    assert fs.uncuttable_pairs == {("e2", "j")}
    assert fs.uncut_pairs == {("e2", "j")}
    assert fs.cuts_all is False
    assert fs.uncut_routes                       # the uncuttable route is shown
    assert all(fs.routes[i].pair == ("e2", "j") for i in fs.uncut_routes)


def test_verified_fix_set_pairs_filter_and_nothing_open():
    nodes = {
        "e": _n("e", NodeRole.ENTRY, 1),
        "j1": _n("j1", NodeRole.CROWN_JEWEL, 2),
        "j2": _n("j2", NodeRole.CROWN_JEWEL, 3),
    }
    edges = [Edge(src="e", dst="j1", fix_candidate_id="A"), Edge(src="e", dst="j2", fix_candidate_id="B")]
    fs = mincut.verified_fix_set(nodes, edges, {}, _priced(["A", "B"]), pairs={("e", "j2")})
    assert fs.selected == ["B"] and fs.target_pairs == {("e", "j2")} and fs.cuts_all

    closed = mincut.verified_fix_set(nodes, [], {}, {})
    assert closed.selected == [] and closed.cuts_all and closed.verified
    assert closed.target_pairs == set()


def test_verified_fix_set_max_iters_exhausted_is_not_cuts_all():
    nodes = {"e": _n("e", NodeRole.ENTRY, 100), "j": _n("j", NodeRole.CROWN_JEWEL, 101)}
    edges = []
    for i in range(3):
        nodes[f"m{i}"] = _n(f"m{i}", i=i)
        edges += [Edge(src="e", dst=f"m{i}", fix_candidate_id=f"in{i}"), Edge(src=f"m{i}", dst="j")]
    fs = mincut.verified_fix_set(nodes, edges, {}, _priced([f"in{i}" for i in range(3)]),
                                 max_routes_per_pair=1, max_iters=1)
    assert fs.verified is False
    assert fs.cuts_all is False
    assert fs.uncut_pairs == {("e", "j")}
    assert fs.optimality == "greedy"


def test_apply_fix_set_drops_every_edge_with_selected_id():
    edges = [
        Edge(src="a", dst="b", fix_candidate_id="X"),
        Edge(src="b", dst="a", fix_candidate_id="X"),
        Edge(src="a", dst="c", fix_candidate_id="Y"),
        Edge(src="a", dst="d"),
    ]
    kept = mincut.apply_fix_set(edges, ["X"])
    assert [(e.src, e.dst) for e in kept] == [("a", "c"), ("a", "d")]
    assert len(edges) == 4


def test_verified_fix_set_matches_brute_force_on_random_graphs():
    from app.engine.wargame import reachability

    rng = random.Random(99)
    for trial in range(40):
        n = rng.randint(3, 7)
        names = [f"n{i}" for i in range(n)]
        nodes = {}
        for i, nm in enumerate(names):
            role = NodeRole.ENTRY if i == 0 else (NodeRole.CROWN_JEWEL if i == n - 1 else NodeRole.INTERMEDIATE)
            nodes[nm] = _n(nm, role, i)
        ids = [f"f{i}" for i in range(rng.randint(1, 5))]
        edges = []
        for _ in range(rng.randint(1, 3 * n)):
            a, b = rng.sample(names, 2)
            edges.append(Edge(src=a, dst=b, fix_candidate_id=rng.choice(ids + [None])))
        cands = _priced(ids)
        for i in ids:
            cands[i] = _cand(i, rng.choice(["network_rule", "credential", "compensating"]))
        fs = mincut.verified_fix_set(nodes, edges, {}, cands, max_hops=2, max_routes_per_pair=1)
        # brute force over every subset of fix ids
        target = reachability.backward_reachability(nodes, edges, {}).open_pairs
        best = None
        for k in range(len(ids) + 1):
            for combo in itertools.combinations(ids, k):
                post = reachability.backward_reachability(nodes, mincut.apply_fix_set(edges, combo), {})
                if not (post.open_pairs & target):
                    c = sum(cands[x].cost for x in combo)
                    best = c if best is None else min(best, c)
        if best is None:
            assert fs.cuts_all is False and fs.uncut_pairs, trial
        else:
            assert fs.cuts_all and fs.verified, trial
            assert fs.optimality == "exact"
            assert fs.total_cost == pytest.approx(best), trial


def test_verified_fix_set_large_instance_converges_and_verifies():
    # > _EXACT_MAX_ELEMENTS fix ids on a cyclic random graph: greedy regime
    # with monotone augmentation. Must verify against the model, and never
    # be labelled exact.
    from app.engine.wargame import reachability

    rng = random.Random(2026)
    n = 120
    nodes = {}
    for i in range(n):
        role = NodeRole.ENTRY if i < 8 else (NodeRole.CROWN_JEWEL if i >= n - 5 else NodeRole.INTERMEDIATE)
        nodes[f"n{i:03d}"] = _n(f"n{i:03d}", role, i)
    names = list(nodes)
    edges = [
        Edge(src=a, dst=rng.choice(names), fix_candidate_id=f"f{rng.randint(0, 60):02d}")
        for a in names for _ in range(4)
    ]
    fs = mincut.verified_fix_set(nodes, edges, {}, {})
    assert fs.target_pairs
    assert fs.cuts_all and fs.verified
    assert fs.optimality == "greedy"
    post = reachability.backward_reachability(nodes, mincut.apply_fix_set(edges, fs.selected), {})
    assert not (post.open_pairs & fs.target_pairs)
    again = mincut.verified_fix_set(nodes, edges, {}, {})
    assert again.selected == fs.selected


def test_verified_fix_set_accepts_a_precomputed_result():
    from app.engine.wargame import reachability

    nodes = {"e": _n("e", NodeRole.ENTRY, 1), "m": _n("m", i=2), "j": _n("j", NodeRole.CROWN_JEWEL, 3)}
    edges = [Edge(src="e", dst="m", fix_candidate_id="A"), Edge(src="e", dst="m", fix_candidate_id="B"),
             Edge(src="m", dst="j", fix_candidate_id="X")]
    cands = _priced(["A", "B"], X="device_patch")
    rr = reachability.backward_reachability(nodes, edges, {})
    a = mincut.verified_fix_set(nodes, edges, {}, cands, result=rr)
    b = mincut.verified_fix_set(nodes, edges, {}, cands)
    assert (a.selected, a.cuts_all, a.optimality) == (b.selected, b.cuts_all, b.optimality)
