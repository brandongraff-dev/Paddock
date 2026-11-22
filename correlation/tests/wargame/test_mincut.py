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
