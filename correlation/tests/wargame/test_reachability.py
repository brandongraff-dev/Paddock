"""Tests for the backward reachability search
(``app.engine.wargame.reachability``).

Pure, deterministic, no DB. Covers the classic PCI demo (open route, then a
deny that closes it), ungoverned/INFERRED and base-label edges, conditional
hops flipping a pair conditional, the weakest-label rule over a mixed route,
max_hops and per-pair caps, closed-pair accounting and determinism.
"""
from __future__ import annotations

from app.engine.wargame import reachability as R
from app.engine.wargame.model import (
    Action,
    Edge,
    EvidenceLabel,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _entry(nid, cidr="192.168.50.0/24"):
    return Node(id=nid, role=NodeRole.ENTRY, cidrs=(cidr,))


def _mid(nid, cidr):
    return Node(id=nid, role=NodeRole.INTERMEDIATE, cidrs=(cidr,))


def _jewel(nid, cidr="10.9.0.0/24"):
    return Node(id=nid, role=NodeRole.CROWN_JEWEL, cidrs=(cidr,))


def _allow_any(rid):
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + "_allow",
                action=Action.ALLOW,
                order=1,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
            )
        ],
        default_action=Action.DENY,
    )


def _deny_pair(rid, src, dst):
    """Deny src→dst, allow everything else."""
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + "_deny",
                action=Action.DENY,
                order=1,
                src_cidrs=(src,),
                dst_cidrs=(dst,),
            ),
            Rule(
                id=rid + "_allow",
                action=Action.ALLOW,
                order=50,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
            ),
        ],
        default_action=Action.DENY,
    )


def _cond_allow(rid):
    return RuleSet(
        id=rid,
        rules=[
            Rule(
                id=rid + "_c",
                action=Action.ALLOW,
                order=1,
                src_cidrs=("0.0.0.0/0",),
                dst_cidrs=("0.0.0.0/0",),
                conditional=True,
            )
        ],
        default_action=Action.DENY,
    )


# --------------------------------------------------------------------------
# the classic demo: guest-wifi → fridge → POS → payments DB
# --------------------------------------------------------------------------

def _demo():
    nodes = {
        "guest": _entry("guest", "192.168.50.0/24"),
        "fridge": _mid("fridge", "10.1.0.0/24"),
        "pos": _mid("pos", "10.2.0.0/24"),
        "paydb": _jewel("paydb", "10.9.0.0/24"),
    }
    edges = [
        Edge(src="guest", dst="fridge", rule_set_id="r1", port=PortRange.single(Proto.TCP, 445)),
        Edge(src="fridge", dst="pos", rule_set_id="r2", port=PortRange.single(Proto.TCP, 9100)),
        Edge(src="pos", dst="paydb", rule_set_id="r3", port=PortRange.single(Proto.TCP, 5432)),
    ]
    rulesets = {"r1": _allow_any("r1"), "r2": _allow_any("r2"), "r3": _allow_any("r3")}
    return nodes, edges, rulesets


def test_classic_demo_open_route():
    nodes, edges, rulesets = _demo()
    res = R.backward_reachability(nodes, edges, rulesets)
    assert ("guest", "paydb") in res.open_pairs
    assert res.closed_pairs == set()
    routes = res.routes_for(("guest", "paydb"))
    assert len(routes) == 1
    route = routes[0]
    # oriented forward, entry→jewel
    assert route.entry == "guest"
    assert route.jewel == "paydb"
    assert [h.src for h in route.hops] == ["guest", "fridge", "pos"]
    assert [h.dst for h in route.hops] == ["fridge", "pos", "paydb"]
    assert route.weakest_label is EvidenceLabel.PROVED_CONFIG
    # ports carried through on the hops
    assert route.hops[-1].port == PortRange.single(Proto.TCP, 5432)
    # rule_ref recorded from the solver verdict
    assert route.hops[0].rule_ref == "r1_allow"


def test_classic_demo_deny_closes_the_pair():
    nodes, edges, rulesets = _demo()
    # A deny on the fridge→POS boundary cuts the only route.
    rulesets["r2"] = _deny_pair("r2", "10.1.0.0/24", "10.2.0.0/24")
    res = R.backward_reachability(nodes, edges, rulesets)
    assert ("guest", "paydb") not in res.open_pairs
    assert ("guest", "paydb") in res.closed_pairs
    assert res.routes == []


# --------------------------------------------------------------------------
# ungoverned / inferred / base-label edges
# --------------------------------------------------------------------------

def test_ungoverned_edge_without_base_labels_is_inferred():
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = [Edge(src="e", dst="j", rule_set_id=None)]
    res = R.backward_reachability(nodes, edges, {})
    route = res.routes_for(("e", "j"))[0]
    assert route.hops[0].labels == frozenset({EvidenceLabel.INFERRED})
    assert route.weakest_label is EvidenceLabel.INFERRED


def test_ungoverned_edge_keeps_base_labels_and_skips_inferred():
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = [
        Edge(
            src="e",
            dst="j",
            rule_set_id=None,
            base_labels=frozenset({EvidenceLabel.OBSERVED}),
        )
    ]
    res = R.backward_reachability(nodes, edges, {})
    labels = res.routes_for(("e", "j"))[0].hops[0].labels
    assert labels == frozenset({EvidenceLabel.OBSERVED})
    assert EvidenceLabel.INFERRED not in labels


def test_governed_edge_merges_base_labels_with_proved_config():
    nodes = {"e": _entry("e", "192.168.50.0/24"), "j": _jewel("j", "10.9.0.0/24")}
    edges = [
        Edge(
            src="e",
            dst="j",
            rule_set_id="r",
            base_labels=frozenset({EvidenceLabel.OBSERVED}),
        )
    ]
    res = R.backward_reachability(nodes, edges, {"r": _allow_any("r")})
    labels = res.routes_for(("e", "j"))[0].hops[0].labels
    assert labels == frozenset({EvidenceLabel.OBSERVED, EvidenceLabel.PROVED_CONFIG})


def test_missing_ruleset_makes_edge_untraversable():
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = [Edge(src="e", dst="j", rule_set_id="does_not_exist")]
    res = R.backward_reachability(nodes, edges, {})
    assert res.routes == []
    assert ("e", "j") in res.closed_pairs


def test_edge_with_unknown_endpoint_is_skipped():
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = [Edge(src="e", dst="ghost", rule_set_id=None), Edge(src="ghost", dst="j", rule_set_id=None)]
    res = R.backward_reachability(nodes, edges, {})
    # 'ghost' is not a node, so neither edge is usable.
    assert res.routes == []


# --------------------------------------------------------------------------
# fix candidates
# --------------------------------------------------------------------------

def test_fix_candidate_id_propagates_to_hop_and_route():
    nodes = {"e": _entry("e"), "m": _mid("m", "10.1.0.0/24"), "j": _jewel("j")}
    edges = [
        Edge(src="e", dst="m", rule_set_id=None, fix_candidate_id="cut-em"),
        Edge(src="m", dst="j", rule_set_id=None),
    ]
    res = R.backward_reachability(nodes, edges, {})
    route = res.routes_for(("e", "j"))[0]
    assert route.hops[0].fix_candidate_ids == frozenset({"cut-em"})
    assert route.hops[1].fix_candidate_ids == frozenset()
    assert route.fix_elements == frozenset({"cut-em"})


# --------------------------------------------------------------------------
# conditional hops
# --------------------------------------------------------------------------

def test_conditional_hop_makes_pair_conditional():
    nodes = {"e": _entry("e", "192.168.50.0/24"), "j": _jewel("j", "10.9.0.0/24")}
    edges = [Edge(src="e", dst="j", rule_set_id="c")]
    res = R.backward_reachability(nodes, edges, {"c": _cond_allow("c")})
    assert ("e", "j") in res.open_pairs
    assert ("e", "j") in res.conditional_pairs
    route = res.routes_for(("e", "j"))[0]
    assert EvidenceLabel.CONDITIONAL in route.hops[0].labels
    assert EvidenceLabel.PROVED_CONFIG not in route.hops[0].labels


def test_pair_with_one_clean_route_is_not_conditional():
    # Two parallel paths to the jewel: one fully proved, one conditional.
    # The pair must NOT be flagged conditional (a clean route exists).
    nodes = {
        "e": _entry("e", "192.168.50.0/24"),
        "clean": _mid("clean", "10.1.0.0/24"),
        "cond": _mid("cond", "10.2.0.0/24"),
        "j": _jewel("j", "10.9.0.0/24"),
    }
    edges = [
        Edge(src="e", dst="clean", rule_set_id="ok"),
        Edge(src="clean", dst="j", rule_set_id="ok"),
        Edge(src="e", dst="cond", rule_set_id="c"),
        Edge(src="cond", dst="j", rule_set_id="ok"),
    ]
    res = R.backward_reachability(
        nodes, edges, {"ok": _allow_any("ok"), "c": _cond_allow("c")}
    )
    assert ("e", "j") in res.open_pairs
    assert ("e", "j") not in res.conditional_pairs


# --------------------------------------------------------------------------
# weakest-label over a mixed route
# --------------------------------------------------------------------------

def test_weakest_label_on_mixed_route():
    # proved_config hop + inferred (ungoverned) hop ⇒ route weakest = inferred.
    nodes = {
        "e": _entry("e", "192.168.50.0/24"),
        "m": _mid("m", "10.1.0.0/24"),
        "j": _jewel("j", "10.9.0.0/24"),
    }
    edges = [
        Edge(src="e", dst="m", rule_set_id="ok"),       # proved_config
        Edge(src="m", dst="j", rule_set_id=None),        # inferred
    ]
    res = R.backward_reachability(nodes, edges, {"ok": _allow_any("ok")})
    route = res.routes_for(("e", "j"))[0]
    assert route.hops[0].labels == frozenset({EvidenceLabel.PROVED_CONFIG})
    assert route.hops[1].labels == frozenset({EvidenceLabel.INFERRED})
    assert route.weakest_label is EvidenceLabel.INFERRED


def test_weakest_label_prefers_conditional_over_proved():
    nodes = {
        "e": _entry("e", "192.168.50.0/24"),
        "m": _mid("m", "10.1.0.0/24"),
        "j": _jewel("j", "10.9.0.0/24"),
    }
    edges = [
        Edge(src="e", dst="m", rule_set_id="c"),         # conditional
        Edge(src="m", dst="j", rule_set_id="ok"),        # proved_config
    ]
    res = R.backward_reachability(
        nodes, edges, {"c": _cond_allow("c"), "ok": _allow_any("ok")}
    )
    assert res.routes_for(("e", "j"))[0].weakest_label is EvidenceLabel.CONDITIONAL


# --------------------------------------------------------------------------
# bounds: max_hops and per-pair cap
# --------------------------------------------------------------------------

def test_max_hops_bounds_route_length():
    # chain of 4 hops: e → a → b → c → j
    nodes = {
        "e": _entry("e"),
        "a": _mid("a", "10.1.0.0/24"),
        "b": _mid("b", "10.2.0.0/24"),
        "c": _mid("c", "10.3.0.0/24"),
        "j": _jewel("j"),
    }
    edges = [
        Edge(src="e", dst="a", rule_set_id=None),
        Edge(src="a", dst="b", rule_set_id=None),
        Edge(src="b", dst="c", rule_set_id=None),
        Edge(src="c", dst="j", rule_set_id=None),
    ]
    tight = R.backward_reachability(nodes, edges, {}, max_hops=3)
    assert tight.routes == []
    # max_hops bounds the *listing* only: the pair is still OPEN (decided
    # exactly) and flagged truncated, never closed.
    assert ("e", "j") in tight.open_pairs
    assert ("e", "j") not in tight.closed_pairs
    assert ("e", "j") in tight.truncated_pairs
    assert ("e", "j") in tight.incomplete_pairs
    assert [w.length for w in tight.witness_routes] == [4]

    loose = R.backward_reachability(nodes, edges, {}, max_hops=4)
    assert len(loose.routes_for(("e", "j"))) == 1
    assert loose.routes_for(("e", "j"))[0].length == 4


def test_max_routes_per_pair_cap():
    # e → m0..m5 → j : six independent simple paths for the one pair.
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = []
    for i in range(6):
        mid = f"m{i}"
        nodes[mid] = _mid(mid, f"10.{i}.0.0/24")
        edges.append(Edge(src="e", dst=mid, rule_set_id=None))
        edges.append(Edge(src=mid, dst="j", rule_set_id=None))
    res = R.backward_reachability(nodes, edges, {}, max_routes_per_pair=3)
    routes = res.routes_for(("e", "j"))
    assert len(routes) == 3
    # shortest-first then lexicographic by node sequence → m0, m1, m2 kept.
    kept_mids = sorted(r.hops[0].dst for r in routes)
    assert kept_mids == ["m0", "m1", "m2"]


def test_shortest_routes_first_then_lexicographic():
    # Two routes to the jewel of different lengths from the same entry.
    nodes = {
        "e": _entry("e"),
        "a": _mid("a", "10.1.0.0/24"),
        "b": _mid("b", "10.2.0.0/24"),
        "j": _jewel("j"),
    }
    edges = [
        Edge(src="e", dst="j", rule_set_id=None),        # length 1
        Edge(src="e", dst="a", rule_set_id=None),
        Edge(src="a", dst="b", rule_set_id=None),
        Edge(src="b", dst="j", rule_set_id=None),         # length 3
    ]
    res = R.backward_reachability(nodes, edges, {})
    routes = res.routes_for(("e", "j"))
    assert [r.length for r in routes] == [1, 3]


# --------------------------------------------------------------------------
# multiple entries / jewels and closed-pair accounting
# --------------------------------------------------------------------------

def test_closed_pairs_enumerate_all_combinations():
    nodes = {
        "e1": _entry("e1"),
        "e2": _entry("e2"),
        "j1": _jewel("j1"),
        "j2": _jewel("j2"),
    }
    # only e1 → j1 is adjacent
    edges = [Edge(src="e1", dst="j1", rule_set_id=None)]
    res = R.backward_reachability(nodes, edges, {})
    assert res.open_pairs == {("e1", "j1")}
    assert res.closed_pairs == {("e1", "j2"), ("e2", "j1"), ("e2", "j2")}


def test_cycle_does_not_hang_and_yields_simple_paths():
    # e ↔ a ↔ j with a back-edge a→e; simple-path guard must prevent loops.
    nodes = {"e": _entry("e"), "a": _mid("a", "10.1.0.0/24"), "j": _jewel("j")}
    edges = [
        Edge(src="e", dst="a", rule_set_id=None),
        Edge(src="a", dst="e", rule_set_id=None),   # back edge (cycle)
        Edge(src="a", dst="j", rule_set_id=None),
    ]
    res = R.backward_reachability(nodes, edges, {})
    routes = res.routes_for(("e", "j"))
    assert len(routes) == 1
    assert [h.src for h in routes[0].hops] == ["e", "a"]


# --------------------------------------------------------------------------
# directionality
# --------------------------------------------------------------------------

def test_graph_is_directed_reverse_edge_does_not_open_pair():
    # Only j → e exists; there is no forward route e → j.
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = [Edge(src="j", dst="e", rule_set_id=None)]
    res = R.backward_reachability(nodes, edges, {})
    assert res.open_pairs == set()
    assert ("e", "j") in res.closed_pairs


# --------------------------------------------------------------------------
# determinism
# --------------------------------------------------------------------------

def _signature(res):
    return (
        [
            (r.entry, r.jewel, tuple((h.src, h.dst, tuple(sorted(l.value for l in h.labels))) for h in r.hops))
            for r in res.routes
        ],
        sorted(res.open_pairs),
        sorted(res.closed_pairs),
        sorted(res.conditional_pairs),
    )


def test_determinism_identical_output():
    nodes, edges, rulesets = _demo()
    # add a second entry and a branch to exercise ordering
    nodes["vpn"] = _entry("vpn", "172.16.0.0/24")
    edges.append(Edge(src="vpn", dst="pos", rule_set_id="r2"))
    first = _signature(R.backward_reachability(nodes, edges, rulesets))
    for _ in range(5):
        assert _signature(R.backward_reachability(nodes, edges, rulesets)) == first


# --------------------------------------------------------------------------
# soundness: open/closed is decided exactly, independent of enumeration
# --------------------------------------------------------------------------

def _chain(n_hops, *, prefix="c"):
    """e -> c1 -> ... -> c{n-1} -> j, ungoverned."""
    names = ["e"] + [f"{prefix}{i}" for i in range(1, n_hops)] + ["j"]
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    for i, n in enumerate(names[1:-1], 1):
        nodes[n] = _mid(n, f"10.{i}.0.0/24")
    edges = [Edge(src=a, dst=b, rule_set_id=None) for a, b in zip(names, names[1:])]
    return nodes, edges


def test_nine_plus_hop_route_is_open_not_closed():
    # A 10-hop route is beyond the default listing limit (8): the old engine
    # derived closed = all - enumerated and called this pair CLOSED.
    nodes, edges = _chain(10)
    res = R.backward_reachability(nodes, edges, {})
    assert res.open_pairs == {("e", "j")}
    assert res.closed_pairs == set()
    assert res.routes == []
    assert res.truncated_pairs == {("e", "j")}
    assert res.incomplete_pairs == {("e", "j")}
    assert len(res.witness_routes) == 1
    w = res.witness_routes[0]
    assert (w.entry, w.jewel, w.length) == ("e", "j", 10)
    assert [h.src for h in w.hops][:2] == ["e", "c1"]


def test_hop_limit_marks_pair_incomplete_but_not_truncated():
    # A 1-hop route fits; a parallel 10-hop route does not. Listed, but the
    # listing is not exhaustive.
    nodes, edges = _chain(10)
    edges.append(Edge(src="e", dst="j", rule_set_id=None))
    res = R.backward_reachability(nodes, edges, {})
    assert [r.length for r in res.routes] == [1]
    assert res.truncated_pairs == set()
    assert res.incomplete_pairs == {("e", "j")}


def test_complete_listing_is_not_flagged():
    nodes, edges, rulesets = _demo()
    res = R.backward_reachability(nodes, edges, rulesets)
    assert res.incomplete_pairs == set()
    assert res.truncated_pairs == set()
    assert res.witness_routes == []
    assert res.budget_exhausted is False


def test_per_pair_cap_marks_pair_incomplete():
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    edges = []
    for i in range(6):
        nodes[f"m{i}"] = _mid(f"m{i}", f"10.{i}.0.0/24")
        edges += [Edge(src="e", dst=f"m{i}"), Edge(src=f"m{i}", dst="j")]
    res = R.backward_reachability(nodes, edges, {}, max_routes_per_pair=3)
    assert len(res.routes) == 3
    assert ("e", "j") in res.incomplete_pairs
    full = R.backward_reachability(nodes, edges, {}, max_routes_per_pair=6, max_hops=2)
    assert len(full.routes) == 6
    assert full.incomplete_pairs == set()


def _dense(k=10):
    """A complete k-node mesh feeding jewel 'a_vault'; 'z_vault' (later in
    sorted order) has a single direct route."""
    nodes = {
        "e": _entry("e"),
        "a_vault": _jewel("a_vault", "10.200.0.0/24"),
        "z_vault": _jewel("z_vault", "10.201.0.0/24"),
    }
    edges = [Edge(src="e", dst="z_vault")]
    for i in range(k):
        m = f"m{i}"
        nodes[m] = _mid(m, f"10.{i}.0.0/24")
        edges += [Edge(src="e", dst=m), Edge(src=m, dst="a_vault")]
        edges += [Edge(src=m, dst=f"m{x}") for x in range(k) if x != i]
    return nodes, edges


def test_dense_first_jewel_does_not_starve_later_jewel():
    nodes, edges = _dense()
    res = R.backward_reachability(nodes, edges, {})
    assert res.open_pairs == {("e", "a_vault"), ("e", "z_vault")}
    assert res.closed_pairs == set()
    z = res.routes_for(("e", "z_vault"))
    assert [r.length for r in z] == [1]
    assert ("e", "z_vault") not in res.incomplete_pairs
    # The mesh pair is capped, so its listing is (honestly) incomplete.
    assert len(res.routes_for(("e", "a_vault"))) == 16
    assert ("e", "a_vault") in res.incomplete_pairs


def test_visit_budget_is_per_jewel_and_never_closes_a_pair():
    nodes, edges = _dense(6)
    # A budget far too small for the mesh: open/closed must be unaffected,
    # and the later jewel still gets its own budget for its direct route.
    res = R.backward_reachability(nodes, edges, {}, visit_budget=3)
    assert res.open_pairs == {("e", "a_vault"), ("e", "z_vault")}
    assert res.closed_pairs == set()
    assert res.budget_exhausted is True
    assert ("e", "a_vault") in res.incomplete_pairs
    assert [r.length for r in res.routes_for(("e", "z_vault"))] == [1]
    # Zero budget: nothing can be listed, every open pair is truncated and
    # still open, with a witness each.
    none = R.backward_reachability(nodes, edges, {}, visit_budget=0)
    assert none.routes == []
    assert none.open_pairs == {("e", "a_vault"), ("e", "z_vault")}
    assert none.truncated_pairs == none.open_pairs
    assert {w.pair for w in none.witness_routes} == none.open_pairs


def test_open_closed_matches_independent_bfs_on_random_graphs():
    import random

    rng = random.Random(1234)
    for trial in range(60):
        n = rng.randint(3, 9)
        names = [f"n{i}" for i in range(n)]
        nodes = {}
        for i, nm in enumerate(names):
            role = NodeRole.INTERMEDIATE
            if i < 2:
                role = NodeRole.ENTRY
            elif i >= n - 2:
                role = NodeRole.CROWN_JEWEL
            nodes[nm] = Node(id=nm, role=role, cidrs=(f"10.{i}.0.0/24",))
        rulesets = {"ok": _allow_any("ok"), "no": RuleSet(id="no", rules=[], default_action=Action.DENY)}
        edges, adj = [], {}
        for _ in range(rng.randint(0, n * 3)):
            a, b = rng.sample(names, 2)
            gate = rng.choice([None, "ok", "no"])
            edges.append(Edge(src=a, dst=b, rule_set_id=gate))
            if gate != "no":
                adj.setdefault(a, set()).add(b)
        truth = set()
        for e in (x for x in names if nodes[x].role is NodeRole.ENTRY):
            seen, stack = {e}, [e]
            while stack:
                for nx in adj.get(stack.pop(), ()):
                    if nx not in seen:
                        seen.add(nx)
                        stack.append(nx)
            truth |= {(e, j) for j in names if nodes[j].role is NodeRole.CROWN_JEWEL and j in seen}
        # Tiny limits stress truncation; the verdict must not depend on them.
        for opts in ({}, {"max_hops": 1, "max_routes_per_pair": 1}, {"visit_budget": 2}):
            res = R.backward_reachability(nodes, edges, rulesets, **opts)
            assert res.open_pairs == truth, (trial, opts)
            assert not (res.closed_pairs & truth), (trial, opts)
            assert {r.pair for r in res.routes} | res.truncated_pairs == truth
            for r in res.routes:
                assert r.length <= opts.get("max_hops", 8)


# --------------------------------------------------------------------------
# conditional / inferred are exact (not decided over the truncated listing)
# --------------------------------------------------------------------------

def test_conditional_is_exact_when_clean_route_is_beyond_hop_limit():
    # Short route is conditional; the only clean route is 10 hops long. The
    # old engine looked only at enumerated routes and called it conditional.
    nodes, edges = _chain(10)
    nodes["e"] = _entry("e", "192.168.50.0/24")
    nodes["j"] = _jewel("j", "10.9.0.0/24")
    edges.append(Edge(src="e", dst="j", rule_set_id="c"))
    res = R.backward_reachability(nodes, edges, {"c": _cond_allow("c")})
    assert ("e", "j") in res.open_pairs
    assert [r.length for r in res.routes] == [1]
    assert ("e", "j") not in res.conditional_pairs


def test_conditional_is_exact_when_clean_route_is_beyond_cap():
    nodes = {"e": _entry("e", "192.168.50.0/24"), "j": _jewel("j", "10.9.0.0/24")}
    rulesets = {"c": _cond_allow("c"), "ok": _allow_any("ok")}
    edges = []
    for i in range(4):  # four short conditional routes fill the cap
        m = f"a{i}"
        nodes[m] = _mid(m, f"10.1.{i}.0/24")
        edges += [Edge(src="e", dst=m, rule_set_id="c"), Edge(src=m, dst="j", rule_set_id="ok")]
    nodes["x"], nodes["y"] = _mid("x", "10.2.0.0/24"), _mid("y", "10.3.0.0/24")
    edges += [Edge(src="e", dst="x", rule_set_id="ok"), Edge(src="x", dst="y", rule_set_id="ok"),
              Edge(src="y", dst="j", rule_set_id="ok")]
    res = R.backward_reachability(nodes, edges, rulesets, max_routes_per_pair=4)
    assert all(
        any(EvidenceLabel.CONDITIONAL in h.labels for h in r.hops) for r in res.routes
    )
    assert ("e", "j") not in res.conditional_pairs


def test_parallel_clean_edge_makes_hop_not_conditional():
    nodes = {"e": _entry("e", "192.168.50.0/24"), "j": _jewel("j", "10.9.0.0/24")}
    rulesets = {"c": _cond_allow("c"), "ok": _allow_any("ok")}
    only_cond = R.backward_reachability(nodes, [Edge(src="e", dst="j", rule_set_id="c")], rulesets)
    assert only_cond.conditional_pairs == {("e", "j")}
    both = R.backward_reachability(
        nodes,
        [Edge(src="e", dst="j", rule_set_id="c"), Edge(src="e", dst="j", rule_set_id="ok")],
        rulesets,
    )
    assert both.conditional_pairs == set()


def test_inferred_pairs():
    nodes = {
        "e": _entry("e", "192.168.50.0/24"),
        "e2": _entry("e2", "192.168.60.0/24"),
        "m": _mid("m", "10.1.0.0/24"),
        "j": _jewel("j", "10.9.0.0/24"),
    }
    edges = [
        Edge(src="e", dst="m", rule_set_id="ok"),
        Edge(src="m", dst="j", rule_set_id=None),          # inferred hop
        Edge(src="e2", dst="j", rule_set_id="ok"),          # proved
    ]
    res = R.backward_reachability(nodes, edges, {"ok": _allow_any("ok")})
    assert res.open_pairs == {("e", "j"), ("e2", "j")}
    assert res.inferred_pairs == {("e", "j")}
    # An OBSERVED base label lifts the ungoverned hop out of "inferred".
    edges[1] = Edge(src="m", dst="j", rule_set_id=None,
                    base_labels=frozenset({EvidenceLabel.OBSERVED}))
    res = R.backward_reachability(nodes, edges, {"ok": _allow_any("ok")})
    assert res.inferred_pairs == set()


# --------------------------------------------------------------------------
# parallel edges keep every fix candidate (route variants)
# --------------------------------------------------------------------------

def test_parallel_edges_with_different_fixes_become_route_variants():
    nodes = {"e": _entry("e"), "m": _mid("m", "10.1.0.0/24"), "j": _jewel("j")}
    edges = [
        Edge(src="e", dst="m", fix_candidate_id="A"),
        Edge(src="e", dst="m", fix_candidate_id="B"),
        Edge(src="m", dst="j", fix_candidate_id="X"),
    ]
    res = R.backward_reachability(nodes, edges, {})
    routes = res.routes_for(("e", "j"))
    assert [r.fix_elements for r in routes] == [frozenset({"A", "X"}), frozenset({"B", "X"})]
    assert res.incomplete_pairs == set()


def test_parallel_edges_with_same_fix_collapse_to_one_route():
    nodes = {"e": _entry("e", "192.168.50.0/24"), "j": _jewel("j", "10.9.0.0/24")}
    edges = [
        Edge(src="e", dst="j", rule_set_id=None, fix_candidate_id="A"),
        Edge(src="e", dst="j", rule_set_id="ok", fix_candidate_id="A"),
    ]
    res = R.backward_reachability(nodes, edges, {"ok": _allow_any("ok")})
    assert len(res.routes) == 1
    # strongest edge represents the group (proved_config beats inferred)
    assert res.routes[0].hops[0].labels == frozenset({EvidenceLabel.PROVED_CONFIG})


def test_parallel_uncuttable_edge_yields_variant_without_that_fix():
    nodes = {"e": _entry("e"), "m": _mid("m", "10.1.0.0/24"), "j": _jewel("j")}
    edges = [
        Edge(src="e", dst="m", fix_candidate_id="A"),
        Edge(src="e", dst="m"),                       # no modelled control
        Edge(src="m", dst="j", fix_candidate_id="X"),
    ]
    res = R.backward_reachability(nodes, edges, {})
    assert sorted(sorted(r.fix_elements) for r in res.routes) == [["A", "X"], ["X"]]


def test_route_variants_respect_the_cap_and_flag_incomplete():
    # 4 hops x 3 parallel fix groups = 81 variants of one node path.
    names = ["e", "a", "b", "c", "j"]
    nodes = {"e": _entry("e"), "j": _jewel("j")}
    for i, n in enumerate(names[1:-1], 1):
        nodes[n] = _mid(n, f"10.{i}.0.0/24")
    edges = [
        Edge(src=s, dst=d, fix_candidate_id=f"{s}{d}{k}")
        for s, d in zip(names, names[1:])
        for k in range(3)
    ]
    res = R.backward_reachability(nodes, edges, {}, max_routes_per_pair=5)
    routes = res.routes_for(("e", "j"))
    assert len(routes) == 5
    assert ("e", "j") in res.incomplete_pairs
    # primary variant first; the next ones deviate on exactly one hop
    assert routes[0].fix_elements == frozenset({"ea0", "ab0", "bc0", "cj0"})
    for r in routes[1:]:
        assert len(r.fix_elements - routes[0].fix_elements) == 1
    again = R.backward_reachability(nodes, edges, {}, max_routes_per_pair=5)
    assert _signature(again) == _signature(res)


def test_shortest_route_helper():
    nodes, edges = _chain(10)
    r = R.shortest_route(nodes, edges, {}, "e", "j")
    assert r is not None and r.length == 10 and r.pair == ("e", "j")
    assert R.shortest_route(nodes, edges, {}, "j", "e") is None
