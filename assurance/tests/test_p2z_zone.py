"""P2 round 2, finding Z-1 (hostfw-1, zone half): a node whose zone could not be established is a POSSIBLE
member of every zone selector.

Before: ``Node.zone`` was one string and ``Selector.zone`` matched by equality, so an agent node that no declared
label and no independent address placed was selected by NO zone selector, and "guest cannot reach pos" read HOLDS
under a lying host. Now a node may carry ``zone_unknown: true``: it never definitely matches a zone selector, it
possibly matches every one. A path to or from it that would violate if it were in the zone makes the verdict
UNKNOWN (never HOLDS), and VIOLATED stays reserved for what is certain without it.
"""
import itertools
import random

import pytest

from paddock_assurance import GraphError, ReachGraph, Verdict, compile_text, evaluate
from paddock_assurance.graph import matches
from paddock_assurance.model import Selector

from helpers import NOW, edge, fact, graph, node
from hostfix import good_facts, hgraph, hnode, host_plan, sshd


def zu(n, **over):
    """Mark a node document zone-unknown (optionally keeping a claimed zone for display)."""
    n = dict(n)
    n["zone_unknown"] = True
    n.update(over)
    return n


COV = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"
GUEST_POS = """
apiVersion: paddock.dev/invariant/v1
id: acme:guest-cannot-reach-pos
title: guest cannot reach pos
subjects: { from: { zone: guest }, to: { zone: pos } }
assert: unreachable
""" + COV


def P(text=GUEST_POS):
    return compile_text(text)


def run(g, text=GUEST_POS):
    return evaluate(P(text), g, NOW)


def base():
    return [node("g1", "guest"), node("p1", "pos"), node("o1", "office")]


# ---- graph document ---------------------------------------------------------------------------------

def test_zone_unknown_is_validated_strictly():
    for bad in ("true", 1, 0, None, [], {}):
        with pytest.raises(GraphError):
            ReachGraph.from_dict({"version": 1, "nodes": [dict(node("x"), zone_unknown=bad)], "edges": []})
    g = ReachGraph.from_dict({"version": 1, "nodes": [dict(node("x"), zone_unknown=False),
                                                      dict(node("y"), zone_unknown=True)], "edges": []})
    assert g.nodes["x"].zone_unknown is False and g.nodes["y"].zone_unknown is True


def test_a_zone_unknown_node_is_never_a_definite_member_of_a_zone_selector_but_possibly_every_one():
    from paddock_assurance.graph import possibly_matches
    sel = Selector(zone="pos")
    n = ReachGraph.from_dict({"version": 1, "nodes": [zu(node("x", "pos"))], "edges": []}).nodes["x"]
    assert not matches(sel, n), "a claimed zone must not make a node a definite member"
    assert possibly_matches(sel, n)
    assert possibly_matches(Selector(zone="guest"), n)
    assert not possibly_matches(Selector(zone="pos", tag="nope"), n)       # every OTHER field still has to match
    plain = ReachGraph.from_dict({"version": 1, "nodes": [node("y", "pos")], "edges": []}).nodes["y"]
    assert matches(sel, plain) and possibly_matches(sel, plain)
    assert not matches(Selector(zone="guest"), plain) and not possibly_matches(Selector(zone="guest"), plain)


def test_a_selector_without_a_zone_treats_a_zone_unknown_node_like_any_other():
    n = ReachGraph.from_dict({"version": 1, "nodes": [zu(node("x", tags=("agent",)))], "edges": []}).nodes["x"]
    assert matches(Selector(tag="agent"), n)


# ---- reach -------------------------------------------------------------------------------------------

def test_a_node_that_may_be_in_the_target_zone_and_is_reachable_from_guest_is_unknown_not_holds():
    """THE finding: guest reaches X, X could be a pos host. Before: HOLDS (X is in no zone, so no selector sees it)."""
    g = graph(base() + [zu(node("x"))], [edge("g1", "x", "22")])
    r = run(g)
    assert r.verdict is Verdict.UNKNOWN, r.to_dict()
    assert "x" in r.unproven_targets and r.violating_targets == []
    assert any(b.node == "x" and b.reason == "zone_unknown" for b in r.blind_spots)
    assert r.valid_until is None and r.evidence_tier is None


def test_a_node_that_may_be_in_the_source_zone_and_reaches_pos_is_unknown_not_holds():
    g = graph(base() + [zu(node("x"))], [edge("x", "p1", "22")])
    r = run(g)
    assert r.verdict is Verdict.UNKNOWN, r.to_dict()
    assert any(b.node == "x" and b.reason == "zone_unknown" for b in r.blind_spots)
    assert any(w.detail.get("zone_unknown") == "x" for w in r.witnesses)


def test_a_claimed_zone_is_not_certain_so_a_violation_through_it_is_unknown_not_violated():
    g = graph(base() + [zu(node("x", "guest"))], [edge("x", "p1", "22")])
    assert run(g).verdict is Verdict.UNKNOWN


def test_a_certain_violation_stays_violated_and_the_possible_extra_target_is_listed_as_unproven():
    g = graph(base() + [zu(node("x"))], [edge("g1", "p1", "22"), edge("g1", "x", "22")])
    r = run(g)
    assert r.verdict is Verdict.VIOLATED
    assert r.violating_targets == ["p1"] and "x" in r.unproven_targets
    assert any(b.node == "x" and b.reason == "zone_unknown" for b in r.blind_spots)


def test_a_zone_unknown_node_nothing_reaches_or_leaves_does_not_spoil_a_holds():
    g = graph(base() + [zu(node("x"))], [edge("g1", "o1", "22")])
    r = run(g)
    assert r.verdict is Verdict.HOLDS, r.to_dict()


def test_a_path_through_a_zone_unknown_node_is_still_a_certain_violation():
    g = graph(base() + [zu(node("x"))], [edge("g1", "x", "22"), edge("x", "p1", "22")])
    assert run(g).verdict is Verdict.VIOLATED


def test_without_any_zone_unknown_node_the_result_is_exactly_what_it_was():
    g = graph(base(), [edge("g1", "o1", "22")])
    r = run(g)
    assert r.verdict is Verdict.HOLDS and not any(b.reason == "zone_unknown" for b in r.blind_spots)
    assert not any(x.startswith("zone_unknown") for x in r.reasons)


def test_a_boundary_that_may_stop_the_search_does_not_turn_a_possible_path_into_a_certain_one():
    """g1 -> fw -> p1 where fw is only POSSIBLY the application boundary (stop_at zone dmz): not certain."""
    text = GUEST_POS.replace("assert: unreachable", "assert: unreachable\nvia: { stop_at: { zone: dmz } }")
    g = graph(base() + [zu(node("fw"))], [edge("g1", "fw", "443"), edge("fw", "p1", "443")])
    r = run(g, text)
    assert r.verdict is Verdict.UNKNOWN, r.to_dict()


def test_an_exception_for_a_zone_does_not_cover_a_node_that_is_only_possibly_in_it():
    """allow {to: zone pos}: X is possibly in pos, so it is not definitely excused; the violation is only possible."""
    text = GUEST_POS.replace("subjects: { from: { zone: guest }, to: { zone: pos } }",
                             "subjects: { from: { zone: guest }, to: { tag: db } }") + (
        "\nallow:\n  - { to: { zone: pos }, reason: legacy till, expires: 2027-01-01 }")
    g = graph(base() + [zu(node("x", tags=("db",)))], [edge("g1", "x", "22")])
    r = run(g, text)
    assert r.verdict is Verdict.UNKNOWN, r.to_dict()


# ---- exposure and covered ----------------------------------------------------------------------------

def test_exposure_from_the_internet_to_a_node_that_may_be_in_the_zone_is_unknown_not_holds():
    text = """
apiVersion: paddock.dev/invariant/v1
id: acme:only-web-in-prod
title: only web in prod
subjects: { from: { zone: internet }, to: { zone: prod } }
assert: exposes-only
ports: [80, 443]
""" + COV
    web = [node("internet", "internet", kind="internet"), node("p1", "prod")]
    g = graph(web + [zu(node("x"))], [edge("internet", "x", "5432"), edge("internet", "p1", "443")])
    assert run(g, text).verdict is Verdict.UNKNOWN
    g = graph(web + [zu(node("x"))], [edge("internet", "p1", "5432"), edge("internet", "x", "5432")])
    r = run(g, text)
    assert r.verdict is Verdict.VIOLATED and "x" in r.unproven_targets and "x" not in r.violating_targets
    g = graph(web + [zu(node("x"))], [edge("internet", "p1", "443"), edge("internet", "x", "443")])
    assert run(g, text).verdict is Verdict.HOLDS


def test_covered_for_a_zone_a_blind_possible_member_is_unknown_not_holds():
    text = """
apiVersion: paddock.dev/invariant/v1
id: acme:prod-covered
title: prod is covered
subjects: { to: { zone: prod } }
assert: covered
evidence: { min_tier: observed, max_age: 24h }
"""
    g = graph([node("p1", "prod"), zu(node("x", tier=None))], [])
    r = run(g, text)
    assert r.verdict is Verdict.UNKNOWN and "x" in r.unproven_targets
    g = graph([node("p1", "prod"), zu(node("x", tier="observed"))], [])
    assert run(g, text).verdict is Verdict.HOLDS
    g = graph([node("p1", "prod", tier=None), zu(node("x", tier=None))], [])
    r = run(g, text)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["p1"] and "x" in r.unproven_targets


# ---- host-config -------------------------------------------------------------------------------------

def _zone_host_plan(extra_assert="host.sshd.password_login_possible == false"):
    text = f"""
apiVersion: paddock.dev/invariant/v1
id: acme:prod-ssh
title: prod ssh
subjects: {{ to: {{ zone: prod }} }}
assert: {extra_assert}
evidence: {{ min_tier: configured, max_age: 6h }}
coverage: {{ require: 1.0 }}
"""
    return compile_text(text)


def test_host_config_a_possible_member_that_fails_the_rule_makes_the_verdict_unknown_not_holds():
    from helpers import NOW as N
    good = good_facts()
    bad = good_facts(sshd=__import__("hostfix").fact(sshd(passwordauthentication="yes")))
    g = hgraph(hnode("agent:a", good, zone="prod", tags=("agent",)),
               zu(hnode("agent:x", bad, tags=("agent",))))
    r = evaluate(_zone_host_plan(), g, N)
    assert r.verdict is Verdict.UNKNOWN, r.to_dict()
    assert "agent:x" in r.unproven_targets and r.violating_targets == []
    assert any(b.node == "agent:x" and b.reason == "zone_unknown" for b in r.blind_spots)
    # a definite violator still wins, and the possible one stays unproven
    g = hgraph(hnode("agent:a", bad, zone="prod", tags=("agent",)), zu(hnode("agent:x", bad, tags=("agent",))))
    r = evaluate(_zone_host_plan(), g, N)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["agent:a"] and "agent:x" in r.unproven_targets
    # a possible member that passes does not spoil anything
    g = hgraph(hnode("agent:a", good, zone="prod", tags=("agent",)), zu(hnode("agent:x", good, tags=("agent",))))
    assert evaluate(_zone_host_plan(), g, N).verdict is Verdict.HOLDS


def test_host_config_only_possible_members_is_an_empty_selection_not_a_pass():
    g = hgraph(zu(hnode("agent:x", good_facts(), tags=("agent",))))
    r = evaluate(_zone_host_plan(), g, NOW)
    assert r.verdict is Verdict.UNKNOWN and r.reasons[0].startswith("empty_selector")


# ---- property: the verdict is the join over every way the zone-unknown nodes could be placed ---------

ZONES = ("guest", "pos", None)


def _random_case(rng):
    n_def = rng.randint(0, 3)
    n_unk = rng.randint(1, 3)
    nodes = [node("g0", "guest"), node("p0", "pos")]
    for i in range(n_def):
        nodes.append(node(f"d{i}", rng.choice(("guest", "pos", "office", None))))
    unk = [f"u{i}" for i in range(n_unk)]
    ids = [n["id"] for n in nodes] + unk
    edges = []
    for s, d in itertools.permutations(ids, 2):
        if rng.random() < 0.18:
            edges.append(edge(s, d, "22"))
    claimed = {u: rng.choice((None, None, "guest", "pos")) for u in unk}
    return nodes, unk, edges, claimed


@pytest.mark.parametrize("seed", range(160))
def test_property_zone_unknown_is_the_join_over_every_placement(seed):
    rng = random.Random(seed)
    nodes, unk, edges, claimed = _random_case(rng)
    unknown_doc = nodes + [zu(node(u, claimed[u])) for u in unk]
    got = run(graph(unknown_doc, edges)).verdict
    outcomes = set()
    for placement in itertools.product(ZONES, repeat=len(unk)):
        concrete = nodes + [node(u, z) for u, z in zip(unk, placement)]
        outcomes.add(run(graph(concrete, edges)).verdict)
    assert outcomes <= {Verdict.HOLDS, Verdict.VIOLATED}
    if outcomes == {Verdict.HOLDS}:
        want = Verdict.HOLDS
    elif outcomes == {Verdict.VIOLATED}:
        want = Verdict.VIOLATED            # certain: violated however the unknown nodes are placed
    else:
        want = Verdict.UNKNOWN
    assert got is want, (seed, got, outcomes)
    if got is Verdict.HOLDS:
        assert all(o is Verdict.HOLDS for o in outcomes)        # never HOLDS when ANY placement violates


def test_host_config_a_zone_unknown_host_picked_by_tag_is_still_a_definite_member():
    """Only a ZONE selector makes a zone-unknown node a possible member: selected by tag it is judged like any host
    (the std host invariants select tag agent/server, and an unplaced agent must still be VIOLATED when it is)."""
    bad = good_facts(sshd=__import__("hostfix").fact(sshd(passwordauthentication="yes")))
    text = """
apiVersion: paddock.dev/invariant/v1
id: acme:ssh
title: ssh
subjects: { to: { tag: [agent] } }
assert: host.sshd.password_login_possible == false
evidence: { min_tier: configured, max_age: 6h }
coverage: { require: 1.0 }
"""
    g = hgraph(zu(hnode("agent:x", bad, tags=("agent",))))
    r = evaluate(compile_text(text), g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["agent:x"], r.to_dict()


# ---- finding protection at scale (rework): no zone-unknown node may fall out of every protection list ----

@pytest.mark.parametrize("n", [3, 40, 70, 250, 5100])
def test_a_certain_violation_lists_every_zone_unknown_node_so_no_finding_closes_on_it(n):
    nodes = [node("g1", "guest"), node("p1", "pos"), node("p2", "pos")]
    edges = [edge("g1", "p1", "22")]
    for i in range(n):
        nodes.append(zu(node("x%05d" % i)))
        edges.append(edge("g1", "x%05d" % i, "22"))
    r = run(graph(nodes, edges)).to_dict()
    assert r["verdict"] == "VIOLATED"
    assert r["violating_targets"] == ["p1"]
    listed = set(r["unproven_targets"])
    blind = {b["node"] for b in r["blind_spots"] if b["direction"] in ("in", "both", "host")}
    gone = [f"x{i:05d}" for i in range(n) if f"x{i:05d}" not in listed and f"x{i:05d}" not in blind]
    cut = bool(r["violating_truncated"])
    # every zone-unknown node is protected, or the whole list is flagged as cut (then nothing closes)
    assert not gone or cut, f"{len(gone)} zone-unknown nodes are in no protection list and the list is not flagged cut"
    # and when the list is whole it is exact: a closing consumer can trust it
    if not cut:
        assert listed >= {f"x{i:05d}" for i in range(n)}


# ---- Z2-1: a possible run that gave up must not leave a zone-known target unprotected ----

def _hole(n):
    """g1(guest) -> p1(pos) is a certain violation; only the zone-unknown x000 has an edge to the zone-known p2."""
    nodes = [node("g1", "guest"), node("p1", "pos"), node("p2", "pos")] + [zu(node("x%03d" % i)) for i in range(n)]
    return graph(nodes, [edge("g1", "p1", "22"), edge("x000", "p2", "22")])


@pytest.mark.parametrize("n", [3, 64, 65, 70, 250])
def test_z21_a_zone_known_target_reachable_only_from_a_zone_unknown_source_is_never_unprotected(n):
    r = run(_hole(n)).to_dict()
    assert r["verdict"] == "VIOLATED" and r["violating_targets"] == ["p1"]
    # protected = listed as unproven, or the whole list is flagged cut (a closing consumer then closes nothing)
    assert "p2" in r["unproven_targets"] or r["violating_truncated"], \
        f"{n} VIOLATED ... p2 in unproven {'p2' in r['unproven_targets']}, truncated {r['violating_truncated']}"


def test_z21_when_the_possible_run_completes_the_list_stays_exact_and_not_cut():
    r = run(_hole(3)).to_dict()
    assert "p2" in r["unproven_targets"] and not r["violating_truncated"]


def test_z21_exposure_and_covered_never_drop_a_possible_target_when_the_possible_run_cannot_finish():
    # exposure has no overlap cap; the join must stay as exact as before there
    text = """
apiVersion: paddock.dev/invariant/v1
id: acme:only-https-to-pos
title: only https to pos
subjects: { from: { zone: guest }, to: { zone: pos } }
assert: exposes-only
ports: [443]
""" + COV
    nodes = [node("g1", "guest"), node("p1", "pos"), node("p2", "pos")] + [zu(node("x%03d" % i)) for i in range(70)]
    g = graph(nodes, [edge("g1", "p1", "22"), edge("x000", "p2", "22")])
    r = run(g, text).to_dict()
    assert r["verdict"] == "VIOLATED"
    assert "p2" in r["unproven_targets"] or r["violating_truncated"], r
