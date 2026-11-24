"""Regression tests for the independent review of P1/P1.5 (evaluator-1..7, runner-8).

Each test here failed on the code it was written against; the docstring says what the old code did.
"""
from __future__ import annotations

import datetime as dt
import time
import tracemalloc

import pytest

from paddock_assurance import (GraphError, ParseError, ReachGraph, Verdict, compile_text, evaluate,
                               parse_invariant)
from tests.helpers import NOW, FRESH, REACH_YAML, dnode, edge, fact, graph, node

COV = [fact("both")]
OVERLAP_REACH = """
apiVersion: paddock.dev/invariant/v1
id: acme:guest-cannot-reach-pos
title: guest cannot reach pos
subjects: {{ from: {{ zone: guest }}, to: {{ tag: pos }} }}
assert: unreachable
{extra}
evidence: {{ min_tier: observed, max_age: 24h }}
coverage: {{ require: 0 }}
"""
OVERLAP_EXPOSE = """
apiVersion: paddock.dev/invariant/v1
id: acme:guest-only-443
title: guest exposes only 443
subjects: {{ from: {{ zone: guest }}, to: {{ tag: pos }} }}
assert: exposes-only
ports: 443
evidence: {{ min_tier: observed, max_age: 24h }}
coverage: {{ require: 0 }}
"""


def _overlap_nodes():
    return [node("g1", "guest"), node("g2", "guest", tags=("pos",)), node("p1", "pos", tags=("pos",))]


# --------------------------------------------------------------------------------------------
# evaluator-1: S intersect T
# --------------------------------------------------------------------------------------------

def test_overlap_reach_a_pos_device_in_the_guest_zone_is_a_target():
    """Old: T = T - S dropped g2, so g1 -> g2 (observed) gave a confident HOLDS."""
    g = graph(_overlap_nodes(), [edge("g1", "g2", "22")])
    r = evaluate(compile_text(OVERLAP_REACH.format(extra="")), g, NOW)
    assert r.verdict is Verdict.VIOLATED
    assert r.violation_count == 1 and r.violating_targets == ["g2"] and not r.violating_truncated
    assert [(h.src, h.dst) for h in r.witnesses[0].hops] == [("g1", "g2")]


def test_overlap_exposure_a_pos_device_in_the_guest_zone_is_a_target():
    g = graph(_overlap_nodes(), [edge("g1", "g2", "22")])
    r = evaluate(compile_text(OVERLAP_EXPOSE.format()), g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["g2"]


def test_overlap_the_trivial_self_path_is_not_a_violation():
    """A node in both sets reaching only itself (a loop, or through its own neighbour) is no
    counterexample: the path must start at a different source."""
    nodes = [node("x", "guest", tags=("pos",)), node("y", "dmz")]
    g = graph(nodes + [node("z", "guest")], [edge("x", "y"), edge("y", "x"), edge("x", "x", "22")])
    r = evaluate(compile_text(OVERLAP_REACH.format(extra="")), g, NOW)
    assert r.verdict is Verdict.HOLDS and r.violating_targets == []
    e = evaluate(compile_text(OVERLAP_EXPOSE.format()), g, NOW)
    assert e.verdict is Verdict.HOLDS      # the x -> x self edge is the trivial path


def test_overlap_a_source_that_is_itself_a_violator_still_reports_its_own_targets():
    """x is reached from s2 (a violation) and is also a source that reaches y directly. y is not a
    downstream effect of the s2 -> x violation: fixing that edge leaves x -> y, so y stays a root
    cause (the origin of a path is not an 'intermediate violator')."""
    g = graph([node("s2", "guest"), node("x", "guest", tags=("pos",)), node("y", "pos", tags=("pos",))],
              [edge("s2", "x", "22"), edge("x", "y", "22")])
    r = evaluate(compile_text(OVERLAP_REACH.format(extra="")), g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["x", "y"]
    assert [(w.hops[0].src, w.hops[-1].dst) for w in r.witnesses] == [("s2", "x"), ("x", "y")]


def test_overlap_with_no_distinct_source_target_pair_is_unknown_not_holds():
    g = graph([node("x", "guest", tags=("pos",))], [])
    for y in (OVERLAP_REACH.format(extra=""), OVERLAP_EXPOSE.format()):
        r = evaluate(compile_text(y), g, NOW)
        assert r.verdict is Verdict.UNKNOWN and r.reasons[0].startswith("empty_selector")


def test_overlap_a_blind_pair_inside_the_overlap_is_unknown():
    nodes = [dnode("g1", "guest"), dnode("g2", "guest", tags=("pos",))]
    g = graph(nodes, [])
    for y in (OVERLAP_REACH.format(extra=""), OVERLAP_EXPOSE.format()):
        r = evaluate(compile_text(y), g, NOW)
        assert r.verdict is Verdict.UNKNOWN and r.reasons[0] == "possible_via_unknown_edges"


def test_overlap_exempt_target_in_the_overlap_is_honoured():
    g = graph(_overlap_nodes(), [edge("g1", "g2", "22")])
    allow = "allow:\n  - { to: { id: g2 }, reason: lab device, expires: 2026-12-31 }"
    r = evaluate(compile_text(OVERLAP_REACH.format(extra=allow)), g, NOW)
    assert r.verdict is Verdict.HOLDS and r.exceptions_used[0]["target"] == "g2"


def _wide_overlap(n: int) -> ReachGraph:
    return graph([node(f"g{i:03d}", "guest", tags=("pos",)) for i in range(n)] + [node("p", "pos")], [])


def test_reach_overlap_larger_than_64_is_unknown_with_those_nodes_as_blind_spots():
    y = OVERLAP_REACH.format(extra="")
    r = evaluate(compile_text(y), _wide_overlap(65), NOW)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["overlapping_selectors_too_large"]
    spots = {b.node for b in r.blind_spots if b.reason == "overlapping_selectors_too_large"}
    assert spots == {f"g{i:03d}" for i in range(65)}
    assert evaluate(compile_text(y), _wide_overlap(64), NOW).verdict is Verdict.HOLDS   # 64 is evaluated


def test_exposure_overlap_is_never_capped():
    """Exposure is one pass over the edges, so any overlap is evaluated exactly (a ``to``-less
    exposes-only has T = every node, i.e. an overlap as large as ``from``)."""
    y = compile_text(OVERLAP_EXPOSE.format())
    g = _wide_overlap(100)
    assert evaluate(y, g, NOW).verdict is Verdict.HOLDS
    doc = {"version": 1, "nodes": [node(f"g{i:03d}", "guest", tags=("pos",)) for i in range(100)],
           "edges": [edge("g000", "g001", "22")]}
    assert evaluate(y, ReachGraph.from_dict(doc), NOW).verdict is Verdict.VIOLATED


def test_violating_targets_lists_every_target_and_flags_truncation():
    """The pinned fields: sorted node refs of EVERY violating target (cap 5000)."""
    n = 5003
    nodes = [node("s", "a")] + [node(f"t{i:05d}", "b") for i in range(n)]
    g = graph(nodes, [edge("s", f"t{i:05d}", "22") for i in range(n)])
    r = evaluate(compile_text(REACH_YAML.format(extra="coverage: { require: 0 }")), g, NOW)
    d = r.to_dict()
    assert d["violation_count"] == n and len(d["violating_targets"]) == 5000
    assert d["violating_targets"] == sorted(d["violating_targets"]) and d["violating_truncated"] is True
    small = evaluate(compile_text(REACH_YAML.format(extra="coverage: { require: 0 }")),
                     graph([node("s", "a"), node("t1", "b"), node("t0", "b")],
                           [edge("s", "t1", "22"), edge("s", "t0", "22")]), NOW).to_dict()
    assert small["violating_targets"] == ["t0", "t1"] and small["violating_truncated"] is False


def test_violating_targets_for_exposure_covered_and_non_violations():
    ex = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:only-web
title: only web
subjects: { from: { id: internet } }
assert: exposes-only
ports: 443
evidence: { min_tier: observed }
coverage: { require: 0 }
""")
    g = graph([node("internet", "internet"), node("w1"), node("w2"), node("w3")],
              [edge("internet", "w2", "22"), edge("internet", "w1", "21"), edge("internet", "w3", "443")])
    r = evaluate(ex, g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["w1", "w2"]
    cov = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:all-covered
title: all covered
subjects: { to: { kind: host } }
assert: covered
evidence: { min_tier: observed }
""")
    gc = graph([dnode("h2"), dnode("h1"), node("h3")], [])
    rc = evaluate(cov, gc, NOW)
    assert rc.verdict is Verdict.VIOLATED and rc.violating_targets == ["h1", "h2"]
    ok = evaluate(cov, graph([node("h1")], []), NOW).to_dict()
    assert ok["violating_targets"] == [] and ok["violating_truncated"] is False


# --------------------------------------------------------------------------------------------
# evaluator-2: valid_until and exceptions
# --------------------------------------------------------------------------------------------

def _allow(expires: str) -> str:
    return f"allow:\n  - {{ to: {{ id: db }}, reason: migration window, expires: {expires} }}"


_DB_REACH = """
apiVersion: paddock.dev/invariant/v1
id: acme:net-cannot-reach-db
title: net cannot reach db
subjects: {{ from: {{ id: internet }}, to: {{ id: db }} }}
assert: unreachable
evidence: {{ min_tier: observed, max_age: 30d }}
coverage: {{ require: 0 }}
{extra}
"""


def test_holds_resting_on_an_exception_expires_with_the_exception():
    """Old: valid_until came from coverage only, so status_at() said HOLDS long after the
    exception lapsed (and the verdict, re-evaluated, was VIOLATED)."""
    # coverage is fresh for 30 days, the exception ends 2026-12-02
    plan = compile_text(_DB_REACH.format(extra=_allow("2026-12-02")))
    doc = {"version": 1, "nodes": [
        dnode("internet", "internet", fact("both", seen=FRESH)),
        dnode("db", "data", fact("both", seen=FRESH))],
        "edges": [edge("internet", "db", "5432")]}
    r = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until == dt.datetime(2026, 12, 2, 23, 59, 59, tzinfo=dt.timezone.utc)
    assert r.status_at(dt.datetime(2026, 12, 2, 23, 0, tzinfo=dt.timezone.utc)) == "HOLDS"
    assert r.status_at(dt.datetime(2028, 1, 5, tzinfo=dt.timezone.utc)) == "EXPIRED"


def test_holds_with_an_exception_and_no_relied_facts_still_has_a_finite_valid_until():
    plan = compile_text(_DB_REACH.format(extra=_allow("2026-12-02")))
    g = graph([node("internet", "internet", tier=None), node("db", "data", tier=None)],
              [edge("internet", "db", "5432")])
    r = evaluate(plan, g, NOW)
    assert r.verdict is Verdict.HOLDS and r.evidence_tier is None
    assert r.valid_until == dt.datetime(2026, 12, 2, 23, 59, 59, tzinfo=dt.timezone.utc)


def test_exposure_valid_until_is_bounded_by_the_exception():
    plan = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:only-web
title: only web
subjects: { from: { id: internet } }
assert: exposes-only
ports: 443
allow:
  - { to: { id: db }, ports: 5432, reason: migration window, expires: 2026-12-02 }
evidence: { min_tier: observed, max_age: 30d }
coverage: { require: 0 }
""")
    doc = {"version": 1, "nodes": [dnode("internet", "internet", fact("both")), dnode("db", None, fact("both"))],
           "edges": [edge("internet", "db", "5432")]}
    r = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    assert r.verdict is Verdict.HOLDS and r.exceptions_used
    assert r.valid_until == dt.datetime(2026, 12, 2, 23, 59, 59, tzinfo=dt.timezone.utc)


def test_an_exception_expiring_beyond_400_days_is_invalid_and_reported():
    far = (NOW.date() + dt.timedelta(days=401)).isoformat()
    last_ok = (NOW.date() + dt.timedelta(days=400)).isoformat()
    g = graph([node("internet", "internet"), node("db", "data")], [edge("internet", "db", "5432")])
    bad = evaluate(compile_text(_DB_REACH.format(extra=_allow(far))), g, NOW)
    assert bad.verdict is Verdict.VIOLATED and bad.exceptions_used == []
    assert [e["invalid_reason"] for e in bad.expired_exceptions] == ["expiry_too_far"]
    assert bad.expired_exceptions[0]["expires"] == far
    good = evaluate(compile_text(_DB_REACH.format(extra=_allow(last_ok))), g, NOW)
    assert good.verdict is Verdict.HOLDS and good.expired_exceptions == []
    gone = evaluate(compile_text(_DB_REACH.format(extra=_allow("2026-11-01"))), g, NOW)
    assert [e["invalid_reason"] for e in gone.expired_exceptions] == ["expired"]


# --------------------------------------------------------------------------------------------
# evaluator-3 / evaluator-4: resource use
# --------------------------------------------------------------------------------------------

def test_many_violators_are_linear_in_time():
    """Old: ``set(bad)`` was rebuilt per target: 20k targets took 22 s."""
    n = 20000
    nodes = [node("s", "a")] + [node(f"t{i}", "b") for i in range(n)]
    g = graph(nodes, [edge("s", f"t{i}", "22") for i in range(n)])
    plan = compile_text(REACH_YAML.format(extra="coverage: { require: 0 }"))
    t0 = time.perf_counter()
    r = evaluate(plan, g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.violation_count == n
    assert time.perf_counter() - t0 < 4.0


def test_exposure_blind_pairs_are_never_materialised():
    """Old: the full blind S x T list was built (n=1500 allocates ~250 MB)."""
    n = 1500
    g = graph([dnode(f"s{i}", "a") for i in range(n)] + [dnode(f"t{i}", "b") for i in range(n)], [])
    plan = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:expo
title: hosts expose only 443
subjects: { from: { zone: a }, to: { zone: b } }
assert: exposes-only
ports: 443
""")
    tracemalloc.start()
    try:
        r = evaluate(plan, g, NOW)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert r.verdict is Verdict.UNKNOWN and len(r.witnesses) == 5
    assert peak < 40_000_000
    # the witnesses are the first five pairs in sorted order
    assert [(w.hops[0].src, w.hops[0].dst) for w in r.witnesses][0] == ("s0", "t0")


def test_exposure_blind_pairs_skip_covered_targets_without_a_quadratic_scan():
    n = 3000
    nodes = [dnode(f"s{i}", "a") for i in range(n)] + [dnode(f"t{i}", "b", fact("in")) for i in range(n)]
    plan = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:expo
title: hosts expose only 443
subjects: { from: { zone: a }, to: { zone: b } }
assert: exposes-only
ports: 443
evidence: { min_tier: observed }
coverage: { require: 0 }
""")
    t0 = time.perf_counter()
    r = evaluate(plan, graph(nodes, []), NOW)
    assert r.verdict is Verdict.HOLDS
    assert time.perf_counter() - t0 < 2.0


# --------------------------------------------------------------------------------------------
# evaluator-5: YAML abuse
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("opener,closer", [("[", "]"), ("{a: ", "}")])
def test_deeply_nested_flow_collections_are_rejected_cheaply(opener, closer):
    """Old: 20k nested ``[`` spent ~35 s in yaml.parse and ended in an uncaught RecursionError."""
    n = 12000          # 20k ``[`` took ~35 s on the old code; ``{a: `` x 12k still fits under 64 KiB
    text = "a: " + opener * n + closer * n
    t0 = time.perf_counter()
    with pytest.raises(ParseError, match="nested"):
        parse_invariant(text)
    assert time.perf_counter() - t0 < 1.0


def test_unbalanced_open_brackets_are_rejected_too():
    with pytest.raises(ParseError, match="nested"):
        parse_invariant("a: " + "[" * 40)


def test_brackets_in_a_normal_document_are_fine():
    parse_invariant(REACH_YAML.format(extra="").replace(
        "title: A cannot reach B", "title: 'A [prod] cannot reach B'"))


@pytest.mark.parametrize("exc", [RecursionError("deep"), RuntimeError("boom"), MemoryError()])
def test_any_parser_failure_becomes_a_parse_error(monkeypatch, exc):
    import yaml

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(yaml, "safe_load", boom)
    with pytest.raises(ParseError):
        parse_invariant("a: 1")


@pytest.mark.parametrize("text", [
    "- " * 30000,                                     # deeply nested block sequences on one line
    "a:\n" + "".join(" " * i + "a:\n" for i in range(1, 280)),   # deep block mappings
    "? " * 20000,                                     # nested complex keys
])
def test_other_deep_documents_fail_fast_with_parse_error(text):
    t0 = time.perf_counter()
    with pytest.raises(ParseError):
        parse_invariant(text)
    assert time.perf_counter() - t0 < 2.0


# --------------------------------------------------------------------------------------------
# evaluator-6: graph loader strictness
# --------------------------------------------------------------------------------------------

def _cov(**kw):
    return {"direction": "in", "tier": "configured", "observed_at": "2026-12-01T11:00:00Z", **kw}


@pytest.mark.parametrize("key,val", [("proto", 0), ("proto", False), ("proto", []), ("proto", ""),
                                     ("origin", []), ("origin", 0), ("origin", ""), ("origin", None),
                                     ("proto", None), ("origin", {}), ("proto", 7)])
def test_a_present_but_not_nonempty_string_qualifier_is_a_graph_error(key, val):
    """Old: ``c.get(key) or ""`` turned a falsy qualifier into 'unqualified', which speaks for every
    protocol and source: a fact silently claimed more than it knew."""
    with pytest.raises(GraphError):
        ReachGraph.from_dict({"nodes": [{"id": "a", "coverage": [_cov(**{key: val})]}]})


def test_absent_qualifiers_and_valid_ones_still_load():
    g = ReachGraph.from_dict({"nodes": [{"id": "a", "coverage": [
        _cov(), _cov(origin="internet", proto="tcp")]}]})
    assert {(c.origin, c.proto) for c in g.nodes["a"].coverage} == {("", ""), ("internet", "tcp")}
    with pytest.raises(GraphError):      # the P0 single-object form is held to the same rule
        ReachGraph.from_dict({"nodes": [{"id": "a", "coverage": {
            "tier": "observed", "observed_at": "2026-12-01T11:00:00Z", "proto": 0}}]})


@pytest.mark.parametrize("doc", [
    {"nodes": [{"id": "a"}], "edges": [{"src": ["a"], "dst": "a"}]},
    {"nodes": [{"id": "a"}], "edges": [{"src": "a", "dst": {"x": 1}}]},
    {"nodes": [{"id": "a"}], "edges": [{"src": 1, "dst": "a"}]},
    {"nodes": [{"id": "a", "coverage": [_cov(observed_at="0001-01-01T00:00:00+05:00")]}]},
    {"nodes": [{"id": "a", "coverage": [_cov(observed_at="9999-12-31T23:59:59-05:00")]}]},
    {"version": True, "nodes": []},
    {"version": 1.0, "nodes": []},
    {"nodes": [{"id": "a"}], "edges": [{"src": "a", "dst": "a", "basis": ["x"]}]},
    {"nodes": [{"id": "a"}], "edges": [{"src": "a", "dst": "a", "proto": ["tcp"]}]},
    {"nodes": [{"id": "a"}], "edges": [{"src": "a", "dst": "a", "last_seen": 0}]},
    {"nodes": [{"id": "a"}], "now": 0},
    {"nodes": [{"id": "a", "zone": {"x": 1}}]},
    {"nodes": [{"id": "a", "class": ["x"]}]},
    {"nodes": [{"id": "a", "coverage": [_cov(tier=["x"])]}]},
    {"nodes": [{"id": "a", "coverage": [_cov(direction=["in"])]}]},
])
def test_malformed_input_raises_graph_error_never_another_exception(doc):
    with pytest.raises(GraphError):
        ReachGraph.from_dict(doc)


# --------------------------------------------------------------------------------------------
# evaluator-7 / runner-8: identifiers
# --------------------------------------------------------------------------------------------

def test_a_trailing_newline_is_not_a_valid_id_selector_value_or_duration():
    """Old: ``$`` also matches before a final newline, so ``acme:x\\n`` was a second, distinct id."""
    base = REACH_YAML.format(extra="")
    a = compile_text(base.replace("acme:a-cannot-reach-b", "acme:x"))
    assert a.id == "acme:x"
    with pytest.raises(ParseError):
        compile_text(base.replace("id: acme:a-cannot-reach-b", 'id: "acme:x\\n"'))
    with pytest.raises(ParseError):
        compile_text(base.replace("from: { zone: a }", 'from: { zone: "a\\n" }'))
    with pytest.raises(ParseError):
        compile_text(base.replace("assert: unreachable", 'assert: unreachable\nevidence: { max_age: "24h\\n" }'))


@pytest.mark.parametrize("bad", [
    "acme:no-log4shell-cve-2021-44228", "acme:cve-2021-44228", "acme:CVE-2021-44228x".lower(),
    "acme:x-ghsa-abcd-2345-wxyz", "acme:ghsa-2222-3333-4444",
])
def test_ids_with_cve_or_ghsa_tokens_are_rejected_with_a_clear_message(bad):
    """The orchestrator's finding identity extracts CVE/GHSA tokens from rule_id, which collapses
    distinct findings of one invariant into one."""
    with pytest.raises(ParseError, match="CVE|GHSA"):
        compile_text(REACH_YAML.format(extra="").replace("acme:a-cannot-reach-b", bad))


@pytest.mark.parametrize("good", ["acme:cve-ish", "acme:cves-2021", "acme:my-cve", "acme:cve-21-44",
                                  "std:no-internet-to-datastore", "acme:ghsa-x"])
def test_ordinary_ids_are_unaffected(good):
    assert compile_text(REACH_YAML.format(extra="").replace("acme:a-cannot-reach-b", good)).id == good


# --------------------------------------------------------------------------------------------
# verification pass: a VIOLATED verdict must say which OTHER targets are only unproven, because
# the orchestrator closes findings of targets that stopped violating (runner-3)
# --------------------------------------------------------------------------------------------

def _unproven_world():
    """a (blind outbound) may reach v (blind inbound) over an unknown edge, and v -> x is known:
    x is not a known violator but is not provably safe either. a2 -> z is the known violation."""
    from tests.helpers import reach
    nodes = [dnode("a", "a"), dnode("a2", "a", fact("both")), dnode("v", "m", fact("out")),
             dnode("x", "b", fact("both")), dnode("z", "b", fact("both"))]
    return reach(), graph(nodes, [edge("a2", "z"), edge("v", "x")])


def test_violated_names_the_targets_that_are_only_possible_through_unknown_edges():
    """Old: a VIOLATED result only listed the known violators, so a consumer could not tell 'x
    stopped violating' from 'x became unprovable' and closed x's finding as fixed."""
    plan, g = _unproven_world()
    r = evaluate(plan, g, NOW)
    assert r.verdict is Verdict.VIOLATED
    assert r.violating_targets == ["z"]
    assert r.unproven_targets == ["x"]
    assert r.to_dict()["unproven_targets"] == ["x"]


def test_unproven_targets_are_empty_when_nothing_is_blind_and_never_repeat_a_violator():
    from tests.helpers import reach
    g = graph([dnode("a", "a", fact("both")), dnode("z", "b", fact("both")), dnode("x", "b", fact("both"))],
              [edge("a", "z")])
    r = evaluate(reach(), g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.unproven_targets == []
    # a violator that is ALSO reachable over an unknown edge is listed once, as a violator
    plan, g2 = _unproven_world()
    r2 = evaluate(plan, graph([dnode("a", "a"), dnode("v", "m", fact("out")), dnode("z", "b", fact("both"))],
                              [edge("a", "z")]), NOW)
    assert r2.violating_targets == ["z"] and "z" not in r2.unproven_targets
