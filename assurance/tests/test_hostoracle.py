"""Host-config evaluation against an independent brute-force oracle, plus the properties that must
hold whatever the data: order invariance, "a violating host always wins", "unusable is never
HOLDS", time-travel validity and digest stability."""
from __future__ import annotations

import copy
import datetime as dt
import random

import pytest

from paddock_assurance import ReachGraph, Verdict, evaluate
from tests import oracle_host as O
from tests.hostfix import NOW, host_plan_doc

SEEDS = range(1500)


def test_implementation_agrees_with_the_oracle_on_random_fact_tables():
    bad = O.find_mismatch(SEEDS)
    assert not bad, "\n".join(bad[:10])


def test_the_oracle_exercises_every_verdict_and_the_hard_cases():
    """Guard against a generator that never produces the interesting outcomes."""
    seen = {"HOLDS": 0, "VIOLATED": 0, "UNKNOWN": 0}
    lowered_holds_with_unknown = 0
    for seed in range(600):
        r, hosts, tree, min_tier, require = O.scenario(seed)
        v = O.estate_verdict(tree, hosts, NOW, min_tier, O.MAX_AGE, require)
        seen[v["verdict"]] += 1
        if v["verdict"] == "HOLDS" and v["unknown"]:
            lowered_holds_with_unknown += 1
    assert all(n >= 40 for n in seen.values()), seen
    assert lowered_holds_with_unknown >= 3


def _plan_and_graph(seed: int, extra: int = 1):
    r, hosts, tree, min_tier, require = O.scenario(seed)
    plan = host_plan_doc(O.render_doc(tree, r), min_tier=min_tier, require=require)
    return plan, hosts, tree, min_tier, require


def _doc(hosts, extra=1):
    return O.to_graph_doc(hosts, extra_nodes=extra)


@pytest.mark.parametrize("seed", range(0, 600, 3))
def test_order_invariance_of_hosts_and_children(seed):
    r, hosts, tree, min_tier, require = O.scenario(seed)
    doc = O.render_doc(tree, random.Random(1))
    plan_a = host_plan_doc(doc, min_tier=min_tier, require=require)
    plan_b = host_plan_doc(O.render_doc(tree, random.Random(2)), min_tier=min_tier, require=require)
    assert plan_a.digest == plan_b.digest                       # whitespace and sibling order
    gdoc = _doc(hosts)
    shuffled = copy.deepcopy(gdoc)
    random.Random(seed).shuffle(shuffled["nodes"])
    a = evaluate(plan_a, ReachGraph.from_dict(gdoc), NOW).to_dict()
    b = evaluate(plan_b, ReachGraph.from_dict(shuffled), NOW).to_dict()
    assert a == b


def test_a_violating_host_always_beats_unknown_and_passing_hosts():
    checked = 0
    for seed in range(0, 1200, 2):
        plan, hosts, tree, min_tier, require = _plan_and_graph(seed)
        r = random.Random(seed + 10_000)
        donor = None
        for _ in range(60):
            for raw in O.random_hosts(r).values():
                if O.host_truth(tree, raw, NOW, min_tier, O.MAX_AGE) is False:
                    donor = raw
                    break
            if donor:
                break
        if donor is None:
            continue
        hosts = dict(hosts)
        hosts["zzz-violator"] = donor
        res = evaluate(plan, ReachGraph.from_dict(_doc(hosts)), NOW)
        assert res.verdict is Verdict.VIOLATED and "zzz-violator" in res.violating_targets, seed
        checked += 1
    assert checked >= 150, checked


@pytest.mark.parametrize("seed", range(0, 900, 2))
def test_unusable_evidence_is_never_holds_and_never_false(seed):
    """Make every fact of every host unusable in one of the ways; the result must be UNKNOWN and no
    host may be reported as violating or holding."""
    plan, hosts, tree, min_tier, require = _plan_and_graph(seed)
    how = ["signed", "stale", "conflict", "future"][seed % 4]
    broken = copy.deepcopy(hosts)
    for raw in broken.values():
        for f in (raw or {}).values():
            if how == "signed":
                f["signed"] = False
            elif how == "stale":
                f["observed_at"] = O.iso(NOW - dt.timedelta(hours=30))
            elif how == "conflict":
                f["conflict"] = True
            else:
                f["observed_at"] = O.iso(NOW + dt.timedelta(minutes=30))
    res = evaluate(plan, ReachGraph.from_dict(_doc(broken)), NOW)
    assert res.verdict is Verdict.UNKNOWN
    assert res.violating_targets == [] and res.witnesses == []
    assert res.hosts["holds"] == 0 and res.hosts["violated"] == 0
    assert res.evidence_tier is None and res.valid_until is None


@pytest.mark.parametrize("how", ["conf", "partial", "unprobed"])
@pytest.mark.parametrize("seed", range(0, 300, 3))
def test_approximate_partial_or_unprobed_data_never_holds(seed, how):
    """Degrade the collector facts the formula reads; the oracle (not the implementation) says what
    is still decidable, and a HOLDS may never rest on a degraded fact."""
    plan, hosts, tree, min_tier, require = _plan_and_graph(seed)
    broken = copy.deepcopy(hosts)
    for raw in broken.values():
        for name, f in (raw or {}).items():
            if how == "conf" and name in ("sshd", "firewall", "patch"):
                f["conf"] = "approximate"
            elif how == "partial" and name in ("sshd", "firewall", "listeners"):
                f["partial"] = True
            elif how == "unprobed" and name == "sshd":
                f["data"]["match"]["unprobed"] = True
    res = evaluate(plan, ReachGraph.from_dict(_doc(broken)), NOW)
    want = O.estate_verdict(tree, broken, NOW, min_tier, O.MAX_AGE, require)
    assert res.verdict.value == want["verdict"]
    if res.verdict is Verdict.HOLDS:
        assert want["holds"], "a HOLDS needs at least one host the oracle also passes"


def test_holds_is_valid_exactly_until_valid_until():
    """Independent time-travel: re-decide with the ORACLE at valid_until (must still hold) and one
    second later (must not), for strict-floor invariants."""
    checked = 0
    for seed in range(3000):
        plan, hosts, tree, min_tier, require = _plan_and_graph(seed)
        if require != 1.0:
            continue
        res = evaluate(plan, ReachGraph.from_dict(_doc(hosts)), NOW)
        if res.verdict is not Verdict.HOLDS:
            continue
        checked += 1
        at = O.estate_verdict(tree, hosts, res.valid_until, min_tier, O.MAX_AGE, require)
        assert at["verdict"] == "HOLDS", f"seed {seed}: HOLDS lapsed before valid_until"
        for step in (dt.timedelta(minutes=1), dt.timedelta(minutes=37)):
            t = NOW + step
            if t <= res.valid_until:
                got = O.estate_verdict(tree, hosts, t, min_tier, O.MAX_AGE, require)["verdict"]
                assert got == "HOLDS", f"seed {seed}"
        future = any(O.when(f["observed_at"]) > NOW + O.SLACK for raw in hosts.values()
                     for f in (raw or {}).values())
        if not future:      # a future-dated fact that becomes usable later may keep a verdict alive
            after = O.estate_verdict(tree, hosts, res.valid_until + dt.timedelta(seconds=1),
                                     min_tier, O.MAX_AGE, require)
            assert after["verdict"] != "HOLDS", f"seed {seed}: valid_until is later than the evidence lasts"
        assert res.status_at(res.valid_until + dt.timedelta(seconds=1)) == "EXPIRED"
    assert checked >= 60, checked


@pytest.mark.parametrize("seed", range(0, 400, 5))
def test_digest_is_stable_and_sensitive(seed):
    r, hosts, tree, min_tier, require = O.scenario(seed)
    a = host_plan_doc(O.render_doc(tree, random.Random(11)), min_tier=min_tier, require=require)
    b = host_plan_doc(O.render_doc(tree, random.Random(12)), min_tier=min_tier, require=require)
    assert a.digest == b.digest
    # wrapping in `not` always changes it
    wrapped = host_plan_doc({"not": O.render_doc(tree, random.Random(11))}, min_tier=min_tier,
                            require=require)
    assert wrapped.digest != a.digest
    # changing any literal of the first leaf changes it
    other = _bump_first_leaf(tree)
    if other is not None:
        c = host_plan_doc(O.render_doc(other, random.Random(11)), min_tier=min_tier, require=require)
        assert c.digest != a.digest


def _bump_first_leaf(node):
    if node[0] == "leaf":
        _, field, params, op, lit = node
        if isinstance(lit, bool):
            return ("leaf", field, params, op, not lit)
        if isinstance(lit, int):
            return ("leaf", field, params, op, lit + 1)
        if op == "in" and len(lit) < 4:
            extra = [v for v in ("yes", "no", "prohibit-password", "forced-commands-only") if v not in lit]
            return ("leaf", field, params, op, tuple(sorted(lit + (extra[0],)))) if extra else None
        return ("leaf", field, params, "==" if op == "!=" else "!=", lit)
    if node[0] == "not":
        inner = _bump_first_leaf(node[1])
        return None if inner is None else ("not", inner)
    inner = _bump_first_leaf(node[1][0])
    return None if inner is None else (node[0], [inner] + list(node[1][1:]))
