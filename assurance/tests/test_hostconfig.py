"""Host-config evaluation: Kleene logic, aggregation, witnesses, blind spots and evidence."""
from __future__ import annotations

import datetime as dt
import itertools
import json

import pytest

from paddock_assurance import Verdict, evaluate
from paddock_assurance import hostexpr as X
from paddock_assurance import kleene as K
from tests.hostfix import (FRESH, KEY, NOW, STALE, fact, firewall, good_facts, hgraph, hnode,
                           host_plan, host_plan_doc, listeners, sshd)

T, F, U = True, False, None


# --------------------------------------------------------------------------------------------
# Kleene truth tables (hard-coded, not derived from the implementation)

ALL_TABLE = {
    (T, T): T, (T, F): F, (T, U): U,
    (F, T): F, (F, F): F, (F, U): F,
    (U, T): U, (U, F): F, (U, U): U,
}
ANY_TABLE = {
    (T, T): T, (T, F): T, (T, U): T,
    (F, T): T, (F, F): F, (F, U): U,
    (U, T): T, (U, F): U, (U, U): U,
}
NOT_TABLE = {T: F, F: T, U: U}


@pytest.mark.parametrize("pair,out", sorted(ALL_TABLE.items(), key=str))
def test_kleene_all_truth_table(pair, out):
    assert K.k_all(pair) is out


@pytest.mark.parametrize("pair,out", sorted(ANY_TABLE.items(), key=str))
def test_kleene_any_truth_table(pair, out):
    assert K.k_any(pair) is out


@pytest.mark.parametrize("v", [T, F, U])
def test_kleene_not_truth_table(v):
    assert K.k_not(v) is NOT_TABLE[v]


@pytest.mark.parametrize("n", [1, 2, 3, 4])
def test_kleene_nary_matches_the_rule_stated_in_words(n):
    for vals in itertools.product([T, F, U], repeat=n):
        exp_all = F if F in vals else (U if U in vals else T)
        exp_any = T if T in vals else (U if U in vals else F)
        assert K.k_all(vals) is exp_all and K.k_any(vals) is exp_any


def test_kleene_identities():
    assert K.k_all([]) is T and K.k_any([]) is F


# --------------------------------------------------------------------------------------------
# the same tables, end to end through the evaluator (one host, three-valued leaves)

# leaf truth by construction: L(True), L(False), L(None) as a tuple (predicate, facts-mutation)
def _leaf_pred(tv):
    return ('host.sshd.maxauthtries <= 4' if tv is T
            else 'host.sshd.maxauthtries <= 2' if tv is F
            else 'host.sshd.maxauthtries <= 3')       # same field; made unknown through another path


def _one_host_verdict(doc, facts):
    g = hgraph(hnode("h", facts))
    r = evaluate(host_plan_doc(doc), g, NOW)
    return r


def test_end_to_end_all_any_not_over_three_valued_leaves():
    # leaves on three DIFFERENT collectors so each can be made unknown independently
    preds = {T: 'host.fw.engine == "nft"', F: 'host.fw.engine == "legacy"'}

    def build(tv_a, tv_b):
        facts = good_facts()
        pa = 'host.sshd.pubkeyauthentication == "yes"' if tv_a is T else 'host.sshd.pubkeyauthentication == "no"'
        pb = preds[tv_b] if tv_b is not U else 'host.patch.reboot_required == false'
        if tv_a is U:
            facts["sshd"]["signed"] = False
        if tv_b is U:
            facts["patch"]["signed"] = False
        return pa, pb, facts

    for tv_a, tv_b in itertools.product([T, F, U], repeat=2):
        pa, pb, facts = build(tv_a, tv_b)
        got_all = _one_host_verdict({"all": [pa, pb]}, facts)
        got_any = _one_host_verdict({"any": [pa, pb]}, facts)
        want = {T: Verdict.HOLDS, F: Verdict.VIOLATED, U: Verdict.UNKNOWN}
        assert got_all.verdict is want[ALL_TABLE[(tv_a, tv_b)]], (tv_a, tv_b, "all")
        assert got_any.verdict is want[ANY_TABLE[(tv_a, tv_b)]], (tv_a, tv_b, "any")
    for tv in (T, F, U):
        pa, _, facts = build(tv, T)
        got = _one_host_verdict({"not": pa}, facts)
        assert got.verdict is {T: Verdict.HOLDS, F: Verdict.VIOLATED, U: Verdict.UNKNOWN}[NOT_TABLE[tv]]


def test_a_repeated_leaf_is_conservative_a_or_not_a_is_unknown_when_a_is():
    facts = good_facts()
    facts["sshd"]["signed"] = False
    a = 'host.sshd.pubkeyauthentication == "yes"'
    r = _one_host_verdict({"any": [a, {"not": a}]}, facts)
    assert r.verdict is Verdict.UNKNOWN              # never HOLDS from an unusable fact
    r = _one_host_verdict({"all": [a, {"not": a}]}, facts)
    assert r.verdict is Verdict.UNKNOWN
    # with a usable fact it is decided the ordinary way
    assert _one_host_verdict({"any": [a, {"not": a}]}, good_facts()).verdict is Verdict.HOLDS
    assert _one_host_verdict({"all": [a, {"not": a}]}, good_facts()).verdict is Verdict.VIOLATED


# --------------------------------------------------------------------------------------------
# a violating value on an unusable fact is UNKNOWN, never VIOLATED and never HOLDS

BAD_SSH = sshd(passwordauthentication="yes")
PW = "host.sshd.password_login_possible == false"


@pytest.mark.parametrize("label,kw", [
    ("stale", {"seen": STALE}),
    ("unsigned", {"signed": False}),
    ("conflict", {"conflict": True}),
    ("future", {"seen": "2026-12-01T09:30:00Z"}),
    ("declared", {"tier": "declared"}),
])
def test_unusable_violating_fact_is_unknown(label, kw):
    r = _one_host_verdict(PW, good_facts(sshd=fact(BAD_SSH, **kw)))
    assert r.verdict is Verdict.UNKNOWN and r.violation_count == 0 and not r.witnesses
    assert r.reasons == ["hosts_unknown:1"]
    assert r.blind_spots and r.blind_spots[0].direction == "host" and r.blind_spots[0].collector == "sshd"


@pytest.mark.parametrize("label,kw", [
    ("stale", {"seen": STALE}),
    ("unsigned", {"signed": False}),
    ("conflict", {"conflict": True}),
    ("approximate", {"conf": "approximate"}),
    ("partial", {"partial": True}),
    ("error", {"status": "error", "reason": "timeout"}),
    ("unavailable", {"status": "unavailable", "reason": "permission_denied"}),
])
def test_unusable_passing_fact_is_never_holds(label, kw):
    r = _one_host_verdict(PW, good_facts(sshd=fact(sshd(), **kw)))
    assert r.verdict is Verdict.UNKNOWN
    assert r.evidence_tier is None and r.valid_until is None


def test_a_usable_violating_fact_is_violated_a_usable_passing_one_holds():
    assert _one_host_verdict(PW, good_facts(sshd=fact(BAD_SSH))).verdict is Verdict.VIOLATED
    assert _one_host_verdict(PW, good_facts()).verdict is Verdict.HOLDS


# --------------------------------------------------------------------------------------------
# aggregation over hosts

def graph3(**per_host):
    return hgraph(*(hnode(name, facts) for name, facts in per_host.items()))


def run(doc, g, now=NOW, **kw):
    return evaluate(host_plan_doc(doc, **kw), g, now)


def test_all_hosts_pass_holds():
    r = run(PW, graph3(a=good_facts(), b=good_facts()))
    assert r.verdict is Verdict.HOLDS and r.reasons == ["no_counterexample"]
    assert r.hosts == {"selected": 2, "holds": 2, "violated": 0, "unknown": 0}
    assert r.evidence_tier.value == "configured"
    assert r.coverage_universe == 2 and r.coverage_covered == 2 and r.violating_targets == []
    assert r.assertion == "host-config"


def test_a_violating_host_beats_an_unknown_host_and_a_passing_one():
    g = graph3(ok=good_facts(), bad=good_facts(sshd=fact(BAD_SSH)),
               silent=good_facts(sshd=fact(sshd(), seen=STALE)), none=None)
    r = run(PW, g)
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["bad"] and r.violation_count == 1
    assert r.unproven_targets == ["none", "silent"]          # undecided hosts are not "proven safe"
    assert {b.node for b in r.blind_spots} == {"none", "silent"}
    assert r.hosts == {"selected": 4, "holds": 1, "violated": 1, "unknown": 2}
    assert r.evidence_tier is None and r.valid_until is None


def test_an_unknown_host_makes_unknown_at_full_floor():
    r = run(PW, graph3(a=good_facts(), b=good_facts(sshd=fact(sshd(), seen=STALE))))
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["hosts_unknown:1"]
    assert r.unproven_targets == ["b"] and r.violating_targets == []


def test_a_host_without_an_agent_is_no_agent_not_out_of_scope():
    r = run(PW, graph3(a=good_facts(), declared=None))
    assert r.verdict is Verdict.UNKNOWN
    (b,) = r.blind_spots
    assert (b.node, b.reason, b.direction, b.collector, b.relevant) == ("declared", "no_agent", "host", None, True)


def test_a_host_with_no_facts_for_the_collector_is_no_sensor():
    r = run(PW, graph3(a=good_facts(), b={"firewall": good_facts()["firewall"]}))
    (b,) = r.blind_spots
    assert (b.node, b.reason, b.collector) == ("b", "no_sensor", "sshd")


def test_empty_selector_is_unknown_never_holds():
    g = hgraph(hnode("a", good_facts(), tags=("web",)))
    r = run(PW, g)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["empty_selector:to"]
    assert r.blind_spots == [] and r.violation_count == 0
    assert evaluate(host_plan_doc(PW), hgraph(), NOW).verdict is Verdict.UNKNOWN


def test_lower_floor_lets_holds_stand_with_unknown_hosts_listed():
    hosts = {f"h{i}": good_facts() for i in range(9)}
    hosts["slow"] = good_facts(sshd=fact(sshd(), seen=STALE))
    g = graph3(**hosts)
    assert run(PW, g, require=1.0).verdict is Verdict.UNKNOWN
    assert run(PW, g, require=0.95).verdict is Verdict.UNKNOWN        # 9/10 < 0.95
    r = run(PW, g, require=0.9)
    assert r.verdict is Verdict.HOLDS and r.reasons == ["no_counterexample", "hosts_unknown:1"]
    assert [b.node for b in r.blind_spots] == ["slow"] and r.unproven_targets == ["slow"]
    assert r.hosts["holds"] == 9 and r.hosts["unknown"] == 1
    # a violating host still wins at any floor
    hosts["bad"] = good_facts(sshd=fact(BAD_SSH))
    assert run(PW, graph3(**hosts), require=0.0).verdict is Verdict.VIOLATED


def test_a_floor_of_zero_never_turns_nothing_into_holds():
    g = graph3(a=good_facts(sshd=fact(sshd(), seen=STALE)), b=None)
    assert run(PW, g, require=0.0).verdict is Verdict.UNKNOWN


def test_selection_uses_subjects_to_and_ignores_other_nodes():
    g = hgraph(hnode("srv", good_facts()), hnode("laptop", good_facts(sshd=fact(BAD_SSH)), tags=("laptop",)))
    r = run(PW, g)
    assert r.verdict is Verdict.HOLDS and r.hosts["selected"] == 1


def test_node_order_does_not_change_the_result():
    nodes = [hnode("a", good_facts()), hnode("b", good_facts(sshd=fact(BAD_SSH))),
             hnode("c", None), hnode("d", good_facts(sshd=fact(sshd(), seen=STALE)))]
    base = run(PW, hgraph(*nodes)).to_dict()
    for perm in itertools.permutations(nodes):
        assert run(PW, hgraph(*perm)).to_dict() == base


def test_child_order_does_not_change_the_result():
    kids = ["host.sshd.maxauthtries <= 4", 'host.sshd.pubkeyauthentication == "yes"',
            "host.fw.engine == \"legacy\"", "host.patch.reboot_required == false"]
    g = graph3(a=good_facts(), b=good_facts(firewall=fact(firewall(), signed=False)))
    base = run({"all": kids}, g).to_dict()
    for perm in itertools.permutations(kids):
        assert run({"all": list(perm)}, g).to_dict() == base


# --------------------------------------------------------------------------------------------
# witnesses

WITNESS_KEYS = ["node", "field", "clause", "predicate", "op", "expected", "observed", "tier",
                "observed_at", "source", "signed", "key_id", "seq", "evidence_ref"]


def test_witness_shape_is_fixed_and_all_strings():
    r = run("host.sshd.maxauthtries <= 2", graph3(h=good_facts()))
    (w,) = r.witnesses
    assert w.hops == () and w.confirmed is False and w.weakest_basis == "configured"
    assert list(w.detail) == WITNESS_KEYS and all(isinstance(v, str) for v in w.detail.values())
    assert w.detail == {
        "node": "h", "field": "host.sshd.maxauthtries", "clause": "0",
        "predicate": "host.sshd.maxauthtries <= 2", "op": "<=", "expected": "2", "observed": "3",
        "tier": "configured", "observed_at": FRESH, "source": "agent", "signed": "true",
        "key_id": KEY, "seq": "7", "evidence_ref": "posture:7"}
    d = json.loads(json.dumps(r.to_dict()))
    assert d["witnesses"][0]["detail"] == w.detail and d["witnesses"][0]["hops"] == []
    assert d["assertion"] == "host-config" and d["violating_targets"] == ["h"]
    assert d["hosts"] == {"selected": 1, "holds": 0, "violated": 1, "unknown": 0}


def test_witness_for_parameterised_set_and_count_leaves():
    g = graph3(h=good_facts(listeners=fact(listeners(ports=(22, 443)))))
    r = run("host.listener(22).process subset_of [\"nginx\"]", g)
    (w,) = r.witnesses
    assert (w.detail["field"], w.detail["op"], w.detail["expected"], w.detail["observed"]) == (
        "host.listener(22).process", "subset_of", "nginx", "sshd")
    r = run("count(host.listeners.addresses) == 0", g)
    assert r.witnesses[0].detail["op"] == "count==" and r.witnesses[0].detail["observed"] == "1"


def test_witnesses_point_at_the_failing_clauses_only_and_use_canonical_clause_paths():
    doc = {"all": ["host.sshd.maxauthtries <= 4", "host.sshd.maxauthtries <= 1",
                   'host.sshd.pubkeyauthentication == "no"']}
    r = run(doc, graph3(h=good_facts()))
    tree = X.parse_assertion(doc)
    got = [(w.detail["clause"], w.detail["predicate"]) for w in r.witnesses]
    want = [(f"0.{i}", X.leaf_text(c)) for i, c in enumerate(tree.children)
            if c.field == "host.sshd.pubkeyauthentication" or c.value == 1]
    assert got == want and len(got) == 2


def test_witness_inside_not_says_so():
    r = run({"not": 'host.sshd.pubkeyauthentication == "yes"'}, graph3(h=good_facts()))
    (w,) = r.witnesses
    assert w.detail["predicate"] == 'not(host.sshd.pubkeyauthentication == "yes")'
    assert w.detail["clause"] == "0.0" and w.detail["observed"] == "yes"


def test_false_any_lists_every_branch_a_true_any_would_not_witness():
    doc = {"any": ["host.sshd.maxauthtries <= 1", "host.sshd.maxauthtries <= 2"]}
    r = run(doc, graph3(h=good_facts()))
    assert len(r.witnesses) == 2
    ok = run({"any": ["host.sshd.maxauthtries <= 1", "host.sshd.maxauthtries <= 9"]}, graph3(h=good_facts()))
    assert ok.verdict is Verdict.HOLDS and ok.witnesses == []


def test_witness_caps_three_per_host_fifty_total_and_every_host_gets_one():
    kids = [f"host.sshd.maxauthtries <= {i}" for i in range(6)]          # 0..2 fail (3 passes? 3<=3)
    g = graph3(h=good_facts())
    r = run({"all": kids}, g)
    assert len(r.witnesses) == 3 and r.violation_count == 1
    hosts = {f"h{i:03d}": good_facts() for i in range(80)}
    r = run("host.sshd.maxauthtries <= 1", graph3(**hosts))
    assert r.violation_count == 80 and len(r.violating_targets) == 80
    assert len(r.witnesses) == 50
    assert [w.detail["node"] for w in r.witnesses] == sorted(h for h in hosts)[:50]
    r = run({"all": kids}, graph3(**hosts))
    firsts = [w for w in r.witnesses]
    assert len(firsts) == 50 and len({w.detail["node"] for w in firsts}) == 50     # fairness


def test_witness_tier_is_the_effective_tier_of_the_fact():
    g = graph3(h=good_facts(sshd=fact(sshd(), tier="observed")))      # claimed observed, capped
    r = run("host.sshd.maxauthtries <= 2", g)
    assert r.witnesses[0].detail["tier"] == "configured"
    assert r.witnesses[0].weakest_basis == "configured"


# --------------------------------------------------------------------------------------------
# blind spots

def test_blind_spot_reason_is_the_most_fundamental_one_per_collector():
    f = good_facts(sshd=fact(sshd(), signed=False, seen=STALE))
    r = run(PW, graph3(h=f))
    (b,) = r.blind_spots
    assert (b.reason, b.collector) == ("unsigned", "sshd")           # unsigned outranks stale


def test_blind_spot_rows_per_collector_and_to_dict_is_additive():
    f = good_facts(sshd=fact(sshd(), seen=STALE), firewall=fact(firewall(), signed=False))
    doc = {"all": [PW, 'host.fw.default_inbound_all_families == "deny"']}
    r = run(doc, graph3(h=f))
    assert [(b.node, b.collector, b.reason) for b in r.blind_spots] == [
        ("h", "firewall", "unsigned"), ("h", "sshd", "stale")]
    d = r.to_dict()
    assert d["blind_spots"][0] == {"node": "h", "reason": "unsigned", "relevant": True,
                                   "direction": "host", "collector": "firewall"}
    # P1 blind spots keep exactly their old keys
    from paddock_assurance.evaluate import BlindSpot
    assert BlindSpot("n", "stale", True, "in").to_dict() == {
        "node": "n", "reason": "stale", "relevant": True, "direction": "in"}


def test_no_agent_host_gets_one_row_without_collector():
    r = run({"all": [PW, 'host.fw.engine == "nft"']}, graph3(h=None))
    assert [(b.reason, b.collector) for b in r.blind_spots] == [("no_agent", None)]


# --------------------------------------------------------------------------------------------
# evidence tier and validity

def test_holds_tier_is_the_weakest_relied_and_valid_until_the_earliest_expiry():
    f = good_facts(sshd=fact(sshd(), seen="2026-12-01T08:00:00Z"),
                   firewall=fact(firewall(), seen="2026-12-01T08:45:00Z", tier="declared"))
    doc = {"all": [PW, 'host.fw.default_inbound_all_families == "deny"']}
    r = run(doc, graph3(h=f), min_tier="declared")
    assert r.verdict is Verdict.HOLDS and r.evidence_tier.value == "declared"
    assert r.valid_until == dt.datetime(2026, 12, 1, 14, 0, tzinfo=dt.timezone.utc)     # 08:00 + 6h
    assert r.status_at(NOW) == "HOLDS"
    assert r.status_at(r.valid_until) == "HOLDS"
    assert r.status_at(r.valid_until + dt.timedelta(seconds=1)) == "EXPIRED"


def test_valid_until_is_the_earliest_across_hosts():
    g = graph3(a=good_facts(sshd=fact(sshd(), seen="2026-12-01T08:00:00Z")),
               b=good_facts(sshd=fact(sshd(), seen="2026-12-01T07:00:00Z")))
    assert run(PW, g).valid_until == dt.datetime(2026, 12, 1, 13, 0, tzinfo=dt.timezone.utc)


def test_any_relies_on_one_true_branch_the_one_that_lasts_longest():
    f = good_facts(sshd=fact(sshd(), seen="2026-12-01T06:00:00Z"),
                   firewall=fact(firewall(), seen="2026-12-01T08:30:00Z"))
    doc = {"any": [PW, 'host.fw.default_inbound_all_families == "deny"']}
    r = run(doc, graph3(h=f))
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until == dt.datetime(2026, 12, 1, 14, 30, tzinfo=dt.timezone.utc)   # via the firewall
    # the stale sshd branch is not needed: the host stays HOLDS while the firewall fact is fresh
    later = NOW + dt.timedelta(hours=5)
    assert evaluate(host_plan_doc(doc), graph3(h=f), later).verdict is Verdict.HOLDS
    assert evaluate(host_plan_doc(doc), graph3(h=f), r.valid_until + dt.timedelta(seconds=1)).verdict \
        is Verdict.UNKNOWN


def test_a_future_dated_unknown_host_caps_the_validity_of_a_lowered_floor_holds():
    hosts = {f"h{i}": good_facts() for i in range(9)}
    hosts["future"] = good_facts(sshd=fact(sshd(), seen="2026-12-01T10:00:00Z"))
    r = run(PW, graph3(**hosts), require=0.9)
    assert r.verdict is Verdict.HOLDS
    # the future host becomes usable (and may then fail) five minutes before its timestamp
    assert r.valid_until == dt.datetime(2026, 12, 1, 9, 55, tzinfo=dt.timezone.utc)


def test_holds_stays_true_until_valid_until_and_not_after():
    g = graph3(a=good_facts(), b=good_facts(sshd=fact(sshd(), seen="2026-12-01T07:15:00Z")))
    plan = host_plan_doc({"all": [PW, "host.sshd.maxauthtries <= 4"]})
    r = evaluate(plan, g, NOW)
    assert r.verdict is Verdict.HOLDS
    step = dt.timedelta(minutes=7)
    t = NOW
    while t <= r.valid_until:
        assert evaluate(plan, g, t).verdict is Verdict.HOLDS, t
        t += step
    assert evaluate(plan, g, r.valid_until).verdict is Verdict.HOLDS
    assert evaluate(plan, g, r.valid_until + dt.timedelta(seconds=1)).verdict is Verdict.UNKNOWN


def test_naive_now_is_refused():
    with pytest.raises(ValueError):
        evaluate(host_plan_doc(PW), graph3(a=good_facts()), dt.datetime(2026, 12, 1))


def test_p1_results_are_unchanged_in_shape():
    """Additive only: no ``hosts`` key and no ``collector`` key on non-host results."""
    from tests.helpers import dnode, edge, fact as cfact, graph, reach
    g = graph([dnode("a", "a", cfact("both")), dnode("b", "b")], [edge("a", "b")])
    d = evaluate(reach(), g, NOW).to_dict()
    assert "hosts" not in d and all("collector" not in b for b in d["blind_spots"])
    assert set(d) == {"invariant", "digest", "severity", "assertion", "verdict", "reasons",
                      "evaluated_at", "valid_until", "evidence_tier", "coverage",
                      "violation_count", "violating_targets", "violating_truncated",
                      "unproven_targets", "witnesses", "blind_spots", "exceptions_used",
                      "expired_exceptions", "confirmation", "boundaries_reached"}


def test_yaml_form_and_mapping_form_evaluate_the_same():
    y = host_plan("""
  all:
    - host.sshd.maxauthtries <= 4
    - host.sshd.pubkeyauthentication == "yes"
""".replace("\n  all", "\n  all"))
    d = host_plan_doc({"all": ["host.sshd.maxauthtries <= 4", 'host.sshd.pubkeyauthentication == "yes"']})
    assert y.digest == d.digest


def test_observed_values_in_witnesses_are_printable_and_capped():
    nasty = "evil\x1b[31m\nname‮" + "x" * 400
    d = listeners(ports=(22,), comms={22: nasty})
    g = graph3(h=good_facts(listeners=fact(d)))
    r = run("host.listener(22).process subset_of [\"sshd\"]", g)
    (w,) = r.witnesses
    obs = w.detail["observed"]
    assert "\x1b" not in obs and "\n" not in obs and "‮" not in obs
    # restricted alphabet [A-Za-z0-9._:/@,-]: everything else is "?" (hostcfg-7), capped at 120
    assert len(obs) <= 120 and obs.startswith("evil??31m?name?")
