"""Tests for the twin-range evaluation harness
(``app.engine.wargame.ranges``).

The harness is the credibility keystone (``docs/WARGAME.md`` §3: "a
published false-'closed' rate"; "No false closed"). These tests cover:

* the engine makes ZERO false-"closed" claims on the whole library — the
  one error the product cannot afford;
* the scorer's arithmetic, checked against a tiny hand-built library with a
  deliberately-wrong ground truth so precision / recall / false-closed are
  computable by hand;
* the conditional-only case is reported open/conditional, never closed;
* determinism; and that every library case matches the real engine.

Pure, deterministic, no database.
"""
from __future__ import annotations

from app.engine.wargame import ranges as R
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action,
    Edge,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)

_WEB = PortRange.single(Proto.TCP, 443)


# --------------------------------------------------------------------------
# tiny environments for the scorer tests (independent of the library)
# --------------------------------------------------------------------------

def _allow_env(entry: str, jewel: str) -> Environment:
    env = Environment()
    env.add_node(Node(id=entry, role=NodeRole.ENTRY, cidrs=("203.0.113.0/24",)))
    env.add_node(Node(id=jewel, role=NodeRole.CROWN_JEWEL, cidrs=("10.0.0.0/24",)))
    env.add_ruleset(
        RuleSet(
            id="allow",
            rules=[
                Rule(
                    id="allow.a",
                    action=Action.ALLOW,
                    order=1,
                    src_cidrs=("0.0.0.0/0",),
                    dst_cidrs=("0.0.0.0/0",),
                )
            ],
            default_action=Action.DENY,
        )
    )
    env.add_edge(Edge(src=entry, dst=jewel, rule_set_id="allow", port=_WEB))
    return env


def _deny_env(entry: str, jewel: str) -> Environment:
    env = Environment()
    env.add_node(Node(id=entry, role=NodeRole.ENTRY, cidrs=("203.0.113.0/24",)))
    env.add_node(Node(id=jewel, role=NodeRole.CROWN_JEWEL, cidrs=("10.0.0.0/24",)))
    env.add_ruleset(RuleSet(id="deny", rules=[], default_action=Action.DENY))
    env.add_edge(Edge(src=entry, dst=jewel, rule_set_id="deny", port=_WEB))
    return env


# --------------------------------------------------------------------------
# the headline guarantee
# --------------------------------------------------------------------------

def test_engine_has_zero_false_closed_on_library():
    """The engine must NEVER report a truly-open pair as closed, on ANY
    library case. This is the published headline number; it must be 0.0.
    If this fails, the engine has a correctness bug — investigate it, do
    not weaken the ground truth."""
    report = R.run_library()
    assert report.false_closed_rate == 0.0
    # And, concretely, no case produced a false-closed pair.
    offenders = {r.case_id: r.false_closed for r in report.cases if r.false_closed}
    assert offenders == {}, f"engine claimed closed on truly-open pairs: {offenders}"


# --------------------------------------------------------------------------
# scorer arithmetic, hand-computed, with a KNOWN-wrong "engine"
# --------------------------------------------------------------------------

def test_scorer_math_with_known_wrong_truth():
    """Build three tiny cases whose outcome we can compute by hand, including
    one whose ground truth is set to the OPPOSITE of reality to force a
    false-closed, and check every metric.

    * c_open  : allow env, truth OPEN   -> engine open, correct.
    * c_closed: deny env,  truth CLOSED -> engine closed, correctly closed.
    * c_lie   : deny env,  truth OPEN   -> engine closed but "truly open",
                so it is a false-closed (the engine is honest; the case's
                declared truth is deliberately wrong to drive the metric).

    By hand over the three:
      engine-closed   = {c_closed, c_lie}           -> 2
      correctly closed = {c_closed}                 -> 1
      false-closed     = {c_lie}                    -> 1  -> rate 1/2 = 0.5
      precision        = 1/2 = 0.5
      truly-closed     = {c_closed}                 -> 1  -> recall 1/1 = 1.0
      engine-open      = {c_open}                   -> 1
      false-open       = {}                         -> rate 0.0
    """
    c_open = R.RangeCase(
        id="c_open",
        description="genuinely open",
        environment=_allow_env("e", "j"),
        truly_open_pairs={("e", "j")},
        truly_closed_pairs=set(),
    )
    c_closed = R.RangeCase(
        id="c_closed",
        description="genuinely closed",
        environment=_deny_env("e", "j"),
        truly_open_pairs=set(),
        truly_closed_pairs={("e", "j")},
    )
    c_lie = R.RangeCase(
        id="c_lie",
        description="closed env, but truth DELIBERATELY set open to force a false-closed",
        environment=_deny_env("e", "j"),
        truly_open_pairs={("e", "j")},
        truly_closed_pairs=set(),
    )

    report = R.score([c_open, c_closed, c_lie])

    assert report.total_pairs == 3
    assert report.false_closed_rate == 0.5
    assert report.closure_precision == 0.5
    assert report.closure_recall == 1.0
    assert report.false_open_rate == 0.0

    by_id = {r.case_id: r for r in report.cases}
    assert by_id["c_open"].correct is True
    assert by_id["c_open"].engine_open == {("e", "j")}
    assert by_id["c_closed"].correct is True
    assert by_id["c_closed"].engine_closed == {("e", "j")}
    # The lie case: the engine says closed; the (wrong) truth says open.
    assert by_id["c_lie"].correct is False
    assert by_id["c_lie"].false_closed == {("e", "j")}


def test_scorer_false_open_is_counted():
    """Mirror case: an open env whose truth is deliberately set CLOSED forces
    a false-open (noise, not a safety failure)."""
    c = R.RangeCase(
        id="c_false_open",
        description="open env, truth set closed",
        environment=_allow_env("e", "j"),
        truly_open_pairs=set(),
        truly_closed_pairs={("e", "j")},
    )
    report = R.score([c])
    assert report.false_open_rate == 1.0
    assert report.false_closed_rate == 0.0  # engine reported nothing closed
    assert report.closure_precision == 1.0  # vacuous: no closed claims
    assert report.cases[0].false_open == {("e", "j")}


def test_scorer_empty_denominators_are_safe():
    """No cases -> every rate 0.0 or the vacuous 1.0, never a divide error."""
    report = R.score([])
    assert report.total_pairs == 0
    assert report.false_closed_rate == 0.0
    assert report.false_open_rate == 0.0
    assert report.closure_precision == 1.0
    assert report.closure_recall == 1.0


# --------------------------------------------------------------------------
# the conditional case is open/conditional, never closed
# --------------------------------------------------------------------------

def test_conditional_case_is_open_not_closed():
    cases = {c.id: c for c in R.library()}
    assert "conditional_only" in cases
    case = cases["conditional_only"]

    # Ground truth is declared NOT closed.
    assert case.truly_closed_pairs == set()

    result = case.environment.reachability()
    pair = next(iter(case.truly_open_pairs))
    # The engine finds it open and flags it conditional, not closed.
    assert pair in result.open_pairs
    assert pair in result.conditional_pairs
    assert pair not in result.closed_pairs

    # And the scorer counts it as open (never closed).
    report = R.score([case])
    assert report.cases[0].engine_open == {pair}
    assert report.cases[0].engine_closed == set()
    assert report.cases[0].correct is True


# --------------------------------------------------------------------------
# every library case matches the real engine
# --------------------------------------------------------------------------

def test_every_library_case_is_correct_under_the_engine():
    """Ground truth matches the real engine on every library case (none was
    built to expose a gap). If any case is incorrect, that is an engine
    correctness finding to report, not a truth to fudge."""
    report = R.run_library()
    wrong = {r.case_id: (r.false_closed, r.false_open) for r in report.cases if not r.correct}
    assert wrong == {}, f"library cases disagree with the engine: {wrong}"


def test_library_has_enough_cases_and_the_required_shapes():
    cases = {c.id: c for c in R.library()}
    assert len(cases) >= 8

    # The eight required shapes plus the multi-entry/multi-jewel matrix.
    for required in (
        "single_open",
        "deny_closes",
        "two_hop_open",
        "conditional_only",
        "decoy_deadend",
        "identity_ungoverned_open",
        "broken_middle_hop",
        "planted_misconfig_open",
        "multi_entry_multi_jewel",
    ):
        assert required in cases, f"missing required case {required!r}"

    # At least one case has multiple entries AND multiple jewels.
    def _entries(env):
        return [n for n in env.nodes.values() if n.role is NodeRole.ENTRY]

    def _jewels(env):
        return [n for n in env.nodes.values() if n.role is NodeRole.CROWN_JEWEL]

    multi = [
        c
        for c in cases.values()
        if len(_entries(c.environment)) >= 2 and len(_jewels(c.environment)) >= 2
    ]
    assert multi, "expected a case with multiple entries and multiple jewels"

    # Truth sets are disjoint and non-trivial everywhere.
    for c in cases.values():
        assert not (c.truly_open_pairs & c.truly_closed_pairs), c.id
        assert c.universe, c.id


# --------------------------------------------------------------------------
# determinism
# --------------------------------------------------------------------------

def test_run_library_is_deterministic():
    assert R.run_library() == R.run_library()


def test_summary_is_safe_text_and_mentions_the_headline():
    report = R.run_library()
    # safe_text must not have replaced it with the fallback.
    assert report.summary != "twin-range accuracy report"
    assert "false-closed" in report.summary


# --------------------------------------------------------------------------
# adversarial cases with oracle-computed truth
# --------------------------------------------------------------------------

import pytest

from app.engine.wargame import mincut
from app.engine.wargame.model import FixSet

_ADVERSARIAL = (
    "long_chain_open",
    "dense_budget_starved",
    "parallel_edges_split_fix",
    "sub_cidr_carveout",
)


@pytest.fixture(scope="module")
def library_report():
    return R.run_library()


def test_adversarial_cases_present_and_pass(library_report):
    by_id = {r.case_id: r for r in library_report.cases}
    for cid in _ADVERSARIAL:
        assert cid in by_id, cid
        assert by_id[cid].correct, (cid, by_id[cid].false_closed, by_id[cid].false_cut)
    assert library_report.false_cut_rate == 0.0
    assert "false-cut" in library_report.summary


def test_oracle_agrees_with_hand_truth_on_the_original_cases():
    """The brute-force oracle must reproduce every hand-declared truth, so
    the adversarial truths it computes can be trusted."""
    for case in R.library():
        if case.id in _ADVERSARIAL:
            continue
        truly_open, truly_closed = R.ground_truth(case.environment)
        assert truly_open == case.truly_open_pairs, case.id
        assert truly_closed == case.truly_closed_pairs, case.id


def test_adversarial_truths_are_what_we_built():
    cases = {c.id: c for c in R.library()}
    assert cases["long_chain_open"].truly_open_pairs == {("r10.internet", "r10.db")}
    assert cases["long_chain_open"].truly_closed_pairs == {("r10.internet", "r10.vault")}
    assert cases["dense_budget_starved"].truly_open_pairs == {
        ("r11.internet", "r11.a_vault"), ("r11.internet", "r11.z_vault")
    }
    assert cases["parallel_edges_split_fix"].truly_open_pairs == {("r12.internet", "r12.db")}
    assert cases["sub_cidr_carveout"].truly_open_pairs == {
        ("r13.lan", "r13.db1"), ("r13.lan", "r13.db2")
    }
    assert cases["sub_cidr_carveout"].truly_closed_pairs == {("r13.lan", "r13.db3")}


def test_long_chain_is_open_and_truncated_in_the_engine():
    case = {c.id: c for c in R.library()}["long_chain_open"]
    rr = case.environment.reachability()
    pair = ("r10.internet", "r10.db")
    assert pair in rr.open_pairs and pair in rr.truncated_pairs
    assert pair not in rr.closed_pairs


def test_dense_case_lists_the_starved_jewel_route():
    case = {c.id: c for c in R.library()}["dense_budget_starved"]
    rr = case.environment.reachability()
    assert [r.length for r in rr.routes_for(("r11.internet", "r11.z_vault"))] == [1]


def test_parallel_case_fix_cuts_both_parallel_edges():
    case = {c.id: c for c in R.library()}["parallel_edges_split_fix"]
    env = case.environment
    cands = R._candidates(env)
    for fs in (
        mincut.fix_set_for(env.reachability(), cands),
        mincut.verified_fix_set(env.nodes, env.edges, env.rulesets, cands),
    ):
        assert fs.selected == ["r12.cut_backup", "r12.cut_primary"]
        assert fs.cuts_all is True


def test_ground_truth_brute_forces_sub_cidr_slices():
    env = Environment()
    env.add_node(Node(id="lan", role=NodeRole.ENTRY, cidrs=("10.0.0.0/24",)))
    env.add_node(Node(id="db", role=NodeRole.CROWN_JEWEL, cidrs=("10.9.0.0/30",)))
    env.add_ruleset(RuleSet(id="fw", rules=[
        Rule(id="slice", action=Action.ALLOW, order=1, src_cidrs=("10.0.0.254/32",),
             dst_cidrs=("10.9.0.2/32",), ports=(PortRange(Proto.TCP, 400, 500),)),
    ]))
    env.add_edge(Edge(src="lan", dst="db", rule_set_id="fw", port=_WEB))
    assert R.ground_truth(env) == ({("lan", "db")}, set())
    # port class outside the allowed range → closed
    env.edges[0] = Edge(src="lan", dst="db", rule_set_id="fw", port=PortRange.single(Proto.TCP, 22))
    assert R.ground_truth(env) == (set(), {("lan", "db")})


def test_ground_truth_refuses_ranges_too_large_to_brute_force():
    env = Environment()
    env.add_node(Node(id="big", role=NodeRole.ENTRY, cidrs=("10.0.0.0/16",)))
    env.add_node(Node(id="db", role=NodeRole.CROWN_JEWEL, cidrs=("10.9.0.0/30",)))
    env.add_ruleset(RuleSet(id="fw", rules=[], default_action=Action.DENY))
    env.add_edge(Edge(src="big", dst="db", rule_set_id="fw", port=_WEB))
    with pytest.raises(ValueError):
        R.ground_truth(env)


def test_scorer_flags_a_false_cut(monkeypatch):
    """A fix set that claims cuts_all but leaves the route open (what the
    parallel-edge collapse used to produce) must be counted."""
    case = {c.id: c for c in R.library()}["parallel_edges_split_fix"]

    def bogus(result, candidates):
        return FixSet(selected=["r12.cut_primary"], total_cost=1.0, cuts_all=True)

    monkeypatch.setattr(mincut, "fix_set_for", bogus)
    report = R.score([case])
    assert report.cases[0].false_cut == {("r12.internet", "r12.db")}
    assert report.cases[0].correct is False
    assert report.false_cut_rate == 1.0
    assert report.false_closed_rate == 0.0
