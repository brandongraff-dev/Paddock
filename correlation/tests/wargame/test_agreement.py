"""Tests for the three-way boundary agreement report."""
from __future__ import annotations

from app.engine.wargame.agreement import (
    AgreementReport,
    BoundaryEvidence,
    SourceVerdict as V,
    assess_boundary,
    from_environment,
)
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action,
    Edge,
    Flow,
    Node,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)

PORT = PortRange.single(Proto.TCP, 5432)


def make_env(conditional=False, action=Action.DENY):
    env = Environment()
    env.add_node(Node("guest", cidrs=("10.1.0.0/16",)))
    env.add_node(Node("db", cidrs=("10.9.0.0/24",)))
    rules = []
    if conditional:
        rules = [Rule(
            id="r1", action=Action.ALLOW, order=1,
            src_cidrs=("10.1.0.0/16",), dst_cidrs=("10.9.0.0/24",),
            ports=(PORT,), conditional=True,
        )]
    env.add_ruleset(RuleSet(id="fw", rules=rules, default_action=action))
    env.add_edge(Edge("guest", "db", rule_set_id="fw", port=PORT))
    return env


def flow(**kw):
    base = dict(src_ip="10.1.2.3", dst_ip="10.9.0.5", proto=Proto.TCP, dst_port=5432)
    base.update(kw)
    return Flow(**base)


def ev(config=V.CLOSED, probe=V.CLOSED, observed=V.UNKNOWN, conditional=False):
    return BoundaryEvidence("guest", "db", PORT, config, probe, observed, conditional)


def test_pass_all_closed_probe_blocked_no_observation():
    r = from_environment(make_env(), "guest", "db", PORT, probe=False)
    assert isinstance(r, AgreementReport)
    assert r.verdict == "pass" and r.agree and r.disagreements == []


def test_pass_with_observed_closed_value():
    assert assess_boundary(ev(observed=V.CLOSED)).verdict == "pass"


def test_real_observed_flow_over_closed_config_fails_open():
    r = from_environment(
        make_env(), "guest", "db", PORT, probe=False,
        observed_flows=[flow(handshake_completed=True)],
    )
    assert r.verdict == "fail_open" and not r.agree
    assert "observed says open but config says closed" in r.disagreements


def test_conditional_rule_yields_conditional():
    r = from_environment(make_env(conditional=True), "guest", "db", PORT, probe=False)
    assert r.verdict == "conditional" and not r.agree


def test_probe_not_run_is_proved_config_not_pass():
    # Config proves the boundary closed but no probe ran: a distinct,
    # weaker verdict than "pass", and the note never claims a probe agreed.
    r = from_environment(make_env(), "guest", "db", PORT, probe=None)
    assert r.verdict == "proved_config" and not r.agree
    assert "no active probe" in r.note
    assert "probe agree" not in r.note


def test_proved_config_with_real_flow_fails_open():
    r = from_environment(
        make_env(), "guest", "db", PORT, probe=None,
        observed_flows=[flow(handshake_completed=True)],
    )
    assert r.verdict == "fail_open"


def test_probe_blocked_but_config_unknown_is_insufficient():
    assert assess_boundary(ev(config=V.UNKNOWN, probe=V.CLOSED)).verdict == "insufficient"


def test_verdict_vocabulary_matches_store_and_schema():
    from pathlib import Path

    from app.engine.wargame import agreement, store

    assert set(agreement.VERDICTS) == set(store.BOUNDARY_VERDICTS)
    assert agreement.CERTIFIABLE_VERDICTS == {"pass", "proved_config"}
    sql = (Path(__file__).resolve().parents[3] / "schema" / "043_wargame_verdicts.sql").read_text()
    for v in agreement.VERDICTS:
        assert f"'{v}'" in sql


def test_config_unknown_is_insufficient():
    r = assess_boundary(ev(config=V.UNKNOWN))
    assert r.verdict == "insufficient" and "configuration" in r.note


def test_probe_crossed_vs_config_closed_fails_open():
    r = from_environment(make_env(), "guest", "db", PORT, probe=True)
    assert r.verdict == "fail_open"
    assert r.disagreements == ["probe says open but config says closed"]


def test_config_open_alone_fails_open():
    r = assess_boundary(ev(config=V.OPEN, probe=V.UNKNOWN))
    assert r.verdict == "fail_open"
    assert r.disagreements == ["config says open"]


def test_dropped_syn_does_not_make_observed_open():
    r = from_environment(
        make_env(), "guest", "db", PORT, probe=False, observed_flows=[flow()],
    )
    assert r.verdict == "pass"


def test_non_crossing_real_flow_ignored():
    other = flow(dst_ip="192.168.1.1", handshake_completed=True)
    r = from_environment(make_env(), "guest", "db", PORT, probe=False,
                         observed_flows=[other])
    assert r.verdict == "pass"


def test_open_beats_conditional():
    r = assess_boundary(ev(probe=V.OPEN, conditional=True, config=V.UNKNOWN))
    assert r.verdict == "fail_open"


def test_deterministic_disagreement_order():
    e = ev(config=V.CLOSED, probe=V.OPEN, observed=V.OPEN)
    a, b = assess_boundary(e), assess_boundary(e)
    assert a == b
    assert a.disagreements == [
        "probe says open but config says closed",
        "observed says open but config says closed",
    ]


# ---------------------------------------------------------------------------
# Pair-level agreement from the end-to-end search (from_reachability)
# ---------------------------------------------------------------------------

from app.engine.wargame.agreement import from_reachability  # noqa: E402
from app.engine.wargame.model import NodeRole  # noqa: E402


def multi_hop_env(conditional=False):
    """guest -> pos (allowed) -> db (allowed): NO direct guest->db edge."""
    env = Environment()
    env.add_node(Node("guest", NodeRole.ENTRY, ("10.1.0.0/16",)))
    env.add_node(Node("pos", NodeRole.INTERMEDIATE, ("10.5.0.0/24",)))
    env.add_node(Node("db", NodeRole.CROWN_JEWEL, ("10.9.0.0/24",)))
    env.add_ruleset(RuleSet(id="fw-pos", rules=[Rule(
        id="a1", action=Action.ALLOW, order=1, src_cidrs=("10.1.0.0/16",),
        dst_cidrs=("10.5.0.0/24",), ports=(PORT,), conditional=conditional,
    )], default_action=Action.DENY))
    env.add_ruleset(RuleSet(id="fw-db", rules=[Rule(
        id="a2", action=Action.ALLOW, order=1, src_cidrs=("10.5.0.0/24",),
        dst_cidrs=("10.9.0.0/24",), ports=(PORT,),
    )], default_action=Action.DENY))
    env.add_edge(Edge("guest", "pos", rule_set_id="fw-pos", port=PORT))
    env.add_edge(Edge("pos", "db", rule_set_id="fw-db", port=PORT))
    return env


def test_multi_hop_open_pair_is_fail_open_not_closed():
    env = multi_hop_env()
    rr = env.reachability()
    assert ("guest", "db") in rr.open_pairs
    # The direct-edge reading would (wrongly, for a pair) say closed:
    assert from_environment(env, "guest", "db", None).verdict != "fail_open"
    r = from_reachability(rr, "guest", "db", env=env)
    assert r.verdict == "fail_open"
    assert r.disagreements == ["config says open"]


def test_multi_hop_conditional_pair_is_conditional():
    env = multi_hop_env(conditional=True)
    rr = env.reachability()
    assert ("guest", "db") in rr.conditional_pairs
    assert from_reachability(rr, "guest", "db", env=env).verdict == "conditional"


def test_closed_pair_without_probe_is_proved_config_never_pass():
    env = multi_hop_env()
    env.rulesets["fw-db"].rules.clear()  # default deny: no route
    rr = env.reachability()
    assert ("guest", "db") in rr.closed_pairs
    r = from_reachability(rr, "guest", "db", env=env)
    assert r.verdict == "proved_config"
    # Only a REAL probe result upgrades it to pass, or reveals it open.
    assert from_reachability(rr, "guest", "db", env=env, probe=False).verdict == "pass"
    assert from_reachability(rr, "guest", "db", env=env, probe=True).verdict == "fail_open"


def test_closed_pair_with_real_observed_flow_fails_open():
    env = multi_hop_env()
    env.rulesets["fw-db"].rules.clear()
    rr = env.reachability()
    seen = flow(src_ip="10.1.4.4", dst_ip="10.9.0.7", dst_port=22, handshake_completed=True)
    assert from_reachability(rr, "guest", "db", env=env, observed_flows=[seen]).verdict == "fail_open"
    dropped = flow(src_ip="10.1.4.4", dst_ip="10.9.0.7")
    assert from_reachability(rr, "guest", "db", env=env, observed_flows=[dropped]).verdict == "proved_config"


def test_unconsidered_or_truncated_not_open_pair_is_never_closed():
    from app.engine.wargame.model import ReachabilityResult

    rr = ReachabilityResult(routes=[], open_pairs=set(), closed_pairs=set())
    assert from_reachability(rr, "x", "y").verdict == "insufficient"
    rr = ReachabilityResult(routes=[], open_pairs=set(), closed_pairs={("x", "y")})
    rr.truncated_pairs = {("x", "y")}
    r = from_reachability(rr, "x", "y")
    assert r.verdict == "insufficient" and "budget" in r.note
