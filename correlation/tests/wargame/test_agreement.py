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


def test_probe_not_run_is_insufficient():
    r = from_environment(make_env(), "guest", "db", PORT, probe=None)
    assert r.verdict == "insufficient" and not r.agree
    assert "probe" in r.note


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
