"""Tests for the Environment model and ProposedChange application."""
from __future__ import annotations

import pytest

from app.engine.wargame.environment import (
    ChangeError,
    ChangeKind,
    ChangeOp,
    Environment,
    ProposedChange,
    apply_change,
    remove_rule,
)
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


def _env() -> Environment:
    env = Environment()
    env.add_node(Node("entry", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("jewel", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    env.add_ruleset(RuleSet("fw", [
        Rule("allow", Action.ALLOW, 10, ("10.9.0.0/24",), ("10.1.0.0/24",),
             (PortRange.single(Proto.TCP, 5432),)),
    ], default_action=Action.DENY))
    env.add_edge(Edge("entry", "jewel", rule_set_id="fw",
                      port=PortRange.single(Proto.TCP, 5432),
                      fix_candidate_id="fw:allow"))
    return env


# -- analysis ----------------------------------------------------------------

def test_reachability_open_then_closed():
    env = _env()
    assert ("entry", "jewel") in env.reachability().open_pairs
    d = env.boundary_decision("entry", "jewel")
    assert d.allowed is True


def test_boundary_decision_missing_edge_is_denied():
    env = _env()
    assert env.boundary_decision("jewel", "entry").allowed is False


# -- change application is non-mutating --------------------------------------

def test_apply_change_does_not_mutate_original():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    after = apply_change(env, change)
    # original still open, copy closed
    assert ("entry", "jewel") in env.reachability().open_pairs
    assert ("entry", "jewel") not in after.reachability().open_pairs
    assert len(env.rulesets["fw"].rules) == 1
    assert len(after.rulesets["fw"].rules) == 0


def test_add_rule_opens_a_route():
    env = Environment()
    env.add_node(Node("e", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("j", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    env.add_ruleset(RuleSet("fw", [], default_action=Action.DENY))
    env.add_edge(Edge("e", "j", rule_set_id="fw", port=PortRange.single(Proto.TCP, 22)))
    assert ("e", "j") not in env.reachability().open_pairs

    op = ChangeOp(ChangeKind.ADD_RULE, ruleset_id="fw",
                  rule=Rule("open_ssh", Action.ALLOW, 10,
                            ("10.9.0.0/24",), ("10.1.0.0/24",),
                            (PortRange.single(Proto.TCP, 22),)))
    after = apply_change(env, ProposedChange([op]))
    assert ("e", "j") in after.reachability().open_pairs


def test_add_rule_keeps_order_sorted():
    env = _env()
    op = ChangeOp(ChangeKind.ADD_RULE, ruleset_id="fw",
                  rule=Rule("deny_all", Action.DENY, 1,
                            ("0.0.0.0/0",), ("0.0.0.0/0",), (PortRange.any(),)))
    after = apply_change(env, ProposedChange([op]))
    # lower order first
    assert [r.id for r in after.rulesets["fw"].rules] == ["deny_all", "allow"]
    # the order-1 deny now shadows the allow → closed
    assert ("entry", "jewel") not in after.reachability().open_pairs


# -- edge / ruleset ops ------------------------------------------------------

def test_remove_edge_closes_pair():
    env = _env()
    op = ChangeOp(ChangeKind.REMOVE_EDGE,
                  edge=Edge("entry", "jewel", rule_set_id="fw"))
    after = apply_change(env, ProposedChange([op]))
    assert ("entry", "jewel") not in after.reachability().open_pairs


def test_add_and_remove_ruleset():
    env = _env()
    rs = RuleSet("fw2", [], default_action=Action.DENY)
    after = apply_change(env, ProposedChange([
        ChangeOp(ChangeKind.ADD_RULESET, ruleset=rs)]))
    assert "fw2" in after.rulesets
    after2 = apply_change(after, ProposedChange([
        ChangeOp(ChangeKind.REMOVE_RULESET, ruleset_id="fw2")]))
    assert "fw2" not in after2.rulesets


# -- malformed changes fail loudly -------------------------------------------

def test_rule_on_unknown_ruleset_raises():
    env = _env()
    with pytest.raises(ChangeError):
        apply_change(env, ProposedChange([
            ChangeOp(ChangeKind.ADD_RULE, ruleset_id="nope",
                     rule=Rule("x", Action.ALLOW, 1, ("0.0.0.0/0",),
                               ("0.0.0.0/0",), (PortRange.any(),)))]))


def test_remove_missing_rule_raises():
    env = _env()
    with pytest.raises(ChangeError):
        apply_change(env, ProposedChange([remove_rule("fw", "ghost")]))


def test_remove_missing_edge_raises():
    env = _env()
    with pytest.raises(ChangeError):
        apply_change(env, ProposedChange([
            ChangeOp(ChangeKind.REMOVE_EDGE,
                     edge=Edge("x", "y", rule_set_id="fw"))]))


def test_affected_ruleset_ids():
    change = ProposedChange([
        remove_rule("fw", "allow"),
        ChangeOp(ChangeKind.ADD_EDGE, edge=Edge("a", "b", rule_set_id="fw3")),
    ])
    assert change.affected_ruleset_ids() == {"fw", "fw3"}
