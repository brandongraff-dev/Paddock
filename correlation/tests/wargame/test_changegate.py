"""Tests for the change-impact proof (``changegate``).

Builds a small modelled environment — an entry segment (10.9.0.0/24)
reaching a crown-jewel DB segment (10.1.0.0/24) across a firewall rule set
"fw" that allows tcp/5432 — and checks that a proposed change's before/after
impact is computed correctly: the crown-jewel routes it opens or closes, the
observed live flows it would break, the boundaries it touches, and the
verdict. Nothing here touches a real network.
"""
from __future__ import annotations

from app.engine.wargame import safety
from app.engine.wargame.changegate import (
    ChangeImpact,
    FlowImpact,
    RouteDelta,
    evaluate_change,
    impact_table,
)
from app.engine.wargame.environment import (
    ChangeKind,
    ChangeOp,
    Environment,
    ProposedChange,
    remove_rule,
)
from app.engine.wargame.model import (
    Action,
    Edge,
    Flow,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)

PAIR = ("entry", "jewel")


def _allow_5432() -> Rule:
    return Rule(
        "allow", Action.ALLOW, 10,
        ("10.9.0.0/24",), ("10.1.0.0/24",),
        (PortRange.single(Proto.TCP, 5432),),
    )


def _env() -> Environment:
    """Entry -> jewel across "fw", which allows tcp/5432 only."""
    env = Environment()
    env.add_node(Node("entry", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("jewel", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    env.add_ruleset(RuleSet("fw", [_allow_5432()], default_action=Action.DENY))
    env.add_edge(Edge("entry", "jewel", rule_set_id="fw",
                      port=PortRange.single(Proto.TCP, 5432),
                      fix_candidate_id="fw:allow"))
    return env


def _pos_flow() -> Flow:
    """A legitimate POS -> payment DB flow that the allow rule permits."""
    return Flow("10.9.0.5", "10.1.0.9", Proto.TCP, 5432,
                handshake_completed=True, dst_side_observed=True)


# ---------------------------------------------------------------------------
# Removing the allow: closes the route AND breaks the live POS flow
# ---------------------------------------------------------------------------

def test_remove_allow_closes_route_and_breaks_flow():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    impact = evaluate_change(env, change, flows=[_pos_flow()])

    # the crown-jewel route is closed
    assert [d.pair for d in impact.routes_closed] == [PAIR]
    assert impact.routes_closed[0].status == "closed"
    assert impact.routes_closed[0].example_route is not None
    assert not impact.routes_opened

    # the legitimate POS -> DB flow is newly denied (what the change breaks)
    assert len(impact.newly_denied_flows) == 1
    broken = impact.newly_denied_flows[0]
    assert isinstance(broken, FlowImpact)
    assert broken.status == "newly_denied"
    assert broken.ruleset_id == "fw"
    assert broken.flow.src_ip == "10.9.0.5"
    assert broken.flow.dst_ip == "10.1.0.9"
    assert not impact.newly_allowed_flows

    assert impact.affected_boundaries == ["fw"]
    assert impact.verdict == "breaks_live_flows"


# ---------------------------------------------------------------------------
# Adding an allow on a new port opens a route to a crown jewel
# ---------------------------------------------------------------------------

def test_add_allow_opens_route():
    # Start with a closed second boundary to a new jewel segment.
    env = _env()
    env.add_node(Node("jewel2", NodeRole.CROWN_JEWEL, ("10.2.0.0/24",)))
    env.add_ruleset(RuleSet("fw2", [], default_action=Action.DENY))
    env.add_edge(Edge("entry", "jewel2", rule_set_id="fw2",
                      port=PortRange.single(Proto.TCP, 22)))

    assert ("entry", "jewel2") not in env.reachability().open_pairs

    op = ChangeOp(ChangeKind.ADD_RULE, ruleset_id="fw2",
                  rule=Rule("open_ssh", Action.ALLOW, 10,
                            ("10.9.0.0/24",), ("10.2.0.0/24",),
                            (PortRange.single(Proto.TCP, 22),)))
    impact = evaluate_change(env, ProposedChange([op], title="open ssh to jewel2"))

    assert [d.pair for d in impact.routes_opened] == [("entry", "jewel2")]
    assert impact.routes_opened[0].status == "opened"
    assert impact.routes_opened[0].example_route is not None
    assert not impact.routes_closed
    assert impact.verdict == "opens_route_to_crown_jewel"


# ---------------------------------------------------------------------------
# A no-op change is safe with empty deltas
# ---------------------------------------------------------------------------

def test_noop_modify_is_safe():
    env = _env()
    # Modify the allow rule to an identical rule: nothing changes.
    op = ChangeOp(ChangeKind.MODIFY_RULE, ruleset_id="fw", rule=_allow_5432())
    impact = evaluate_change(env, ProposedChange([op], title="no-op"),
                             flows=[_pos_flow()])

    assert impact.routes_opened == []
    assert impact.routes_closed == []
    assert impact.newly_denied_flows == []
    assert impact.newly_allowed_flows == []
    assert impact.verdict == "safe"


# ---------------------------------------------------------------------------
# A flow on an unaffected port is not reported
# ---------------------------------------------------------------------------

def test_flow_on_unaffected_port_not_reported():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    # This flow targets tcp/9999 — denied both before and after, so no flip.
    other = Flow("10.9.0.5", "10.1.0.9", Proto.TCP, 9999,
                 handshake_completed=True)
    impact = evaluate_change(env, change, flows=[other])

    assert impact.newly_denied_flows == []
    assert impact.newly_allowed_flows == []
    # the route still closes, but with no broken flow the verdict is safe
    assert [d.pair for d in impact.routes_closed] == [PAIR]
    assert impact.verdict == "safe"


# ---------------------------------------------------------------------------
# Adding a firewall set evaluates its rules (newly allowed)
# ---------------------------------------------------------------------------

def test_newly_allowed_alone_is_safe_but_noted():
    # An ungoverned edge (already open) to a jewel; the change adds a rule
    # set that governs a *different* flow, newly allowing it without opening
    # any new crown-jewel route.
    env = _env()
    env.add_ruleset(RuleSet("fw3", [
        Rule("allow3", Action.ALLOW, 10, ("10.9.0.0/24",), ("10.1.0.0/24",),
             (PortRange.single(Proto.TCP, 8080),)),
    ], default_action=Action.DENY))
    op = ChangeOp(ChangeKind.ADD_RULE, ruleset_id="fw3",
                  rule=Rule("allow_extra", Action.ALLOW, 5,
                            ("10.9.0.0/24",), ("10.1.0.0/24",),
                            (PortRange.single(Proto.TCP, 8443),)))
    flow = Flow("10.9.0.5", "10.1.0.9", Proto.TCP, 8443)
    impact = evaluate_change(env, ProposedChange([op], title="open 8443"),
                             flows=[flow])

    assert len(impact.newly_allowed_flows) == 1
    assert impact.newly_allowed_flows[0].status == "newly_allowed"
    assert not impact.newly_denied_flows
    assert not impact.routes_opened
    assert impact.verdict == "safe"
    # ...but the summary notes the newly-permitted traffic.
    assert "newly allow" in impact.summary().lower()


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_determinism():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    flows = [
        Flow("10.9.0.7", "10.1.0.3", Proto.TCP, 5432, handshake_completed=True),
        _pos_flow(),
        Flow("10.9.0.2", "10.1.0.1", Proto.TCP, 5432),
    ]
    a = evaluate_change(env, change, flows=flows)
    b = evaluate_change(_env(), change, flows=flows)

    assert a == b
    assert a.routes_closed == b.routes_closed
    assert a.newly_denied_flows == b.newly_denied_flows
    # flow impacts are sorted by (ruleset_id, src_ip, dst_ip, dst_port)
    keys = [(fi.flow.src_ip, fi.flow.dst_ip) for fi in a.newly_denied_flows]
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Summary / table safety and content
# ---------------------------------------------------------------------------

def test_summary_is_safe_and_mentions_counts():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    impact = evaluate_change(env, change, flows=[_pos_flow()])

    summary = impact.summary()
    assert not safety.contains_unsafe_token(summary)
    assert "breaks_live_flows" in summary
    assert "close 5432" in summary
    # counts are present
    assert "1" in summary          # one broken flow / one closed route
    assert "routes" in summary.lower()


def test_impact_table_is_printable_and_safe():
    env = _env()
    change = ProposedChange([remove_rule("fw", "allow")], title="close 5432")
    impact = evaluate_change(env, change, flows=[_pos_flow()])

    lines = impact_table(impact)
    assert isinstance(lines, list)
    assert all(isinstance(line, str) for line in lines)
    joined = "\n".join(lines)
    assert not safety.contains_unsafe_token(joined)
    assert "close 5432" in joined
    assert "breaks_live_flows" in joined
    # the closed route and the broken flow both appear
    assert any("entry -> jewel" in line for line in lines)
    assert any("10.9.0.5 -> 10.1.0.9" in line for line in lines)


def test_change_impact_dataclass_shape():
    # RouteDelta / FlowImpact / ChangeImpact are the documented shapes.
    rd = RouteDelta(PAIR, "opened", None)
    assert rd.pair == PAIR and rd.example_route is None
    ci = ChangeImpact(change_title="t")
    assert ci.verdict == "safe"
    assert ci.routes_opened == [] and ci.newly_denied_flows == []
