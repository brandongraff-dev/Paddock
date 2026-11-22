"""Runnable change-gate demo (docs/WARGAME.md §2.3, §5).

Shows the capability a change board actually pays for: given a proposed
firewall change, Wargame says — before anything is applied — which routes
to the crown jewels it opens, and which live flows it would break. It also
parses a Terraform plan into the same change model, and prints the
before/after scorecard.

    python -m app.engine.wargame.demo_changegate

Everything is a model. Nothing is applied and nothing is exploited.
"""
from __future__ import annotations

from . import report
from .agreement import from_environment
from .changegate import evaluate_change, impact_table
from .environment import (
    ChangeKind,
    ChangeOp,
    Environment,
    ProposedChange,
    apply_change,
    remove_rule,
)
from .model import (
    Action,
    Edge,
    EvidenceLabel,
    Flow,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from .parsers.terraform import parse_plan


def build_env() -> Environment:
    """A payments environment: the DB firewall (sg-db) admits the POS tier,
    not guest Wi-Fi. So the POS→DB hop is open; a direct guest→DB hop is
    closed."""
    env = Environment()
    env.add_node(Node("guest_wifi", NodeRole.ENTRY, ("10.9.0.0/24",),
                      reason="guest wireless"))
    env.add_node(Node("pos", NodeRole.ENTRY, ("10.5.0.0/24",),
                      reason="point-of-sale tier"))
    env.add_node(Node("payments_db", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",),
                      reason="cardholder data", jewel_kind="cardholder_data"))
    env.add_ruleset(RuleSet("sg-db", [
        Rule("allow_pos", Action.ALLOW, 10, ("10.5.0.0/24",), ("0.0.0.0/0",),
             (PortRange.single(Proto.TCP, 5432),), vendor="aws",
             cost_class="cloud_policy"),
    ], default_action=Action.DENY, vendor="aws"))
    env.add_edge(Edge("pos", "payments_db", rule_set_id="sg-db",
                      port=PortRange.single(Proto.TCP, 5432),
                      fix_candidate_id="sg-db:allow_pos"))
    env.add_edge(Edge("guest_wifi", "payments_db", rule_set_id="sg-db",
                      port=PortRange.single(Proto.TCP, 5432)))
    return env


# A minimal `terraform show -json` plan that opens the DB firewall to guest.
_PLAN = {
    "resource_changes": [
        {
            "address": "aws_security_group_rule.guest_to_db",
            "type": "aws_security_group_rule",
            "name": "guest_to_db",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {
                    "type": "ingress",
                    "from_port": 5432,
                    "to_port": 5432,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.9.0.0/24"],
                    "security_group_id": "sg-db",
                },
                "after_unknown": {},
            },
        }
    ]
}


def main() -> None:
    env = build_env()
    print("= Wargame change gate =\n")
    print("Crown jewel: payments_db (cardholder data)")
    before = env.reachability()
    print("Open entry→jewel pairs now:", sorted(before.open_pairs), "\n")

    # 1) A Terraform plan, parsed into the change model.
    parsed = parse_plan(_PLAN)
    print("Terraform plan parsed:")
    print(f"  {parsed.title}")
    print(f"  affected rule sets: {sorted(parsed.affected_ruleset_ids())}")
    # Apply only the ops this environment actually has a rule set for.
    applicable = ProposedChange(
        ops=[op for op in parsed.ops
             if op.kind == ChangeKind.ADD_RULE and op.ruleset_id in env.rulesets],
        title="Open DB firewall to guest Wi-Fi (CHG from Terraform)",
        source=parsed.source,
    )

    # 2) Change-impact proof for that plan.
    pos_flow = Flow("10.5.0.5", "10.1.0.9", Proto.TCP, 5432, handshake_completed=True)
    impact = evaluate_change(env, applicable, flows=[pos_flow])
    print("\nChange-impact proof (opening the DB to guest):")
    for line in impact_table(impact):
        print(f"  {line}")
    for d in impact.routes_opened:
        print(f"  OPENS a route to {d.pair[1]} from {d.pair[0]}")

    # 3) A change that breaks a live flow: remove the POS→DB allow.
    breaking = ProposedChange([remove_rule("sg-db", "allow_pos")],
                              title="Remove POS→DB allow")
    impact2 = evaluate_change(env, breaking, flows=[pos_flow])
    print("\nChange-impact proof (removing the POS→DB allow):")
    for line in impact_table(impact2):
        print(f"  {line}")
    for fi in impact2.newly_denied_flows:
        print(f"  WOULD BREAK live flow {fi.flow.src_ip}->{fi.flow.dst_ip} "
              f"tcp/{fi.flow.dst_port} (seen on the wire)")

    # 4) Boundary agreement + scorecard, before vs after opening the DB.
    after_env = apply_change(env, applicable)
    print("\nBoundary agreement (guest_wifi → payments_db, tcp/5432):")
    before_ag = from_environment(env, "guest_wifi", "payments_db",
                                 PortRange.single(Proto.TCP, 5432), probe=False)
    after_ag = from_environment(after_env, "guest_wifi", "payments_db",
                                PortRange.single(Proto.TCP, 5432),
                                observed_flows=[Flow("10.9.0.5", "10.1.0.9",
                                                     Proto.TCP, 5432,
                                                     handshake_completed=True)])
    print(f"  before change: {before_ag.verdict}")
    print(f"  after change:  {after_ag.verdict}  ({'; '.join(after_ag.disagreements) or after_ag.note})")

    print("\nScorecard:")
    sc_before = report.build_scorecard(before, coverage_pct=97.0,
                                       blind_spots=["serial links to OT"])
    sc_after = report.build_scorecard(after_env.reachability(), coverage_pct=97.0,
                                      blind_spots=["serial links to OT"])
    print(f"  before: {sc_before.board_line}")
    print(f"  after:  {sc_after.board_line}")


if __name__ == "__main__":
    main()
