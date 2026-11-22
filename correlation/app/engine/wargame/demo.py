"""A runnable Wargame demo over a tiny modelled environment.

Builds the canonical scene — guest Wi-Fi reaching a payment database
through a smart fridge and a POS controller — then runs the whole
pipeline and prints it: the open route with per-hop evidence, the
cheapest fix that cuts it, a signed certificate for a boundary proved
closed, and the impossible-traffic alert raised when a flow crosses that
closed boundary anyway.

Nothing here touches a real network and nothing is exploited; it reasons
over a model. Run it with::

    python -m app.engine.wargame.demo

This is illustrative, not a benchmark; the engine's real inputs come from
firewall/cloud configs, observed flows and the twin.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import certificate, mincut, reachability
from .impossible import ClosedBoundary, classify_flow
from .model import (
    Action,
    Assumption,
    Corroboration,
    Edge,
    EvidenceLabel,
    FixCandidate,
    Flow,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)


def build_demo() -> tuple[dict[str, Node], list[Edge], dict[str, RuleSet]]:
    nodes = {
        "guest_wifi": Node("guest_wifi", NodeRole.ENTRY, ("10.9.0.0/24",),
                           reason="guest wireless"),
        "fridge": Node("fridge", NodeRole.INTERMEDIATE, ("10.9.0.50/32",)),
        "pos": Node("pos", NodeRole.INTERMEDIATE, ("10.5.0.0/24",)),
        "payments_db": Node("payments_db", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",),
                            reason="cardholder data", jewel_kind="cardholder_data"),
        "clinic_wifi": Node("clinic_wifi", NodeRole.ENTRY, ("10.8.0.0/24",),
                            reason="clinic wireless"),
    }
    rulesets = {
        "fw_pos": RuleSet("fw_pos", [
            Rule("allow_fridge_pos", Action.ALLOW, 10,
                 ("10.9.0.0/24",), ("10.5.0.0/24",),
                 (PortRange.single(Proto.TCP, 8080),)),
        ], default_action=Action.DENY),
        "fw_db": RuleSet("fw_db", [
            Rule("allow_pos_db", Action.ALLOW, 10,
                 ("10.5.0.0/24",), ("10.1.0.0/24",),
                 (PortRange.single(Proto.TCP, 5432),)),
        ], default_action=Action.DENY),
        "fw_clinic": RuleSet("fw_clinic", [
            Rule("deny_clinic_db", Action.DENY, 10,
                 ("10.8.0.0/24",), ("10.1.0.0/24",), (PortRange.any(),)),
        ], default_action=Action.DENY),
    }
    edges = [
        Edge("guest_wifi", "fridge", rule_set_id=None,
             base_labels=frozenset({EvidenceLabel.OBSERVED})),
        Edge("fridge", "pos", rule_set_id="fw_pos",
             port=PortRange.single(Proto.TCP, 8080),
             fix_candidate_id="close_pos_8080"),
        Edge("pos", "payments_db", rule_set_id="fw_db",
             port=PortRange.single(Proto.TCP, 5432),
             fix_candidate_id="close_db_5432"),
        Edge("clinic_wifi", "payments_db", rule_set_id="fw_clinic",
             port=PortRange.any()),
    ]
    return nodes, edges, rulesets


def main() -> None:
    nodes, edges, rulesets = build_demo()
    result = reachability.backward_reachability(nodes, edges, rulesets)

    print("= Wargame demo =\n")
    print("Crown jewel: payments_db (cardholder data)\n")

    print("Open routes to the crown jewel:")
    for r in result.routes_for(("guest_wifi", "payments_db")):
        chain = " -> ".join([r.hops[0].src] + [h.dst for h in r.hops])
        print(f"  {chain}")
        for h in r.hops:
            labels = ",".join(sorted(lb.value for lb in h.labels))
            port = f" {h.port.proto.value}/{h.port.low}" if h.port else ""
            print(f"      {h.src} -> {h.dst}{port}  [{labels}]")
        print(f"  weakest evidence on route: {r.weakest_label.value}\n")

    candidates = {
        "close_pos_8080": FixCandidate("close_pos_8080", "rule", "network_rule",
                                       "Remove fridge->POS 8080 allow", cost=1.0),
        "close_db_5432": FixCandidate("close_db_5432", "rule", "network_rule",
                                      "Remove POS->payments 5432 allow", cost=1.0),
    }
    fs = mincut.fix_set_for(result, candidates)
    print("Cheapest fix set that cuts every open route "
          f"({fs.optimality}, cost {fs.total_cost}):")
    for cid in fs.selected:
        print(f"  - {candidates[cid].description}")
    print(f"  cuts all routes: {fs.cuts_all}\n")

    issued = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    cert = certificate.build_certificate(
        boundary_src="clinic_wifi", boundary_dst="payments_db",
        port=PortRange.single(Proto.TCP, 5432),
        config_hashes=(certificate.hash_snapshot("fw_clinic deny 10.8/24->10.1/24"),),
        assumptions=[Assumption("no_unmodelled_links",
                                "No links outside the modelled topology.")],
        corroboration=Corroboration(0, 30, sensor_on_protected_side=True),
        issued_at=issued, ttl_hours=24)
    cert = certificate.sign(cert, b"demo-key")
    print("Closed-boundary certificate:")
    print(f"  claim: {cert.claim}")
    print(f"  assumptions: {[a.key for a in cert.assumptions]}")
    print(f"  signed & verifies: {certificate.verify(cert, b'demo-key')}")
    print(f"  current at issue+1h: {certificate.is_current(cert, issued.replace(hour=13))}\n")

    boundary = ClosedBoundary(("10.8.0.0/24",), ("10.1.0.0/24",),
                              PortRange.single(Proto.TCP, 5432),
                              cert.fingerprint, "clinic_wifi", "payments_db")
    flow = Flow("10.8.0.5", "10.1.0.9", Proto.TCP, 5432, handshake_completed=True)
    alert = classify_flow(flow, [boundary])
    print("Impossible-traffic check (a flow across the boundary we proved closed):")
    if alert:
        print(f"  ALERT [{alert.severity}] {alert.boundary_src} -> "
              f"{alert.boundary_dst} contradicts certificate "
              f"{alert.contradicts_certificate[:12]}...")
    dropped = Flow("10.8.0.5", "10.1.0.9", Proto.TCP, 5432)
    print(f"  a dropped SYN raises an alert: {classify_flow(dropped, [boundary]) is not None} "
          "(a dropped SYN proves the boundary works)")


if __name__ == "__main__":
    main()
