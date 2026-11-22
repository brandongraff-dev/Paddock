"""Full-pipeline Wargame demo: model → routes → fix → evidence.

Assembles an environment from declared segments, a firewall rule set, an
identity (vendor-VPN) path and an ingested observed flow; then shows the
backward search finding a route to the crown jewel *through the POS tier*
even though the direct firewall boundary is closed, the cheapest fix that
cuts it, the boundary agreement verdict, a PCI evidence pack, and the
scorecard.

    python -m app.engine.wargame.demo_assess

Everything is a model. Nothing is applied and nothing is exploited.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import compliance, report
from .agreement import from_environment
from .fabric import EdgeSpec, SegmentSpec, TopologySpec
from .identity import IdentityPrincipal, PrincipalKind, build_identity_layer
from .ingest import parse_flows
from .mincut import fix_set_for
from .model import (
    Action,
    EvidenceLabel,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from .routing import RoutingFabric, RouteEntry, RouteTableModel
from .topology import build_topology


def main() -> None:
    print("= Wargame full assessment =\n")
    print("Crown jewel: payments_db (cardholder data / the CDE)\n")

    # 1) Declared segments and the firewall rule set that guards the DB.
    spec = TopologySpec(
        segments=[
            SegmentSpec("guest_wifi", ("10.9.0.0/24",), reason="guest wireless",
                        metadata={"role": "entry"}),
            SegmentSpec("pos", ("10.5.0.0/24",), reason="point-of-sale tier"),
            SegmentSpec("payments_db", ("10.1.0.0/24",), reason="cardholder data"),
        ],
        edges=[
            # Guest Wi-Fi can reach the POS tier (seen on the wire).
            EdgeSpec("guest_wifi", "pos", base_labels=frozenset({EvidenceLabel.OBSERVED}),
                     fix_candidate_id="seg:guest->pos"),
            # POS reaches the DB, gated by the DB security group.
            EdgeSpec("pos", "payments_db", rule_set_id="sg-db",
                     port=PortRange.single(Proto.TCP, 5432),
                     fix_candidate_id="sg-db:allow_pos"),
        ],
    )
    # Mark the crown jewel (SegmentSpec role via metadata isn't enough — set it).
    from .model import NodeRole
    spec.segments[0].role = NodeRole.ENTRY
    spec.segments[2].role = NodeRole.CROWN_JEWEL
    spec.segments[2].jewel_kind = "cardholder_data"

    rulesets = {
        "sg-db": RuleSet("sg-db", [
            Rule("allow_pos", Action.ALLOW, 10, ("10.5.0.0/24",), ("0.0.0.0/0",),
                 (PortRange.single(Proto.TCP, 5432),), vendor="aws",
                 cost_class="cloud_policy"),
        ], default_action=Action.DENY, vendor="aws"),
    }

    # 2) An identity path: a vendor VPN account that can reach the POS tier.
    principals = [IdentityPrincipal("vendor_vpn", PrincipalKind.VENDOR_VPN,
                                    reason="HVAC maintenance VPN")]
    id_nodes, id_edges = build_identity_layer(
        principals, shared_cred_map={"vendor_vpn": ["pos"]})

    # 3) An observed flow ingested from a Zeek-style log (POS→DB, established).
    flows = parse_flows(
        [{"id.orig_h": "10.5.0.5", "id.resp_h": "10.1.0.9", "id.resp_p": 5432,
          "proto": "tcp", "conn_state": "SF"}], fmt="zeek")

    # 4) A routing oracle (here: everything in 10/8 is routable).
    routing = RoutingFabric([
        RouteTableModel("rt-main", (RouteEntry("10.0.0.0/8", "local"),),
                        associated_cidrs=("10.0.0.0/8",)),
    ])

    result_topo = build_topology(
        spec, rulesets, observed_flows=flows,
        extra_nodes=id_nodes, extra_edges=id_edges,
        route_reachable=routing.reachable)
    env = result_topo.environment
    if result_topo.warnings:
        print("Assembly notes:")
        for w in result_topo.warnings[:4]:
            print(f"  - {w}")
        print()

    # 5) Backward search: who reaches the crown jewel?
    rr = env.reachability()
    print("Open routes to payments_db:")
    for pair in sorted(rr.open_pairs):
        if pair[1] != "payments_db":
            continue
        route = rr.routes_for(pair)[0]
        chain = " -> ".join([route.hops[0].src] + [h.dst for h in route.hops])
        print(f"  {chain}   (weakest evidence: {route.weakest_label.value})")
    print()

    # 6) The cheapest fix that cuts every route to the jewel.
    from .model import FixCandidate
    candidates = {
        "seg:guest->pos": FixCandidate("seg:guest->pos", "edge", "segment_move",
                                       "Isolate guest Wi-Fi from the POS VLAN", cost=3.0),
        "sg-db:allow_pos": FixCandidate("sg-db:allow_pos", "rule", "cloud_policy",
                                        "Scope the DB security group off the POS CIDR", cost=1.0),
        "identity:vendor_vpn->pos": FixCandidate(
            "identity:vendor_vpn->pos", "credential", "credential",
            "Scope/rotate the vendor VPN credential", cost=2.0),
    }
    fs = fix_set_for(rr, candidates)
    print(f"Cheapest fix set ({fs.optimality}, cost {fs.total_cost}):")
    for cid in fs.selected:
        print(f"  - {candidates[cid].description}")
    print(f"  cuts all routes to crown jewels: {fs.cuts_all}\n")

    # 7) Boundary agreement for the DIRECT guest→CDE firewall boundary.
    ag_guest = from_environment(env, "guest_wifi", "payments_db",
                                PortRange.single(Proto.TCP, 5432), probe=False)
    print("Direct firewall boundary guest_wifi → payments_db (tcp/5432):")
    print(f"  verdict: {ag_guest.verdict}  "
          f"({ag_guest.note or '; '.join(ag_guest.disagreements)})")
    print("  (note: the DIRECT boundary is closed, yet a route exists via POS "
          "— that is the point of searching end-to-end)\n")

    # 8) PCI evidence pack from the boundary verdicts.
    pack = compliance.pci_segmentation_pack(
        boundary_reports=[ag_guest],
        generated_at=datetime(2026, 11, 22, tzinfo=timezone.utc).isoformat(),
        coverage_pct=0.97, has_probe=True)
    print(f"PCI evidence pack ({pack.framework}), fingerprint "
          f"{pack.fingerprint[:12]}…:")
    for item in pack.items:
        print(f"  {item.control_id}: {item.status.value}")
    print()

    # 9) Scorecard.
    sc = report.build_scorecard(rr, agreement_reports=[ag_guest],
                                coverage_pct=97.0,
                                blind_spots=["serial links to building HVAC"])
    print("Scorecard:")
    print(f"  {sc.board_line}")

    # 10) Routing oracle sanity: a blackholed destination is not reachable.
    bh = RoutingFabric([RouteTableModel(
        "rt-x", (RouteEntry("10.1.0.0/24", "blackhole"),),
        associated_cidrs=("10.5.0.0/24",))])
    print("\nRouting check: POS → DB with a blackhole route is reachable? "
          f"{bh.reachable('10.5.0.0/24', '10.1.0.9/32')}  (blackhole = no route)")


if __name__ == "__main__":
    main()
