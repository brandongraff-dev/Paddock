"""Impossible-traffic detector: a real flow crossed a boundary proved closed.

A certificate says no route exists across a boundary. If *real* traffic
crosses it anyway, the proof or the model is wrong, so we alert.

Only a flow that actually got through counts (completed handshake,
destination-side observation, or a firewall allow log). Broadcast and
management noise is suppressed. A human resolves every alert with a cited
reason; the model is NEVER auto-amended to explain traffic away, since that
could legitimise an attacker's tunnel.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .model import (
    Flow,
    ImpossibleResolution,
    ImpossibleTrafficAlert,
    PortRange,
    _ip_in_cidr,
)


@dataclass(frozen=True)
class ClosedBoundary:
    """A boundary a valid certificate proved closed."""

    src_cidrs: tuple[str, ...]
    dst_cidrs: tuple[str, ...]
    port: Optional[PortRange]
    certificate_fingerprint: str
    boundary_src: str
    boundary_dst: str


#: Flow kinds that are noise, never evidence of a crossing:
#:  arp        - link-local address resolution, never routed across a boundary.
#:  mdns       - multicast service discovery chatter.
#:  dhcp       - address assignment broadcasts/relays.
#:  lb_health  - load-balancer probes, expected by design.
#:  vpn_encap  - the outer tunnel packets; the inner flow is what matters.
#:  nat        - translated duplicates of a flow already seen.
#:  mgmt       - management-plane chatter (SNMP, monitoring, NTP) by design.
#:  icmp       - control/diagnostic messages, not application traffic.
SUPPRESSED_KINDS: frozenset[str] = frozenset(
    {"arp", "mdns", "dhcp", "lb_health", "vpn_encap", "nat", "mgmt", "icmp"}
)


def flow_is_real(flow: Flow) -> bool:
    """True iff the flow demonstrably got through and is not suppressed noise.

    A bare dropped SYN (no completed handshake, no destination-side
    observation, no firewall allow log) returns False: a dropped SYN proves
    the boundary WORKS, so it must not contradict the certificate.
    """
    if flow.is_broadcast or flow.kind in SUPPRESSED_KINDS:
        return False
    return bool(
        flow.handshake_completed or flow.dst_side_observed or flow.firewall_allow_logged
    )


def flow_crosses(flow: Flow, b: ClosedBoundary) -> bool:
    """True iff the flow goes from ``b``'s source side to its destination side
    on a port the boundary covers (``b.port`` None means any port)."""
    if not any(_ip_in_cidr(flow.src_ip, c) for c in b.src_cidrs):
        return False
    if not any(_ip_in_cidr(flow.dst_ip, c) for c in b.dst_cidrs):
        return False
    return b.port is None or b.port.contains(flow.proto, flow.dst_port)


def classify_flow(
    flow: Flow, closed_boundaries: list[ClosedBoundary]
) -> Optional[ImpossibleTrafficAlert]:
    """Return a critical alert if a real flow crosses a closed boundary.

    With several matching boundaries the one with the lexicographically
    smallest certificate fingerprint is chosen, so output is deterministic.
    Returns None for noise, dropped attempts, and non-crossing flows. The
    inputs are not modified.
    """
    if not flow_is_real(flow):
        return None
    matches = [b for b in closed_boundaries if flow_crosses(flow, b)]
    if not matches:
        return None
    b = min(matches, key=lambda m: m.certificate_fingerprint)
    note = (
        f"Real traffic crossed {b.boundary_src} -> {b.boundary_dst}, which "
        f"certificate {b.certificate_fingerprint} proved closed. Possible "
        "causes: (1) an asset or path missing from the model, (2) a defect "
        "in a rule the proof relied on, or (3) a bypass such as a tunnel or "
        "unmanaged link. A human must investigate and cite a reason."
    )
    return ImpossibleTrafficAlert(
        flow=flow,
        contradicts_certificate=b.certificate_fingerprint,
        boundary_src=b.boundary_src,
        boundary_dst=b.boundary_dst,
        severity="critical",
        note=note,
    )


def resolve(
    alert: ImpossibleTrafficAlert,
    resolution: ImpossibleResolution,
    reason: str,
    resolved_by: str,
) -> dict[str, Any]:
    """Record a human resolution of an alert.

    Requires a non-blank ``reason`` and a non-empty ``resolved_by`` (raises
    ``ValueError`` otherwise). Returns a new record dict; it does not touch
    the alert, any graph, certificate, or model. The model is NEVER
    auto-amended: adding a missing asset or fixing a rule is a separate,
    human-driven action.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("a cited reason is required to resolve an alert")
    if not isinstance(resolved_by, str) or not resolved_by.strip():
        raise ValueError("resolved_by is required to resolve an alert")
    return {
        "alert": alert,
        "resolution": resolution,
        "reason": reason.strip(),
        "resolved_by": resolved_by.strip(),
    }
