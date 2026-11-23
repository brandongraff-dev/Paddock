"""Topology assembly contract: declared segments + parsed rule sets → a
searchable :class:`~app.engine.wargame.environment.Environment`.

The parsers produce rule sets and bindings; the solver searches an
environment of nodes and edges. This module is the shared vocabulary for
the layer that joins them — :mod:`.topology` builds the environment,
:mod:`.identity` contributes identity/credential nodes and edges, and
:mod:`.ingest` contributes observed flows and imported hops, all expressed
in the specs defined here.

Pure data plus a couple of helpers; no I/O, no search.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Optional

from .environment import Environment
from .model import Edge, EvidenceLabel, Node, NodeRole, PortRange


# A route-reachability oracle: does a route exist between two CIDRs (routing
# tables, not firewall rules)? Supplied by :mod:`.routing` when available.
# Returning True for everything (the default) means "routing not modelled".
RouteReachable = Callable[[str, str], bool]


@dataclass
class SegmentSpec:
    """A declared segment/host/zone and the addresses it owns."""

    id: str
    cidrs: tuple[str, ...] = ()
    role: NodeRole = NodeRole.INTERMEDIATE
    reason: str = ""
    jewel_kind: str = ""
    metadata: dict = field(default_factory=dict)

    def to_node(self) -> Node:
        return Node(
            id=self.id,
            role=self.role,
            cidrs=tuple(self.cidrs),
            reason=self.reason,
            jewel_kind=self.jewel_kind,
            metadata=dict(self.metadata),
        )


@dataclass
class EdgeSpec:
    """A declared directed adjacency, optionally gated by a parsed rule set
    (by id). ``base_labels`` carries evidence independent of the solver
    (OBSERVED from flows, IMPORTED from a pentest)."""

    src: str
    dst: str
    rule_set_id: Optional[str] = None
    port: Optional[PortRange] = None
    base_labels: frozenset[EvidenceLabel] = frozenset()
    fix_candidate_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_edge(self) -> Edge:
        return Edge(
            src=self.src,
            dst=self.dst,
            rule_set_id=self.rule_set_id,
            port=self.port,
            base_labels=frozenset(self.base_labels),
            fix_candidate_id=self.fix_candidate_id,
            metadata=dict(self.metadata),
        )


@dataclass
class TopologySpec:
    """What the customer declares: their segments, the adjacencies between
    them, and optional maps from a rule set's binding (zone / interface /
    subnet) to a segment id so bindings can be checked or auto-wired."""

    segments: list[SegmentSpec] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)
    zone_to_segment: dict[str, str] = field(default_factory=dict)
    subnet_to_segment: dict[str, str] = field(default_factory=dict)

    def segment_ids(self) -> set[str]:
        return {s.id for s in self.segments}


@dataclass
class TopologyWarning:
    message: str
    ref: str = ""

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"{self.message}" + (f" ({self.ref})" if self.ref else "")


@dataclass
class TopologyResult:
    """The assembled environment plus an honest account of what was
    inferred or couldn't be wired."""

    environment: Environment
    warnings: list[TopologyWarning] = field(default_factory=list)
    discovered_edges: list[Edge] = field(default_factory=list)

    def add_warning(self, message: str, ref: str = "") -> None:
        self.warnings.append(TopologyWarning(message, ref))


# ---------------------------------------------------------------------------
# helpers shared by the assembly layer
# ---------------------------------------------------------------------------

def segment_for_ip(spec: TopologySpec, ip: str) -> Optional[str]:
    """The id of the most specific declared segment whose CIDRs contain
    ``ip`` (longest-prefix wins), or ``None``. Never raises."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: Optional[str] = None
    best_len = -1
    for seg in spec.segments:
        for c in seg.cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            if addr in net and net.prefixlen > best_len:
                best, best_len = seg.id, net.prefixlen
    return best


def always_reachable(_src_cidr: str, _dst_cidr: str) -> bool:
    """Default :data:`RouteReachable`: routing not modelled ⇒ don't block."""
    return True
