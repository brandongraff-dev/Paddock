"""Topology assembler: declared segments + parsed rule sets → an
:class:`~app.engine.wargame.environment.Environment` the solver can search.

This is the layer the fabric contract (:mod:`.fabric`) names. The customer
declares their segments and the adjacencies between them; the parsers hand us
vendor-neutral rule sets and the bindings that say where each is enforced;
identity/ingest contribute extra nodes, extra edges and observed flows. This
module joins them into one environment and is honest, in warnings, about
everything it inferred or could not wire.

DEFENSIVE. Nothing here sends a packet or represents an exploit. It is pure,
deterministic graph assembly: the same inputs always produce the same
environment, discovered-edge list and warning list.
"""
from __future__ import annotations

from dataclasses import replace

from .environment import Environment
from .fabric import (
    RouteReachable,
    TopologyResult,
    TopologySpec,
    segment_for_ip,
)
from .impossible import flow_is_real
from .model import Edge, EvidenceLabel, Flow, Node
from .parsers.base import RuleSetBinding


def build_topology(
    spec: TopologySpec,
    rulesets: dict[str, "RuleSet"],  # noqa: F821 - forward ref to model.RuleSet
    *,
    bindings: list[RuleSetBinding] = (),
    observed_flows: list[Flow] = (),
    extra_nodes: list[Node] = (),
    extra_edges: list[Edge] = (),
    route_reachable: RouteReachable | None = None,
) -> TopologyResult:
    """Assemble the environment described by ``spec`` and ``rulesets``.

    See :mod:`.fabric` for the shared vocabulary and ``docs/WARGAME.md`` §2.1
    for the product semantics. The steps are documented inline; each appends
    to ``edges`` / ``warnings`` / ``discovered`` in a fixed pipeline order, so
    the output is deterministic.
    """
    warnings: list[tuple[str, str]] = []
    discovered: list[Edge] = []

    def warn(message: str, ref: str = "") -> None:
        warnings.append((message, ref))

    # -- 1. Nodes: one per declared segment, then identity/ingest nodes. ----
    #    extra_nodes win on an id collision (they carry richer, later info).
    nodes: dict[str, Node] = {seg.id: seg.to_node() for seg in spec.segments}
    for n in extra_nodes:
        if n.id in nodes:
            warn(f"extra node overrides declared segment: {n.id}", n.id)
        nodes[n.id] = n

    # -- 2. Rule sets (copied so callers can't mutate ours through it). -----
    rulesets = dict(rulesets)

    edges: list[Edge] = []

    # -- 3. Declared edges. -------------------------------------------------
    for espec in spec.edges:
        edge = espec.to_edge()
        if edge.src not in nodes or edge.dst not in nodes:
            warn(f"edge endpoint unknown: {edge.src}->{edge.dst}",
                 f"{edge.src}->{edge.dst}")
            continue
        if edge.rule_set_id is not None and edge.rule_set_id not in rulesets:
            # Keep the edge: the solver treats a missing set as
            # non-traversable, so the gap is visible rather than silently
            # opened.
            warn(f"edge references unknown rule set: {edge.rule_set_id}",
                 f"{edge.src}->{edge.dst}")
        if route_reachable is not None:
            src_cidrs = nodes[edge.src].cidrs
            dst_cidrs = nodes[edge.dst].cidrs
            if src_cidrs and dst_cidrs:
                if not any(
                    route_reachable(sc, dc)
                    for sc in src_cidrs
                    for dc in dst_cidrs
                ):
                    # A firewall rule with no underlying route is not a real
                    # hop.
                    warn(f"no route between {edge.src} and {edge.dst}",
                         f"{edge.src}->{edge.dst}")
                    continue
        edges.append(edge)

    # -- 4. Binding auto-wire. ----------------------------------------------
    #    When a binding's two sides both resolve to known segments and no
    #    declared edge already carries that rule set between them, wire a
    #    governed edge from the binding. Sorted for determinism; conservative:
    #    a binding whose endpoints don't both resolve is skipped silently.
    for b in sorted(
        bindings,
        key=lambda x: (
            x.ruleset_id, x.src_zone, x.dst_zone,
            x.interface, x.direction, x.attached_to,
        ),
    ):
        src_seg, dst_seg = _binding_endpoints(spec, b)
        if src_seg is None or dst_seg is None or src_seg == dst_seg:
            continue
        if any(
            e.src == src_seg and e.dst == dst_seg and e.rule_set_id == b.ruleset_id
            for e in edges
        ):
            continue
        edge = Edge(src=src_seg, dst=dst_seg, rule_set_id=b.ruleset_id)
        edges.append(edge)
        discovered.append(edge)
        warn(
            f"auto-wired governed edge {src_seg}->{dst_seg} "
            f"via rule set {b.ruleset_id}",
            b.ruleset_id,
        )

    # -- 5. Observed flows. -------------------------------------------------
    #    Only a flow that demonstrably got through (impossible.flow_is_real)
    #    becomes evidence. A cross-segment flow already explained by an edge
    #    enriches it with OBSERVED; one that isn't surfaces drift as a
    #    discovered ungoverned edge + a warning.
    for flow in observed_flows:
        if not flow_is_real(flow):
            continue
        src_seg = segment_for_ip(spec, flow.src_ip)
        dst_seg = segment_for_ip(spec, flow.dst_ip)
        if src_seg is None or dst_seg is None or src_seg == dst_seg:
            continue
        idx = next(
            (i for i, e in enumerate(edges)
             if e.src == src_seg and e.dst == dst_seg),
            None,
        )
        if idx is not None:
            existing = edges[idx]
            if EvidenceLabel.OBSERVED not in existing.base_labels:
                edges[idx] = replace(
                    existing,
                    base_labels=existing.base_labels | {EvidenceLabel.OBSERVED},
                )
            continue
        edge = Edge(
            src=src_seg,
            dst=dst_seg,
            base_labels=frozenset({EvidenceLabel.OBSERVED}),
        )
        edges.append(edge)
        discovered.append(edge)
        warn("observed flow not explained by a declared edge",
             f"{src_seg}->{dst_seg}")

    # -- 6. Extra edges (identity / ingest / imported hops). ----------------
    for edge in extra_edges:
        if edge.src not in nodes or edge.dst not in nodes:
            warn(f"extra edge endpoint unknown: {edge.src}->{edge.dst}",
                 f"{edge.src}->{edge.dst}")
            continue
        edges.append(edge)

    env = Environment(nodes=nodes, edges=edges, rulesets=rulesets)
    result = TopologyResult(
        environment=env,
        discovered_edges=discovered,
    )
    for message, ref in warnings:
        result.add_warning(message, ref)
    return result


def _binding_endpoints(
    spec: TopologySpec, b: RuleSetBinding
) -> tuple[str | None, str | None]:
    """Resolve a binding's source and destination segments, or ``None`` for a
    side that doesn't map.

    * A zone pair (PAN / Fortinet ``srcintf``/``dstintf``) maps each zone via
      ``spec.zone_to_segment``.
    * An interface-bound ACL (ASA ``access-group``) names one side; the
      direction decides which (``in`` ⇒ the interface is the source side,
      ``out`` ⇒ the destination side).
    * Attached objects (AWS SG → ENIs, NACL → subnets) map via
      ``spec.subnet_to_segment`` (falling back to ``zone_to_segment``) and
      fill whichever side is still open.

    Interfaces and zones are both looked up in ``zone_to_segment``, as the
    fabric contract describes.
    """
    zseg = spec.zone_to_segment
    sseg = spec.subnet_to_segment
    src = zseg.get(b.src_zone) if b.src_zone else None
    dst = zseg.get(b.dst_zone) if b.dst_zone else None

    if b.interface:
        iface_seg = zseg.get(b.interface)
        if iface_seg is not None:
            if b.direction == "out":
                if dst is None:
                    dst = iface_seg
            elif src is None:
                src = iface_seg

    for obj in b.attached_to:
        seg = sseg.get(obj) or zseg.get(obj)
        if seg is None:
            continue
        if dst is None and seg != src:
            dst = seg
        elif src is None and seg != dst:
            src = seg

    return src, dst
