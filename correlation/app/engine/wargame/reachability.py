"""Backward reachability search for Wargame.

Works *backward* from the crown jewels over a **directed, rule-aware** graph
to find every route an intrusion could take from an entry point (internet,
guest/IoT segment, vendor VPN, shared credential) to a crown jewel, and
labels every hop with the evidence behind it. It reasons purely over graph
structure and config — it never emits an exploit, a payload or a command.
See ``docs/WARGAME.md`` §2.1 (backward search) and §2.4 (evidence ladder).

The unit is the ``(entry, jewel)`` pair. A pair is *open* when at least one
route survives; *closed* when no route does (honestly: "no open route in the
model"); *conditional* when every open route leans on a hop the config can't
prove (so it needs a probe or observation to settle).

Determinism. Neighbours are visited in sorted ``id`` order; routes are
emitted shortest-first and then lexicographically by their node-id sequence.
The same inputs always yield identical output.

Termination. Three structural bounds keep enumeration finite and bounded:
``max_hops`` (edges per route), simple paths only (no repeated node), and a
per-pair cap. A global visit budget (:data:`_VISIT_BUDGET`) backstops
pathological graphs; if it is hit, enumeration stops early and the result is
whatever was found so far (still deterministic, since the search order is
fixed). The cut-off is documented rather than silent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import rules
from .model import (
    Edge,
    EvidenceLabel,
    Hop,
    LABEL_STRENGTH,
    Node,
    NodeRole,
    PortRange,
    ReachabilityResult,
    Route,
    RuleSet,
)

#: Backstop on total DFS expansion steps across all jewels. The structural
#: bounds (max_hops + simple paths + per-pair cap) normally bite first; this
#: only matters for a dense, highly-connected graph. Deterministic: the
#: search visits neighbours in a fixed order, so an early cut-off is stable.
_VISIT_BUDGET = 200_000


@dataclass(frozen=True)
class _HopTemplate:
    """A traversable directed edge reduced to the hop it contributes."""

    labels: frozenset[EvidenceLabel]
    port: Optional[PortRange]
    rule_ref: str
    fix_candidate_ids: frozenset[str]

    def _strength_key(self) -> tuple[int, str, str]:
        """Deterministic preference key when parallel edges connect a pair:
        strongest weakest-label first, then by rule_ref, then port repr."""
        weakest = min(
            (LABEL_STRENGTH[lb] for lb in self.labels),
            default=LABEL_STRENGTH[EvidenceLabel.UNKNOWN],
        )
        return (weakest, self.rule_ref, repr(self.port))


def _edge_template(
    edge: Edge,
    nodes: dict[str, Node],
    rulesets: dict[str, RuleSet],
) -> Optional[_HopTemplate]:
    """Reduce an edge to a :class:`_HopTemplate`, or ``None`` if the edge is
    not traversable (a closed hop, a missing ruleset, or an endpoint that is
    not in ``nodes``).

    Labelling follows ``docs/WARGAME.md`` §2.4:

    * start from ``edge.base_labels``;
    * ungoverned edge (``rule_set_id is None``) is traversable, and gains
      ``INFERRED`` only when it carries no base labels;
    * governed edge is evaluated with :func:`rules.boundary_permits` over the
      endpoints' CIDRs — denied ⇒ not traversable; allowed & not conditional
      ⇒ ``PROVED_CONFIG``; allowed & conditional ⇒ ``CONDITIONAL`` (and no
      ``PROVED_CONFIG``).
    """
    if edge.src not in nodes or edge.dst not in nodes:
        return None

    labels: set[EvidenceLabel] = set(edge.base_labels)
    rule_ref = ""

    if edge.rule_set_id is None:
        if not labels:
            labels.add(EvidenceLabel.INFERRED)
    else:
        ruleset = rulesets.get(edge.rule_set_id)
        if ruleset is None:
            # Governed edge whose control is not defined here: we cannot
            # prove it open, so it is not traversable.
            return None
        decision = rules.boundary_permits(
            ruleset,
            nodes[edge.src].cidrs,
            nodes[edge.dst].cidrs,
            edge.port,
        )
        if not decision.allowed:
            return None  # closed hop
        rule_ref = decision.matched_rule or ""
        if decision.conditional:
            labels.add(EvidenceLabel.CONDITIONAL)
        else:
            labels.add(EvidenceLabel.PROVED_CONFIG)

    fix_ids = (
        frozenset({edge.fix_candidate_id})
        if edge.fix_candidate_id
        else frozenset()
    )
    return _HopTemplate(
        labels=frozenset(labels),
        port=edge.port,
        rule_ref=rule_ref,
        fix_candidate_ids=fix_ids,
    )


def backward_reachability(
    nodes: dict[str, Node],
    edges: list[Edge],
    rulesets: dict[str, RuleSet],
    *,
    max_hops: int = 8,
    max_routes_per_pair: int = 16,
) -> ReachabilityResult:
    """Enumerate entry→jewel routes by searching backward from the jewels.

    See the module docstring for semantics, determinism and termination.
    """
    # -- 1. Reduce edges to a collapsed directed adjacency ------------------
    # One representative hop per ordered node pair (strongest evidence wins,
    # deterministically), so a node-sequence route is unique.
    forward: dict[str, dict[str, _HopTemplate]] = {}
    reverse: dict[str, set[str]] = {}
    for edge in edges:
        tmpl = _edge_template(edge, nodes, rulesets)
        if tmpl is None:
            continue
        existing = forward.get(edge.src, {}).get(edge.dst)
        if existing is None or tmpl._strength_key() > existing._strength_key():
            forward.setdefault(edge.src, {})[edge.dst] = tmpl
        reverse.setdefault(edge.dst, set()).add(edge.src)

    entries = sorted(n.id for n in nodes.values() if n.role is NodeRole.ENTRY)
    jewels = sorted(n.id for n in nodes.values() if n.role is NodeRole.CROWN_JEWEL)
    entry_set = set(entries)

    # -- 2. Backward DFS from each jewel ------------------------------------
    routes: list[Route] = []
    budget = [_VISIT_BUDGET]

    def _build_route(entry: str, jewel: str, fwd_nodes: list[str]) -> Route:
        hops: list[Hop] = []
        for a, b in zip(fwd_nodes, fwd_nodes[1:]):
            tmpl = forward[a][b]
            hops.append(
                Hop(
                    src=a,
                    dst=b,
                    labels=tmpl.labels,
                    port=tmpl.port,
                    rule_ref=tmpl.rule_ref,
                    fix_candidate_ids=tmpl.fix_candidate_ids,
                )
            )
        return Route(entry=entry, jewel=jewel, hops=hops)

    for jewel in jewels:
        # path is the reverse-order node list [jewel, ..., current]; visited
        # guards simple paths. Recursion depth is bounded by max_hops.
        def _dfs(current: str, path: list[str], visited: set[str]) -> None:
            if budget[0] <= 0:
                return
            if current in entry_set and len(path) >= 2:
                fwd_nodes = list(reversed(path))  # entry → ... → jewel
                routes.append(_build_route(current, jewel, fwd_nodes))
                # Keep descending: a longer path from a *different* entry may
                # pass through this one.
            if len(path) - 1 >= max_hops:
                return  # hop budget reached (edges == len(path)-1)
            for pred in sorted(reverse.get(current, ())):
                if pred in visited:
                    continue  # simple path only
                budget[0] -= 1
                if budget[0] <= 0:
                    return
                visited.add(pred)
                path.append(pred)
                _dfs(pred, path, visited)
                path.pop()
                visited.remove(pred)

        _dfs(jewel, [jewel], {jewel})

    # -- 3. Order deterministically and cap per pair ------------------------
    routes.sort(
        key=lambda r: (
            r.entry,
            r.jewel,
            r.length,
            tuple(h.src for h in r.hops) + (r.jewel,),
        )
    )
    capped: list[Route] = []
    per_pair: dict[tuple[str, str], int] = {}
    for r in routes:
        n = per_pair.get(r.pair, 0)
        if n >= max_routes_per_pair:
            continue
        per_pair[r.pair] = n + 1
        capped.append(r)

    # -- 4. Classify pairs --------------------------------------------------
    open_pairs: set[tuple[str, str]] = {r.pair for r in capped}
    # Simpler accepted definition: every (entry, jewel) combination that is
    # not open. This reads as "no open route in the model" — it does not try
    # to distinguish a pair that was cut by a deny from one that never had any
    # adjacency at all.
    all_pairs = {(e, j) for e in entries for j in jewels}
    closed_pairs = all_pairs - open_pairs

    # A pair is conditional when *every* one of its open routes contains at
    # least one CONDITIONAL hop (so no route is a clean proved-open path).
    conditional_pairs: set[tuple[str, str]] = set()
    for pair in open_pairs:
        pair_routes = [r for r in capped if r.pair == pair]
        if all(
            any(EvidenceLabel.CONDITIONAL in h.labels for h in r.hops)
            for r in pair_routes
        ):
            conditional_pairs.add(pair)

    return ReachabilityResult(
        routes=capped,
        open_pairs=open_pairs,
        closed_pairs=closed_pairs,
        conditional_pairs=conditional_pairs,
    )
