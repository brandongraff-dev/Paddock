"""Backward reachability search for Wargame.

Works *backward* from the crown jewels over a **directed, rule-aware** graph
to find every route an intrusion could take from an entry point (internet,
guest/IoT segment, vendor VPN, shared credential) to a crown jewel, and
labels every hop with the evidence behind it. It reasons purely over graph
structure and config — it never emits an exploit, a payload or a command.
See ``docs/WARGAME.md`` §2.1 (backward search) and §2.4 (evidence ladder).

Two separate jobs, deliberately kept apart
-------------------------------------------

1. **Deciding** open / closed / conditional — *exact*. The unit is the
   ``(entry, jewel)`` pair. A pair is *open* iff the jewel is reachable from
   the entry over the traversable edges, decided by a reverse breadth-first
   search from each jewel with **no hop limit and no budget**. It is *closed*
   iff it is not open ("no route exists in the model"). Because this pass is
   exact, no enumeration limit can ever turn an open pair into a closed one —
   the core "no false closed" invariant (``docs/WARGAME_ENGINE.md`` §1.4).

   * *conditional* — open over all traversable edges, but **not** open over
     the subgraph of edges that carry no ``CONDITIONAL`` label. Equivalently:
     every route (of any length) leans on at least one conditional hop.
   * *inferred* (:attr:`ReachabilityResult.inferred_pairs`) — the same test
     for the bottom of the evidence ladder: open, but not open over the edges
     whose weakest label is stronger than ``INFERRED``. Every route leans on a
     hop the model merely infers (``INFERRED``/``UNKNOWN``). Such pairs stay
     *open* (an ungoverned adjacency is permitted by default — the
     conservative direction) and are **not** folded into ``conditional_pairs``
     (that set keeps its established meaning and scorecard count); they are
     exposed so a report or certificate can ask for corroboration.

2. **Listing example routes** — *bounded*. Simple paths are enumerated by a
   backward depth-first search, shortest first (iterative deepening on the
   route length), bounded by ``max_hops`` (edges per route), a per-pair cap
   (``max_routes_per_pair``) and a **per-jewel** visit budget
   (:data:`_VISIT_BUDGET`, so a dense neighbourhood around one jewel cannot
   starve the others). Routes are *examples*: a pair that the exact pass
   found open but for which no route fits inside the limits stays OPEN and
   is recorded in :attr:`ReachabilityResult.truncated_pairs` (with one
   shortest witness route, possibly longer than ``max_hops``, in
   :attr:`ReachabilityResult.witness_routes`). A pair whose listed routes
   may not be *all* of its routes (cap hit, hop limit bit, budget ran out) is
   in :attr:`ReachabilityResult.incomplete_pairs`; a fix set computed over
   such a listing is not proven to cut the pair (see
   :func:`.mincut.verified_fix_set`).

Parallel edges
--------------

Two or more traversable edges between the same ordered node pair are *not*
collapsed into one hop with one fix id (that dropped the other edges' fix
ids, so the min-cut could "cut" a hop that a parallel edge still carried).
Instead, parallel edges are grouped by their ``fix_candidate_id`` (edges
with the same id — or with none — are interchangeable for cutting) and each
node path is expanded into one **route variant per combination of groups**,
each hop being one concrete edge. Cutting every variant of a node path is
exactly "for some hop, cut *all* of its parallel edges", so the hitting set
over variants is correct. To keep output deterministic and small:

* within a group the strongest edge represents it (strongest weakest-label,
  then ``rule_ref``, then port — the old "strongest wins" key), so with no
  differing fix ids the output is exactly one route per node path, as
  before;
* the *primary* variant (every hop's strongest edge) of each node path comes
  first, then variants that deviate on one hop, then on two, …; variants are
  generated lazily and count toward ``max_routes_per_pair``, so the output is
  never larger than the cap; a pair whose variants were cut off by the cap
  is in ``incomplete_pairs``.

Determinism. Neighbours are visited in sorted ``id`` order; routes are
emitted per pair shortest-first, then primary-before-alternate variants,
then lexicographically by node-id sequence. The same inputs always yield
identical output.
"""
from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass
from typing import Iterator, Optional

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

#: Backstop on DFS expansion steps **per crown jewel** for route
#: *enumeration* (it never affects open/closed, which is decided exactly).
#: Each jewel gets its own budget, so jewels later in sorted order are not
#: starved by a dense neighbourhood around an earlier one. Deterministic: the
#: search visits neighbours in a fixed order, so an early cut-off is stable,
#: and it is reported (``budget_exhausted`` / ``incomplete_pairs``).
_VISIT_BUDGET = 200_000

_INFERRED_STRENGTH = LABEL_STRENGTH[EvidenceLabel.INFERRED]


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
        return (self._weakest_strength(), self.rule_ref, repr(self.port))

    def _weakest_strength(self) -> int:
        return min(
            (LABEL_STRENGTH[lb] for lb in self.labels),
            default=LABEL_STRENGTH[EvidenceLabel.UNKNOWN],
        )

    @property
    def is_conditional(self) -> bool:
        return EvidenceLabel.CONDITIONAL in self.labels

    @property
    def is_inferred_only(self) -> bool:
        """The hop's weakest evidence is INFERRED or UNKNOWN."""
        return self._weakest_strength() <= _INFERRED_STRENGTH


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


# ---------------------------------------------------------------------------
# The traversable graph
# ---------------------------------------------------------------------------


class _Graph:
    """The traversable directed graph, reduced from nodes/edges/rulesets.

    * ``hops[(a, b)]`` — one representative :class:`_HopTemplate` per
      distinct fix-candidate group of the parallel ``a -> b`` edges, primary
      (overall strongest) first; see the module docstring.
    * ``succ`` / ``pred`` — sorted neighbour lists over all traversable
      edges; ``pred_clean`` over edges with no CONDITIONAL label;
      ``pred_evidenced`` over edges whose weakest label beats INFERRED.
    """

    def __init__(
        self,
        nodes: dict[str, Node],
        edges: list[Edge],
        rulesets: dict[str, RuleSet],
    ) -> None:
        per_pair: dict[tuple[str, str], list[_HopTemplate]] = {}
        clean: set[tuple[str, str]] = set()
        evidenced: set[tuple[str, str]] = set()
        for edge in edges:
            tmpl = _edge_template(edge, nodes, rulesets)
            if tmpl is None:
                continue
            key = (edge.src, edge.dst)
            per_pair.setdefault(key, []).append(tmpl)
            if not tmpl.is_conditional:
                clean.add(key)
            if not tmpl.is_inferred_only:
                evidenced.add(key)

        self.hops: dict[tuple[str, str], list[_HopTemplate]] = {}
        for key, tmpls in per_pair.items():
            # Stable sort, strongest first: among exact ties the earliest
            # edge in input order wins, matching the historical behaviour.
            ordered = sorted(tmpls, key=lambda t: t._strength_key(), reverse=True)
            reps: list[_HopTemplate] = []
            seen: set[frozenset[str]] = set()
            for t in ordered:
                if t.fix_candidate_ids in seen:
                    continue
                seen.add(t.fix_candidate_ids)
                reps.append(t)
            self.hops[key] = reps

        def _adj(keys, by_src: bool) -> dict[str, list[str]]:
            out: dict[str, set[str]] = {}
            for a, b in keys:
                if by_src:
                    out.setdefault(a, set()).add(b)
                else:
                    out.setdefault(b, set()).add(a)
            return {k: sorted(v) for k, v in out.items()}

        self.succ = _adj(self.hops.keys(), by_src=True)
        self.pred = _adj(self.hops.keys(), by_src=False)
        self.pred_clean = _adj(clean, by_src=False)
        self.pred_evidenced = _adj(evidenced, by_src=False)

    def primary(self, a: str, b: str) -> _HopTemplate:
        return self.hops[(a, b)][0]


def _reverse_reach(pred: dict[str, list[str]], start: str) -> set[str]:
    """Every node that can reach ``start`` (excluding ``start`` itself unless
    it lies on a cycle back to itself)."""
    seen: set[str] = set()
    queue = deque([start])
    while queue:
        cur = queue.popleft()
        for p in pred.get(cur, ()):
            if p not in seen:
                seen.add(p)
                queue.append(p)
    return seen


def _forward_dist(succ: dict[str, list[str]], start: str) -> dict[str, int]:
    """Hop distance from ``start`` to every node it reaches (start → 0)."""
    dist = {start: 0}
    queue = deque([start])
    while queue:
        cur = queue.popleft()
        for s in succ.get(cur, ()):
            if s not in dist:
                dist[s] = dist[cur] + 1
                queue.append(s)
    return dist


def _hop(a: str, b: str, tmpl: _HopTemplate) -> Hop:
    return Hop(
        src=a,
        dst=b,
        labels=tmpl.labels,
        port=tmpl.port,
        rule_ref=tmpl.rule_ref,
        fix_candidate_ids=tmpl.fix_candidate_ids,
    )


def _shortest_route(g: _Graph, entry: str, jewel: str) -> Optional[Route]:
    """A deterministic shortest route (primary edge per hop) from ``entry``
    to ``jewel`` with no hop limit, or ``None`` when unreachable. BFS with
    sorted successors and first-discovery parents."""
    parent: dict[str, str] = {entry: entry}
    queue = deque([entry])
    while queue:
        cur = queue.popleft()
        if cur == jewel and cur != entry:
            break
        for s in g.succ.get(cur, ()):
            if s not in parent:
                parent[s] = cur
                queue.append(s)
    if jewel not in parent or jewel == entry:
        return None
    seq = [jewel]
    while seq[-1] != entry:
        seq.append(parent[seq[-1]])
    seq.reverse()
    hops = [_hop(a, b, g.primary(a, b)) for a, b in zip(seq, seq[1:])]
    return Route(entry=entry, jewel=jewel, hops=hops)


def _variant_indices(counts: list[int]) -> Iterator[tuple[int, ...]]:
    """Variant index tuples for a node path whose hop ``i`` has
    ``counts[i]`` representative edges, lazily, primary first: ordered by the
    number of hops that deviate from the primary edge, then by which hops
    (lexicographic positions), then by which alternate (lexicographic)."""
    n = len(counts)
    base = [0] * n
    yield tuple(base)
    multi = [i for i, c in enumerate(counts) if c > 1]
    for k in range(1, len(multi) + 1):
        for positions in itertools.combinations(multi, k):
            for values in itertools.product(*(range(1, counts[p]) for p in positions)):
                idx = list(base)
                for p, v in zip(positions, values):
                    idx[p] = v
                yield tuple(idx)


# ---------------------------------------------------------------------------
# Bounded route enumeration for one jewel
# ---------------------------------------------------------------------------


@dataclass
class _JewelEnum:
    routes: list[tuple[tuple, Route]]
    incomplete: set[str]          # entries whose listing may be partial
    exhausted: bool


def _enumerate_jewel(
    g: _Graph,
    jewel: str,
    entries: list[str],
    reaching: dict[str, dict[str, int]],
    *,
    max_hops: int,
    cap: int,
    budget: int,
) -> _JewelEnum:
    """List up to ``cap`` routes per entry into ``jewel``, shortest first.

    Iterative deepening on the exact route length ``L = 1..max_hops``: pass
    ``L`` collects the simple paths of exactly ``L`` edges, then caps per
    pair in (variant rank, node sequence) order. A predecessor is only
    expanded when some not-yet-capped, not-on-path entry can still reach it
    within the length (``reaching[node][entry]`` is the forward BFS distance,
    an admissible lower bound), so capped pairs stop costing work and the
    search goes nowhere that cannot produce a route.
    """
    entry_set = set(entries)
    counts = {e: 0 for e in entries}
    capped: set[str] = set()
    incomplete: set[str] = set()
    out: list[tuple[tuple, Route]] = []
    remaining = [budget]
    exhausted = False

    for L in range(1, max_hops + 1):
        if len(capped) == len(entries):
            break
        last_pass = L == max_hops
        found: dict[str, list[list[str]]] = {}
        path = [jewel]
        visited = {jewel}

        def dfs(current: str, d: int) -> bool:
            """Returns False when the budget is exhausted."""
            if d == L:
                if current in entry_set and current not in capped:
                    found.setdefault(current, []).append(list(reversed(path)))
                if not last_pass:
                    return True
            for p in g.pred.get(current, ()):
                if p in visited:
                    continue
                reach = reaching.get(p)
                if not reach:
                    continue
                eligible = False
                for e, de in reach.items():
                    if e in capped or e in visited:
                        continue
                    if d + 1 + de <= L:
                        eligible = True
                        if not last_pass:
                            break
                    elif last_pass:
                        # A route for (e, jewel) through p would exceed
                        # max_hops: the listing for e may be incomplete.
                        incomplete.add(e)
                if not eligible:
                    continue
                remaining[0] -= 1
                if remaining[0] < 0:
                    return False
                visited.add(p)
                path.append(p)
                ok = dfs(p, d + 1)
                path.pop()
                visited.remove(p)
                if not ok:
                    return False
            return True

        if not dfs(jewel, 0):
            exhausted = True

        for e in sorted(found):
            capacity = cap - counts[e]
            cands: list[tuple[tuple, list[str], tuple[int, ...]]] = []
            for fwd in sorted(found[e]):
                pairs = list(zip(fwd, fwd[1:]))
                n_reps = [len(g.hops[ab]) for ab in pairs]
                for gen_i, idx in enumerate(
                    itertools.islice(_variant_indices(n_reps), capacity + 1)
                ):
                    rank = sum(1 for v in idx if v)
                    cands.append(((rank, tuple(fwd), gen_i), fwd, idx))
            cands.sort(key=lambda c: c[0])
            if len(cands) > capacity:
                incomplete.add(e)
            for key, fwd, idx in cands[:capacity]:
                hops = [
                    _hop(a, b, g.hops[(a, b)][i])
                    for (a, b), i in zip(zip(fwd, fwd[1:]), idx)
                ]
                route = Route(entry=e, jewel=jewel, hops=hops)
                out.append(((e, jewel, L) + key, route))
            counts[e] += min(len(cands), capacity)
            if counts[e] >= cap:
                capped.add(e)
                if not last_pass:
                    # Longer routes may exist that we will not list.
                    incomplete.add(e)

        if exhausted:
            incomplete.update(entries)
            break

    return _JewelEnum(routes=out, incomplete=incomplete, exhausted=exhausted)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def backward_reachability(
    nodes: dict[str, Node],
    edges: list[Edge],
    rulesets: dict[str, RuleSet],
    *,
    max_hops: int = 8,
    max_routes_per_pair: int = 16,
    visit_budget: Optional[int] = None,
) -> ReachabilityResult:
    """Decide every ``(entry, jewel)`` pair exactly and list example routes.

    ``open_pairs`` / ``closed_pairs`` / ``conditional_pairs`` /
    ``inferred_pairs`` are exact (graph reachability, no hop limit).
    ``routes`` are examples bounded by ``max_hops``, ``max_routes_per_pair``
    and ``visit_budget`` (per jewel; default :data:`_VISIT_BUDGET`);
    ``truncated_pairs``, ``incomplete_pairs``, ``witness_routes`` and
    ``budget_exhausted`` say where the listing fell short. See the module
    docstring for semantics, parallel edges, determinism and termination.
    """
    g = _Graph(nodes, edges, rulesets)

    entries = sorted(n.id for n in nodes.values() if n.role is NodeRole.ENTRY)
    jewels = sorted(n.id for n in nodes.values() if n.role is NodeRole.CROWN_JEWEL)

    # -- 1. Exact classification (no hop limit, no budget) ------------------
    all_pairs = {(e, j) for e in entries for j in jewels}
    open_pairs: set[tuple[str, str]] = set()
    clean_pairs: set[tuple[str, str]] = set()
    evidenced_pairs: set[tuple[str, str]] = set()
    for j in jewels:
        anc = _reverse_reach(g.pred, j)
        if not anc:
            continue
        anc_clean = _reverse_reach(g.pred_clean, j)
        anc_evid = _reverse_reach(g.pred_evidenced, j)
        for e in entries:
            if e == j or e not in anc:
                continue
            open_pairs.add((e, j))
            if e in anc_clean:
                clean_pairs.add((e, j))
            if e in anc_evid:
                evidenced_pairs.add((e, j))
    closed_pairs = all_pairs - open_pairs
    conditional_pairs = open_pairs - clean_pairs
    inferred_pairs = open_pairs - evidenced_pairs

    # -- 2. Bounded enumeration of example routes ---------------------------
    # reaching[node][entry] = forward hop distance entry -> node.
    reaching: dict[str, dict[str, int]] = {}
    for e in entries:
        for n, dist in _forward_dist(g.succ, e).items():
            reaching.setdefault(n, {})[e] = dist

    budget = _VISIT_BUDGET if visit_budget is None else visit_budget
    keyed: list[tuple[tuple, Route]] = []
    incomplete_pairs: set[tuple[str, str]] = set()
    budget_exhausted = False
    for j in jewels:
        reach_entries = [e for e in entries if (e, j) in open_pairs]
        if not reach_entries:
            continue
        res = _enumerate_jewel(
            g,
            j,
            reach_entries,
            reaching,
            max_hops=max_hops,
            cap=max_routes_per_pair,
            budget=budget,
        )
        keyed.extend(res.routes)
        incomplete_pairs |= {(e, j) for e in res.incomplete}
        budget_exhausted = budget_exhausted or res.exhausted

    keyed.sort(key=lambda kr: kr[0])
    routes = [r for _, r in keyed]

    # -- 3. Where the listing fell short ------------------------------------
    listed = {r.pair for r in routes}
    truncated_pairs = open_pairs - listed
    incomplete_pairs = (incomplete_pairs | truncated_pairs) & open_pairs
    witness_routes: list[Route] = []
    for e, j in sorted(truncated_pairs):
        w = _shortest_route(g, e, j)
        if w is not None:
            witness_routes.append(w)

    return ReachabilityResult(
        routes=routes,
        open_pairs=open_pairs,
        closed_pairs=closed_pairs,
        conditional_pairs=conditional_pairs,
        truncated_pairs=truncated_pairs,
        incomplete_pairs=incomplete_pairs,
        inferred_pairs=inferred_pairs,
        witness_routes=witness_routes,
        budget_exhausted=budget_exhausted,
    )


def shortest_route(
    nodes: dict[str, Node],
    edges: list[Edge],
    rulesets: dict[str, RuleSet],
    entry: str,
    jewel: str,
) -> Optional[Route]:
    """One deterministic shortest ``entry -> jewel`` route with **no hop
    limit** (each hop uses its strongest parallel edge), or ``None`` when the
    jewel is unreachable from the entry. Used as a witness for pairs whose
    routes do not fit inside the enumeration limits."""
    return _shortest_route(_Graph(nodes, edges, rulesets), entry, jewel)
