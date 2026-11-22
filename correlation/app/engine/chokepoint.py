"""Choke-point engine: node-capacitated minimum cut over the asset graph.

DEFENSIVE feature. Answers the only question a CISO or insurer pays for:
*"which fewest fixes cut the most paths to our crown jewels?"* It reasons
purely over graph structure + existing open findings and never emits
exploitation steps — narratives are routed through the same reject filter
the attack-path writer uses.

Algorithm (see docs/WARGAME.md / schema 039):

* Reuse :class:`AttackPathEngine` to load the asset graph and compute the
  current ranked attack paths (same four bulk queries, no N+1).
* Build a *node-capacitated* flow network and solve it with Dinic:

  - split every asset ``v`` into ``v_in -> v_out``; that split edge carries
    the node's *removal cost*. Internet-facing sources and crown-jewel
    targets get INFINITE capacity (you never "cut" the door or the jewel),
    every intermediate asset gets capacity **1** so the min-cut *value* is
    the NUMBER of assets removed — i.e. the fewest fixes.
  - each undirected graph edge ``{u, v}`` becomes ``u_out -> v_in`` and
    ``v_out -> u_in`` with INFINITE capacity (edges are never cut, nodes are).
  - a super-source ``S`` feeds every source's ``v_in`` and every target's
    ``v_out`` feeds a super-sink ``T`` (both INFINITE).

* The max-flow value is the size of the minimum cut. Recover the actual cut
  NODE set from the residual graph: BFS the nodes reachable from ``S``; a
  split edge ``v_in -> v_out`` whose tail is reachable but whose head is not
  crosses the cut, so ``v`` is a choke point. Only finite (capacity-1)
  split edges can cross, so sources and targets are never selected.

* Rank the choke points greedily by *marginal* paths removed (cover the most
  still-uncovered attack paths first), ties broken by asset id for
  determinism. ``cut_rank`` is 1-based; ``reduction_pct`` is the cumulative
  share of paths removed through that rank.

* Upsert one row per asset by a stable fingerprint and prune stale rows in a
  single transaction, exactly like :mod:`attackpath`.

Everything is async; SQL is parameterized asyncpg. Output is deterministic
for a fixed graph.
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from decimal import Decimal
from typing import Any, Optional

from ..db import Database
from .attackpath import (
    AttackPathEngine,
    classify_source,
    classify_target,
    contains_unsafe_token,  # noqa: F401  (re-exported for callers/tests)
    entry_cost,
    is_kev_finding,
    max_severity,
    safe_narrative,
)

log = logging.getLogger(__name__)

# A very large integer used as the "infinite" capacity on uncuttable edges
# (node splits for sources/targets, and every graph edge). A finite node cut
# can be at most the number of intermediate assets, which is far below this,
# so a max-flow value >= INF means some source reaches a jewel with no
# intermediate asset to remove — there is no finite cut.
INF = 1 << 50

# Asset kinds that represent a network segment / host boundary; segmenting
# these is the natural remediation when they sit on several paths.
NETWORK_KINDS: frozenset[str] = frozenset(
    {"ipv4", "ipv6", "host", "network", "subnet", "cidr"}
)

# Asset kinds that represent an exposed access point; the cheap fix is to
# restrict reachability rather than rip the asset out.
ACCESS_KINDS: frozenset[str] = frozenset({"port", "service", "endpoint"})

# Business-value tiers that make an owner-less asset a decommission candidate.
_LOW_VALUE: frozenset[str] = frozenset({"low", "none", "minimal", "retired"})


# ----------------------------------------------------------------------------
# Dinic max-flow / min-cut (integer capacities, iterative blocking flow)
# ----------------------------------------------------------------------------

class _Dinic:
    """Dinic's algorithm. Iterative DFS so deep graphs can't blow the stack.

    Edges are stored as ``[to, residual_cap, rev_index]`` pairs; each forward
    edge has a matching reverse edge (initial cap 0) at ``rev_index`` in the
    adjacency list of ``to``.
    """

    def __init__(self, n: int) -> None:
        self.n = n
        self.graph: list[list[list[int]]] = [[] for _ in range(n)]
        self.level: list[int] = []
        self.it: list[int] = []

    def add_edge(self, u: int, v: int, cap: int) -> None:
        self.graph[u].append([v, cap, len(self.graph[v])])
        self.graph[v].append([u, 0, len(self.graph[u]) - 1])

    def _bfs(self, s: int, t: int) -> bool:
        self.level = [-1] * self.n
        self.level[s] = 0
        q: deque[int] = deque([s])
        while q:
            u = q.popleft()
            for v, cap, _ in self.graph[u]:
                if cap > 0 and self.level[v] < 0:
                    self.level[v] = self.level[u] + 1
                    q.append(v)
        return self.level[t] >= 0

    def _augment(self, s: int, t: int) -> int:
        """Find and apply one augmenting path in the current level graph."""
        stack: list[int] = [s]
        path: list[tuple[int, int]] = []  # (node, edge index taken)
        while stack:
            u = stack[-1]
            if u == t:
                push = INF
                for nu, ei in path:
                    push = min(push, self.graph[nu][ei][1])
                for nu, ei in path:
                    e = self.graph[nu][ei]
                    e[1] -= push
                    self.graph[e[0]][e[2]][1] += push
                return push
            advanced = False
            while self.it[u] < len(self.graph[u]):
                e = self.graph[u][self.it[u]]
                v, cap = e[0], e[1]
                if cap > 0 and self.level[v] == self.level[u] + 1:
                    path.append((u, self.it[u]))
                    stack.append(v)
                    advanced = True
                    break
                self.it[u] += 1
            if not advanced:
                # Dead end for this phase: prune and retreat.
                self.level[u] = -1
                stack.pop()
                if path:
                    path.pop()
        return 0

    def max_flow(self, s: int, t: int) -> int:
        flow = 0
        while self._bfs(s, t):
            self.it = [0] * self.n
            while True:
                f = self._augment(s, t)
                if f == 0:
                    break
                flow += f
                if flow >= INF:
                    return flow
        return flow

    def reachable_from(self, s: int) -> list[bool]:
        """Nodes reachable from ``s`` along edges with residual capacity.

        In the residual graph after a max flow this is the source side of the
        unique source-minimal minimum cut, so it is independent of which max
        flow was found — the recovered cut is deterministic.
        """
        seen = [False] * self.n
        seen[s] = True
        q: deque[int] = deque([s])
        while q:
            u = q.popleft()
            for v, cap, _ in self.graph[u]:
                if cap > 0 and not seen[v]:
                    seen[v] = True
                    q.append(v)
        return seen


# ----------------------------------------------------------------------------
# Pure helpers (unit-testable without a database)
# ----------------------------------------------------------------------------

def choke_fingerprint(asset_id: str) -> str:
    """Stable hash of the asset id: one choke_points row per asset per run."""
    return hashlib.sha256(asset_id.encode("utf-8")).hexdigest()


def action_hint(
    asset: dict[str, Any], findings: list[dict[str, Any]], paths_cut: int
) -> str:
    """Cheapest neutralising action, as a hint (never an exploit instruction).

    Precedence, deliberately simple and documented:

    * ``patch``        — the asset carries a KEV or critical finding.
    * ``segment``      — a network/host node sitting on multiple paths.
    * ``decommission`` — owner-less *and* flagged low business value.
    * ``restrict``     — an exposed access point (port/service/endpoint).
    * ``review``       — anything else.
    """
    kev = any(is_kev_finding(f) for f in findings)
    critical = any(f.get("severity") == "critical" for f in findings)
    if kev or critical:
        return "patch"
    kind = asset.get("kind")
    if kind in NETWORK_KINDS and paths_cut >= 2:
        return "segment"
    md = asset.get("metadata") or {}
    owner = md.get("owner")
    biz = str(md.get("business_value") or md.get("value_tier") or "").lower()
    if not owner and biz in _LOW_VALUE:
        return "decommission"
    if kind in ACCESS_KINDS:
        return "restrict"
    return "review"


def _narrative(
    asset: dict[str, Any], paths_cut: int, total_paths: int, hint: str
) -> str:
    """Neutral route-and-impact text, forced to a safe fallback if the asset
    value reads like exploitation guidance."""
    kind = asset.get("kind") or "asset"
    label = AttackPathEngine._label(asset)
    candidate = (
        f"Removing {kind}:{label} cuts {paths_cut} of {total_paths} "
        f"source-to-crown-jewel path(s). Suggested action: {hint}."
    )
    # Fallback uses only the enum-safe kind, counts, and the action hint.
    fallback = (
        f"Removing this {kind} cuts {paths_cut} of {total_paths} path(s) to "
        f"crown jewels. Suggested action: {hint}."
    )
    return safe_narrative(candidate, fallback)


def _classify(graph: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Internet-facing sources and crown-jewel targets (same rules as the
    attack-path engine). Reuses its port parent-IP lookup."""
    helper = AttackPathEngine(None)  # classification needs no database
    sources: dict[str, str] = {}
    targets: dict[str, str] = {}
    for aid, a in graph["assets"].items():
        parent_ip = (
            helper._parent_ip(graph, aid) if a["kind"] == "port" else None
        )
        is_src, sreason = classify_source(
            a, parent_ip=parent_ip, public_nets=graph["public_nets"]
        )
        if is_src:
            sources[aid] = sreason  # type: ignore[assignment]
        is_tgt, treason = classify_target(a)
        if is_tgt:
            targets[aid] = treason  # type: ignore[assignment]
    return sources, targets


def _min_cut_nodes(
    graph: dict[str, Any], sources: dict[str, str], targets: dict[str, str]
) -> list[str]:
    """Build the node-capacitated flow network, solve it, and recover the
    minimum-cut node set. Returns the choke-point asset ids (sorted)."""
    assets = graph["assets"]
    adj = graph["adj"]
    ids = sorted(assets)
    idx = {aid: i for i, aid in enumerate(ids)}

    def v_in(i: int) -> int:
        return 2 * i

    def v_out(i: int) -> int:
        return 2 * i + 1

    n = len(ids)
    S = 2 * n
    T = 2 * n + 1
    dinic = _Dinic(2 * n + 2)

    # Node splits: INFINITE for uncuttable sources/targets, 1 for intermediate.
    for aid in ids:
        i = idx[aid]
        cap = INF if (aid in sources or aid in targets) else 1
        dinic.add_edge(v_in(i), v_out(i), cap)

    # Undirected graph edges -> both directed traversals, INFINITE (never cut).
    for a in ids:
        ia = idx[a]
        for b in adj.get(a, ()):
            if a < b and b in idx:
                ib = idx[b]
                dinic.add_edge(v_out(ia), v_in(ib), INF)
                dinic.add_edge(v_out(ib), v_in(ia), INF)

    for aid in sorted(sources):
        dinic.add_edge(S, v_in(idx[aid]), INF)
    for aid in sorted(targets):
        dinic.add_edge(v_out(idx[aid]), T, INF)

    flow = dinic.max_flow(S, T)
    if flow >= INF:
        # A source reaches a jewel with no removable asset in between: no
        # finite node cut exists, so there are no choke points to recommend.
        return []

    seen = dinic.reachable_from(S)
    cut: list[str] = []
    for aid in ids:
        if aid in sources or aid in targets:
            continue
        i = idx[aid]
        if seen[v_in(i)] and not seen[v_out(i)]:
            cut.append(aid)
    return cut


def compute_choke_points(
    graph: dict[str, Any], paths: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Pure computation over an in-memory graph + the current attack paths.

    ``graph`` has the shape produced by ``AttackPathEngine._load_graph``;
    ``paths`` is the list returned by ``AttackPathEngine.compute_paths`` (each
    path has a ``"hops"`` list of ``{"asset_id", ...}``). Returns one dict per
    choke point, ranked, with keys matching the ``choke_points`` columns.
    """
    sources, targets = _classify(graph)
    if not sources or not targets:
        return []

    cut = _min_cut_nodes(graph, sources, targets)
    if not cut:
        return []

    # Which attack paths each choke point sits on (by path index).
    path_assets: list[set[str]] = [
        {h["asset_id"] for h in p.get("hops", [])} for p in paths
    ]
    total_paths = len(paths)
    on_paths: dict[str, set[int]] = {
        aid: {i for i, pa in enumerate(path_assets) if aid in pa}
        for aid in cut
    }

    # Greedy ranking: at each step pick the choke point that newly covers the
    # most still-uncovered paths; ties broken by asset id (we scan sorted and
    # keep the first strict maximum, i.e. the smallest id). Deterministic.
    remaining = sorted(cut)
    covered: set[int] = set()
    ranked: list[dict[str, Any]] = []
    rank = 0
    while remaining:
        best: Optional[str] = None
        best_marginal = -1
        for aid in remaining:
            marginal = len(on_paths[aid] - covered)
            if marginal > best_marginal:
                best, best_marginal = aid, marginal
        assert best is not None
        remaining.remove(best)
        covered |= on_paths[best]
        rank += 1

        asset = graph["assets"][best]
        findings = graph["findings_by_asset"].get(best, [])
        paths_cut = len(on_paths[best])
        hint = action_hint(asset, findings, paths_cut)
        reduction = (
            round(100.0 * len(covered) / total_paths, 2) if total_paths else 0.0
        )
        ranked.append(
            {
                "asset_id": best,
                "paths_cut": paths_cut,
                "in_min_cut": True,
                "cut_rank": rank,
                "reduction_pct": reduction,
                "total_paths": total_paths,
                "action_hint": hint,
                "narrative": _narrative(asset, paths_cut, total_paths, hint),
                "fingerprint": choke_fingerprint(best),
                "metadata": {
                    "kind": asset.get("kind"),
                    "action_hint": hint,
                    "max_severity": max_severity(findings),
                    "kev": any(is_kev_finding(f) for f in findings),
                    "removal_cost": entry_cost(findings),
                    "paths_cut": paths_cut,
                },
            }
        )
    return ranked


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------

class ChokePointEngine:
    def __init__(
        self,
        db: Database,
        redis: Any = None,
        events_stream: str = "stream:events",
    ) -> None:
        self._db = db
        self._redis = redis
        self._events_stream = events_stream
        # The attack-path engine owns the graph loader and the path computer;
        # we reuse both rather than duplicate the four bulk queries.
        self._paths_engine = AttackPathEngine(db, redis, events_stream)

    def set_redis(self, redis: Any) -> None:
        self._redis = redis
        self._paths_engine.set_redis(redis)

    async def _load_graph(self) -> dict[str, Any]:
        """Same four bulk queries as the attack-path engine (no N+1)."""
        return await self._paths_engine._load_graph()

    async def _persist(
        self, choke_points: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Upsert all choke points by fingerprint and prune stale rows in a
        single transaction, so the table always reflects the current graph.

        tenant_id is never set on INSERT — RLS / the column default fills it,
        and the conflict target is ``(tenant_id, fingerprint)``.
        """
        inserted: list[dict[str, Any]] = []
        seen = [c["fingerprint"] for c in choke_points]
        async with self._db.acquire() as conn:
            async with conn.transaction():
                for c in choke_points:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO choke_points (
                          asset_id, paths_cut, in_min_cut, cut_rank,
                          reduction_pct, total_paths, action_hint, narrative,
                          fingerprint, computed_at, metadata
                        ) VALUES (
                          $1::uuid, $2, $3, $4, $5::numeric, $6, $7, $8, $9,
                          NOW(), $10::jsonb
                        )
                        ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                          asset_id      = EXCLUDED.asset_id,
                          paths_cut     = EXCLUDED.paths_cut,
                          in_min_cut    = EXCLUDED.in_min_cut,
                          cut_rank      = EXCLUDED.cut_rank,
                          reduction_pct = EXCLUDED.reduction_pct,
                          total_paths   = EXCLUDED.total_paths,
                          action_hint   = EXCLUDED.action_hint,
                          narrative     = EXCLUDED.narrative,
                          computed_at   = NOW(),
                          metadata      = EXCLUDED.metadata
                        RETURNING id::text AS id, (xmax = 0) AS inserted
                        """,
                        c["asset_id"],
                        c["paths_cut"],
                        c["in_min_cut"],
                        c["cut_rank"],
                        Decimal(str(c["reduction_pct"])),
                        c["total_paths"],
                        c["action_hint"],
                        c["narrative"],
                        c["fingerprint"],
                        c["metadata"],
                    )
                    if row is not None and row["inserted"]:
                        inserted.append({**c, "id": row["id"]})
                # Stale cleanup: with an empty `seen`, `<> ALL('{}')` is
                # vacuously true, so the table is cleared.
                await conn.execute(
                    "DELETE FROM choke_points "
                    "WHERE fingerprint <> ALL($1::text[])",
                    seen,
                )
        return inserted

    async def run(self) -> dict[str, Any]:
        """Load the graph, compute paths + choke points, persist. Returns a
        summary."""
        started = time.monotonic()
        graph = await self._load_graph()
        paths = self._paths_engine.compute_paths(graph)
        choke_points = compute_choke_points(graph, paths)
        inserted = await self._persist(choke_points)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "choke-point run: %d choke points (%d new) over %d paths in %.1fms",
            len(choke_points),
            len(inserted),
            len(paths),
            elapsed_ms,
        )
        return {
            "choke_points": len(choke_points),
            "inserted": len(inserted),
            "elapsed_ms": elapsed_ms,
        }

    async def count(self) -> int:
        val = await self._db.fetchval("SELECT COUNT(*) FROM choke_points")
        return int(val or 0)
