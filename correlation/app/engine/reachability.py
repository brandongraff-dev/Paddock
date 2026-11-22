"""Crown-jewel reachability / exposure engine.

DEFENSIVE feature. For every crown-jewel target, answers: how many
internet-facing sources can reach it, over how many current attack paths, in
how few hops, and is it currently proven-closed (no source can reach it in the
model). One row per crown jewel is persisted to `crown_jewel_exposure`.

Reuses the attack-path engine for graph loading, path computation and
source/target classification; nothing is reimplemented here. Reachability is a
hop-capped BFS (cap = attackpath.MAX_HOPS) over the undirected adjacency.
Output is deterministic for a fixed graph (ordered by asset_id).
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from decimal import Decimal
from typing import Any, Optional

from .. import tenancy
from ..db import Database
from .attackpath import (
    MAX_HOPS,
    AttackPathEngine,
    classify_source,
    classify_target,
)

log = logging.getLogger(__name__)

# Cap on source ids recorded in row metadata (the count column is uncapped).
_META_SOURCE_CAP = 20


def _classify(
    graph: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (source_reason, target_reason) maps, as attackpath classifies."""
    helper = AttackPathEngine(db=None)  # type: ignore[arg-type]
    assets = graph["assets"]
    sources: dict[str, str] = {}
    targets: dict[str, str] = {}
    for aid, a in assets.items():
        parent_ip = helper._parent_ip(graph, aid) if a["kind"] == "port" else None
        is_src, sreason = classify_source(
            a, parent_ip=parent_ip, public_nets=graph["public_nets"]
        )
        if is_src:
            sources[aid] = sreason or ""
        is_tgt, treason = classify_target(a)
        if is_tgt:
            targets[aid] = treason or ""
    return sources, targets


def _hops_from(adj: dict[str, list[str]], start: str) -> dict[str, int]:
    """BFS hop distance from `start`, bounded by MAX_HOPS."""
    dist = {start: 0}
    q: deque[str] = deque([start])
    while q:
        u = q.popleft()
        if dist[u] >= MAX_HOPS:
            continue
        for v in adj.get(u, ()):
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def compute_exposure(
    graph: dict[str, Any], paths: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Pure: one exposure dict per crown-jewel target, ordered by asset_id."""
    sources, targets = _classify(graph)
    adj = graph["adj"]

    paths_by_target: dict[str, list[dict[str, Any]]] = {}
    for p in paths:
        paths_by_target.setdefault(p["target_asset_id"], []).append(p)

    # Per target: {source_id: hops}. BFS from each target (undirected graph, so
    # symmetric) -- one BFS per jewel rather than per source.
    out: list[dict[str, Any]] = []
    for tid in sorted(targets):
        dist = _hops_from(adj, tid) if sources else {tid: 0}
        reach = {s: dist[s] for s in sources if s != tid and s in dist}
        tpaths = paths_by_target.get(tid, [])
        count = len(reach)
        open_n = len(tpaths)
        out.append(
            {
                "asset_id": tid,
                "target_reason": targets[tid],
                "reachable_source_count": count,
                "open_path_count": open_n,
                "min_hops": min(reach.values()) if reach else None,
                "max_exploitability": (
                    max(float(p["exploitability"]) for p in tpaths)
                    if tpaths
                    else 0
                ),
                "kev_on_any_path": any(bool(p.get("kev_on_path")) for p in tpaths),
                "proven_closed": count == 0 and open_n == 0,
                "metadata": {
                    "sources": sorted(reach)[:_META_SOURCE_CAP],
                    "max_hops": MAX_HOPS,
                },
            }
        )
    return out


class ReachabilityEngine:
    def __init__(
        self,
        db: Database,
        redis: Any = None,
        events_stream: str = "stream:events",
    ) -> None:
        self._db = db
        self._redis = redis
        self._events_stream = events_stream
        self._attack = AttackPathEngine(self._db)

    def set_redis(self, redis: Any) -> None:
        self._redis = redis

    async def _previously_closed(self) -> dict[str, bool]:
        rows = await self._db.fetch(
            "SELECT asset_id::text AS asset_id, proven_closed "
            "FROM crown_jewel_exposure"
        )
        return {r["asset_id"]: bool(r["proven_closed"]) for r in rows}

    async def _persist(self, rows: list[dict[str, Any]]) -> None:
        """Upsert all rows and prune stale ones in a single transaction.

        tenant_id is never passed: RLS / the column default fill it.
        """
        seen = [r["asset_id"] for r in rows]
        async with self._db.acquire() as conn:
            async with conn.transaction():
                for r in rows:
                    await conn.execute(
                        """
                        INSERT INTO crown_jewel_exposure (
                          asset_id, target_reason, reachable_source_count,
                          open_path_count, min_hops, max_exploitability,
                          kev_on_any_path, proven_closed, computed_at, metadata
                        ) VALUES (
                          $1::uuid, $2, $3, $4, $5, $6::numeric, $7, $8,
                          NOW(), $9::jsonb
                        )
                        ON CONFLICT (tenant_id, asset_id) DO UPDATE SET
                          target_reason          = EXCLUDED.target_reason,
                          reachable_source_count = EXCLUDED.reachable_source_count,
                          open_path_count        = EXCLUDED.open_path_count,
                          min_hops               = EXCLUDED.min_hops,
                          max_exploitability     = EXCLUDED.max_exploitability,
                          kev_on_any_path        = EXCLUDED.kev_on_any_path,
                          proven_closed          = EXCLUDED.proven_closed,
                          computed_at            = NOW(),
                          metadata               = EXCLUDED.metadata
                        """,
                        r["asset_id"],
                        r["target_reason"],
                        r["reachable_source_count"],
                        r["open_path_count"],
                        r["min_hops"],
                        Decimal(str(r["max_exploitability"])),
                        r["kev_on_any_path"],
                        r["proven_closed"],
                        r["metadata"],
                    )
                # Stale prune: with an empty `seen`, `<> ALL('{}')` is
                # vacuously true, so the table is cleared.
                await conn.execute(
                    "DELETE FROM crown_jewel_exposure "
                    "WHERE asset_id <> ALL($1::uuid[])",
                    seen,
                )

    async def _publish_new(
        self, rows: list[dict[str, Any]], was_closed: dict[str, bool]
    ) -> None:
        """Event for jewels newly exposed (new row, or previously closed)."""
        if self._redis is None:
            return
        for r in rows:
            if r["proven_closed"] or was_closed.get(r["asset_id"]) is False:
                continue
            event = {
                "event": "crown_jewel_exposed",
                "asset_id": r["asset_id"],
                "target_reason": r["target_reason"],
                "reachable_source_count": r["reachable_source_count"],
                "open_path_count": r["open_path_count"],
                "min_hops": r["min_hops"],
                "max_exploitability": r["max_exploitability"],
                "kev_on_any_path": r["kev_on_any_path"],
            }
            try:
                await self._redis.xadd(
                    self._events_stream,
                    {"event": json.dumps(tenancy.stamp_event(event), default=str)},
                )
            except Exception:
                log.exception("failed to publish crown_jewel_exposed event")

    async def run(self) -> dict[str, Any]:
        started = time.monotonic()
        graph = await self._attack._load_graph()
        paths = self._attack.compute_paths(graph)
        rows = compute_exposure(graph, paths)
        was_closed: dict[str, bool] = (
            await self._previously_closed() if self._redis is not None else {}
        )
        await self._persist(rows)
        await self._publish_new(rows, was_closed)
        exposed = sum(1 for r in rows if not r["proven_closed"])
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "reachability run: %d crown jewels (%d exposed) in %.1fms",
            len(rows),
            exposed,
            elapsed_ms,
        )
        return {
            "crown_jewels": len(rows),
            "exposed": exposed,
            "elapsed_ms": elapsed_ms,
        }

    async def count(self) -> int:
        val = await self._db.fetchval("SELECT COUNT(*) FROM crown_jewel_exposure")
        return int(val or 0)
