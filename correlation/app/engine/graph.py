"""Async BFS/DFS helpers over the asset graph.

Everything parameterized through asyncpg; no string concatenation into SQL.

Edge kinds exist in the schema as free text (`asset_edges.kind TEXT`) so
we don't narrow them at the DB level — callers pass `kinds=` filters.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Iterable, Optional

from ..db import Database


# Kinds we traverse by default when computing blast radius: anything that
# carries code / data between nodes or publishes them.
BLAST_EDGE_KINDS: tuple[str, ...] = (
    "hosts",
    "runs",
    "resolves_to",
    "references",
)


class Graph:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------

    async def get_asset(self, asset_id: str) -> Optional[dict[str, Any]]:
        row = await self._db.fetchrow(
            """
            SELECT id::text, kind, value, canonical, metadata, confidence,
                   source, first_seen, last_seen
            FROM assets WHERE id = $1::uuid
            """,
            asset_id,
        )
        return dict(row) if row else None

    async def _outgoing(
        self, ids: Iterable[str], kinds: Optional[tuple[str, ...]]
    ) -> list[dict[str, Any]]:
        id_list = list({str(i) for i in ids})
        if not id_list:
            return []
        if kinds:
            sql = """
                SELECT e.id::text        AS edge_id,
                       e.src_id::text    AS src_id,
                       e.dst_id::text    AS dst_id,
                       e.kind            AS edge_kind,
                       e.metadata        AS edge_metadata,
                       a.id::text        AS asset_id,
                       a.kind            AS asset_kind,
                       a.value           AS asset_value,
                       a.metadata        AS asset_metadata
                FROM asset_edges e
                JOIN assets a ON a.id = e.dst_id
                WHERE e.src_id = ANY($1::uuid[]) AND e.kind = ANY($2::text[])
            """
            rows = await self._db.fetch(sql, id_list, list(kinds))
        else:
            sql = """
                SELECT e.id::text        AS edge_id,
                       e.src_id::text    AS src_id,
                       e.dst_id::text    AS dst_id,
                       e.kind            AS edge_kind,
                       e.metadata        AS edge_metadata,
                       a.id::text        AS asset_id,
                       a.kind            AS asset_kind,
                       a.value           AS asset_value,
                       a.metadata        AS asset_metadata
                FROM asset_edges e
                JOIN assets a ON a.id = e.dst_id
                WHERE e.src_id = ANY($1::uuid[])
            """
            rows = await self._db.fetch(sql, id_list)
        return [dict(r) for r in rows]

    async def _incoming(
        self, ids: Iterable[str], kinds: Optional[tuple[str, ...]]
    ) -> list[dict[str, Any]]:
        id_list = list({str(i) for i in ids})
        if not id_list:
            return []
        if kinds:
            sql = """
                SELECT e.id::text      AS edge_id,
                       e.src_id::text  AS src_id,
                       e.dst_id::text  AS dst_id,
                       e.kind          AS edge_kind,
                       e.metadata      AS edge_metadata,
                       a.id::text      AS asset_id,
                       a.kind          AS asset_kind,
                       a.value         AS asset_value,
                       a.metadata      AS asset_metadata
                FROM asset_edges e
                JOIN assets a ON a.id = e.src_id
                WHERE e.dst_id = ANY($1::uuid[]) AND e.kind = ANY($2::text[])
            """
            rows = await self._db.fetch(sql, id_list, list(kinds))
        else:
            sql = """
                SELECT e.id::text      AS edge_id,
                       e.src_id::text  AS src_id,
                       e.dst_id::text  AS dst_id,
                       e.kind          AS edge_kind,
                       e.metadata      AS edge_metadata,
                       a.id::text      AS asset_id,
                       a.kind          AS asset_kind,
                       a.value         AS asset_value,
                       a.metadata      AS asset_metadata
                FROM asset_edges e
                JOIN assets a ON a.id = e.src_id
                WHERE e.dst_id = ANY($1::uuid[])
            """
            rows = await self._db.fetch(sql, id_list)
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    async def neighbors(
        self,
        asset_id: str,
        depth: int = 1,
        kinds: Optional[Iterable[str]] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """BFS outward for `depth` hops; return every reached asset (not the
        root). De-duplicated by asset id, ordered by first-reached."""
        depth = max(1, int(depth))
        kind_tuple = tuple(kinds) if kinds else None

        visited: set[str] = {str(asset_id)}
        order: list[dict[str, Any]] = []
        frontier: set[str] = {str(asset_id)}

        for _ in range(depth):
            if not frontier:
                break
            rows = await self._outgoing(frontier, kind_tuple)
            next_frontier: set[str] = set()
            for row in rows:
                aid = row["asset_id"]
                if aid in visited:
                    continue
                visited.add(aid)
                order.append(
                    {
                        "id": aid,
                        "kind": row["asset_kind"],
                        "value": row["asset_value"],
                        "metadata": row["asset_metadata"],
                        "via_edge": row["edge_kind"],
                    }
                )
                next_frontier.add(aid)
                if len(order) >= limit:
                    return order
            frontier = next_frontier
        return order

    async def subgraph(
        self,
        root_id: str,
        depth: int = 2,
        limit: int = 500,
        kinds: Optional[Iterable[str]] = None,
    ) -> dict[str, Any]:
        """Collect nodes and edges reachable within `depth` hops."""
        root = await self.get_asset(root_id)
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        if root:
            nodes[root_id] = {
                "id": root_id,
                "kind": root["kind"],
                "value": root["value"],
                "metadata": root["metadata"],
            }
        kind_tuple = tuple(kinds) if kinds else None
        frontier: set[str] = {str(root_id)}

        for _ in range(max(1, int(depth))):
            if not frontier or len(nodes) >= limit:
                break
            rows = await self._outgoing(frontier, kind_tuple)
            next_frontier: set[str] = set()
            for row in rows:
                aid = row["asset_id"]
                edges.append(
                    {
                        "id": row["edge_id"],
                        "src": row["src_id"],
                        "dst": row["dst_id"],
                        "kind": row["edge_kind"],
                        "metadata": row["edge_metadata"],
                    }
                )
                if aid not in nodes:
                    nodes[aid] = {
                        "id": aid,
                        "kind": row["asset_kind"],
                        "value": row["asset_value"],
                        "metadata": row["asset_metadata"],
                    }
                    next_frontier.add(aid)
                if len(nodes) >= limit:
                    break
            frontier = next_frontier

        return {"nodes": list(nodes.values()), "edges": edges}

    async def path(
        self,
        src: str,
        dst: str,
        max_depth: int = 4,
        kinds: Optional[Iterable[str]] = None,
    ) -> Optional[list[dict[str, Any]]]:
        """BFS shortest edge-path from src to dst. Returns the list of edges
        or None."""
        src, dst = str(src), str(dst)
        if src == dst:
            return []
        kind_tuple = tuple(kinds) if kinds else None

        prev: dict[str, tuple[str, dict[str, Any]]] = {}
        visited: set[str] = {src}
        frontier: list[str] = [src]

        for _ in range(max(1, int(max_depth))):
            if not frontier:
                break
            rows = await self._outgoing(frontier, kind_tuple)
            next_frontier: list[str] = []
            for row in rows:
                aid = row["asset_id"]
                if aid in visited:
                    continue
                visited.add(aid)
                prev[aid] = (
                    row["src_id"],
                    {
                        "id": row["edge_id"],
                        "src": row["src_id"],
                        "dst": row["dst_id"],
                        "kind": row["edge_kind"],
                        "metadata": row["edge_metadata"],
                    },
                )
                if aid == dst:
                    # Walk backwards.
                    out: deque[dict[str, Any]] = deque()
                    cur = dst
                    while cur != src:
                        parent, edge = prev[cur]
                        out.appendleft(edge)
                        cur = parent
                    return list(out)
                next_frontier.append(aid)
            frontier = next_frontier
        return None

    # ------------------------------------------------------------------
    # Helpers used by blast / chain scoping
    # ------------------------------------------------------------------

    async def host_of(self, asset_id: str) -> Optional[str]:
        """Nearest host-ish ancestor (ipv4/ipv6/subdomain/domain) for the
        given asset. Walks incoming edges for up to 3 hops."""
        asset = await self.get_asset(asset_id)
        if asset is None:
            return None
        if asset["kind"] in ("ipv4", "ipv6", "subdomain", "domain"):
            return asset_id

        visited: set[str] = {asset_id}
        frontier = {asset_id}
        for _ in range(3):
            rows = await self._incoming(frontier, None)
            if not rows:
                return None
            next_frontier: set[str] = set()
            for row in rows:
                aid = row["asset_id"]
                if aid in visited:
                    continue
                visited.add(aid)
                if row["asset_kind"] in (
                    "ipv4",
                    "ipv6",
                    "subdomain",
                    "domain",
                ):
                    return aid
                next_frontier.add(aid)
            frontier = next_frontier
        return None

    async def public_exposure(self, asset_id: str) -> bool:
        """True if any incoming edge within 2 hops has
        `metadata.public=true` or if the asset itself is an endpoint."""
        asset = await self.get_asset(asset_id)
        if asset is None:
            return False
        if asset["kind"] == "endpoint":
            return True
        md = asset.get("metadata") or {}
        if md.get("public") is True:
            return True

        frontier = {asset_id}
        visited: set[str] = {asset_id}
        for _ in range(2):
            rows = await self._incoming(frontier, None)
            if not rows:
                return False
            next_frontier: set[str] = set()
            for row in rows:
                aid = row["asset_id"]
                emeta = row.get("edge_metadata") or {}
                ameta = row.get("asset_metadata") or {}
                if emeta.get("public") is True or ameta.get("public") is True:
                    return True
                if row["asset_kind"] == "endpoint":
                    return True
                if aid in visited:
                    continue
                visited.add(aid)
                next_frontier.add(aid)
            frontier = next_frontier
        return False
