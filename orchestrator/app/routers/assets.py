"""Asset graph HTTP endpoints.

- bulk upsert by (kind, canonical) with shallow metadata merge
- list / get-one / BFS subgraph
- whole-surface top-N graph for the dashboard hero page
- edge upsert through /edges/bulk, and the `_edge`-sentinel workaround
  the passive worker currently uses inside /assets/bulk

Insert-vs-update is detected with the `xmax = 0` trick on the
INSERT ... ON CONFLICT ... DO UPDATE RETURNING row, so we know when to
publish `asset_added` / `edge_added` on the event stream. Updates don't
publish.
"""
from __future__ import annotations

import json
import logging
from collections import deque
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import Principal, classification_rank_sql, current_principal
from ..config import settings
from ..db import get_pool
from ..models import (
    AssetBulkIn,
    AssetBulkOut,
    AssetEdgeOut,
    AssetGraphOut,
    AssetIn,
    AssetKind,
    AssetOut,
    EdgeBulkIn,
    EdgeBulkOut,
    EdgeIn,
    GraphEdgeOut,
    GraphNodeOut,
    SurfaceGraphOut,
)
from ..queue import get_redis, publish_event
from ..scope import normalize

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/assets", tags=["assets"])
edges_router = APIRouter(prefix="/v1/edges", tags=["assets"])

# ABAC: an asset is visible only when its classification rank is <= the
# caller's clearance rank. Pushed into SQL so over-classified assets never
# leave the DB.
_ASSET_ABAC = f"{classification_rank_sql('a.classification')} <= "


# --------------------------------------------------------------------------- #
# Blast score (shared SQL fragment)
# --------------------------------------------------------------------------- #

def _blast_score_expr(alias: str = "a") -> str:
    """SQL expression for an asset's blast score.

    Reads the asset's own ``metadata.blast_score`` (safe cast: null unless it
    is a JSON number), and when absent falls back to the MAX blast_score among
    the asset's *open* findings. `alias` is an internal, hardcoded table alias
    (never user input), so string-building it here is injection-safe.
    """
    own = (
        f"CASE WHEN jsonb_typeof({alias}.metadata->'blast_score') = 'number' "
        f"THEN ({alias}.metadata->>'blast_score')::float ELSE NULL END"
    )
    fallback = (
        "(SELECT MAX("
        "CASE WHEN jsonb_typeof(bf.metadata->'blast_score') = 'number' "
        "THEN (bf.metadata->>'blast_score')::float ELSE NULL END) "
        f"FROM findings bf WHERE bf.asset_id = {alias}.id AND bf.status = 'open')"
    )
    return f"COALESCE({own}, {fallback})"


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #

def _canonical(kind: str, value: str, explicit: str | None) -> str:
    if explicit:
        return explicit.strip().lower()
    v = value.strip()
    if kind in {"domain", "subdomain", "ipv4", "ipv6", "endpoint"}:
        return normalize(v) or v.lower()
    # service / technology / certificate / port / etc: lowercase the full value
    return v.lower()


# --------------------------------------------------------------------------- #
# Bulk upsert (assets + _edge sentinel)
# --------------------------------------------------------------------------- #

_BULK_SQL = """
INSERT INTO assets (kind, value, canonical, source, confidence, metadata)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (tenant_id, kind, canonical) DO UPDATE SET
    last_seen = NOW(),
    metadata  = assets.metadata || EXCLUDED.metadata,
    confidence = GREATEST(assets.confidence, EXCLUDED.confidence),
    value     = COALESCE(NULLIF(EXCLUDED.value, ''), assets.value)
RETURNING id, kind, value, canonical, first_seen, last_seen, confidence,
          source, metadata, (xmax = 0) AS was_inserted
"""

_EDGE_UPSERT_SQL = """
INSERT INTO asset_edges (src_id, dst_id, kind, metadata)
VALUES ($1, $2, $3, $4::jsonb)
ON CONFLICT (src_id, dst_id, kind) DO UPDATE SET
    last_seen = NOW(),
    metadata = asset_edges.metadata || EXCLUDED.metadata
RETURNING id, src_id, dst_id, kind, first_seen, last_seen, metadata,
          (xmax = 0) AS was_inserted
"""


def _edge_metadata(item: AssetIn) -> dict[str, Any]:
    """Pick the shape the passive worker uses in `_edge` items.

    The worker sends either {src_kind, src_canonical, dst_kind, dst_canonical,
    edge_kind, edge_metadata?} or the older {src_kind, src_value, dst_kind,
    dst_value, kind} shape (see docs/PASSIVE_NOTES.md section 3). We accept
    both and look up by (kind, canonical) in both cases.
    """
    md = item.metadata or {}
    src_kind = md.get("src_kind")
    src_canonical = md.get("src_canonical") or md.get("src_value")
    dst_kind = md.get("dst_kind")
    dst_canonical = md.get("dst_canonical") or md.get("dst_value")
    edge_kind = md.get("edge_kind") or md.get("kind")
    edge_metadata = md.get("edge_metadata") or {
        k: v
        for k, v in md.items()
        if k
        not in {
            "src_kind",
            "src_canonical",
            "src_value",
            "dst_kind",
            "dst_canonical",
            "dst_value",
            "edge_kind",
            "kind",
            "edge_metadata",
        }
    }
    return {
        "src_kind": src_kind,
        "src_canonical": src_canonical,
        "dst_kind": dst_kind,
        "dst_canonical": dst_canonical,
        "edge_kind": edge_kind,
        "edge_metadata": edge_metadata,
    }


async def _resolve_endpoint(con, kind: str | None, canonical: str | None) -> UUID | None:
    if not kind or not canonical:
        return None
    row = await con.fetchrow(
        "SELECT id FROM assets WHERE kind = $1 AND canonical = $2",
        kind,
        _canonical(kind, canonical, None),
    )
    return row["id"] if row else None


@router.post("/bulk", response_model=AssetBulkOut)
async def bulk_upsert(
    body: AssetBulkIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    inserted = 0
    updated = 0
    edges_inserted = 0
    edges_updated = 0
    edges_skipped = 0
    out: list[AssetOut] = []
    asset_events: list[dict[str, Any]] = []
    edge_events: list[dict[str, Any]] = []

    # Partition the payload: real assets first (so later `_edge` items can
    # resolve their endpoints inside the same bulk call), edges second.
    real_assets: list[AssetIn] = []
    edge_items: list[AssetIn] = []
    for item in body.items:
        if item.kind == "_edge":
            edge_items.append(item)
        else:
            real_assets.append(item)

    async with pool.acquire() as con:
        async with con.transaction():
            for item in real_assets:
                canonical = _canonical(item.kind, item.value, item.canonical)
                row = await con.fetchrow(
                    _BULK_SQL,
                    item.kind,
                    item.value,
                    canonical,
                    item.source,
                    item.confidence,
                    json.dumps(item.metadata),
                )
                d = dict(row)
                was_inserted = d.pop("was_inserted")
                if was_inserted:
                    inserted += 1
                    asset_events.append(
                        {
                            "event": "asset_added",
                            "asset_id": str(d["id"]),
                            "kind": d["kind"],
                            "value": d["value"],
                            "canonical": d["canonical"],
                            "source": d["source"],
                            "ts": d["first_seen"].isoformat(),
                        }
                    )
                else:
                    updated += 1
                if isinstance(d.get("metadata"), str):
                    d["metadata"] = json.loads(d["metadata"])
                out.append(AssetOut.model_validate(d))

            # Now materialize the edges.
            for item in edge_items:
                parsed = _edge_metadata(item)
                src_id = await _resolve_endpoint(
                    con, parsed["src_kind"], parsed["src_canonical"]
                )
                dst_id = await _resolve_endpoint(
                    con, parsed["dst_kind"], parsed["dst_canonical"]
                )
                if src_id is None or dst_id is None or not parsed["edge_kind"]:
                    edges_skipped += 1
                    continue
                erow = await con.fetchrow(
                    _EDGE_UPSERT_SQL,
                    src_id,
                    dst_id,
                    parsed["edge_kind"],
                    json.dumps(parsed["edge_metadata"] or {}),
                )
                was_inserted = erow["was_inserted"]
                if was_inserted:
                    edges_inserted += 1
                    edge_events.append(
                        {
                            "event": "edge_added",
                            "edge_id": str(erow["id"]),
                            "src_id": str(src_id),
                            "dst_id": str(dst_id),
                            "kind": erow["kind"],
                        }
                    )
                else:
                    edges_updated += 1

    # Publish *after* the transaction so we never emit for a rolled-back row.
    for ev in (*asset_events, *edge_events):
        try:
            await publish_event(r, ev)
        except Exception:
            logger.exception("publish_event_failed", extra=ev)

    return AssetBulkOut(
        inserted=inserted,
        updated=updated,
        items=out,
        edges_inserted=edges_inserted,
        edges_updated=edges_updated,
        edges_skipped_missing_endpoint=edges_skipped,
    )


# --------------------------------------------------------------------------- #
# Dedicated edges endpoint for clean callers
# --------------------------------------------------------------------------- #

@edges_router.post("/bulk", response_model=EdgeBulkOut)
async def bulk_edges(
    body: EdgeBulkIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    edges_inserted = 0
    edges_updated = 0
    edges_skipped = 0
    events: list[dict[str, Any]] = []

    async with pool.acquire() as con:
        async with con.transaction():
            for e in body.edges:
                src_id = e.src_id
                dst_id = e.dst_id
                if src_id is None:
                    src_id = await _resolve_endpoint(
                        con, e.src_kind, e.src_canonical
                    )
                if dst_id is None:
                    dst_id = await _resolve_endpoint(
                        con, e.dst_kind, e.dst_canonical
                    )
                if src_id is None or dst_id is None:
                    edges_skipped += 1
                    continue
                erow = await con.fetchrow(
                    _EDGE_UPSERT_SQL,
                    src_id,
                    dst_id,
                    e.kind,
                    json.dumps(e.metadata or {}),
                )
                was_inserted = erow["was_inserted"]
                if was_inserted:
                    edges_inserted += 1
                    events.append(
                        {
                            "event": "edge_added",
                            "edge_id": str(erow["id"]),
                            "src_id": str(src_id),
                            "dst_id": str(dst_id),
                            "kind": erow["kind"],
                        }
                    )
                else:
                    edges_updated += 1

    for ev in events:
        try:
            await publish_event(r, ev)
        except Exception:
            logger.exception("publish_event_failed", extra=ev)

    return EdgeBulkOut(
        edges_inserted=edges_inserted,
        edges_updated=edges_updated,
        edges_skipped_missing_endpoint=edges_skipped,
    )


# --------------------------------------------------------------------------- #
# Whole-surface graph for the dashboard hero
# --------------------------------------------------------------------------- #

@router.get("/graph", response_model=SurfaceGraphOut)
async def surface_graph(
    limit: int = Query(500, ge=1, le=2000),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Top-N most-connected assets + the edges among them.

    Degree = number of asset_edges rows the asset participates in on either
    side. `open_high_crit_count` is the count of open high-or-critical
    findings on the asset, so the UI can style the glow ring.
    """
    top_sql = """
        WITH degree_counts AS (
            SELECT asset_id, COUNT(*) AS degree
              FROM (
                SELECT src_id AS asset_id FROM asset_edges
                UNION ALL
                SELECT dst_id AS asset_id FROM asset_edges
              ) e
             GROUP BY asset_id
        ),
        hi_findings AS (
            SELECT asset_id, COUNT(*) AS c
              FROM findings
             WHERE status = 'open' AND severity IN ('high', 'critical')
             GROUP BY asset_id
        )
        SELECT a.id, a.kind, a.value, a.canonical, a.metadata,
               COALESCE(d.degree, 0) AS degree,
               COALESCE(f.c, 0) AS open_high_crit_count,
               {blast} AS blast_score
          FROM assets a
     LEFT JOIN degree_counts d ON d.asset_id = a.id
     LEFT JOIN hi_findings f ON f.asset_id = a.id
         WHERE {abac}$2
         ORDER BY degree DESC, a.last_seen DESC
         LIMIT $1
    """.format(blast=_blast_score_expr("a"), abac=_ASSET_ABAC)
    async with pool.acquire() as con:
        node_rows = await con.fetch(top_sql, limit, principal.clearance_rank)
        node_ids = [r["id"] for r in node_rows]
        if node_ids:
            edge_rows = await con.fetch(
                """
                SELECT id, src_id, dst_id, kind
                  FROM asset_edges
                 WHERE src_id = ANY($1::uuid[]) AND dst_id = ANY($1::uuid[])
                """,
                node_ids,
            )
        else:
            edge_rows = []

    nodes: list[GraphNodeOut] = []
    for r in node_rows:
        md = r["metadata"]
        if isinstance(md, str):
            md = json.loads(md)
        nodes.append(
            GraphNodeOut(
                id=r["id"],
                kind=r["kind"],
                value=r["value"],
                canonical=r["canonical"],
                degree=int(r["degree"]),
                open_high_crit_count=int(r["open_high_crit_count"]),
                metadata=md or {},
                blast_score=r["blast_score"],
            )
        )
    edges = [
        GraphEdgeOut(id=r["id"], src_id=r["src_id"], dst_id=r["dst_id"], kind=r["kind"])
        for r in edge_rows
    ]
    return SurfaceGraphOut(nodes=nodes, edges=edges)


# --------------------------------------------------------------------------- #
# List + get
# --------------------------------------------------------------------------- #

@router.get("", response_model=list[AssetOut])
async def list_assets(
    kind: AssetKind | None = None,
    value: str | None = None,
    canonical: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    clauses: list[str] = []
    args: list[Any] = []
    if kind is not None:
        args.append(kind)
        clauses.append(f"kind = ${len(args)}")
    if value is not None:
        args.append(value)
        clauses.append(f"value ILIKE ${len(args)}")
    if canonical is not None:
        args.append(canonical.lower())
        clauses.append(f"canonical = ${len(args)}")
    args.append(principal.clearance_rank)
    clauses.append(f"{_ASSET_ABAC}${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.extend([limit, offset])
    sql = f"""
        SELECT a.id, a.kind, a.value, a.canonical, a.first_seen, a.last_seen,
               a.confidence, a.source, a.metadata, a.classification,
               {_blast_score_expr("a")} AS blast_score
          FROM assets a
          {where}
         ORDER BY a.last_seen DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [_row_to_asset(r) for r in rows]


@router.get("/{asset_id}", response_model=AssetGraphOut)
async def get_asset(
    asset_id: UUID,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Asset + depth-1 neighbourhood."""
    graph = await _bfs_subgraph(pool, asset_id, depth=1, clearance_rank=principal.clearance_rank)
    if not graph.nodes:
        raise HTTPException(status_code=404, detail="asset not found")
    return graph


@router.get("/{asset_id}/graph", response_model=AssetGraphOut)
async def get_asset_graph(
    asset_id: UUID,
    depth: int = Query(2, ge=1, le=settings.graph_max_depth),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    graph = await _bfs_subgraph(
        pool, asset_id, depth=depth, clearance_rank=principal.clearance_rank
    )
    if not graph.nodes:
        raise HTTPException(status_code=404, detail="asset not found")
    return graph


# --------------------------------------------------------------------------- #
# BFS implementation
# --------------------------------------------------------------------------- #

async def _bfs_subgraph(
    pool, root: UUID, depth: int, clearance_rank: int = 3
) -> AssetGraphOut:
    depth = min(depth, settings.graph_max_depth)
    node_cap = settings.graph_max_nodes

    visited: set[UUID] = set()
    nodes_by_id: dict[UUID, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    truncated = False

    async with pool.acquire() as con:
        root_row = await con.fetchrow(
            f"""
            SELECT a.id, a.kind, a.value, a.canonical, a.first_seen, a.last_seen,
                   a.confidence, a.source, a.metadata, a.classification,
                   {_blast_score_expr("a")} AS blast_score
              FROM assets a WHERE a.id = $1
                AND {_ASSET_ABAC}$2
            """,
            root,
            clearance_rank,
        )
        if root_row is None:
            return AssetGraphOut(
                root=root, depth=depth, truncated=False, nodes=[], edges=[]
            )
        nodes_by_id[root] = dict(root_row)
        visited.add(root)

        frontier: deque[tuple[UUID, int]] = deque([(root, 0)])
        while frontier:
            current, d = frontier.popleft()
            if d >= depth:
                continue
            if len(nodes_by_id) >= node_cap:
                truncated = True
                break

            edge_rows = await con.fetch(
                """
                SELECT id, src_id, dst_id, kind, first_seen, last_seen, metadata
                  FROM asset_edges
                 WHERE src_id = $1 OR dst_id = $1
                """,
                current,
            )
            neighbour_ids: list[UUID] = []
            for er in edge_rows:
                edges.append(dict(er))
                other = er["dst_id"] if er["src_id"] == current else er["src_id"]
                if other not in visited:
                    neighbour_ids.append(other)

            if neighbour_ids:
                asset_rows = await con.fetch(
                    f"""
                    SELECT a.id, a.kind, a.value, a.canonical, a.first_seen,
                           a.last_seen, a.confidence, a.source, a.metadata,
                           a.classification,
                           {_blast_score_expr("a")} AS blast_score
                      FROM assets a
                     WHERE a.id = ANY($1::uuid[])
                       AND {_ASSET_ABAC}$2
                    """,
                    neighbour_ids,
                    clearance_rank,
                )
                for ar in asset_rows:
                    aid = ar["id"]
                    if aid in visited:
                        continue
                    if len(nodes_by_id) >= node_cap:
                        truncated = True
                        break
                    nodes_by_id[aid] = dict(ar)
                    visited.add(aid)
                    frontier.append((aid, d + 1))

    seen_edges: set[UUID] = set()
    unique_edges: list[dict[str, Any]] = []
    for e in edges:
        if e["id"] in seen_edges:
            continue
        seen_edges.add(e["id"])
        unique_edges.append(e)

    return AssetGraphOut(
        root=root,
        depth=depth,
        truncated=truncated,
        nodes=[_dict_to_asset(d) for d in nodes_by_id.values()],
        edges=[_dict_to_edge(d) for d in unique_edges],
    )


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _row_to_asset(row) -> AssetOut:
    d = dict(row)
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    return AssetOut.model_validate(d)


def _dict_to_asset(d: dict[str, Any]) -> AssetOut:
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    return AssetOut.model_validate(d)


def _dict_to_edge(d: dict[str, Any]) -> AssetEdgeOut:
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    return AssetEdgeOut.model_validate(d)
