"""Ask (NL-query) + LLM triage clusters + Neo4j graph proxy (Tier 3).

Two of these endpoints are thin proxies to sibling services (brain, graphsync).
Both MUST degrade gracefully: the orchestrator never hard-fails when an
upstream is down. httpx is imported lazily so the dependency stays optional and
an import failure degrades like any other connection failure.

- `POST /v1/ask`                      forward {question, asked_by?} to brain `/ask`;
                                      on failure -> {ok:false, engine:"unavailable",
                                      note:"brain service not reachable"} (never 5xx).
- `GET  /v1/clusters`                 LLM/template triage clusters, newest first.
- `GET  /v1/graph/paths`              forward to graphsync `/paths`; degrade to
                                      {available:false, reason}.
- `GET  /v1/graph/neighborhood/{id}`  forward to graphsync `/neighborhood/{id}`;
                                      degrade to {available:false, reason}.

The brain validates/executes only read-only SELECTs over the ask_* views; this
router merely relays the question and the already-safe result.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from ..config import settings
from ..db import get_pool
from ..models import AskIn, ClusterOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["ask"])

# Short timeout for the proxied calls: a slow/dead upstream degrades quickly
# rather than stalling the request.
_PROXY_TIMEOUT = 6.0


# --------------------------------------------------------------------------- #
# Ask -> brain proxy
# --------------------------------------------------------------------------- #

@router.post("/ask")
async def ask(body: AskIn) -> dict[str, Any]:
    """Forward a natural-language question to the brain service.

    On success the brain's body is relayed verbatim (with `ok` defaulted to
    true when absent). On any connection failure -- including httpx being
    unavailable -- the response degrades to the documented unreachable body and
    a 200, so the dashboard's Ask page never sees a 5xx.
    """
    url = settings.brain_url.rstrip("/") + "/ask"
    payload = {"question": body.question, "asked_by": body.asked_by}
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("ok", True)
            return data
        # Unexpected non-object body: wrap it so the shape stays predictable.
        return {"ok": True, "engine": "unknown", "answer_rows": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("brain_unreachable", extra={"error": str(exc)})
        return {
            "ok": False,
            "engine": "unavailable",
            "note": "brain service not reachable",
        }


# --------------------------------------------------------------------------- #
# Clusters (LLM / template triage)
# --------------------------------------------------------------------------- #

@router.get("/clusters", response_model=list[ClusterOut])
async def list_clusters(
    engine: str | None = Query(None, description="'llm' | 'template'"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Finding clusters, newest first."""
    clauses: list[str] = []
    args: list[Any] = []
    if engine is not None:
        args.append(engine)
        clauses.append(f"engine = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.extend([limit, offset])
    sql = f"""
        SELECT id, label, summary, severity, finding_ids, engine,
               created_at, metadata
          FROM finding_clusters
          {where}
         ORDER BY created_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    out: list[ClusterOut] = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("metadata"), str):
            d["metadata"] = json.loads(d["metadata"])
        elif d.get("metadata") is None:
            d["metadata"] = {}
        if d.get("finding_ids") is None:
            d["finding_ids"] = []
        out.append(ClusterOut.model_validate(d))
    return out


# --------------------------------------------------------------------------- #
# Graph -> graphsync proxy
# --------------------------------------------------------------------------- #

async def _graphsync_get(path: str, params: dict[str, Any]) -> dict[str, Any]:
    """GET a graphsync endpoint, degrading to {available:false, reason} on any
    failure (unreachable, timeout, httpx missing, or a 4xx/5xx upstream)."""
    url = settings.graphsync_url.rstrip("/") + path
    clean = {k: v for k, v in params.items() if v is not None}
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.get(url, params=clean)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return data
        return {"available": True, "result": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("graphsync_unreachable", extra={"path": path, "error": str(exc)})
        return {"available": False, "reason": f"graphsync unreachable: {exc!s}"}


@router.get("/graph/paths")
async def graph_paths(
    source: str | None = None,
    target: str | None = None,
    max: int | None = Query(None, ge=1, le=20),
) -> dict[str, Any]:
    """Proxy shortest exploit-weighted paths from graphsync."""
    return await _graphsync_get(
        "/paths", {"source": source, "target": target, "max": max}
    )


@router.get("/graph/neighborhood/{asset_id}")
async def graph_neighborhood(
    asset_id: UUID,
    depth: int | None = Query(None, ge=1, le=6),
) -> dict[str, Any]:
    """Proxy a k-hop neighborhood for an asset from graphsync."""
    return await _graphsync_get(
        f"/neighborhood/{asset_id}", {"depth": depth}
    )
