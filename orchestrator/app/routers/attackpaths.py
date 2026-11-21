"""Attack-path read API + recompute trigger.

Attack paths are weighted routes through the asset graph from an
internet-facing source to a crown-jewel target. They are *computed* by the
correlation service (which writes the `attack_paths` table directly); this
router only reads them and exposes a recompute trigger.

- `GET  /v1/attack-paths` -- paged `{items,total,limit,offset}`, ordered by
  exploitability DESC, with source/target summaries and hops enriched with
  each hop's asset value/kind + max_severity (one bulk asset lookup per page,
  no N+1).
- `GET  /v1/attack-paths/{id}` -- full path, every hop enriched with its asset
  and its findings (id, title, severity).
- `POST /v1/attack-paths/recompute` -- prefer a synchronous call to the
  correlation service; fall back to a Redis job. Never fails hard when
  correlation is down.

No endpoint here aids exploitation: narratives describe routes and are stored
as the compute service wrote them; nothing is probed or launched.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..config import settings
from ..db import get_pool
from ..models import (
    AttackPathHopOut,
    AttackPathOut,
    AttackPathPage,
    HopFindingRef,
    PathAssetRef,
    RecomputeOut,
    Severity,
)
from ..queue import get_redis
from .. import tenancy
from ..service_client import service_headers

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/attack-paths", tags=["attack-paths"])


_PATH_COLS = (
    "id, source_asset_id, target_asset_id, hops, length, total_cost, "
    "exploitability, severity, title, narrative, kev_on_path, fingerprint, "
    "computed_at, metadata"
)


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _coerce_path_row(row) -> dict[str, Any]:
    """Normalize a raw attack_paths row: JSONB -> dict/list, NUMERIC -> float."""
    d = dict(row)
    for col in ("hops", "metadata"):
        v = d.get(col)
        if isinstance(v, str):
            d[col] = json.loads(v)
    if not isinstance(d.get("hops"), list):
        d["hops"] = []
    if not isinstance(d.get("metadata"), dict):
        d["metadata"] = {}
    for col in ("total_cost", "exploitability"):
        if d.get(col) is not None:
            d[col] = float(d[col])
    return d


def _hop_asset_ids(hops: list[dict[str, Any]]) -> list[UUID]:
    ids: list[UUID] = []
    for h in hops:
        aid = h.get("asset_id")
        if aid is None:
            continue
        try:
            ids.append(aid if isinstance(aid, UUID) else UUID(str(aid)))
        except (ValueError, TypeError):
            continue
    return ids


async def _asset_map(con, ids: list[UUID]) -> dict[UUID, dict[str, Any]]:
    """Bulk (value, kind) lookup for a set of asset ids. One query."""
    if not ids:
        return {}
    rows = await con.fetch(
        "SELECT id, value, kind FROM assets WHERE id = ANY($1::uuid[])",
        list({i for i in ids}),
    )
    return {r["id"]: {"value": r["value"], "kind": r["kind"]} for r in rows}


def _build_hop(
    hop: dict[str, Any],
    asset_map: dict[UUID, dict[str, Any]],
    finding_map: dict[UUID, HopFindingRef] | None = None,
) -> AttackPathHopOut:
    aid_raw = hop.get("asset_id")
    aid: UUID | None = None
    if aid_raw is not None:
        try:
            aid = aid_raw if isinstance(aid_raw, UUID) else UUID(str(aid_raw))
        except (ValueError, TypeError):
            aid = None

    enriched = asset_map.get(aid) if aid is not None else None
    # Prefer the enriched asset value/kind; fall back to what the hop carried.
    value = enriched["value"] if enriched else hop.get("value")
    kind = enriched["kind"] if enriched else hop.get("kind")

    finding_ids: list[UUID] = []
    for fid in hop.get("finding_ids") or []:
        try:
            finding_ids.append(fid if isinstance(fid, UUID) else UUID(str(fid)))
        except (ValueError, TypeError):
            continue

    findings: list[HopFindingRef] = []
    if finding_map:
        for fid in finding_ids:
            ref = finding_map.get(fid)
            if ref is not None:
                findings.append(ref)

    cost = hop.get("entry_cost")
    return AttackPathHopOut(
        asset_id=aid,
        kind=kind,
        value=value,
        max_severity=hop.get("max_severity"),
        entry_cost=float(cost) if cost is not None else None,
        edge_kind_in=hop.get("edge_kind_in"),
        finding_ids=finding_ids,
        findings=findings,
    )


def _build_path(
    d: dict[str, Any],
    asset_map: dict[UUID, dict[str, Any]],
    finding_map: dict[UUID, HopFindingRef] | None = None,
) -> AttackPathOut:
    hops = [_build_hop(h, asset_map, finding_map) for h in d.get("hops", [])]

    def _ref(aid: UUID | None) -> PathAssetRef | None:
        if aid is None:
            return None
        a = asset_map.get(aid)
        return PathAssetRef(
            id=aid,
            value=a["value"] if a else None,
            kind=a["kind"] if a else None,
        )

    return AttackPathOut(
        id=d["id"],
        source_asset_id=d["source_asset_id"],
        target_asset_id=d["target_asset_id"],
        source=_ref(d["source_asset_id"]),
        target=_ref(d["target_asset_id"]),
        length=int(d["length"]),
        total_cost=d["total_cost"],
        exploitability=d["exploitability"],
        severity=d["severity"],
        kev_on_path=bool(d["kev_on_path"]),
        title=d["title"],
        narrative=d.get("narrative"),
        hops=hops,
        computed_at=d["computed_at"],
        fingerprint=d["fingerprint"],
        metadata=d.get("metadata", {}),
    )


# --------------------------------------------------------------------------- #
# List + detail
# --------------------------------------------------------------------------- #

@router.get("", response_model=AttackPathPage)
async def list_attack_paths(
    severity: Severity | None = None,
    kev: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if severity is not None:
        args.append(severity)
        clauses.append(f"severity = ${len(args)}")
    if kev is not None:
        args.append(kev)
        clauses.append(f"kev_on_path = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    sql_count = f"SELECT COUNT(*) FROM attack_paths {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_PATH_COLS}
          FROM attack_paths
          {where}
         ORDER BY exploitability DESC, computed_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
        dicts = [_coerce_path_row(r) for r in rows]

        # One bulk asset lookup for the whole page: source, target, and every
        # hop asset across all rows (no N+1).
        wanted: set[UUID] = set()
        for d in dicts:
            if d["source_asset_id"] is not None:
                wanted.add(d["source_asset_id"])
            if d["target_asset_id"] is not None:
                wanted.add(d["target_asset_id"])
            wanted.update(_hop_asset_ids(d["hops"]))
        amap = await _asset_map(con, list(wanted))

    items = [_build_path(d, amap) for d in dicts]
    return AttackPathPage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )


@router.get("/{path_id}", response_model=AttackPathOut)
async def get_attack_path(path_id: UUID, pool=Depends(get_pool)):
    """Full path: every hop enriched with its asset + its findings."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_PATH_COLS} FROM attack_paths WHERE id = $1", path_id
        )
        if row is None:
            raise HTTPException(status_code=404, detail="attack path not found")
        d = _coerce_path_row(row)

        wanted: set[UUID] = set()
        if d["source_asset_id"] is not None:
            wanted.add(d["source_asset_id"])
        if d["target_asset_id"] is not None:
            wanted.add(d["target_asset_id"])
        wanted.update(_hop_asset_ids(d["hops"]))
        amap = await _asset_map(con, list(wanted))

        # Enrich every hop's findings (id, title, severity) in one query.
        all_fids: set[UUID] = set()
        for h in d["hops"]:
            for fid in h.get("finding_ids") or []:
                try:
                    all_fids.add(fid if isinstance(fid, UUID) else UUID(str(fid)))
                except (ValueError, TypeError):
                    continue
        finding_map: dict[UUID, HopFindingRef] = {}
        if all_fids:
            frows = await con.fetch(
                "SELECT id, title, severity FROM findings WHERE id = ANY($1::uuid[])",
                list(all_fids),
            )
            finding_map = {
                fr["id"]: HopFindingRef(
                    id=fr["id"], title=fr["title"], severity=fr["severity"]
                )
                for fr in frows
            }

    return _build_path(d, amap, finding_map)


# --------------------------------------------------------------------------- #
# Recompute trigger
# --------------------------------------------------------------------------- #

@router.post("/recompute", response_model=RecomputeOut)
async def recompute_attack_paths(r=Depends(get_redis)):
    """Trigger a recompute of attack paths.

    Preferred path: a short synchronous POST to the correlation service's
    `/compute-paths`. If that is unreachable (or httpx is unavailable), fall
    back to publishing a `correlate:recompute_paths` job on Redis. The request
    never fails hard when correlation is down -- the worst case is
    `{queued:false, reason}` (correlation unreachable *and* the enqueue failed).
    """
    url = settings.correlation_url.rstrip("/") + "/compute-paths"

    # 1) Try the synchronous correlation call.
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5.0) as http:
            resp = await http.post(url, json={}, headers=service_headers())
        if resp.status_code < 400:
            computed = None
            try:
                body = resp.json()
                if isinstance(body, dict):
                    val = body.get("computed", body.get("count"))
                    if val is not None:
                        computed = int(val)
            except Exception:  # noqa: BLE001
                computed = None
            return RecomputeOut(queued=False, computed=computed)
        logger.warning(
            "correlation_compute_paths_http_error",
            extra={"status": resp.status_code},
        )
    except Exception as exc:  # noqa: BLE001
        # Connection refused / DNS / timeout / httpx missing -> fall back.
        logger.info("correlation_unreachable_falling_back", extra={"error": str(exc)})

    # 2) Fall back to a Redis job on the correlate queue.
    try:
        await r.xadd(
            settings.queue_correlate,
            {
                "job": json.dumps(
                    {
                        "kind": "correlate_recompute_paths",
                        "op": "recompute_paths",
                        # every queued unit of work names its tenant
                        "tenant_id": tenancy.current_tenant_id(),
                    }
                )
            },
        )
        return RecomputeOut(queued=True)
    except Exception as exc:  # noqa: BLE001
        logger.exception("recompute_enqueue_failed")
        return RecomputeOut(queued=False, reason=f"correlation unreachable: {exc!s}")
