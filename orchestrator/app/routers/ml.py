"""Adaptive ML risk + anomaly read/ack API and the retrain proxy (Tier 4).

The mlrisk service (`mlrisk/`, HTTP :8098) learns from analyst triage to rank
open findings (`ml_risk_scores`), flags statistical outliers (`anomalies`), and
versions every training run (`ml_models`, newest marked active). This router is
*read + ack*: it serves learned scores (with their explainability rationale),
the active models, and the anomaly feed; it flips an anomaly's ack flag; and it
proxies a retrain request to the mlrisk service, degrading cleanly if it is down.

- `GET  /v1/ml/risk?limit=&offset=`            scores joined to finding+asset,
                                               ml_risk DESC, incl rationale.
- `GET  /v1/ml/model`                          active models per kind + metrics
                                               + feature importance + cold_start.
- `POST /v1/ml/retrain`                         proxy to mlrisk `/retrain`;
                                               degrade to {ok:false, note} if down.
- `GET  /v1/anomalies?acknowledged=&severity=&limit=&offset=`  paged, score DESC.
- `POST /v1/anomalies/{id}/ack`                 set acknowledged.

The ML layer explains its scores (feature contributions) and flags cold-start;
it ranks and surfaces -- humans decide. No exploitation, no attack automation.
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
    AnomalyOut,
    AnomalyPage,
    MlModelOut,
    MlRiskAssetRef,
    MlRiskFindingRef,
    MlRiskPage,
    MlRiskRationale,
    MlRiskRow,
    Severity,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ml", tags=["ml"])
anomalies_router = APIRouter(prefix="/v1/anomalies", tags=["ml"])

# Short timeout for the proxied retrain call: a slow/dead upstream degrades
# quickly rather than stalling the request (mirrors ask.py).
_PROXY_TIMEOUT = 6.0

_SEV_ARRAY = "ARRAY['info','low','medium','high','critical']"


# --------------------------------------------------------------------------- #
# ML risk scores (learned ranking + explainability)
# --------------------------------------------------------------------------- #

def _row_to_ml_risk(row) -> MlRiskRow:
    d = dict(row)
    rationale_raw = d.get("rationale")
    if isinstance(rationale_raw, str):
        rationale_raw = json.loads(rationale_raw)
    if not isinstance(rationale_raw, list):
        rationale_raw = []
    rationale = [
        MlRiskRationale.model_validate(item)
        for item in rationale_raw
        if isinstance(item, dict) and "feature" in item
    ]
    finding = MlRiskFindingRef(
        title=d.get("finding_title"),
        severity=d.get("finding_severity"),
        rule_source=d.get("finding_rule_source"),
    )
    asset = MlRiskAssetRef(value=d.get("asset_value"), kind=d.get("asset_kind"))
    return MlRiskRow(
        finding_id=d["finding_id"],
        ml_risk=float(d["ml_risk"]),
        model_version=d.get("model_version"),
        rationale=rationale,
        scored_at=d.get("scored_at"),
        finding=finding,
        asset=asset,
    )


@router.get("/risk", response_model=MlRiskPage)
async def list_ml_risk(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Learned per-finding risk scores, highest `ml_risk` first.

    Each row carries the finding + asset summary and the rationale (top
    contributing signals) so the dashboard can show *why* it ranked high.
    Joined in one query (no N+1).
    """
    sql_count = "SELECT COUNT(*) FROM ml_risk_scores s JOIN findings f ON f.id = s.finding_id"
    sql = """
        SELECT s.finding_id, s.ml_risk, s.model_version, s.rationale, s.scored_at,
               f.title AS finding_title,
               f.severity AS finding_severity,
               f.rule_source AS finding_rule_source,
               a.value AS asset_value,
               a.kind AS asset_kind
          FROM ml_risk_scores s
          JOIN findings f ON f.id = s.finding_id
          LEFT JOIN assets a ON a.id = f.asset_id
         ORDER BY s.ml_risk DESC, s.scored_at DESC
         LIMIT $1 OFFSET $2
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count)
        rows = await con.fetch(sql, limit, offset)
    items = [_row_to_ml_risk(r) for r in rows]
    return MlRiskPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# Active models (risk_ranker + anomaly_detector)
# --------------------------------------------------------------------------- #

def _row_to_model(row) -> MlModelOut:
    d = dict(row)
    for col in ("metrics", "feature_importance"):
        if isinstance(d.get(col), str):
            d[col] = json.loads(d[col])
        elif d.get(col) is None:
            d[col] = {}
    return MlModelOut.model_validate(d)


@router.get("/model")
async def get_active_models(pool=Depends(get_pool)) -> dict[str, Any]:
    """The active model of each kind (null when none trained yet).

    Shape: {risk_ranker: {...}|null, anomaly_detector: {...}|null}. When more
    than one is somehow active for a kind, the highest version wins.
    """
    sql = """
        SELECT id, kind, version, algo, trained_at, n_samples, metrics,
               feature_importance, cold_start, active, notes
          FROM ml_models
         WHERE active = TRUE
         ORDER BY kind, version DESC
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql)
    out: dict[str, Any] = {"risk_ranker": None, "anomaly_detector": None}
    for r in rows:
        kind = r["kind"]
        if kind in out and out[kind] is None:
            out[kind] = _row_to_model(r)
    return out


# --------------------------------------------------------------------------- #
# Retrain proxy -> mlrisk
# --------------------------------------------------------------------------- #

@router.post("/retrain")
async def retrain(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Forward a retrain request to the mlrisk service.

    On success the mlrisk body is relayed verbatim (with `ok` defaulted to
    true). On any connection failure -- including httpx being unavailable --
    the response degrades to {ok:false, note:...} and a 200, so the dashboard
    never sees a 5xx.
    """
    url = settings.mlrisk_url.rstrip("/") + "/retrain"
    payload = body or {}
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("ok", True)
            return data
        return {"ok": True, "result": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("mlrisk_unreachable", extra={"error": str(exc)})
        return {"ok": False, "note": f"mlrisk service not reachable: {exc!s}"}


# --------------------------------------------------------------------------- #
# Anomalies (paged feed + ack)
# --------------------------------------------------------------------------- #

def _row_to_anomaly(row) -> AnomalyOut:
    d = dict(row)
    if isinstance(d.get("features"), str):
        d["features"] = json.loads(d["features"])
    elif d.get("features") is None:
        d["features"] = {}
    if d.get("score") is not None:
        d["score"] = float(d["score"])
    return AnomalyOut.model_validate(d)


_ANOMALY_COLS = (
    "id, subject_type, subject_id, subject_label, score, severity, reason, "
    "features, model_version, detected_at, acknowledged"
)


@anomalies_router.get("", response_model=AnomalyPage)
async def list_anomalies(
    acknowledged: bool | None = Query(None, description="filter by ack state"),
    severity: Severity | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Paged anomaly feed, most anomalous (highest score) first."""
    clauses: list[str] = []
    args: list[Any] = []
    if acknowledged is not None:
        args.append(acknowledged)
        clauses.append(f"acknowledged = ${len(args)}")
    if severity is not None:
        args.append(severity)
        clauses.append(f"severity = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql_count = f"SELECT COUNT(*) FROM anomalies {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_ANOMALY_COLS}
          FROM anomalies
          {where}
         ORDER BY score DESC, detected_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_anomaly(r) for r in rows]
    return AnomalyPage(items=items, total=int(total or 0), limit=limit, offset=offset)


@anomalies_router.post("/{anomaly_id}/ack", response_model=AnomalyOut)
async def ack_anomaly(anomaly_id: UUID, pool=Depends(get_pool)):
    """Mark an anomaly acknowledged (idempotent)."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            UPDATE anomalies SET acknowledged = TRUE
             WHERE id = $1
         RETURNING {_ANOMALY_COLS}
            """,
            anomaly_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="anomaly not found")
    return _row_to_anomaly(row)
