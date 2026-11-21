"""Threat-intel fusion read/config API + proxy (schema 013).

The `threatintel/` service (HTTP :8100) ingests STIX 2.1 / TAXII 2.1 IOCs into
`ti_indicators`, matches them DEFENSIVELY against the owner's own assets +
findings, and writes `ti_matches` plus `threat_intel` findings. This router is
mostly *read + config*: it serves indicators, matches (the important part --
"your asset X is a known-bad indicator Y"), feeds, and a summary, and it stores
the user-configured feed rows. The two *network* actions (poll a feed, ingest a
bundle) are PROXIED to the threatintel service and DEGRADE cleanly when it is
down -- never a 5xx.

- `GET    /v1/ti/feeds`                 list configured feeds.
- `POST   /v1/ti/feeds`                 register a TAXII / STIX_URL feed (stored).
- `DELETE /v1/ti/feeds/{id}`            remove a feed.
- `POST   /v1/ti/feeds/{id}/poll`       proxy poll -> threatintel; degrade if down.
- `GET    /v1/ti/indicators`            paged; filter type / label / q.
- `GET    /v1/ti/matches`               paged; join indicator + subject summary.
- `POST   /v1/ti/ingest`                proxy a STIX bundle -> threatintel; degrade.
- `GET    /v1/ti/summary`               counts by indicator type + match + feed count.

Nothing here scans or contacts an indicator; the service only ever reaches
user-configured feed URLs. These endpoints surface where YOUR surface is
exposed.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..config import settings
from ..db import get_pool
from ..service_client import service_headers

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ti", tags=["threat-intel"])

# Short timeout for proxied calls: a slow/dead upstream degrades fast rather
# than stalling the request (mirrors ml.py / ask.py).
_PROXY_TIMEOUT = 8.0

_SEV_ARRAY = "ARRAY['info','low','medium','high','critical']"

IndicatorType = str  # ti_indicators.type CHECK: ipv4/ipv6/domain/url/file_*/email/cidr
FeedKind = str       # ti_feeds.kind CHECK: taxii/stix_url/stix_upload/manual


def _threatintel_url() -> str:
    """Base URL of the threatintel service (config-driven, with a safe default)."""
    return str(getattr(settings, "threatintel_url", "http://threatintel:8100")).rstrip("/")


# --------------------------------------------------------------------------- #
# Local response models (we do not touch the shared models.py).
# --------------------------------------------------------------------------- #

class TiFeedIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    kind: str = Field(description="taxii | stix_url | stix_upload | manual")
    url: str | None = None
    collection: str | None = None
    enabled: bool = True


class TiFeedOut(BaseModel):
    id: UUID
    name: str
    kind: str
    url: str | None = None
    collection: str | None = None
    enabled: bool
    last_poll: datetime | None = None
    last_status: str | None = None
    indicator_count: int = 0
    created_at: datetime


class TiIndicatorOut(BaseModel):
    id: UUID
    stix_id: str | None = None
    type: str
    value: str
    pattern: str | None = None
    labels: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)
    threat_actor: str | None = None
    confidence: int = 50
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    feed_id: UUID | None = None
    feed_name: str | None = None
    source: str | None = None
    created_at: datetime


class TiIndicatorPage(BaseModel):
    items: list[TiIndicatorOut]
    total: int
    limit: int
    offset: int


class TiMatchSubject(BaseModel):
    """A compact view of what matched -- the owner's asset (or a finding's asset)."""
    asset_id: UUID | None = None
    asset_kind: str | None = None
    asset_value: str | None = None
    finding_id: UUID | None = None
    finding_title: str | None = None
    finding_severity: str | None = None


class TiMatchIndicator(BaseModel):
    id: UUID
    type: str
    value: str
    labels: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)
    threat_actor: str | None = None
    confidence: int = 50


class TiMatchOut(BaseModel):
    id: UUID
    subject_type: str
    matched_value: str
    severity: str
    finding_id: UUID | None = None
    matched_at: datetime
    indicator: TiMatchIndicator
    subject: TiMatchSubject


class TiMatchPage(BaseModel):
    items: list[TiMatchOut]
    total: int
    limit: int
    offset: int


class TiSummary(BaseModel):
    indicators: int
    matches: int
    feeds: int
    by_type: dict[str, int]


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _row_to_feed(row) -> TiFeedOut:
    return TiFeedOut.model_validate(dict(row))


def _row_to_indicator(row) -> TiIndicatorOut:
    d = dict(row)
    d["labels"] = list(d.get("labels") or [])
    d["malware"] = list(d.get("malware") or [])
    if d.get("confidence") is not None:
        d["confidence"] = int(d["confidence"])
    return TiIndicatorOut.model_validate(d)


def _row_to_match(row) -> TiMatchOut:
    d = dict(row)
    indicator = TiMatchIndicator(
        id=d["indicator_id"],
        type=d["indicator_type"],
        value=d["indicator_value"],
        labels=list(d.get("indicator_labels") or []),
        malware=list(d.get("indicator_malware") or []),
        threat_actor=d.get("indicator_threat_actor"),
        confidence=int(d.get("indicator_confidence") or 50),
    )
    subject = TiMatchSubject(
        asset_id=d.get("asset_id"),
        asset_kind=d.get("asset_kind"),
        asset_value=d.get("asset_value"),
        finding_id=d.get("subject_finding_id"),
        finding_title=d.get("finding_title"),
        finding_severity=d.get("finding_severity"),
    )
    return TiMatchOut(
        id=d["id"],
        subject_type=d["subject_type"],
        matched_value=d["matched_value"],
        severity=d["severity"],
        finding_id=d.get("finding_id"),
        matched_at=d["matched_at"],
        indicator=indicator,
        subject=subject,
    )


# --------------------------------------------------------------------------- #
# Feeds (config, stored server-side in ti_feeds)
# --------------------------------------------------------------------------- #

_FEED_COLS = (
    "id, name, kind, url, collection, enabled, last_poll, last_status, "
    "indicator_count, created_at"
)


@router.get("/feeds", response_model=list[TiFeedOut])
async def list_feeds(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_FEED_COLS} FROM ti_feeds ORDER BY created_at DESC"
        )
    return [_row_to_feed(r) for r in rows]


@router.post("/feeds", response_model=TiFeedOut, status_code=201)
async def create_feed(body: TiFeedIn, pool=Depends(get_pool)):
    if body.kind not in ("taxii", "stix_url", "stix_upload", "manual"):
        raise HTTPException(status_code=422, detail="invalid feed kind")
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            INSERT INTO ti_feeds (name, kind, url, collection, enabled)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (name) DO UPDATE SET
                kind = EXCLUDED.kind,
                url = EXCLUDED.url,
                collection = EXCLUDED.collection,
                enabled = EXCLUDED.enabled
            RETURNING {_FEED_COLS}
            """,
            body.name, body.kind, body.url, body.collection, body.enabled,
        )
    return _row_to_feed(row)


@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(feed_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        result = await con.execute("DELETE FROM ti_feeds WHERE id = $1", feed_id)
    if not result.endswith(" 1"):
        raise HTTPException(status_code=404, detail="feed not found")
    return None


@router.post("/feeds/{feed_id}/poll")
async def poll_feed(feed_id: UUID, pool=Depends(get_pool)) -> dict[str, Any]:
    """Proxy a poll to the threatintel service; degrade if it is unreachable."""
    # Confirm the feed exists locally so we give a clean 404 without a round-trip.
    async with pool.acquire() as con:
        exists = await con.fetchval("SELECT 1 FROM ti_feeds WHERE id = $1", feed_id)
    if not exists:
        raise HTTPException(status_code=404, detail="feed not found")
    url = f"{_threatintel_url()}/poll/{feed_id}"
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.post(url, headers=service_headers())
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("ok", True)
            return data
        return {"ok": True, "result": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("threatintel_unreachable", extra={"error": str(exc), "op": "poll"})
        return {"ok": False, "note": f"threatintel service not reachable: {exc!s}"}


# --------------------------------------------------------------------------- #
# Indicators (paged)
# --------------------------------------------------------------------------- #

_IND_COLS = (
    "i.id, i.stix_id, i.type, i.value, i.pattern, i.labels, i.malware, "
    "i.threat_actor, i.confidence, i.valid_from, i.valid_until, i.feed_id, "
    "i.source, i.created_at, f.name AS feed_name"
)


@router.get("/indicators", response_model=TiIndicatorPage)
async def list_indicators(
    type: str | None = Query(None, description="indicator type filter"),
    label: str | None = Query(None, description="match a single label"),
    q: str | None = Query(None, description="substring match on value"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if type is not None:
        args.append(type)
        clauses.append(f"i.type = ${len(args)}")
    if label is not None:
        args.append(label)
        clauses.append(f"${len(args)} = ANY(i.labels)")
    if q is not None:
        args.append(f"%{q}%")
        clauses.append(f"i.value ILIKE ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    sql_count = f"SELECT COUNT(*) FROM ti_indicators i {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_IND_COLS}
          FROM ti_indicators i
          LEFT JOIN ti_feeds f ON f.id = i.feed_id
          {where}
         ORDER BY i.created_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_indicator(r) for r in rows]
    return TiIndicatorPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# Matches (paged; the important surface -- your asset <-> known-bad indicator)
# --------------------------------------------------------------------------- #

@router.get("/matches", response_model=TiMatchPage)
async def list_matches(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Matches joined to the indicator and a subject summary.

    For an `asset` match the subject is that asset; for a `finding` match it is
    the finding plus the asset it hangs off. Worst severity first. One grouped
    query (no N+1).
    """
    sql_count = "SELECT COUNT(*) FROM ti_matches"
    sql = f"""
        SELECT m.id, m.subject_type, m.subject_id, m.matched_value, m.severity,
               m.finding_id, m.matched_at,
               i.id AS indicator_id, i.type AS indicator_type,
               i.value AS indicator_value, i.labels AS indicator_labels,
               i.malware AS indicator_malware,
               i.threat_actor AS indicator_threat_actor,
               i.confidence AS indicator_confidence,
               COALESCE(a.id, fa.id) AS asset_id,
               COALESCE(a.kind, fa.kind) AS asset_kind,
               COALESCE(a.value, fa.value) AS asset_value,
               f.id AS subject_finding_id, f.title AS finding_title,
               f.severity AS finding_severity
          FROM ti_matches m
          JOIN ti_indicators i ON i.id = m.indicator_id
          LEFT JOIN assets a ON a.id = m.subject_id AND m.subject_type = 'asset'
          LEFT JOIN findings f ON f.id = m.subject_id AND m.subject_type = 'finding'
          LEFT JOIN assets fa ON fa.id = f.asset_id
         ORDER BY array_position({_SEV_ARRAY}, m.severity) DESC, m.matched_at DESC
         LIMIT $1 OFFSET $2
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count)
        rows = await con.fetch(sql, limit, offset)
    items = [_row_to_match(r) for r in rows]
    return TiMatchPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# Ingest proxy -> threatintel
# --------------------------------------------------------------------------- #

@router.post("/ingest")
async def ingest(body: dict[str, Any]) -> dict[str, Any]:
    """Forward a STIX bundle (or {"url": ...}) to the threatintel service.

    On success the service body is relayed (with `ok` defaulted true). On any
    connection failure the response degrades to {ok:false, note:...} and a 200,
    so the dashboard never sees a 5xx.
    """
    url = f"{_threatintel_url()}/ingest/stix"
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.post(url, json=body or {}, headers=service_headers())
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("ok", True)
            return data
        return {"ok": True, "result": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("threatintel_unreachable", extra={"error": str(exc), "op": "ingest"})
        return {"ok": False, "note": f"threatintel service not reachable: {exc!s}"}


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

@router.get("/summary", response_model=TiSummary)
async def summary(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        indicators = await con.fetchval("SELECT COUNT(*) FROM ti_indicators")
        matches = await con.fetchval("SELECT COUNT(*) FROM ti_matches")
        feeds = await con.fetchval("SELECT COUNT(*) FROM ti_feeds")
        type_rows = await con.fetch(
            "SELECT type, COUNT(*) AS c FROM ti_indicators GROUP BY type"
        )
    return TiSummary(
        indicators=int(indicators or 0),
        matches=int(matches or 0),
        feeds=int(feeds or 0),
        by_type={r["type"]: int(r["c"]) for r in type_rows},
    )
