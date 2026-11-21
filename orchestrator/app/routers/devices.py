"""IoT / OT device inventory endpoints.

A thin read layer over the asset graph for the device-discovery module
(``otdiscovery``). Devices are ``iot_device`` / ``ot_device`` assets whose
``metadata`` carries the passive fingerprint (vendor/model/type/protocols/mac);
``network_segment`` assets hold the observed subnets, joined to devices by a
``member_of`` edge. Exposure is expressed as findings on the device asset
(``ot_it_exposure``, ``ot_public_exposure`` with rule_source ``policy``, plus
``cve_match`` findings).

This router is read-only: it never triggers discovery and never probes a
device. All models are declared inline here (the shared models module is a
fixed contract we don't extend for this feature).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..auth import Principal, classification_rank_sql, current_principal
from ..db import get_pool

router = APIRouter(prefix="/v1/devices", tags=["devices"])

_DEVICE_KINDS = ("iot_device", "ot_device")
_EXPOSURE_RULES = ("ot_it_exposure", "ot_public_exposure")

# ABAC: an asset/finding is visible only when its classification rank is <= the
# caller's clearance. Pushed into SQL so over-classified rows never leave PG.
_ASSET_ABAC = f"{classification_rank_sql('a.classification')} <= "


# --------------------------------------------------------------------------- #
# Inline models
# --------------------------------------------------------------------------- #

DeviceRole = Literal["iot", "ot"]


class DeviceOut(BaseModel):
    id: UUID
    kind: str
    role: DeviceRole
    value: str
    canonical: str
    vendor: str | None = None
    model: str | None = None
    type: str | None = None
    mac: str | None = None
    ips: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    os: str | None = None
    confidence: int = 0
    segment: str | None = None
    first_seen: datetime
    last_seen: datetime
    open_finding_count: int = 0
    exposed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DevicePage(BaseModel):
    items: list[DeviceOut]
    total: int
    limit: int
    offset: int


class FindingBrief(BaseModel):
    id: UUID
    rule_id: str
    rule_source: str
    severity: str
    status: str
    title: str
    description: str | None = None
    cvss: float | None = None
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class SegmentOut(BaseModel):
    id: UUID
    value: str
    canonical: str
    classification: str | None = None
    internet_facing: bool = False
    device_count: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeviceDetailOut(BaseModel):
    device: DeviceOut
    findings: list[FindingBrief]
    segment: SegmentOut | None = None


class DeviceSummaryOut(BaseModel):
    total: int
    ot_total: int
    iot_total: int
    by_role: dict[str, int]
    by_type: dict[str, int]
    by_vendor: dict[str, int]
    exposed_ot: int
    it_ot_violations: int
    internet_facing_ot: int
    segments: int


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _md(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value or {}


def _role_for_kind(kind: str) -> DeviceRole:
    return "ot" if kind == "ot_device" else "iot"


def _device_from_row(row: Any) -> DeviceOut:
    d = dict(row)
    md = _md(d.get("metadata"))
    return DeviceOut(
        id=d["id"],
        kind=d["kind"],
        role=_role_for_kind(d["kind"]),
        value=d["value"],
        canonical=d["canonical"],
        vendor=md.get("vendor"),
        model=md.get("model"),
        type=md.get("type"),
        mac=md.get("mac"),
        ips=list(md.get("ips") or []),
        protocols=list(md.get("protocols") or []),
        os=md.get("os"),
        confidence=int(md.get("confidence") or d.get("confidence") or 0),
        segment=md.get("segment"),
        first_seen=d["first_seen"],
        last_seen=d["last_seen"],
        open_finding_count=int(d.get("open_finding_count") or 0),
        exposed=bool(d.get("exposed_count") or 0),
        metadata=md,
    )


# --------------------------------------------------------------------------- #
# Summary  (declared before /{device_id} so the literal path wins)
# --------------------------------------------------------------------------- #

@router.get("/summary", response_model=DeviceSummaryOut)
async def device_summary(
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    abac = f"{_ASSET_ABAC}$1"
    async with pool.acquire() as con:
        role_rows = await con.fetch(
            f"""
            SELECT a.kind, COUNT(*) AS n
              FROM assets a
             WHERE a.kind = ANY($2::text[]) AND {abac}
             GROUP BY a.kind
            """,
            principal.clearance_rank, list(_DEVICE_KINDS),
        )
        by_kind = {r["kind"]: int(r["n"]) for r in role_rows}
        ot_total = by_kind.get("ot_device", 0)
        iot_total = by_kind.get("iot_device", 0)

        type_rows = await con.fetch(
            f"""
            SELECT COALESCE(a.metadata->>'type', 'unknown') AS t, COUNT(*) AS n
              FROM assets a
             WHERE a.kind = ANY($2::text[]) AND {abac}
             GROUP BY t ORDER BY n DESC
            """,
            principal.clearance_rank, list(_DEVICE_KINDS),
        )
        vendor_rows = await con.fetch(
            f"""
            SELECT COALESCE(a.metadata->>'vendor', 'unknown') AS v, COUNT(*) AS n
              FROM assets a
             WHERE a.kind = ANY($2::text[]) AND {abac}
             GROUP BY v ORDER BY n DESC
            """,
            principal.clearance_rank, list(_DEVICE_KINDS),
        )
        segments = await con.fetchval(
            f"""
            SELECT COUNT(*) FROM assets a
             WHERE a.kind = 'network_segment' AND {abac}
            """,
            principal.clearance_rank,
        )
        # Exposed OT = distinct OT devices carrying an open exposure finding.
        exposed_ot = await con.fetchval(
            f"""
            SELECT COUNT(DISTINCT a.id)
              FROM assets a JOIN findings f ON f.asset_id = a.id
             WHERE a.kind = 'ot_device' AND f.status = 'open'
               AND f.rule_id = ANY($2::text[]) AND {abac}
            """,
            principal.clearance_rank, list(_EXPOSURE_RULES),
        )
        it_ot_violations = await con.fetchval(
            f"""
            SELECT COUNT(DISTINCT a.id)
              FROM assets a JOIN findings f ON f.asset_id = a.id
             WHERE a.kind = 'ot_device' AND f.status = 'open'
               AND f.rule_id = 'ot_it_exposure' AND {abac}
            """,
            principal.clearance_rank,
        )
        internet_facing_ot = await con.fetchval(
            f"""
            SELECT COUNT(DISTINCT a.id)
              FROM assets a JOIN findings f ON f.asset_id = a.id
             WHERE a.kind = 'ot_device' AND f.status = 'open'
               AND f.rule_id = 'ot_public_exposure' AND {abac}
            """,
            principal.clearance_rank,
        )

    return DeviceSummaryOut(
        total=ot_total + iot_total,
        ot_total=ot_total,
        iot_total=iot_total,
        by_role={"ot": ot_total, "iot": iot_total},
        by_type={r["t"]: int(r["n"]) for r in type_rows},
        by_vendor={r["v"]: int(r["n"]) for r in vendor_rows},
        exposed_ot=int(exposed_ot or 0),
        it_ot_violations=int(it_ot_violations or 0),
        internet_facing_ot=int(internet_facing_ot or 0),
        segments=int(segments or 0),
    )


# --------------------------------------------------------------------------- #
# List
# --------------------------------------------------------------------------- #

@router.get("", response_model=DevicePage)
async def list_devices(
    type: str | None = Query(None, max_length=64),
    role: DeviceRole | None = None,
    vendor: str | None = Query(None, max_length=128),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    clauses: list[str] = []
    args: list[Any] = []

    if role is not None:
        args.append("ot_device" if role == "ot" else "iot_device")
        clauses.append(f"a.kind = ${len(args)}")
    else:
        args.append(list(_DEVICE_KINDS))
        clauses.append(f"a.kind = ANY(${len(args)}::text[])")

    if type is not None:
        args.append(type)
        clauses.append(f"a.metadata->>'type' = ${len(args)}")
    if vendor is not None:
        args.append(f"%{vendor}%")
        clauses.append(f"a.metadata->>'vendor' ILIKE ${len(args)}")

    args.append(principal.clearance_rank)
    clauses.append(f"{_ASSET_ABAC}${len(args)}")
    where = "WHERE " + " AND ".join(clauses)

    count_sql = f"SELECT COUNT(*) FROM assets a {where}"

    args_list = list(args)
    args_list.extend([limit, offset])
    list_sql = f"""
        SELECT a.id, a.kind, a.value, a.canonical, a.first_seen, a.last_seen,
               a.confidence, a.metadata,
               (SELECT COUNT(*) FROM findings f
                 WHERE f.asset_id = a.id AND f.status = 'open') AS open_finding_count,
               (SELECT COUNT(*) FROM findings f
                 WHERE f.asset_id = a.id AND f.status = 'open'
                   AND f.rule_id = ANY(${len(args_list) + 1}::text[])) AS exposed_count
          FROM assets a
          {where}
         ORDER BY a.last_seen DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(count_sql, *args)
        rows = await con.fetch(list_sql, *args_list, list(_EXPOSURE_RULES))

    return DevicePage(
        items=[_device_from_row(r) for r in rows],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


# --------------------------------------------------------------------------- #
# Detail
# --------------------------------------------------------------------------- #

@router.get("/{device_id}", response_model=DeviceDetailOut)
async def get_device(
    device_id: UUID,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            SELECT a.id, a.kind, a.value, a.canonical, a.first_seen, a.last_seen,
                   a.confidence, a.metadata,
                   (SELECT COUNT(*) FROM findings f
                     WHERE f.asset_id = a.id AND f.status = 'open') AS open_finding_count,
                   (SELECT COUNT(*) FROM findings f
                     WHERE f.asset_id = a.id AND f.status = 'open'
                       AND f.rule_id = ANY($3::text[])) AS exposed_count
              FROM assets a
             WHERE a.id = $1 AND a.kind = ANY($2::text[])
               AND {_ASSET_ABAC}$4
            """,
            device_id, list(_DEVICE_KINDS), list(_EXPOSURE_RULES),
            principal.clearance_rank,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="device not found")

        finding_rows = await con.fetch(
            """
            SELECT f.id, f.rule_id, f.rule_source, f.severity, f.status,
                   f.title, f.description, f.cvss, f.first_seen, f.last_seen,
                   f.metadata
              FROM findings f
             WHERE f.asset_id = $1
             ORDER BY
               CASE f.severity
                 WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                 WHEN 'low' THEN 3 ELSE 4 END,
               f.last_seen DESC
            """,
            device_id,
        )

        seg_row = await con.fetchrow(
            """
            SELECT seg.id, seg.value, seg.canonical, seg.metadata
              FROM asset_edges e
              JOIN assets seg ON seg.id = e.dst_id
             WHERE e.src_id = $1 AND e.kind = 'member_of'
               AND seg.kind = 'network_segment'
             LIMIT 1
            """,
            device_id,
        )

    device = _device_from_row(row)

    findings: list[FindingBrief] = []
    for fr in finding_rows:
        fd = dict(fr)
        findings.append(FindingBrief(
            id=fd["id"],
            rule_id=fd["rule_id"],
            rule_source=fd["rule_source"],
            severity=fd["severity"],
            status=fd["status"],
            title=fd["title"],
            description=fd.get("description"),
            cvss=float(fd["cvss"]) if fd.get("cvss") is not None else None,
            first_seen=fd["first_seen"],
            last_seen=fd["last_seen"],
            metadata=_md(fd.get("metadata")),
        ))

    segment: SegmentOut | None = None
    if seg_row is not None:
        seg_md = _md(seg_row["metadata"])
        segment = SegmentOut(
            id=seg_row["id"],
            value=seg_row["value"],
            canonical=seg_row["canonical"],
            classification=seg_md.get("classification"),
            internet_facing=bool(seg_md.get("internet_facing")),
            device_count=seg_md.get("device_count"),
            metadata=seg_md,
        )

    return DeviceDetailOut(device=device, findings=findings, segment=segment)
