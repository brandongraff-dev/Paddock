"""Supplier (third-party) monitoring.

Tenants list the domains of the vendors they depend on. A scheduled PASSIVE
assessment (the same engine as the public exposure report: DNS + CT only, no
traffic to the supplier) produces a grade and a diff against the last run.
Changes raise events through the integrations framework:

* ``supplier.grade_changed``  -- the letter grade moved (drop = medium/high)
* ``supplier.dangling_dns``   -- a new possible-takeover / dangling record
* ``supplier.cert_expiring``  -- a new expired / soon-to-expire certificate

Because the supplier is not the tenant's own asset, nothing here needs
proof-of-control and nothing here ever touches the supplier directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import tenancy
from ..auth import Principal, current_principal
from ..db import get_pool
from . import clients, engine
from .config import growth_settings
from .domains import DomainError, validate_public_domain

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/suppliers", tags=["suppliers"])

MAX_SUPPLIERS = 500
GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
DANGLING_RULES = frozenset({"dangling_cname_takeover", "dangling_cname_expired_domain", "dangling_cname", "dangling_ns"})
CERT_RULES = frozenset({"cert_expired", "cert_expiring"})
Criticality = Literal["low", "medium", "high", "critical"]


# --------------------------------------------------------------------------- #
# Diff (pure)
# --------------------------------------------------------------------------- #

def diff_assessments(
    prev_grade: str | None,
    prev_findings: list[dict[str, Any]] | None,
    grade: str,
    score: int,
    prev_score: int | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    prev_ids = {f["id"] for f in (prev_findings or [])}
    cur_ids = {f["id"] for f in findings}
    new = [f for f in findings if f["id"] not in prev_ids]
    resolved = [f for f in (prev_findings or []) if f["id"] not in cur_ids]

    def brief(f):
        return {"id": f["id"], "rule": f["rule"], "severity": f["severity"], "title": f["title"], "host": f.get("host")}

    direction = "none"
    if prev_grade is not None and prev_grade != grade:
        direction = "drop" if GRADE_ORDER.get(grade, 9) > GRADE_ORDER.get(prev_grade, 9) else "improve"
    return {
        "first": prev_grade is None,
        "grade_from": prev_grade,
        "grade_to": grade,
        "grade_direction": direction,
        "score_from": prev_score,
        "score_to": score,
        "score_delta": (score - prev_score) if prev_score is not None else None,
        "new": [brief(f) for f in new],
        "resolved": [brief(f) for f in resolved],
        "new_dangling": [brief(f) for f in new if f["rule"] in DANGLING_RULES],
        "new_cert_expiring": [brief(f) for f in new if f["rule"] in CERT_RULES],
    }


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #

async def emit_events(pool, supplier: dict[str, Any], assessment_id: uuid.UUID, changes: dict[str, Any], tenant_id: str):
    from ..integrations.base import Event
    from ..integrations.service import dashboard_url, emit

    base = {
        "supplier_id": str(supplier["id"]), "supplier": supplier["name"], "domain": supplier["domain"],
        "criticality": supplier["criticality"], "assessment_id": str(assessment_id),
    }
    url = dashboard_url("/suppliers")
    events: list[Event] = []
    if changes["grade_direction"] != "none":
        dropped = changes["grade_direction"] == "drop"
        sev = "info"
        if dropped:
            sev = "high" if changes["grade_to"] in ("D", "F") or supplier["criticality"] in ("high", "critical") else "medium"
        events.append(Event(
            type="supplier.grade_changed", id=f"supplier.grade_changed:{assessment_id}", tenant_id=tenant_id,
            severity=sev, url=url,
            title=f"{supplier['name']} grade {'dropped' if dropped else 'improved'}: "
                  f"{changes['grade_from']} to {changes['grade_to']}",
            summary=f"Passive assessment of {supplier['domain']} moved from {changes['grade_from']} to {changes['grade_to']} "
                    f"(score {changes['score_from']} to {changes['score_to']}).",
            data={**base, "grade_from": changes["grade_from"], "grade_to": changes["grade_to"],
                  "direction": changes["grade_direction"], "score": changes["score_to"],
                  "new_findings": [f["title"] for f in changes["new"][:5]]},
        ))
    if changes["new_dangling"]:
        n = len(changes["new_dangling"])
        events.append(Event(
            type="supplier.dangling_dns", id=f"supplier.dangling_dns:{assessment_id}", tenant_id=tenant_id,
            severity="high", url=url,
            title=f"{supplier['name']}: {n} new possible dangling DNS record(s)",
            summary="A DNS record at this supplier points at a resource that no longer exists (possible takeover). "
                    "Detected passively from DNS; the supplier was not contacted.",
            data={**base, "count": n, "hosts": [f["host"] for f in changes["new_dangling"]][:10]},
        ))
    if changes["new_cert_expiring"]:
        n = len(changes["new_cert_expiring"])
        worst = "high" if any(f["severity"] == "high" for f in changes["new_cert_expiring"]) else "medium"
        events.append(Event(
            type="supplier.cert_expiring", id=f"supplier.cert_expiring:{assessment_id}", tenant_id=tenant_id,
            severity=worst, url=url,
            title=f"{supplier['name']}: {n} certificate(s) expired or expiring",
            summary="Certificate-transparency data shows a certificate for a live host is expired or about to be.",
            data={**base, "count": n, "hosts": [f["host"] for f in changes["new_cert_expiring"]][:10]},
        ))
    for ev in events:
        await emit(pool, ev)
    return [e.type for e in events]


# --------------------------------------------------------------------------- #
# Running assessments (current tenant context)
# --------------------------------------------------------------------------- #

async def claim_due(pool, limit: int) -> list[dict[str, Any]]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """WITH picked AS MATERIALIZED (
                   SELECT id FROM suppliers WHERE enabled AND next_run_at <= NOW()
                    ORDER BY next_run_at LIMIT $1 FOR UPDATE SKIP LOCKED)
               UPDATE suppliers s SET next_run_at = NOW() + make_interval(mins => $2)
                 FROM picked WHERE s.id = picked.id
               RETURNING s.id, s.domain, s.name, s.criticality, s.interval_hours, s.last_grade, s.last_score,
                         s.last_assessment_id, s.consecutive_failures""",
            limit,
            growth_settings.supplier_lease_minutes,
        )
    return [dict(r) for r in rows]


async def assess_supplier(pool, supplier: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Run one passive assessment, store it, update the supplier, emit events."""
    tenant_id = tenancy.current_tenant_id() or tenancy.DEFAULT_TENANT_ID
    resolver, ct = clients.get_clients()
    try:
        result = await asyncio.wait_for(
            engine.assess(supplier["domain"], resolver=resolver, ct=ct, now=now), timeout=150
        )
    except Exception as exc:  # noqa: BLE001
        msg = "domain does not resolve" if isinstance(exc, engine.DomainNotFound) else "assessment failed"
        if not isinstance(exc, engine.DomainNotFound):
            logger.exception("supplier_assessment_failed", extra={"domain": supplier["domain"]})
        fails = int(supplier.get("consecutive_failures") or 0) + 1
        backoff = min(24, 2 ** (fails - 1))
        async with pool.acquire() as con:
            await con.execute(
                """UPDATE suppliers SET last_error = $2, consecutive_failures = $3,
                          next_run_at = NOW() + make_interval(hours => $4) WHERE id = $1""",
                supplier["id"], msg, fails, backoff,
            )
        return {"ok": False, "error": msg}

    full = result.full()
    async with pool.acquire() as con:
        prev = await con.fetchrow(
            "SELECT grade, score, findings FROM supplier_assessments WHERE supplier_id = $1 "
            "ORDER BY created_at DESC LIMIT 1",
            supplier["id"],
        )
        prev_findings = None
        if prev is not None:
            prev_findings = prev["findings"] if isinstance(prev["findings"], list) else json.loads(prev["findings"] or "[]")
        changes = diff_assessments(
            prev["grade"] if prev else None, prev_findings, result.grade, result.score,
            prev["score"] if prev else None, full["findings"],
        )
        summary = engine.public_summary(full)
        async with con.transaction():
            aid = await con.fetchval(
                """INSERT INTO supplier_assessments (supplier_id, domain, grade, score, summary, findings, changes)
                   VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb) RETURNING id""",
                supplier["id"], supplier["domain"], result.grade, result.score,
                json.dumps(summary), json.dumps(full["findings"], default=str), json.dumps(changes),
            )
            await con.execute(
                """UPDATE suppliers SET last_assessed_at = NOW(), last_grade = $2, last_score = $3,
                          last_assessment_id = $4, last_error = NULL, consecutive_failures = 0,
                          next_run_at = NOW() + make_interval(hours => interval_hours)
                    WHERE id = $1""",
                supplier["id"], result.grade, result.score, aid,
            )
            # keep the history bounded
            await con.execute(
                """DELETE FROM supplier_assessments WHERE supplier_id = $1 AND id NOT IN (
                       SELECT id FROM supplier_assessments WHERE supplier_id = $1
                        ORDER BY created_at DESC LIMIT 120)""",
                supplier["id"],
            )
    events = await emit_events(pool, supplier, aid, changes, tenant_id)
    return {"ok": True, "assessment_id": aid, "grade": result.grade, "changes": changes, "events": events}


async def run_due(pool, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Run due suppliers for EVERY active tenant (the background loop and tests)."""
    out: list[dict[str, Any]] = []
    for tid in await tenancy.list_tenant_ids(pool):
        with tenancy.tenant_context(tid):
            for sup in await claim_due(pool, limit or growth_settings.supplier_batch):
                res = await assess_supplier(pool, sup)
                out.append({"tenant_id": tid, "domain": sup["domain"], **res})
    return out


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

class SupplierIn(BaseModel):
    domain: str = Field(..., max_length=300)
    name: Optional[str] = Field(None, max_length=120)
    criticality: Criticality = "medium"
    interval_hours: int = Field(168, ge=1, le=8760)
    notes: Optional[str] = Field(None, max_length=2000)


class SupplierPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    criticality: Optional[Criticality] = None
    interval_hours: Optional[int] = Field(None, ge=1, le=8760)
    enabled: Optional[bool] = None
    notes: Optional[str] = Field(None, max_length=2000)


class SupplierOut(BaseModel):
    id: uuid.UUID
    domain: str
    name: str
    criticality: str
    notes: Optional[str] = None
    enabled: bool
    interval_hours: int
    next_run_at: datetime
    last_assessed_at: Optional[datetime] = None
    last_grade: Optional[str] = None
    last_score: Optional[int] = None
    last_error: Optional[str] = None
    created_at: datetime


class AssessmentOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    grade: str
    score: int
    changes: dict[str, Any]


class SupplierDetail(SupplierOut):
    history: list[AssessmentOut]
    findings: list[dict[str, Any]]
    summary: Optional[dict[str, Any]] = None


_COLS = ("id, domain, name, criticality, notes, enabled, interval_hours, next_run_at, last_assessed_at, "
         "last_grade, last_score, last_error, created_at")


def _j(v: Any, default: Any) -> Any:
    if v is None:
        return default
    return json.loads(v) if isinstance(v, (str, bytes)) else v


@router.get("", response_model=list[SupplierOut])
async def list_suppliers(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(f"SELECT {_COLS} FROM suppliers ORDER BY name, domain LIMIT {MAX_SUPPLIERS}")
    return [dict(r) for r in rows]


@router.post("", response_model=SupplierOut, status_code=201)
async def add_supplier(body: SupplierIn, pool=Depends(get_pool), principal: Principal = Depends(current_principal)):
    try:
        domain = validate_public_domain(body.domain)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message}) from exc
    tid = tenancy.current_tenant_id() or tenancy.DEFAULT_TENANT_ID
    async with pool.acquire() as con:
        async with con.transaction():
            await con.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"supplier:{tid}:{domain}")
            if await con.fetchval("SELECT 1 FROM suppliers WHERE domain = $1", domain):
                raise HTTPException(status_code=409, detail="supplier already monitored")
            if await con.fetchval("SELECT COUNT(*) FROM suppliers") >= MAX_SUPPLIERS:
                raise HTTPException(status_code=409, detail="supplier limit reached")
            r = await con.fetchrow(
                f"""INSERT INTO suppliers (domain, name, criticality, interval_hours, notes, created_by)
                    VALUES ($1,$2,$3,$4,$5,$6) RETURNING {_COLS}""",
                domain, (body.name or domain).strip(), body.criticality, body.interval_hours, body.notes,
                principal.actor,
            )
    return dict(r)


@router.get("/{supplier_id}", response_model=SupplierDetail)
async def get_supplier(supplier_id: uuid.UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        r = await con.fetchrow(f"SELECT {_COLS}, last_assessment_id FROM suppliers WHERE id = $1", supplier_id)
        if r is None:
            raise HTTPException(status_code=404, detail="supplier not found")
        hist = await con.fetch(
            "SELECT id, created_at, grade, score, changes FROM supplier_assessments "
            "WHERE supplier_id = $1 ORDER BY created_at DESC LIMIT 60", supplier_id,
        )
        last = None
        if r["last_assessment_id"]:
            last = await con.fetchrow(
                "SELECT findings, summary FROM supplier_assessments WHERE id = $1", r["last_assessment_id"]
            )
    d = {k: r[k] for k in r.keys() if k != "last_assessment_id"}
    d["history"] = [{**dict(h), "changes": _j(h["changes"], {})} for h in hist]
    d["findings"] = _j(last["findings"], []) if last else []
    d["summary"] = _j(last["summary"], None) if last else None
    return d


@router.patch("/{supplier_id}", response_model=SupplierOut)
async def patch_supplier(supplier_id: uuid.UUID, body: SupplierPatch, pool=Depends(get_pool)):
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="nothing to update")
    sets, args = [], []
    for k, v in fields.items():
        args.append(v)
        sets.append(f"{k} = ${len(args)}")
    args.append(supplier_id)
    async with pool.acquire() as con:
        r = await con.fetchrow(
            f"UPDATE suppliers SET {', '.join(sets)} WHERE id = ${len(args)} RETURNING {_COLS}", *args
        )
    if r is None:
        raise HTTPException(status_code=404, detail="supplier not found")
    return dict(r)


@router.delete("/{supplier_id}", status_code=204)
async def delete_supplier(supplier_id: uuid.UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        n = await con.fetchval("WITH d AS (DELETE FROM suppliers WHERE id = $1 RETURNING 1) SELECT COUNT(*) FROM d", supplier_id)
    if not n:
        raise HTTPException(status_code=404, detail="supplier not found")


@router.post("/{supplier_id}/assess", response_model=SupplierOut, status_code=202)
async def assess_now(supplier_id: uuid.UUID, pool=Depends(get_pool)):
    """Queue an immediate re-assessment; the runner picks it up within seconds."""
    async with pool.acquire() as con:
        r = await con.fetchrow(
            f"UPDATE suppliers SET next_run_at = NOW(), enabled = TRUE WHERE id = $1 RETURNING {_COLS}", supplier_id
        )
    if r is None:
        raise HTTPException(status_code=404, detail="supplier not found")
    return dict(r)
