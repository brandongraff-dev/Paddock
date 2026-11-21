"""The free public exposure report.

``POST /v1/public/exposure-report``  {domain, email?, consent?, captcha_token?}
``GET  /v1/public/exposure-report/{id}``

Unauthenticated by design, and therefore built to be harmless:

* PASSIVE only (DNS + CT via :mod:`app.growth.engine`) -- there is no way to
  make Paddock send a packet to the submitted domain, so no proof-of-control
  is needed and it cannot be used as an attack tool.
* strict domain validation (:mod:`app.growth.domains`), per-IP / per-domain /
  global-daily limits and a CAPTCHA hook (:mod:`app.growth.abuse`).
* one assessment per domain per 24 h: repeat requests get the cached report.
* the public response carries grade, reasons and counts plus a teaser with
  masked host names. Full findings stay in the database.
* the rows live in the platform (default) tenant; nothing here reads or
  reveals tenant data or internal state.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import tenancy
from ..auth import client_ip
from ..db import get_pool
from . import abuse, clients, engine
from .config import growth_settings
from .domains import DomainError, validate_public_domain

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/public/exposure-report", tags=["public"])

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
JOB_TIMEOUT_SEC = 150
STALE_RUNNING_MINUTES = 10
MAX_ATTEMPTS = 3


def _platform():
    """Public rows belong to the platform tenant, whoever is calling."""
    return tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class ExposureReportIn(BaseModel):
    domain: str = Field(..., max_length=300)
    email: Optional[str] = Field(None, max_length=320)
    consent: bool = False
    captcha_token: Optional[str] = Field(None, max_length=4096)


class ExposureSubmitOut(BaseModel):
    id: uuid.UUID
    domain: str
    status: Literal["queued", "running", "done", "failed"]
    cached: bool
    email_stored: bool


class Cta(BaseModel):
    text: str
    url: str


class ExposureReportOut(BaseModel):
    id: uuid.UUID
    domain: str
    status: Literal["queued", "running", "done", "failed"]
    created_at: datetime
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    summary: Optional[dict[str, Any]] = None
    teaser: Optional[dict[str, Any]] = None
    cta: Optional[Cta] = None
    passive_notice: str = (
        "Built only from public DNS and certificate-transparency data. "
        "No traffic was sent to this domain."
    )


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #

def validate_email(email: str | None) -> str | None:
    if email is None or not email.strip():
        return None
    e = email.strip()
    if len(e) > 254 or not _EMAIL_RE.match(e) or ".." in e:
        raise HTTPException(status_code=422, detail={"code": "invalid_email", "message": "enter a valid email"})
    return e.lower()


async def submit(
    pool,
    redis,
    *,
    domain: str,
    email: str | None,
    consent: bool,
    ip: str | None,
) -> tuple[dict[str, Any], bool, bool]:
    """Queue (or reuse) an assessment. Returns (row, cached, email_stored)."""
    with _platform():
        async with pool.acquire() as con:
            async with con.transaction():
                await con.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"exposure:{domain}")
                row = await con.fetchrow(
                    """SELECT id, domain, status FROM exposure_reports
                        WHERE domain = $1
                          AND (status IN ('queued','running')
                               OR (status = 'done'
                                   AND finished_at > NOW() - make_interval(hours => $2)))
                        ORDER BY created_at DESC LIMIT 1""",
                    domain,
                    growth_settings.cache_hours,
                )
                cached = row is not None
                if row is None:
                    await abuse.limit_domain(redis, domain)
                    await abuse.limit_global(redis)
                    depth = await con.fetchval(
                        "SELECT COUNT(*) FROM exposure_reports WHERE status IN ('queued','running')"
                    )
                    if depth >= growth_settings.max_queue_depth:
                        raise HTTPException(status_code=503, detail="busy; try again shortly")
                    row = await con.fetchrow(
                        """INSERT INTO exposure_reports (domain, ip_hash)
                           VALUES ($1, $2) RETURNING id, domain, status""",
                        domain,
                        abuse.ip_hash(ip),
                    )
                stored = False
                if email and consent:
                    await con.execute(
                        """INSERT INTO exposure_leads (report_id, domain, email, consent, ip_hash)
                           VALUES ($1, $2, $3, TRUE, $4)
                           ON CONFLICT (email, domain) DO UPDATE
                              SET report_id = EXCLUDED.report_id, consent_at = NOW()""",
                        row["id"],
                        domain,
                        email,
                        abuse.ip_hash(ip),
                    )
                    stored = True
    return dict(row), cached, stored


async def claim_pending(pool, limit: int = 3) -> list[dict[str, Any]]:
    with _platform():
        async with pool.acquire() as con:
            async with con.transaction():
                # stale runners: re-queue (or give up)
                await con.execute(
                    """UPDATE exposure_reports
                          SET status = CASE WHEN attempts >= $2 THEN 'failed' ELSE 'queued' END,
                              error = CASE WHEN attempts >= $2 THEN 'assessment_failed' END,
                              finished_at = CASE WHEN attempts >= $2 THEN NOW() END
                        WHERE status = 'running'
                          AND started_at < NOW() - make_interval(mins => $1)""",
                    STALE_RUNNING_MINUTES,
                    MAX_ATTEMPTS,
                )
                rows = await con.fetch(
                    """WITH picked AS MATERIALIZED (
                           SELECT id FROM exposure_reports WHERE status = 'queued'
                            ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED)
                       UPDATE exposure_reports r SET status = 'running', started_at = NOW(),
                              attempts = r.attempts + 1
                         FROM picked WHERE r.id = picked.id
                       RETURNING r.id, r.domain""",
                    limit,
                )
    return [dict(r) for r in rows]


async def run_one(pool, report_id: uuid.UUID, domain: str) -> str:
    """Assess one claimed report and store the outcome. Returns the status."""
    import json

    resolver, ct = clients.get_clients()
    status, error = "done", None
    result: engine.Assessment | None = None
    try:
        result = await asyncio.wait_for(
            engine.assess(domain, resolver=resolver, ct=ct), timeout=JOB_TIMEOUT_SEC
        )
    except engine.DomainNotFound:
        status, error = "failed", "domain_not_found"
    except Exception:  # noqa: BLE001
        logger.exception("exposure_assessment_failed", extra={"domain": domain})
        status, error = "failed", "assessment_failed"
    with _platform():
        async with pool.acquire() as con:
            if result is not None:
                full = result.full()
                await con.execute(
                    """UPDATE exposure_reports
                          SET status = 'done', finished_at = NOW(), grade = $2, score = $3,
                              summary = $4::jsonb, findings = $5::jsonb, error = NULL
                        WHERE id = $1""",
                    report_id,
                    result.grade,
                    result.score,
                    json.dumps(engine.public_summary(full)),
                    json.dumps(full["findings"], default=str),
                )
            else:
                await con.execute(
                    "UPDATE exposure_reports SET status = 'failed', finished_at = NOW(), error = $2 WHERE id = $1",
                    report_id,
                    error,
                )
    return status


async def run_pending(pool, limit: int = 3) -> int:
    """Claim and run queued reports (the runner loop and the tests call this)."""
    claimed = await claim_pending(pool, limit)
    if claimed:
        await asyncio.gather(*(run_one(pool, c["id"], c["domain"]) for c in claimed))
    return len(claimed)


async def load_public(pool, report_id: uuid.UUID) -> ExposureReportOut | None:
    import json

    with _platform():
        async with pool.acquire() as con:
            r = await con.fetchrow(
                """SELECT id, domain, status, created_at, finished_at, error, summary, findings
                     FROM exposure_reports WHERE id = $1""",
                report_id,
            )
    if r is None:
        return None
    out = ExposureReportOut(
        id=r["id"], domain=r["domain"], status=r["status"], created_at=r["created_at"],
        finished_at=r["finished_at"],
    )
    if r["status"] == "failed":
        out.error = r["error"] if r["error"] in ("domain_not_found", "assessment_failed") else "assessment_failed"
    if r["status"] == "done":
        summary = r["summary"] if isinstance(r["summary"], dict) else json.loads(r["summary"] or "{}")
        findings = r["findings"] if isinstance(r["findings"], list) else json.loads(r["findings"] or "[]")
        out.summary = summary
        out.teaser = engine.teaser(
            {"findings": findings, "domain": r["domain"]}, limit=3
        )
        hidden = out.teaser["hidden"]
        out.cta = Cta(
            text=(
                f"{hidden} more finding{'s' if hidden != 1 else ''} and the fix steps are in the full report. "
                if hidden else "Keep it this way: "
            ) + "Verify ownership of this domain to unlock every host, remediation steps and continuous monitoring.",
            url=growth_settings.signup_url,
        )
    return out


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

def _enabled() -> None:
    if not growth_settings.public_enabled:
        raise HTTPException(status_code=404, detail="not found")


@router.post("", response_model=ExposureSubmitOut, status_code=202)
async def create_report(body: ExposureReportIn, request: Request, pool=Depends(get_pool)):
    _enabled()
    redis = request.app.state.redis
    ip = client_ip(request)
    try:
        domain = validate_public_domain(body.domain)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message}) from exc
    email = validate_email(body.email)
    await abuse.limit_ip_post(redis, ip)
    if not await abuse.get_captcha_verifier().verify(body.captcha_token, ip):
        raise HTTPException(status_code=403, detail={"code": "captcha_failed", "message": "verification failed"})
    row, cached, stored = await submit(
        pool, redis, domain=domain, email=email, consent=body.consent, ip=ip
    )
    return JSONResponse(
        ExposureSubmitOut(
            id=row["id"], domain=row["domain"], status=row["status"], cached=cached, email_stored=stored
        ).model_dump(mode="json"),
        status_code=202,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/{report_id}", response_model=ExposureReportOut)
async def get_report(report_id: str, request: Request, pool=Depends(get_pool)):
    _enabled()
    await abuse.limit_ip_get(request.app.state.redis, client_ip(request))
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="not found") from None
    out = await load_public(pool, rid)
    if out is None:
        raise HTTPException(status_code=404, detail="not found")
    return JSONResponse(out.model_dump(mode="json"), headers={"Cache-Control": "no-store"})
