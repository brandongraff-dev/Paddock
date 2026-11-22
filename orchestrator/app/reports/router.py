"""Reports API.

- `GET  /v1/reports/executive?period=30d&format=json|html|pdf[&end=ISO][&download=1]`
- `GET  /v1/reports/compliance`                       framework list + status counts
- `GET  /v1/reports/compliance/{framework}?format=json|html|pdf`
- `GET  /v1/reports/digest/preview?period=7d&format=json|text|html`
- `GET  /v1/reports/digests`                          digest run history
- `POST /v1/reports/digest/send`                      admin: build + emit now

Reports are read-capability. Every query is ABAC-filtered by the caller's
clearance, and every report fetch is written to the audit log as an export
(reports are made to be forwarded). PDF rendering runs in a worker thread.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

from ..auth import Principal, current_principal, require
from ..billing import gate as billing_gate
from ..db import get_pool
from . import compliance, digest, render
from .metrics import build_report, parse_period
from .models import CompliancePack, DigestRunOut, FrameworkSummary, ReportData

router = APIRouter(prefix="/v1/reports", tags=["reports"])

Fmt = Literal["json", "html", "pdf"]


def _days(period: str, default: int) -> int:
    try:
        return parse_period(period, default)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _mark_export(request: Request, principal: Principal) -> None:
    request.state.audit_restricted = True
    request.state.audit_classification = principal.clearance


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "report"


async def _document(html: str, fmt: str, filename: str, download: bool) -> Response:
    if fmt == "html":
        headers = (
            {"Content-Disposition": f'attachment; filename="{filename}.html"'} if download else {}
        )
        return HTMLResponse(html, headers=headers)
    try:
        pdf = await run_in_threadpool(render.html_to_pdf, html)
    except render.PdfUnavailable as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    disp = "attachment" if download else "inline"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disp}; filename="{filename}.pdf"'},
    )


@router.get("/executive", response_model=ReportData)
async def executive_report(
    request: Request,
    period: str = Query("30d", description="Window length, e.g. 7d, 30d, 90d, 12w"),
    format: Fmt = Query("json"),
    end: datetime | None = Query(None, description="Window end (default now)"),
    download: bool = False,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    days = _days(period, 30)
    if end is not None and end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    report = await build_report(pool, days=days, end=end, clearance=principal.clearance)
    _mark_export(request, principal)
    if format == "json":
        return report
    html = render.render_executive_html(report)
    name = f"paddock-executive-{days}d-{report.window.end:%Y-%m-%d}"
    return await _document(html, format, name, download)


@router.get(
    "/compliance", response_model=list[FrameworkSummary],
    dependencies=[Depends(billing_gate.require_paid("compliance_packs"))],
)
async def compliance_frameworks(
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    _mark_export(request, principal)
    return await compliance.summaries(pool, clearance=principal.clearance)


@router.get(
    "/compliance/{framework}", response_model=CompliancePack,
    dependencies=[Depends(billing_gate.require_paid("compliance_packs"))],
)
async def compliance_pack(
    framework: str,
    request: Request,
    format: Fmt = Query("json"),
    download: bool = False,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    if framework not in compliance.framework_ids():
        raise HTTPException(
            status_code=404, detail=f"unknown framework; one of {compliance.framework_ids()}"
        )
    pack = await compliance.build_pack(pool, framework, clearance=principal.clearance)
    _mark_export(request, principal)
    if format == "json":
        return pack
    html = compliance.render_pack_html(pack)
    name = f"paddock-{_slug(framework)}-evidence-{pack.generated_at:%Y-%m-%d}"
    return await _document(html, format, name, download)


@router.get("/digest/preview")
async def digest_preview(
    request: Request,
    period: str = Query("7d"),
    format: Literal["json", "text", "html"] = Query("json"),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """What the next digest would say, at the digest clearance (never above yours)."""
    days = _days(period, 7)
    from .config import report_settings
    from .metrics import clearance_rank_of

    clr = report_settings.digest_clearance
    if clearance_rank_of(principal.clearance) < clearance_rank_of(clr):
        clr = principal.clearance
    r, text, html = await digest.build_digest(pool, days=days, clearance=clr)
    _mark_export(request, principal)
    if format == "text":
        return PlainTextResponse(text)
    if format == "html":
        return HTMLResponse(html)
    return {
        "highlights": r.highlights,
        "metrics": digest._metrics(r),
        "text": text,
        "period": r.window.model_dump(mode="json"),
        "clearance": clr,
    }


@router.get("/digests", response_model=list[DigestRunOut])
async def digest_history(limit: int = Query(20, ge=1, le=200), pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """SELECT id, workspace, status, event_id, detail, period_start, period_end
                 FROM report_digests ORDER BY generated_at DESC LIMIT $1""",
            limit,
        )
    return [DigestRunOut(**dict(r)) for r in rows]


@router.post("/digest/send", response_model=DigestRunOut, dependencies=[Depends(require("admin"))])
async def digest_send(period: str = Query("7d"), pool=Depends(get_pool)):
    days = _days(period, 7)
    res = await digest.send_digest(pool, kind="manual", days=days)
    assert res is not None  # manual runs are never deduplicated
    return res
