"""Auto-remediation read API + propose proxy (schema 014 ``remediations``).

The ``remediation/`` service (HTTP :8102) runs the hardened pipeline that
PROPOSES constrained, prompt-injection-checked fixes and (optionally) opens a
PR — NEVER auto-merged. This router is read + proxy:

- `POST /v1/remediation/propose` {finding_id}  proxy -> remediation service;
                                                degrade cleanly if it is down.
- `GET  /v1/remediation`                        paged list, newest first, with
                                                verifier + injection SUMMARIES.
- `GET  /v1/remediation/{id}`                   full record incl. the diff and
                                                the full verifier/injection reports.

The orchestrator never generates or gates a diff itself; it relays the request
and serves the stored, already-verified records. The propose proxy must DEGRADE
(never 5xx) when the service is unreachable, mirroring ask.py / threatintel.py.
"""
from __future__ import annotations

import json
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
router = APIRouter(prefix="/v1/remediation", tags=["remediation"])

# Short timeout: a slow/dead upstream degrades fast rather than stalling.
_PROXY_TIMEOUT = 10.0


def _remediation_url() -> str:
    return str(getattr(settings, "remediation_url", "http://remediation:8102")).rstrip("/")


# --------------------------------------------------------------------------- #
# Local response models (we do NOT touch the shared models.py).
# --------------------------------------------------------------------------- #

class ProposeIn(BaseModel):
    finding_id: str = Field(min_length=1)
    created_by: str | None = None


class InjectionSummary(BaseModel):
    flagged: bool = False
    blocked: bool = False
    categories: list[str] = Field(default_factory=list)
    summary: str = "no injection detected"


class VerifierSummary(BaseModel):
    gate_ok: bool | None = None
    verify_ok: bool | None = None
    verdict: str | None = None
    summary: str | None = None
    rejection_reason: str | None = None
    pr_opened: bool | None = None


class RemediationRow(BaseModel):
    id: UUID
    finding_id: UUID | None = None
    repo: str | None = None
    kind: str
    summary: str
    status: str
    base_branch: str | None = None
    head_branch: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    created_by: str | None = None
    created_at: datetime
    verified_at: datetime | None = None
    injection: InjectionSummary = Field(default_factory=InjectionSummary)
    verifier: VerifierSummary = Field(default_factory=VerifierSummary)


class RemediationPage(BaseModel):
    items: list[RemediationRow]
    total: int
    limit: int
    offset: int


class RemediationDetail(RemediationRow):
    diff: str | None = None
    verifier_report: dict[str, Any] = Field(default_factory=dict)
    injection_checks: dict[str, Any] = Field(default_factory=dict)


_COLS = (
    "id, finding_id, repo, kind, summary, status, base_branch, head_branch, "
    "diff, verifier_report, injection_checks, pr_url, pr_number, created_by, "
    "created_at, verified_at"
)


def _as_json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    if isinstance(value, dict):
        return value
    return {}


def _injection_summary(checks: dict[str, Any]) -> InjectionSummary:
    """Collapse the per-stage injection_checks into one summary. ``blocked`` is
    true if ANY stage (finding fields or PR body) carried injected content."""
    flagged = blocked = False
    categories: set[str] = set()
    parts: list[str] = []
    for stage in ("finding", "pr"):
        rec = checks.get(stage)
        if not isinstance(rec, dict):
            continue
        flagged = flagged or bool(rec.get("flagged"))
        blocked = blocked or bool(rec.get("blocked"))
        categories.update(rec.get("categories") or [])
        if rec.get("summary") and rec.get("flagged"):
            parts.append(f"{stage}: {rec['summary']}")
    summary = "; ".join(parts) if parts else "no injection detected"
    return InjectionSummary(
        flagged=flagged, blocked=blocked,
        categories=sorted(categories), summary=summary,
    )


def _verifier_summary(report: dict[str, Any]) -> VerifierSummary:
    gate = report.get("gate") if isinstance(report.get("gate"), dict) else {}
    verify = report.get("verify") if isinstance(report.get("verify"), dict) else {}
    pr = report.get("pr") if isinstance(report.get("pr"), dict) else {}
    return VerifierSummary(
        gate_ok=gate.get("ok"),
        verify_ok=verify.get("ok"),
        verdict=verify.get("verdict"),
        summary=verify.get("summary") or report.get("rejection_reason"),
        rejection_reason=report.get("rejection_reason"),
        pr_opened=pr.get("opened"),
    )


def _row_to_model(row: Any, *, detail: bool) -> RemediationRow:
    d = dict(row)
    report = _as_json(d.get("verifier_report"))
    checks = _as_json(d.get("injection_checks"))
    base = {
        "id": d["id"],
        "finding_id": d.get("finding_id"),
        "repo": d.get("repo"),
        "kind": d["kind"],
        "summary": d["summary"],
        "status": d["status"],
        "base_branch": d.get("base_branch"),
        "head_branch": d.get("head_branch"),
        "pr_url": d.get("pr_url"),
        "pr_number": d.get("pr_number"),
        "created_by": d.get("created_by"),
        "created_at": d["created_at"],
        "verified_at": d.get("verified_at"),
        "injection": _injection_summary(checks),
        "verifier": _verifier_summary(report),
    }
    if detail:
        return RemediationDetail(
            **base, diff=d.get("diff"),
            verifier_report=report, injection_checks=checks,
        )
    return RemediationRow(**base)


# --------------------------------------------------------------------------- #
# propose -> remediation service (proxy; degrade if down)
# --------------------------------------------------------------------------- #

@router.post("/propose")
async def propose(body: ProposeIn) -> dict[str, Any]:
    """Forward a propose request to the remediation service.

    On success the service body is relayed (with ``ok`` defaulted). On any
    connection failure the response degrades to {ok:false, note:...} and a 200,
    so the dashboard never sees a 5xx.
    """
    url = f"{_remediation_url()}/propose"
    payload = {"finding_id": body.finding_id, "created_by": body.created_by}
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT) as http:
            resp = await http.post(url, json=payload, headers=service_headers())
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data.setdefault("ok", True)
            return data
        return {"ok": True, "result": data}
    except Exception as exc:  # noqa: BLE001
        logger.info("remediation_unreachable", extra={"error": str(exc), "op": "propose"})
        return {
            "ok": False,
            "engine": "unavailable",
            "note": f"remediation service not reachable: {exc!s}",
        }


# --------------------------------------------------------------------------- #
# list (paged, summaries)
# --------------------------------------------------------------------------- #

@router.get("", response_model=RemediationPage)
async def list_remediations(
    status: str | None = Query(None, description="proposed|verifying|verified|rejected|pr_open|merged|failed"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if status is not None:
        args.append(status)
        clauses.append(f"status = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql_count = f"SELECT COUNT(*) FROM remediations {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_COLS}
          FROM remediations
          {where}
         ORDER BY created_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_model(r, detail=False) for r in rows]
    return RemediationPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# --------------------------------------------------------------------------- #
# detail (full diff + reports)
# --------------------------------------------------------------------------- #

@router.get("/{rid}", response_model=RemediationDetail)
async def get_remediation(rid: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_COLS} FROM remediations WHERE id = $1", rid
        )
    if row is None:
        raise HTTPException(status_code=404, detail="remediation not found")
    return _row_to_model(row, detail=True)
