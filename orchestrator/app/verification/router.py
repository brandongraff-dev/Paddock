"""Verification HTTP API.

* ``POST /v1/findings/{id}/verify``          queue a safe check (capability ``scan``)
* ``POST /v1/findings/verify/bulk``          the same for up to 100 findings
* ``GET  /v1/findings/{id}/verifications``   the ledger for one finding
* ``POST /v1/verifications/{id}/result``     worker callback (capability ``write``)
* ``POST /v1/remediation/{id}/merged``       a fix PR was merged: re-verify (``triage``)

The checks are non-destructive and only ever run against a target whose scope
entry has a verified/attested proof-of-control; a refused request is recorded
on the ledger and answered with its reason (403).
"""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import audit
from ..auth import Principal, current_principal
from ..db import get_pool
from ..queue import get_redis
from . import service
from .models import (
    BulkVerifyIn,
    BulkVerifyItem,
    BulkVerifyOut,
    RemediationMergedIn,
    ResultIn,
    VerificationHistoryOut,
    VerificationOut,
    VerifyIn,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["verification"])


async def _visible(pool, principal: Principal, finding_id: UUID):
    """The finding row if the caller's clearance allows it (same ABAC as GET /findings)."""
    from ..routers.findings import _FINDING_ABAC

    async with pool.acquire() as con:
        return await con.fetchrow(
            f"SELECT f.id, f.status, f.exploitability, f.last_verified_at, f.fix_verified_at "
            f"FROM findings f WHERE f.id = $1 AND {_FINDING_ABAC}$2",
            finding_id, principal.clearance_rank,
        )


async def _audit(request: Request, pool, principal: Principal, finding_id, details: dict) -> None:
    try:
        await audit.record(
            pool, action="update", actor=principal.actor, actor_role=principal.role,
            resource_type="findings", resource_id=str(finding_id), method=request.method,
            path=request.url.path, status=200,
            request_id=getattr(request.state, "request_id", None),
            details={"transition": "verify_requested", **details},
        )
    except Exception:  # noqa: BLE001 -- never fail the request on audit
        logger.exception("verification_audit_failed")


async def _verify_one(request: Request, pool, r, principal: Principal, finding_id: UUID,
                      *, trigger: str, reason: str | None) -> VerificationOut:
    row = await _visible(pool, principal, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    # A manual re-check of a finding marked fixed is a "prove it's fixed" check.
    purpose = "fix" if row["status"] == "fixed" else "exploitability"
    out = await service.request(
        pool, r, finding_id=finding_id, purpose=purpose, trigger=trigger,
        requested_by=principal.actor, reason=reason,
    )
    if not out.already_in_flight:
        await _audit(request, pool, principal, finding_id,
                     {"verification_id": str(out.id), "purpose": purpose, "trigger": trigger,
                      "status": out.status, "reason": out.reason})
    return out


@router.post("/findings/verify/bulk", response_model=BulkVerifyOut)
async def verify_bulk(
    body: BulkVerifyIn, request: Request,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    items: list[BulkVerifyItem] = []
    seen: set[UUID] = set()
    for fid in body.finding_ids:
        if fid in seen:
            continue
        seen.add(fid)
        try:
            out = await _verify_one(request, pool, r, principal, fid, trigger="bulk", reason=None)
        except HTTPException:
            items.append(BulkVerifyItem(finding_id=fid, outcome="not_found", reason="finding not found"))
            continue
        except Exception as e:  # noqa: BLE001 -- one bad finding must not sink the batch
            logger.exception("bulk_verify_failed", extra={"finding_id": str(fid)})
            items.append(BulkVerifyItem(finding_id=fid, outcome="error", reason=type(e).__name__))
            continue
        outcome = ("already_in_flight" if out.already_in_flight
                   else "refused" if out.status in ("refused", "cancelled")
                   else "error" if out.status == "error" else "queued")
        items.append(BulkVerifyItem(finding_id=fid, outcome=outcome, verification_id=out.id,
                                    reason=out.reason if outcome in ("refused", "error") else None))
    return BulkVerifyOut(
        requested=len(items), queued=sum(1 for i in items if i.outcome == "queued"),
        refused=sum(1 for i in items if i.outcome == "refused"), items=items,
    )


@router.post("/findings/{finding_id}/verify", response_model=VerificationOut, status_code=202)
async def verify_finding(
    finding_id: UUID, request: Request, body: VerifyIn | None = None,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    """Queue a safe check for this finding. 202 with the ledger row; 403 with the
    refusal reason (and a ledger row) when scope or proof-of-control says no."""
    out = await _verify_one(request, pool, r, principal, finding_id, trigger="manual",
                            reason=(body.reason if body else None))
    if out.status == "refused":
        raise HTTPException(status_code=403, detail={
            "error": "verification_refused", "reason": out.reason, "verification_id": str(out.id)})
    if out.status == "cancelled":
        raise HTTPException(status_code=409, detail={
            "error": "verification_cancelled", "reason": out.reason, "verification_id": str(out.id)})
    if out.status == "error":
        raise HTTPException(status_code=503, detail={
            "error": "verification_unavailable", "reason": out.reason, "verification_id": str(out.id)})
    return out


@router.get("/findings/{finding_id}/verifications", response_model=VerificationHistoryOut)
async def list_verifications(
    finding_id: UUID, limit: int = 50,
    pool=Depends(get_pool), principal: Principal = Depends(current_principal),
):
    row = await _visible(pool, principal, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {service._COLS} FROM finding_verifications WHERE finding_id = $1 "
            "ORDER BY requested_at DESC LIMIT $2",
            finding_id, max(1, min(limit, 200)),
        )
    return VerificationHistoryOut(
        finding_id=finding_id, exploitability=row["exploitability"],
        last_verified_at=row["last_verified_at"], fix_verified_at=row["fix_verified_at"],
        items=[service.row_out(x) for x in rows],
    )


@router.post("/verifications/{verification_id}/result", response_model=VerificationOut)
async def post_result(
    verification_id: UUID, body: ResultIn, request: Request,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    """Worker callback: only the service key, only for the dispatched job
    (``X-Paddock-Scan`` must be the scan the verification was queued as). A user
    or API key, even an admin's, can never post a verdict."""
    if principal.kind != "service":
        raise HTTPException(status_code=403, detail="verification results come from the worker job only")
    try:
        return await service.apply_result(pool, r, verification_id, body, actor=principal.actor,
                                          job_scan_id=request.headers.get("x-paddock-scan"))
    except service.ResultRejected as e:
        raise HTTPException(status_code=403, detail=str(e))
    except service.FindingNotFound:
        raise HTTPException(status_code=404, detail="verification not found")
    except service.AlreadyDecided as e:
        raise HTTPException(status_code=409, detail=f"verification already {e.status}")


@router.post("/remediation/{remediation_id}/merged")
async def remediation_merged(
    remediation_id: UUID, request: Request, body: RemediationMergedIn | None = None,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    """Record that a remediation PR was merged; if its finding is marked fixed, a
    safe re-check is scheduled (after the PR deploy delay)."""
    try:
        return await service.remediation_merged(pool, r, remediation_id, actor=principal.actor)
    except service.FindingNotFound:
        raise HTTPException(status_code=404, detail="remediation not found")
