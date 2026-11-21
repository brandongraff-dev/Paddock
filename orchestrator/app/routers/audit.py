"""Audit-log read + integrity-verify endpoints (auditor/admin).

- ``GET /v1/audit``        -- paged, filterable view of the hash-chained log.
- ``GET /v1/audit/verify`` -- walks the caller's tenant chain (streamed) and
  checks its head against the latest external anchor (truncation / rewrite).
- ``POST /v1/audit/anchor`` -- publish the chain head to the anchor sink now
  (admin; the background loop does this every AUDIT_ANCHOR_INTERVAL_SEC).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import audit as audit_svc
from ..auth import require_scope
from ..billing import gate as billing_gate
from ..db import get_pool
from ..models import AuditAnchorOut, AuditEntryOut, AuditPage, AuditVerifyOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/audit", tags=["audit"])


def _row_to_entry(row) -> AuditEntryOut:
    d = dict(row)
    if isinstance(d.get("details"), str):
        d["details"] = json.loads(d["details"])
    elif d.get("details") is None:
        d["details"] = {}
    return AuditEntryOut.model_validate(d)


@router.get("", response_model=AuditPage, dependencies=[Depends(require_scope("audit"))])
async def list_audit(
    actor: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if actor is not None:
        args.append(actor)
        clauses.append(f"actor = ${len(args)}")
    if action is not None:
        args.append(action)
        clauses.append(f"action = ${len(args)}")
    if resource_type is not None:
        args.append(resource_type)
        clauses.append(f"resource_type = ${len(args)}")
    if from_ is not None:
        args.append(from_)
        clauses.append(f"ts >= ${len(args)}")
    if to is not None:
        args.append(to)
        clauses.append(f"ts <= ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_sql = f"SELECT COUNT(*) FROM audit_log {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT id, ts, actor, actor_role, action, resource_type, resource_id,
               method, path, status, classification, justification, ip,
               request_id, details, prev_hash, entry_hash
          FROM audit_log
          {where}
         ORDER BY id DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(count_sql, *args)
        rows = await con.fetch(sql, *args_list)
    return AuditPage(
        items=[_row_to_entry(r) for r in rows],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


@router.get("/verify", response_model=AuditVerifyOut, dependencies=[Depends(require_scope("audit"))])
async def verify_audit(request: Request, pool=Depends(get_pool)):
    kwargs = {}
    if hasattr(request.app.state, "audit_anchor_sink"):
        kwargs["sink"] = request.app.state.audit_anchor_sink
    result = await audit_svc.verify(pool, **kwargs)
    return AuditVerifyOut(**result)


@router.post(
    "/anchor", response_model=AuditAnchorOut,
    dependencies=[Depends(require_scope("admin")), Depends(billing_gate.require_paid("audit_anchoring"))],
)
async def anchor_audit(request: Request, pool=Depends(get_pool)):
    kwargs = {}
    if hasattr(request.app.state, "audit_anchor_sink"):
        kwargs["sink"] = request.app.state.audit_anchor_sink
    try:
        result = await audit_svc.anchor_head(pool, **kwargs)
    except audit_svc.AuditIntegrityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except audit_svc.AnchorSinkError as exc:
        raise HTTPException(status_code=502, detail=f"anchor sink: {exc}") from exc
    return AuditAnchorOut(**result)
