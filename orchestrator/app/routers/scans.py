"""Scan intake and lifecycle.

Scope-checks before enqueue, writes the scans row, pushes to Redis
Streams. Also owns the PATCH / start / complete / fail lifecycle
endpoints workers call as a job moves through the FSM.

No endpoint here performs any outbound action itself; this is a job
intake, not a worker. Attack-aid scan kinds are refused up front.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import scope as scope_svc
from ..billing import gate as billing_gate
from ..db import get_pool
from ..models import (
    ScanCompleteIn,
    ScanFailIn,
    ScanIn,
    ScanOut,
    ScanPatch,
    ScanStartIn,
    ScanStatus,
)
from ..queue import enqueue_scan, get_redis, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/scans", tags=["scans"])

# Hard refusal list -- these align with the "Do-not-build" section of
# CONTRACTS.md. If a caller asks for one of these kinds we 400 outright,
# we do not scope-check and we do not enqueue.
_REFUSED_KINDS = {
    "exploit",
    "exploit_launch",
    "cred_stuff",
    "credential_stuffing",
    "password_spray",
    "brute_force",
    "waf_bypass",
    "stealth_scan",
    "fragment_scan",
    "session_hijack",
    "exfil",
}

_TERMINAL_STATES = {"completed", "failed", "cancelled"}


# --------------------------------------------------------------------------- #
# Shared enqueue/dispatch helpers
#
# These factor the "write a scans row + push the job onto the right Redis
# stream" path so the scheduler loop and the /run-now endpoint reuse the exact
# same dispatch the public POST /v1/scans uses. The scope-check still runs for
# every scheduled target (see `dispatch_scoped_scan`).
# --------------------------------------------------------------------------- #

_INSERT_SCAN_SQL = """
    INSERT INTO scans (kind, target, status, priority, config, parent_scan_id)
    VALUES ($1, $2, 'queued', $3, $4::jsonb, $5)
    RETURNING id, kind, target, status, priority, queued_at, started_at,
              finished_at, worker_id, config, result_summary, error,
              parent_scan_id
"""


class ScanKindRefused(Exception):
    """Raised when a refused (offensive) scan kind is dispatched."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class ScopeDenied(Exception):
    """Raised when a target fails the scope check during dispatch."""

    def __init__(self, decision: scope_svc.ScopeDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


async def _insert_and_enqueue(
    pool,
    r,
    *,
    kind: str,
    normalized_target: str,
    config: dict[str, Any],
    priority: int,
    parent_scan_id: UUID | None,
    matched_entry_id: int | None,
):
    """Write the scans row and push the job. Returns a ScanOut.

    On an enqueue failure the row is marked failed and the error re-raised so
    callers can surface it (the HTTP endpoint maps it to a 503).
    """
    async with pool.acquire() as con:
        row = await con.fetchrow(
            _INSERT_SCAN_SQL,
            kind,
            normalized_target,
            priority,
            json.dumps(config),
            parent_scan_id,
        )

    scan_id = row["id"]
    job = {
        "scan_id": str(scan_id),
        "kind": kind,
        "target": normalized_target,
        "config": config,
        "scope_matched_entry": matched_entry_id,
        "parent_scan_id": str(parent_scan_id) if parent_scan_id else None,
    }
    try:
        await enqueue_scan(r, job)
    except Exception:
        logger.exception("enqueue_failed", extra={"scan_id": str(scan_id)})
        async with pool.acquire() as con:
            await con.execute(
                "UPDATE scans SET status='failed', error='enqueue_failed' WHERE id=$1",
                scan_id,
            )
        raise
    return _row_to_scan(row)


async def dispatch_scoped_scan(
    pool,
    r,
    *,
    kind: str,
    target: str,
    config: dict[str, Any] | None = None,
    priority: int = 5,
    worker: str = "orchestrator.scheduler",
    reason: str = "scheduled_scan",
):
    """Refuse-check -> scope-check -> enqueue a scan for a single target.

    Used by the scheduler loop and the /run-now endpoint. Raises
    `ScanKindRefused` for an offensive kind (before any scope check or DB
    write) and `ScopeDenied` when the target is out of scope.
    """
    if kind.lower() in _REFUSED_KINDS:
        raise ScanKindRefused(kind)
    decision = await scope_svc.check(pool, target=target, worker=worker, reason=reason)
    if not decision.allow:
        raise ScopeDenied(decision)
    return await _insert_and_enqueue(
        pool,
        r,
        kind=kind,
        normalized_target=decision.normalized,
        config=config or {},
        priority=priority,
        parent_scan_id=None,
        matched_entry_id=decision.matched_entry_id,
    )


# --------------------------------------------------------------------------- #
# Create (with parent-scan inheritance)
# --------------------------------------------------------------------------- #

@router.post(
    "", response_model=ScanOut, status_code=201,
    dependencies=[Depends(billing_gate.require_quota("assets"))],
)
async def create_scan(
    body: ScanIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    if body.kind.lower() in _REFUSED_KINDS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "refused_kind",
                "message": (
                    "This scan kind is not supported by paddock. "
                    "Workers in this platform perform discovery and probing "
                    "only; see docs/CONTRACTS.md Do-not-build list."
                ),
            },
        )

    # If a parent is provided AND the parent exists, inherit its scope
    # decision (the parent was already scope-checked when it was created).
    # If the parent id is unknown, fall back to a fresh scope-check.
    normalized_target: str
    matched_entry_id: int | None = None
    scope_inherited = False
    if body.parent_scan_id is not None:
        async with pool.acquire() as con:
            parent = await con.fetchrow(
                "SELECT id, target FROM scans WHERE id = $1", body.parent_scan_id
            )
        if parent is not None:
            # Parent already passed scope; just normalize this child's own
            # target for storage / enqueue. No new scope_decisions row.
            normalized_target = scope_svc.normalize(body.target)
            if not normalized_target:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "empty_target_after_normalize"},
                )
            scope_inherited = True

    if not scope_inherited:
        decision = await scope_svc.check(
            pool, target=body.target, worker="orchestrator.scan_intake",
            reason="scan_create",
        )
        if not decision.allow:
            raise HTTPException(
                status_code=403,
                detail={
                    "allow": False,
                    "reason": decision.reason,
                    "normalized": decision.normalized,
                },
            )
        normalized_target = decision.normalized
        matched_entry_id = decision.matched_entry_id

    try:
        return await _insert_and_enqueue(
            pool,
            r,
            kind=body.kind,
            normalized_target=normalized_target,
            config=body.config,
            priority=body.priority,
            parent_scan_id=body.parent_scan_id,
            matched_entry_id=matched_entry_id,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="scan queue unavailable")


# --------------------------------------------------------------------------- #
# Lifecycle PATCH + convenience aliases
# --------------------------------------------------------------------------- #

@router.patch("/{scan_id}", response_model=ScanOut)
async def patch_scan(
    scan_id: UUID,
    patch: ScanPatch,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    """Advance a scan through its FSM.

    - `started_at = NOW()` the first time status becomes `running`.
    - `finished_at = NOW()` the first time status becomes a terminal state
      (`completed`, `failed`, `cancelled`).
    - Idempotent: a repeat PATCH with the same status is a no-op on the
      timestamps that are already set.
    - Emits `scan_started` / `scan_completed` / `scan_failed` only on an
      actual status transition (not on re-posts).
    """
    async with pool.acquire() as con:
        async with con.transaction():
            current = await con.fetchrow(
                "SELECT status FROM scans WHERE id = $1 FOR UPDATE",
                scan_id,
            )
            if current is None:
                raise HTTPException(status_code=404, detail="scan not found")

            old_status = current["status"]
            new_status = patch.status or old_status
            transition = patch.status is not None and patch.status != old_status

            # Build dynamic UPDATE.
            set_parts: list[str] = []
            args: list[Any] = []

            if patch.status is not None:
                args.append(patch.status)
                set_parts.append(f"status = ${len(args)}")

            if patch.result_summary is not None:
                args.append(json.dumps(patch.result_summary))
                set_parts.append(
                    f"result_summary = result_summary || ${len(args)}::jsonb"
                )

            if patch.error is not None:
                args.append(patch.error)
                set_parts.append(f"error = ${len(args)}")

            if patch.worker_id is not None:
                args.append(patch.worker_id)
                set_parts.append(f"worker_id = ${len(args)}")

            # Timestamps are set only on the first transition into their
            # state, so idempotent re-posts don't rewrite them.
            if new_status == "running":
                set_parts.append(
                    "started_at = COALESCE(started_at, NOW())"
                )
            if new_status in _TERMINAL_STATES:
                set_parts.append(
                    "finished_at = COALESCE(finished_at, NOW())"
                )

            if not set_parts:
                # Nothing to update, but we still 200 back the row.
                row = await con.fetchrow(_SCAN_SELECT_SQL, scan_id)
                return _row_to_scan(row)

            args.append(scan_id)
            sql = f"""
                UPDATE scans SET {", ".join(set_parts)}
                 WHERE id = ${len(args)}
             RETURNING id, kind, target, status, priority, queued_at, started_at,
                       finished_at, worker_id, config, result_summary, error,
                       parent_scan_id
            """
            row = await con.fetchrow(sql, *args)

    if transition:
        event: dict[str, Any] | None = None
        if new_status == "running":
            event = {
                "event": "scan_started",
                "scan_id": str(scan_id),
                "kind": row["kind"],
                "target": row["target"],
                "worker_id": row["worker_id"],
            }
        elif new_status == "completed":
            event = {
                "event": "scan_completed",
                "scan_id": str(scan_id),
                "kind": row["kind"],
                "target": row["target"],
            }
        elif new_status == "failed":
            event = {
                "event": "scan_failed",
                "scan_id": str(scan_id),
                "kind": row["kind"],
                "target": row["target"],
                "error": row["error"],
            }
        if event is not None:
            try:
                await publish_event(r, event)
            except Exception:
                logger.exception("publish_event_failed", extra=event)

    return _row_to_scan(row)


@router.post("/{scan_id}/start", response_model=ScanOut)
async def start_scan(
    scan_id: UUID,
    body: ScanStartIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    patch = ScanPatch(status="running", worker_id=body.worker_id)
    return await patch_scan(scan_id, patch, pool, r)


@router.post("/{scan_id}/complete", response_model=ScanOut)
async def complete_scan(
    scan_id: UUID,
    body: ScanCompleteIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    patch = ScanPatch(status="completed", result_summary=body.result_summary)
    return await patch_scan(scan_id, patch, pool, r)


@router.post("/{scan_id}/fail", response_model=ScanOut)
async def fail_scan(
    scan_id: UUID,
    body: ScanFailIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    patch = ScanPatch(status="failed", error=body.error)
    return await patch_scan(scan_id, patch, pool, r)


# --------------------------------------------------------------------------- #
# Read-only
# --------------------------------------------------------------------------- #

_SCAN_SELECT_SQL = """
    SELECT id, kind, target, status, priority, queued_at, started_at,
           finished_at, worker_id, config, result_summary, error,
           parent_scan_id
      FROM scans
     WHERE id = $1
"""


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(_SCAN_SELECT_SQL, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return _row_to_scan(row)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    target: str | None = None,
    status: ScanStatus | None = None,
    parent_scan_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses = []
    args: list[Any] = []
    if target is not None:
        args.append(scope_svc.normalize(target))
        clauses.append(f"target = ${len(args)}")
    if status is not None:
        args.append(status)
        clauses.append(f"status = ${len(args)}")
    if parent_scan_id is not None:
        args.append(parent_scan_id)
        clauses.append(f"parent_scan_id = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.extend([limit, offset])
    sql = f"""
        SELECT id, kind, target, status, priority, queued_at, started_at,
               finished_at, worker_id, config, result_summary, error,
               parent_scan_id
          FROM scans
          {where}
         ORDER BY queued_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [_row_to_scan(r) for r in rows]


def _row_to_scan(row) -> ScanOut:
    d = dict(row)
    for col in ("config", "result_summary"):
        if isinstance(d.get(col), str):
            d[col] = json.loads(d[col])
    return ScanOut.model_validate(d)
