"""Finding lifecycle API: triage transitions + suppression rules (schema 019).

- ``POST /v1/findings/{id}/accept``          risk accepted   (reason required, optional expiry)
- ``POST /v1/findings/{id}/false-positive``  false positive  (reason required, optional expiry,
                                             optional ``suppress`` to feed it back as a rule)
- ``POST /v1/findings/{id}/reopen``          back to ``open``
- ``GET/POST /v1/suppressions``, ``GET/PATCH/DELETE /v1/suppressions/{id}``

RBAC: every mutation needs the ``triage`` capability (see ``auth._RULES``).
Every transition is written to ``finding_status_history`` and the hash-chained
audit log with its reason, actor and expiry. Transitions on a primary finding
propagate to the duplicates collapsed into it, so the issue moves as one.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from .. import audit
from .. import lifecycle
from ..auth import Principal, current_principal
from ..db import get_pool
from ..queue import get_redis, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/findings", tags=["findings", "lifecycle"])
suppressions_router = APIRouter(prefix="/v1/suppressions", tags=["lifecycle"])


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

def _aware(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v


class DismissIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    accepted_until: datetime | None = None
    # false-positive only: also create a suppression rule for this rule_id on
    # this asset so the same noise is suppressed at ingest next time.
    suppress: bool = False

    @field_validator("reason")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("reason must be at least 3 non-blank characters")
        return v

    @field_validator("accepted_until")
    @classmethod
    def _future(cls, v: datetime | None) -> datetime | None:
        v = _aware(v)
        if v is not None and v <= datetime.now(timezone.utc):
            raise ValueError("accepted_until must be in the future")
        return v


class ReopenIn(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class TransitionOut(BaseModel):
    finding: lifecycle.FindingLifecycleOut
    from_status: str
    to_status: str
    propagated_to: int = 0
    suppression_id: UUID | None = None


class SuppressionIn(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    rule_id: str | None = Field(default=None, max_length=256)
    rule_source: str | None = Field(default=None, max_length=64)
    asset_pattern: str | None = Field(default=None, max_length=512)
    tag: str | None = Field(default=None, max_length=128)
    reason: str = Field(min_length=3, max_length=2000)
    expires_at: datetime | None = None
    enabled: bool = True
    apply_existing: bool = True

    @field_validator("expires_at")
    @classmethod
    def _future(cls, v: datetime | None) -> datetime | None:
        v = _aware(v)
        if v is not None and v <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return v


class SuppressionPatch(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    reason: str | None = Field(default=None, min_length=3, max_length=2000)
    expires_at: datetime | None = None
    enabled: bool | None = None


class SuppressionOut(BaseModel):
    id: UUID
    name: str | None
    rule_id: str | None
    rule_source: str | None
    asset_pattern: str | None
    tag: str | None
    reason: str
    author: str
    expires_at: datetime | None
    enabled: bool
    active: bool
    match_count: int
    suppressed_now: int = 0
    last_matched_at: datetime | None
    created_at: datetime
    updated_at: datetime


_SUP_COLS = (
    "s.id, s.name, s.rule_id, s.rule_source, s.asset_pattern, s.tag, s.reason, "
    "s.author, s.expires_at, s.enabled, s.match_count, s.last_matched_at, "
    "s.created_at, s.updated_at, "
    "(SELECT COUNT(*) FROM findings f WHERE f.suppressed_by = s.id) AS suppressed_now"
)


def _sup_out(row) -> SuppressionOut:
    d = dict(row)
    d["active"] = lifecycle.suppression_active(d)
    d["suppressed_now"] = int(d.get("suppressed_now") or 0)
    return SuppressionOut.model_validate(d)


# --------------------------------------------------------------------------- #
# Transitions
# --------------------------------------------------------------------------- #

async def _transition(
    request: Request,
    pool,
    r,
    principal: Principal,
    finding_id: UUID,
    *,
    to_status: str,
    reason: str | None,
    accepted_until: datetime | None,
    transition: str,
    allowed_from: frozenset[str] | None = None,
    suppress: bool = False,
) -> TransitionOut:
    from .findings import _FINDING_ABAC, fetch_enriched

    async with pool.acquire() as con:
        async with con.transaction():
            cur = await con.fetchrow(
                "SELECT f.id, f.status, f.rule_id, f.asset_id, a.value AS asset_value "
                "FROM findings f LEFT JOIN assets a ON a.id = f.asset_id "
                f"WHERE f.id = $1 AND {_FINDING_ABAC}$2 FOR UPDATE OF f",
                finding_id, principal.clearance_rank,
            )
            if cur is None:
                raise HTTPException(status_code=404, detail="finding not found")
            from_status = cur["status"]
            if allowed_from is not None and from_status not in allowed_from:
                raise HTTPException(
                    status_code=409,
                    detail=f"cannot {transition} a finding in status '{from_status}'",
                )
            await con.execute(
                """
                UPDATE findings
                   SET status = $2, status_reason = $3, status_by = $4,
                       status_changed_at = NOW(), accepted_until = $5,
                       fix_verified_at = NULL
                 WHERE id = $1
                """,
                finding_id, to_status, reason, principal.actor, accepted_until,
            )
            await lifecycle.record_history(con, finding_id, from_status, to_status, reason,
                                           accepted_until, principal.actor)
            # The duplicates collapsed into this primary move with it.
            dup_rows = await con.fetch(
                """
                UPDATE findings
                   SET status = $2, status_reason = $3, status_by = $4,
                       status_changed_at = NOW(), accepted_until = $5,
                       fix_verified_at = NULL
                 WHERE duplicate_of = $1 AND status IS DISTINCT FROM $2
             RETURNING id
                """,
                finding_id, to_status, reason, principal.actor, accepted_until,
            )
            for d in dup_rows:
                await lifecycle.record_history(con, d["id"], None, to_status,
                                               f"follows primary {finding_id}: {reason or ''}".strip(),
                                               accepted_until, principal.actor)
            sup_id = None
            if suppress:
                sup_id = await con.fetchval(
                    """
                    INSERT INTO finding_suppressions
                        (name, rule_id, asset_pattern, reason, author, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
                    """,
                    f"false positive: {cur['rule_id']}",
                    _glob_literal(cur["rule_id"]),
                    _glob_literal(cur["asset_value"]) if cur["asset_value"] else None,
                    reason or "false positive",
                    principal.actor,
                    accepted_until,
                )
            rows = await fetch_enriched(con, [finding_id])

    details: dict[str, Any] = {
        "transition": transition, "from": from_status, "to": to_status, "reason": reason,
        "accepted_until": accepted_until.isoformat() if accepted_until else None,
        "propagated_to": len(dup_rows),
    }
    if sup_id:
        details["suppression_id"] = str(sup_id)
    await _audit(request, pool, principal, "findings", str(finding_id), details)
    event = "finding_reopened" if to_status == "open" else "finding_closed"
    try:
        await publish_event(r, {"event": event, "finding_id": str(finding_id),
                                "status": to_status, "reason": reason})
    except Exception:  # noqa: BLE001
        logger.exception("publish_event_failed")
    return TransitionOut(finding=rows[0], from_status=from_status, to_status=to_status,
                         propagated_to=len(dup_rows), suppression_id=sup_id)


def _glob_literal(v: str) -> str:
    """Escape fnmatch metacharacters so a value matches only itself."""
    return "".join(f"[{c}]" if c in "*?[" else c for c in v)


async def _audit(request: Request, pool, principal: Principal, rtype: str, rid: str,
                 details: dict[str, Any], action: str = "update") -> None:
    try:
        await audit.record(
            pool, action=action,
            actor=principal.actor, actor_role=principal.role,
            resource_type=rtype, resource_id=rid, method=request.method,
            path=request.url.path, status=200,
            justification=request.headers.get("x-justification"),
            request_id=getattr(request.state, "request_id", None), details=details,
        )
    except Exception:  # noqa: BLE001 -- never fail the request on audit
        logger.exception("lifecycle_audit_failed", extra={"resource_id": rid})


@router.post("/{finding_id}/accept", response_model=TransitionOut)
async def accept_finding(
    finding_id: UUID, body: DismissIn, request: Request,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    """Risk accepted. A fixed finding cannot be accepted (reopen it first)."""
    return await _transition(
        request, pool, r, principal, finding_id, to_status="accepted", reason=body.reason,
        accepted_until=body.accepted_until, transition="accept",
        allowed_from=frozenset({"open", "triaged", "accepted", "accepted_risk",
                                "false_positive", "wontfix"}),
    )


@router.post("/{finding_id}/false-positive", response_model=TransitionOut)
async def mark_false_positive(
    finding_id: UUID, body: DismissIn, request: Request,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    return await _transition(
        request, pool, r, principal, finding_id, to_status="false_positive",
        reason=body.reason, accepted_until=body.accepted_until, transition="false_positive",
        suppress=body.suppress,
    )


@router.post("/{finding_id}/reopen", response_model=TransitionOut)
async def reopen_finding(
    finding_id: UUID, request: Request, body: ReopenIn | None = None,
    pool=Depends(get_pool), r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    reason = (body.reason.strip() if body and body.reason else None) or None
    return await _transition(
        request, pool, r, principal, finding_id, to_status="open", reason=reason,
        accepted_until=None, transition="reopen",
        allowed_from=frozenset({"triaged", "accepted", "accepted_risk", "false_positive",
                                "fixed", "wontfix"}),
    )


# --------------------------------------------------------------------------- #
# Suppressions CRUD
# --------------------------------------------------------------------------- #

@suppressions_router.get("", response_model=list[SuppressionOut])
async def list_suppressions(
    active: bool | None = None,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    where = ""
    if active is True:
        where = "WHERE s.enabled AND (s.expires_at IS NULL OR s.expires_at > NOW())"
    elif active is False:
        where = "WHERE NOT (s.enabled AND (s.expires_at IS NULL OR s.expires_at > NOW()))"
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_SUP_COLS} FROM finding_suppressions s {where} "
            "ORDER BY s.created_at DESC LIMIT $1 OFFSET $2",
            limit, offset,
        )
    return [_sup_out(r) for r in rows]


@suppressions_router.post("", response_model=SuppressionOut, status_code=201)
async def create_suppression(
    body: SuppressionIn, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    if not (body.rule_id or body.asset_pattern or body.tag):
        raise HTTPException(
            status_code=422, detail="a suppression needs rule_id, asset_pattern or tag"
        )
    async with pool.acquire() as con:
        async with con.transaction():
            sid = await con.fetchval(
                """
                INSERT INTO finding_suppressions
                    (name, rule_id, rule_source, asset_pattern, tag, reason, author,
                     expires_at, enabled)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
                """,
                body.name, body.rule_id, body.rule_source, body.asset_pattern, body.tag,
                body.reason.strip(), principal.actor, body.expires_at, body.enabled,
            )
            applied = 0
            if body.apply_existing and body.enabled:
                sup = body.model_dump()
                sup["id"] = sid
                applied = await lifecycle.apply_suppression_to_existing(con, sup)
            row = await con.fetchrow(
                f"SELECT {_SUP_COLS} FROM finding_suppressions s WHERE s.id = $1", sid
            )
    await _audit(request, pool, principal, "suppressions", str(sid), {
        **body.model_dump(mode="json"), "applied_existing": applied,
    }, action="create")
    return _sup_out(row)


@suppressions_router.get("/{sup_id}", response_model=SuppressionOut)
async def get_suppression(sup_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_SUP_COLS} FROM finding_suppressions s WHERE s.id = $1", sup_id
        )
    if row is None:
        raise HTTPException(status_code=404, detail="suppression not found")
    return _sup_out(row)


@suppressions_router.patch("/{sup_id}", response_model=SuppressionOut)
async def patch_suppression(
    sup_id: UUID, patch: SuppressionPatch, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    fields = patch.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="no patch fields supplied")
    if "expires_at" in fields:
        fields["expires_at"] = _aware(fields["expires_at"])
    sets, args = [], []
    for col in ("name", "reason", "expires_at", "enabled"):
        if col in fields:
            args.append(fields[col])
            sets.append(f"{col} = ${len(args)}")
    args.append(sup_id)
    async with pool.acquire() as con:
        async with con.transaction():
            updated = await con.fetchrow(
                f"UPDATE finding_suppressions SET {', '.join(sets)}, updated_at = NOW() "
                f"WHERE id = ${len(args)} RETURNING *",
                *args,
            )
            if updated is None:
                raise HTTPException(status_code=404, detail="suppression not found")
            sup = dict(updated)
            released = applied = 0
            if not lifecycle.suppression_active(sup):
                released = await lifecycle.release_suppression(con, sup_id)
            elif fields.get("enabled") is True:
                applied = await lifecycle.apply_suppression_to_existing(con, sup)
            row = await con.fetchrow(
                f"SELECT {_SUP_COLS} FROM finding_suppressions s WHERE s.id = $1", sup_id
            )
    await _audit(request, pool, principal, "suppressions", str(sup_id), {
        **patch.model_dump(mode="json", exclude_unset=True),
        "released": released, "applied_existing": applied,
    })
    return _sup_out(row)


@suppressions_router.delete("/{sup_id}", status_code=204)
async def delete_suppression(
    sup_id: UUID, request: Request, pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    async with pool.acquire() as con:
        async with con.transaction():
            released = await lifecycle.release_suppression(con, sup_id)
            gone = await con.fetchval(
                "DELETE FROM finding_suppressions WHERE id = $1 RETURNING id", sup_id
            )
    if gone is None:
        raise HTTPException(status_code=404, detail="suppression not found")
    await _audit(request, pool, principal, "suppressions", str(sup_id),
                 {"released": released}, action="delete")
