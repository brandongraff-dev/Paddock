"""SOURCE integration sync status + manual "sync now" (schema 025).

    GET  /v1/integration-sync                     latest run per SOURCE integration
    GET  /v1/integration-sync/{id}/runs           run history (newest first)
    POST /v1/integration-sync/{id}                run a pull now (admin; RBAC default)

Scheduled pulls happen in the scheduler loop (``app/scheduler.py`` ->
``app/integrations/runtime.py``). The integration CRUD itself lives in the
integrations core router; this one only reads/writes ``integration_sync_runs``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import Principal, current_principal, require
from ..db import get_pool
from ..queue import get_redis

router = APIRouter(prefix="/v1/integration-sync", tags=["integrations"])


class SyncRunOut(BaseModel):
    id: int
    integration_id: UUID
    trigger: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    counts: dict[str, Any] = Field(default_factory=dict)
    detail: str | None = None


class SyncStatusOut(BaseModel):
    integration_id: UUID
    kind: str
    name: str
    enabled: bool
    last_run: SyncRunOut | None = None
    # Additive (schema 031 UI): when the scheduler will pull next, and how many
    # scope suggestions from this integration still await a human.
    interval_minutes: int | None = None
    next_run_at: datetime | None = None
    pending_suggestions: int = 0


class SyncNowOut(BaseModel):
    status: str
    detail: str | None = None
    counts: dict[str, Any] = Field(default_factory=dict)
    run_id: int | None = None


def _run(row) -> SyncRunOut:
    d = dict(row)
    if isinstance(d.get("counts"), str):
        d["counts"] = json.loads(d["counts"])
    return SyncRunOut.model_validate(d)


_RUN_COLS = "id, integration_id, trigger, status, started_at, finished_at, counts, detail"


@router.get("", response_model=list[SyncStatusOut])
async def sync_status(pool=Depends(get_pool)):
    from ..integrations.base import Capability
    from ..integrations.runtime import connector_class

    from ..integrations.runtime import _json, interval_minutes, sync_enabled

    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT id, kind, name, enabled, config FROM integrations ORDER BY name")
        runs = await con.fetch(
            f"SELECT DISTINCT ON (integration_id) {_RUN_COLS} FROM integration_sync_runs "
            "ORDER BY integration_id, started_at DESC")
        pend = await con.fetch(
            "SELECT integration_id, COUNT(*) AS n FROM scope_suggestions "
            "WHERE status = 'pending' GROUP BY integration_id")
    last = {r["integration_id"]: _run(r) for r in runs}
    pending = {r["integration_id"]: int(r["n"]) for r in pend}
    out: list[SyncStatusOut] = []
    for r in rows:
        try:
            if Capability.SOURCE not in connector_class(r["kind"]).capabilities:
                continue
        except KeyError:
            continue
        run = last.get(r["id"])
        every = interval_minutes(_json(r["config"]))
        nxt = None
        if r["enabled"] and sync_enabled():
            nxt = (run.started_at + timedelta(minutes=every)) if run else datetime.now(timezone.utc)
        out.append(SyncStatusOut(integration_id=r["id"], kind=r["kind"], name=r["name"],
                                 enabled=r["enabled"], last_run=run, interval_minutes=every,
                                 next_run_at=nxt, pending_suggestions=pending.get(r["id"], 0)))
    return out


@router.get("/{integration_id}/runs", response_model=list[SyncRunOut])
async def sync_runs(integration_id: UUID, limit: int = Query(20, ge=1, le=200),
                    pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_RUN_COLS} FROM integration_sync_runs WHERE integration_id = $1 "
            "ORDER BY started_at DESC LIMIT $2", integration_id, limit)
    return [_run(r) for r in rows]


@router.post("/{integration_id}", response_model=SyncNowOut)
async def sync_now(integration_id: UUID, request: Request, pool=Depends(get_pool),
                   r=Depends(get_redis), principal: Principal = Depends(current_principal)):
    from ..integrations.runtime import run_source_sync

    factory = getattr(request.app.state, "integration_http_factory", None)
    res = await run_source_sync(pool, r, integration_id, trigger="manual",
                                actor=principal.actor, http_factory=factory)
    if res.get("detail") == "integration not found":
        raise HTTPException(status_code=404, detail="integration not found")
    if res["status"] == "error" and res.get("run_id") is None:
        raise HTTPException(status_code=422, detail=res.get("detail"))
    return SyncNowOut(status=res["status"], detail=res.get("detail") or None,
                      counts=res.get("counts") or {}, run_id=res.get("run_id"))


# --------------------------------------------------------------------------- #
# Scope suggestions (schema 031). A cloud SOURCE leaves PENDING rows; a human
# accepts one through the NORMAL scope add (validation, audit, cache, and the
# proof-of-control that still gates any scan) or dismisses it. Nothing here
# widens scope by itself.
# --------------------------------------------------------------------------- #

class SuggestionOut(BaseModel):
    id: int
    integration_id: UUID
    integration_name: str | None = None
    source: str
    kind: str
    value: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    status: str
    first_seen: datetime
    last_seen: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    scope_entry_id: int | None = None


class AcceptIn(BaseModel):
    model_config = {"extra": "forbid"}
    auth_doc_ref: str | None = Field(default=None, max_length=512)
    notes: str | None = Field(default=None, max_length=2048)


class DismissIn(BaseModel):
    model_config = {"extra": "forbid"}
    reason: str | None = Field(default=None, max_length=2048)


class AcceptOut(BaseModel):
    suggestion: SuggestionOut
    scope_entry: dict[str, Any]


_SUG_COLS = ("s.id, s.integration_id, i.name AS integration_name, s.source, s.kind, s.value, "
             "s.evidence, s.status, s.first_seen, s.last_seen, s.decided_by, s.decided_at, "
             "s.scope_entry_id")


def _sug(row) -> SuggestionOut:
    d = dict(row)
    if isinstance(d.get("evidence"), str):
        d["evidence"] = json.loads(d["evidence"])
    return SuggestionOut.model_validate(d)


@router.get("/suggestions", response_model=list[SuggestionOut])
async def list_suggestions(status_filter: str = Query("pending", alias="status"),
                           integration_id: UUID | None = None,
                           limit: int = Query(200, ge=1, le=1000), pool=Depends(get_pool)):
    if status_filter not in ("pending", "accepted", "dismissed", "all"):
        raise HTTPException(status_code=422, detail="invalid status filter")
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_SUG_COLS} FROM scope_suggestions s "
            "LEFT JOIN integrations i ON i.id = s.integration_id "
            "WHERE ($1 = 'all' OR s.status = $1) AND ($2::uuid IS NULL OR s.integration_id = $2) "
            "ORDER BY s.last_seen DESC, s.id LIMIT $3", status_filter, integration_id, limit)
    return [_sug(r) for r in rows]


async def _load_pending(con, suggestion_id: int):
    row = await con.fetchrow(
        f"SELECT {_SUG_COLS} FROM scope_suggestions s "
        "LEFT JOIN integrations i ON i.id = s.integration_id WHERE s.id = $1", suggestion_id)
    if row is None:
        raise HTTPException(status_code=404, detail="suggestion not found")
    if row["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"suggestion is already {row['status']}")
    return row


@router.post("/suggestions/{suggestion_id}/accept", response_model=AcceptOut,
             dependencies=[Depends(require("admin"))])
async def accept_suggestion(suggestion_id: int, body: AcceptIn, request: Request,
                            pool=Depends(get_pool), r=Depends(get_redis),
                            principal: Principal = Depends(current_principal)):
    """Add the suggested value to scope through the normal scope add. The entry
    still needs proof-of-control (``/v1/scope/{id}/challenge`` + ``/verify``)
    before anything is scanned."""
    from .. import audit
    from ..models import ScopeEntryIn
    from . import scope as scope_router

    async with pool.acquire() as con:
        row = await _load_pending(con, suggestion_id)
    entry_in = ScopeEntryIn(
        kind=row["kind"], value=row["value"], added_by=principal.actor,
        auth_doc_ref=body.auth_doc_ref,
        notes=body.notes or f"Accepted from {row['source']} suggestion #{suggestion_id}",
        metadata={"suggested_by": row["source"], "suggestion_id": suggestion_id})
    entry = await scope_router.add_scope(entry_in, pool=pool, r=r)   # validates / refuses like any add
    async with pool.acquire() as con:
        upd = await con.fetchrow(
            "UPDATE scope_suggestions SET status = 'accepted', decided_by = $2, decided_at = NOW(), "
            "scope_entry_id = $3 WHERE id = $1 AND status = 'pending' RETURNING id",
            suggestion_id, principal.actor, entry.id)
        if upd is None:
            raise HTTPException(status_code=409, detail="suggestion was decided concurrently")
        new = await con.fetchrow(
            f"SELECT {_SUG_COLS} FROM scope_suggestions s "
            "LEFT JOIN integrations i ON i.id = s.integration_id WHERE s.id = $1", suggestion_id)
        with_proof = (await scope_router._with_proofs(con, [entry]))[0]
    try:
        await audit.record(pool, action="scope_suggestion_accept", actor=principal.actor,
                           actor_role=principal.role, resource_type="scope_suggestion",
                           resource_id=str(suggestion_id),
                           details={"kind": row["kind"], "value": row["value"],
                                    "scope_entry_id": entry.id, "source": row["source"]})
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).exception("scope_suggestion_audit_failed")
    return AcceptOut(suggestion=_sug(new), scope_entry=json.loads(with_proof.model_dump_json()))


@router.post("/suggestions/{suggestion_id}/dismiss", response_model=SuggestionOut,
             dependencies=[Depends(require("admin"))])
async def dismiss_suggestion(suggestion_id: int, body: DismissIn, pool=Depends(get_pool),
                             principal: Principal = Depends(current_principal)):
    """Dismiss: the suggestion stays recorded (so the next sync does not re-raise it)."""
    from .. import audit

    async with pool.acquire() as con:
        await _load_pending(con, suggestion_id)
        await con.execute(
            "UPDATE scope_suggestions SET status = 'dismissed', decided_by = $2, decided_at = NOW() "
            "WHERE id = $1 AND status = 'pending'", suggestion_id, principal.actor)
        new = await con.fetchrow(
            f"SELECT {_SUG_COLS} FROM scope_suggestions s "
            "LEFT JOIN integrations i ON i.id = s.integration_id WHERE s.id = $1", suggestion_id)
    try:
        await audit.record(pool, action="scope_suggestion_dismiss", actor=principal.actor,
                           actor_role=principal.role, resource_type="scope_suggestion",
                           resource_id=str(suggestion_id), details={"reason": body.reason})
    except Exception:  # noqa: BLE001
        pass
    return _sug(new)
