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
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import Principal, current_principal
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

    async with pool.acquire() as con:
        rows = await con.fetch("SELECT id, kind, name, enabled FROM integrations ORDER BY name")
        runs = await con.fetch(
            f"SELECT DISTINCT ON (integration_id) {_RUN_COLS} FROM integration_sync_runs "
            "ORDER BY integration_id, started_at DESC")
    last = {r["integration_id"]: _run(r) for r in runs}
    out: list[SyncStatusOut] = []
    for r in rows:
        try:
            if Capability.SOURCE not in connector_class(r["kind"]).capabilities:
                continue
        except KeyError:
            continue
        out.append(SyncStatusOut(integration_id=r["id"], kind=r["kind"], name=r["name"],
                                 enabled=r["enabled"], last_run=last.get(r["id"])))
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
