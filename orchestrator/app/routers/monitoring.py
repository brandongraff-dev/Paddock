"""Continuous-monitoring schedules CRUD + run-now.

The scheduler loop (`app.scheduler`) consumes the rows this router writes. No
endpoint here probes anything; `/run-now` only enqueues scans through the same
dispatch path `POST /v1/scans` uses (scope check included).

Timing validation: when `croniter` is installed a non-empty `cron` must parse;
otherwise a schedule must carry `config.every_n_minutes` so the loop has an
interval to fall back on.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import scheduler as scheduler_mod
from ..db import get_pool
from ..middleware import require_scope_admin
from ..models import (
    ScheduleIn,
    ScheduleOut,
    SchedulePatch,
    ScheduleRunOut,
)
from ..queue import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/schedules", tags=["monitoring"])

_COLS = (
    "id, name, scan_kind, target_scope, cron, enabled, last_run_at, "
    "next_run_at, last_status, config"
)


def _validate_timing(cron: str | None, config: dict[str, Any] | None) -> None:
    """Require either a croniter-valid cron or config.every_n_minutes."""
    config = config or {}
    every = config.get("every_n_minutes")
    has_interval = isinstance(every, (int, float)) and not isinstance(every, bool) and every > 0

    if scheduler_mod.croniter_available() and cron:
        if not scheduler_mod._croniter.is_valid(cron):  # type: ignore[union-attr]
            raise HTTPException(status_code=422, detail="invalid cron expression")
        return

    if has_interval:
        return

    if not scheduler_mod.croniter_available():
        raise HTTPException(
            status_code=422,
            detail="croniter is not installed; config.every_n_minutes is required",
        )
    raise HTTPException(
        status_code=422,
        detail="provide a valid cron expression or config.every_n_minutes",
    )


@router.get("", response_model=list[ScheduleOut])
async def list_schedules(
    enabled: bool | None = None,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if enabled is not None:
        args.append(enabled)
        clauses.append(f"enabled = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.extend([limit, offset])
    sql = f"""
        SELECT {_COLS}
          FROM schedules
          {where}
         ORDER BY created_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [scheduler_mod.row_to_schedule(r) for r in rows]


@router.post(
    "",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope_admin)],
)
async def create_schedule(body: ScheduleIn, pool=Depends(get_pool)):
    _validate_timing(body.cron, body.config)
    # Seed next_run_at from now so the loop picks it up on its next tick.
    next_run = scheduler_mod.compute_next_run(
        datetime.now(timezone.utc), cron=body.cron or None, config=body.config
    )
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            INSERT INTO schedules (
                name, scan_kind, target_scope, cron, enabled, config,
                created_by, next_run_at
            ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
            RETURNING {_COLS}
            """,
            body.name,
            body.scan_kind,
            body.target_scope,
            body.cron,
            body.enabled,
            json.dumps(body.config),
            body.created_by,
            next_run,
        )
    return scheduler_mod.row_to_schedule(row)


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleOut,
    dependencies=[Depends(require_scope_admin)],
)
async def patch_schedule(
    schedule_id: UUID,
    patch: SchedulePatch,
    pool=Depends(get_pool),
):
    fields = patch.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="no patch fields supplied")

    async with pool.acquire() as con:
        current = await con.fetchrow(
            "SELECT cron, config FROM schedules WHERE id = $1", schedule_id
        )
        if current is None:
            raise HTTPException(status_code=404, detail="schedule not found")

        cur_config = current["config"]
        if isinstance(cur_config, str):
            cur_config = json.loads(cur_config)
        eff_cron = fields.get("cron", current["cron"])
        eff_config = fields.get("config", cur_config)
        if "cron" in fields or "config" in fields:
            _validate_timing(eff_cron, eff_config)

        set_parts: list[str] = []
        args: list[Any] = []
        for col in ("name", "scan_kind", "target_scope", "cron", "enabled"):
            if col in fields:
                args.append(fields[col])
                set_parts.append(f"{col} = ${len(args)}")
        if "config" in fields:
            args.append(json.dumps(fields["config"] or {}))
            set_parts.append(f"config = ${len(args)}::jsonb")
        # Recompute next_run_at when the timing inputs changed.
        if "cron" in fields or "config" in fields:
            args.append(
                scheduler_mod.compute_next_run(
                    datetime.now(timezone.utc),
                    cron=(eff_cron or None),
                    config=eff_config,
                )
            )
            set_parts.append(f"next_run_at = ${len(args)}")

        args.append(schedule_id)
        row = await con.fetchrow(
            f"""
            UPDATE schedules
               SET {", ".join(set_parts)}
             WHERE id = ${len(args)}
         RETURNING {_COLS}
            """,
            *args,
        )
    return scheduler_mod.row_to_schedule(row)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope_admin)],
)
async def delete_schedule(schedule_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        res = await con.execute("DELETE FROM schedules WHERE id = $1", schedule_id)
    if res.rsplit(" ", 1)[-1] == "0":
        raise HTTPException(status_code=404, detail="schedule not found")
    return None


@router.post("/{schedule_id}/run-now", response_model=ScheduleRunOut)
async def run_schedule_now(
    schedule_id: UUID,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    """Enqueue the schedule's scan(s) immediately, regardless of next_run_at."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_COLS} FROM schedules WHERE id = $1", schedule_id
        )
    if row is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return await scheduler_mod.run_schedule(pool, r, row, datetime.now(timezone.utc))
