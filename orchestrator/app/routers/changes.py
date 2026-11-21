"""Change-intelligence read/ack API + alert-rule CRUD.

`surface_changes` is the ledger of everything that changed in the attack
surface; it is written by the changewatch service. This router reads it,
acknowledges rows, and summarizes it for the dashboard. It also owns the
`alert_rules` CRUD (the orchestrator is the writer of record for rules) and
exposes the per-rule delivery log.

Safety: alert targets are opaque URLs stored exactly as given; this router
only validates the URL *scheme* (http/https) and never dereferences them --
delivery is the changewatch service's job, and it POSTs only to the
user-configured target.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ..db import get_pool
from ..middleware import require_scope_admin
from ..models import (
    AlertDeliveryOut,
    AlertRuleIn,
    AlertRuleOut,
    AlertRulePatch,
    ChangePage,
    ChangeSummaryDay,
    ChangeSummaryOut,
    ChangeType,
    Severity,
    SurfaceChangeOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/changes", tags=["changes"])
alerts_router = APIRouter(prefix="/v1/alert-rules", tags=["alerts"])


_CHANGE_COLS = (
    "id, change_type, asset_id, asset_kind, asset_value, severity, summary, "
    "detail, detected_at, acknowledged, ack_by, ack_at"
)
_RULE_COLS = (
    "id, name, enabled, match, channel, target, created_at, last_fired"
)


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _row_to_change(row) -> SurfaceChangeOut:
    d = dict(row)
    if isinstance(d.get("detail"), str):
        d["detail"] = json.loads(d["detail"])
    elif d.get("detail") is None:
        d["detail"] = {}
    return SurfaceChangeOut.model_validate(d)


def _row_to_rule(row) -> AlertRuleOut:
    d = dict(row)
    if isinstance(d.get("match"), str):
        d["match"] = json.loads(d["match"])
    elif d.get("match") is None:
        d["match"] = {}
    return AlertRuleOut.model_validate(d)


# --------------------------------------------------------------------------- #
# Changes: list / ack / summary
# --------------------------------------------------------------------------- #

@router.get("", response_model=ChangePage)
async def list_changes(
    type: ChangeType | None = None,
    severity: Severity | None = None,
    since: datetime | None = None,
    acknowledged: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if type is not None:
        args.append(type)
        clauses.append(f"change_type = ${len(args)}")
    if severity is not None:
        args.append(severity)
        clauses.append(f"severity = ${len(args)}")
    if since is not None:
        args.append(since)
        clauses.append(f"detected_at >= ${len(args)}")
    if acknowledged is not None:
        args.append(acknowledged)
        clauses.append(f"acknowledged = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    sql_count = f"SELECT COUNT(*) FROM surface_changes {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_CHANGE_COLS}
          FROM surface_changes
          {where}
         ORDER BY detected_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_change(r) for r in rows]
    return ChangePage(items=items, total=int(total or 0), limit=limit, offset=offset)


# NOTE: /summary is declared before /{change_id}/ack so the literal path is
# matched first (FastAPI tries routes in declaration order).
@router.get("/summary", response_model=ChangeSummaryOut)
async def changes_summary(
    window_days: int = Query(7, ge=1, le=365),
    pool=Depends(get_pool),
):
    """Counts by type and a per-day severity breakdown over the window."""
    async with pool.acquire() as con:
        by_type_rows = await con.fetch(
            f"""
            SELECT change_type, COUNT(*) AS c
              FROM surface_changes
             WHERE detected_at >= NOW() - ($1::int * INTERVAL '1 day')
             GROUP BY change_type
            """,
            window_days,
        )
        by_day_rows = await con.fetch(
            f"""
            SELECT (detected_at AT TIME ZONE 'UTC')::date AS day,
                   severity,
                   COUNT(*) AS c
              FROM surface_changes
             WHERE detected_at >= NOW() - ($1::int * INTERVAL '1 day')
             GROUP BY 1, 2
             ORDER BY 1
            """,
            window_days,
        )

    by_type = {r["change_type"]: int(r["c"]) for r in by_type_rows}
    total = sum(by_type.values())

    days: dict[Any, dict[str, int]] = {}
    for r in by_day_rows:
        bucket = days.setdefault(
            r["day"],
            {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        )
        sev = r["severity"]
        if sev in bucket:
            bucket[sev] = int(r["c"])
    by_day = [
        ChangeSummaryDay(day=day, **counts) for day, counts in sorted(days.items())
    ]
    return ChangeSummaryOut(by_type=by_type, by_day=by_day, total=total)


@router.post("/{change_id}/ack", response_model=SurfaceChangeOut)
async def ack_change(
    change_id: UUID,
    request: Request,
    pool=Depends(get_pool),
):
    """Acknowledge a change: set acknowledged, ack_by (X-User or 'operator'),
    ack_at=NOW(). 404 if unknown."""
    actor = request.headers.get("X-User") or "operator"
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            UPDATE surface_changes
               SET acknowledged = TRUE, ack_by = $2, ack_at = NOW()
             WHERE id = $1
         RETURNING {_CHANGE_COLS}
            """,
            change_id,
            actor,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="change not found")
    return _row_to_change(row)


# --------------------------------------------------------------------------- #
# Alert rules: CRUD + deliveries
# --------------------------------------------------------------------------- #

def _validate_channel_target(channel: str, target: str | None) -> None:
    """Non-log channels require an http(s) target. Scheme-only validation --
    the URL is stored opaquely and never dereferenced here."""
    if channel == "log":
        return
    if not target:
        raise HTTPException(
            status_code=422,
            detail=f"channel '{channel}' requires a target URL",
        )
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=422,
            detail="target must be an http(s) URL",
        )


@alerts_router.get("", response_model=list[AlertRuleOut])
async def list_alert_rules(
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
        SELECT {_RULE_COLS}
          FROM alert_rules
          {where}
         ORDER BY created_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [_row_to_rule(r) for r in rows]


@alerts_router.post(
    "",
    response_model=AlertRuleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope_admin)],
)
async def create_alert_rule(body: AlertRuleIn, pool=Depends(get_pool)):
    _validate_channel_target(body.channel, body.target)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            INSERT INTO alert_rules (name, enabled, match, channel, target)
            VALUES ($1, $2, $3::jsonb, $4, $5)
            RETURNING {_RULE_COLS}
            """,
            body.name,
            body.enabled,
            json.dumps(body.match or {}),
            body.channel,
            body.target,
        )
    return _row_to_rule(row)


@alerts_router.patch(
    "/{rule_id}",
    response_model=AlertRuleOut,
    dependencies=[Depends(require_scope_admin)],
)
async def patch_alert_rule(
    rule_id: UUID,
    patch: AlertRulePatch,
    pool=Depends(get_pool),
):
    fields = patch.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="no patch fields supplied")

    async with pool.acquire() as con:
        current = await con.fetchrow(
            "SELECT channel, target FROM alert_rules WHERE id = $1", rule_id
        )
        if current is None:
            raise HTTPException(status_code=404, detail="alert rule not found")

        # Validate the resolved (merged) channel/target combination.
        eff_channel = fields.get("channel", current["channel"])
        eff_target = fields.get("target", current["target"])
        _validate_channel_target(eff_channel, eff_target)

        set_parts: list[str] = []
        args: list[Any] = []
        for col in ("name", "channel", "target", "enabled"):
            if col in fields:
                args.append(fields[col])
                set_parts.append(f"{col} = ${len(args)}")
        if "match" in fields:
            args.append(json.dumps(fields["match"] or {}))
            set_parts.append(f"match = ${len(args)}::jsonb")

        args.append(rule_id)
        row = await con.fetchrow(
            f"""
            UPDATE alert_rules
               SET {", ".join(set_parts)}
             WHERE id = ${len(args)}
         RETURNING {_RULE_COLS}
            """,
            *args,
        )
    return _row_to_rule(row)


@alerts_router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope_admin)],
)
async def delete_alert_rule(rule_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        res = await con.execute("DELETE FROM alert_rules WHERE id = $1", rule_id)
    # asyncpg returns e.g. "DELETE 1" / "DELETE 0".
    if res.rsplit(" ", 1)[-1] == "0":
        raise HTTPException(status_code=404, detail="alert rule not found")
    return None


@alerts_router.get("/{rule_id}/deliveries", response_model=list[AlertDeliveryOut])
async def list_rule_deliveries(
    rule_id: UUID,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, rule_id, change_id, status, channel, response, delivered_at
              FROM alert_deliveries
             WHERE rule_id = $1
             ORDER BY delivered_at DESC
             LIMIT $2 OFFSET $3
            """,
            rule_id,
            limit,
            offset,
        )
    return [AlertDeliveryOut.model_validate(dict(r)) for r in rows]
