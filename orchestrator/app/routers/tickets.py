"""Tickets + ownership rules + SLA policies.

- Tickets are created by the triage service; this router reads them (with the
  finding + asset summary joined in, no N+1), serves a summary, and owns the
  operator-facing PATCH (status / owner_team / contact).
- Owners (`asset_owners`) and SLA policies (`sla_policies`) are small config
  tables the operator edits here. Owner mutations are gated by
  `require_scope_admin` (a no-op in the MVP, wired for later auth).

No endpoint here performs any outbound action.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..db import get_pool
from ..middleware import require_scope_admin
from ..models import (
    TICKET_CLOSED_STATUSES,
    OwnerIn,
    OwnerOut,
    OwnerPatch,
    Severity,
    SlaPolicyOut,
    SlaPolicyPatch,
    TicketAssetRef,
    TicketFindingRef,
    TicketOut,
    TicketPage,
    TicketPatch,
    TicketStatus,
    TicketSummary,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/tickets", tags=["tickets"])
owners_router = APIRouter(prefix="/v1/owners", tags=["owners"])
sla_router = APIRouter(prefix="/v1/sla-policies", tags=["sla"])


# --------------------------------------------------------------------------- #
# Tickets
# --------------------------------------------------------------------------- #

# One LEFT-JOIN query feeds both list and detail so the asset/finding summary
# is resolved without a per-row follow-up query (no N+1).
_TICKET_COLS = (
    "t.id, t.finding_id, t.title, t.severity, t.owner_team, t.contact, "
    "t.system, t.external_url, t.status, t.sla_hours, t.sla_due, t.breached, "
    "t.opened_at, t.closed_at, "
    "a.value AS asset_value, a.kind AS asset_kind, "
    "f.title AS finding_title, f.rule_source AS finding_rule_source"
)
_TICKET_FROM = (
    "FROM tickets t "
    "LEFT JOIN findings f ON f.id = t.finding_id "
    "LEFT JOIN assets a ON a.id = f.asset_id"
)


def _row_to_ticket(row) -> TicketOut:
    d = dict(row)
    asset_value = d.pop("asset_value", None)
    asset_kind = d.pop("asset_kind", None)
    finding_title = d.pop("finding_title", None)
    finding_rule_source = d.pop("finding_rule_source", None)

    asset = None
    if asset_value is not None or asset_kind is not None:
        asset = TicketAssetRef(value=asset_value, kind=asset_kind)
    finding = None
    if finding_title is not None or finding_rule_source is not None:
        finding = TicketFindingRef(title=finding_title, rule_source=finding_rule_source)

    d["asset"] = asset
    d["finding"] = finding
    return TicketOut.model_validate(d)


@router.get("", response_model=TicketPage)
async def list_tickets(
    status: TicketStatus | None = None,
    team: str | None = None,
    severity: Severity | None = None,
    breached: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if status is not None:
        args.append(status)
        clauses.append(f"t.status = ${len(args)}")
    if team is not None:
        args.append(team)
        clauses.append(f"t.owner_team = ${len(args)}")
    if severity is not None:
        args.append(severity)
        clauses.append(f"t.severity = ${len(args)}")
    if breached is not None:
        args.append(breached)
        clauses.append(f"t.breached = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    sql_count = f"SELECT COUNT(*) FROM tickets t {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_TICKET_COLS}
          {_TICKET_FROM}
          {where}
         ORDER BY t.opened_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_ticket(r) for r in rows]
    return TicketPage(items=items, total=int(total or 0), limit=limit, offset=offset)


# Declared before /{ticket_id} so the literal path wins.
@router.get("/summary", response_model=TicketSummary)
async def tickets_summary(pool=Depends(get_pool)):
    closed = ", ".join(f"'{s}'" for s in TICKET_CLOSED_STATUSES)
    open_pred = f"t.status NOT IN ({closed})"
    async with pool.acquire() as con:
        open_count = await con.fetchval(
            f"SELECT COUNT(*) FROM tickets t WHERE {open_pred}"
        )
        breached_count = await con.fetchval(
            f"SELECT COUNT(*) FROM tickets t WHERE t.breached = TRUE AND {open_pred}"
        )
        resolved_7d = await con.fetchval(
            f"""
            SELECT COUNT(*) FROM tickets t
             WHERE t.status IN ({closed})
               AND t.closed_at >= NOW() - INTERVAL '7 days'
            """
        )
        by_team_rows = await con.fetch(
            f"""
            SELECT COALESCE(t.owner_team, 'unassigned') AS team, COUNT(*) AS c
              FROM tickets t
             WHERE {open_pred}
             GROUP BY 1
            """
        )
        by_sev_rows = await con.fetch(
            f"""
            SELECT t.severity AS severity, COUNT(*) AS c
              FROM tickets t
             WHERE {open_pred}
             GROUP BY 1
            """
        )
    return TicketSummary(
        open=int(open_count or 0),
        breached=int(breached_count or 0),
        resolved_7d=int(resolved_7d or 0),
        by_team={r["team"]: int(r["c"]) for r in by_team_rows},
        by_severity={r["severity"]: int(r["c"]) for r in by_sev_rows},
    )


@router.get("/{ticket_id}", response_model=TicketOut)
async def get_ticket(ticket_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_TICKET_COLS} {_TICKET_FROM} WHERE t.id = $1", ticket_id
        )
    if row is None:
        raise HTTPException(status_code=404, detail="ticket not found")
    return _row_to_ticket(row)


@router.patch("/{ticket_id}", response_model=TicketOut)
async def patch_ticket(
    ticket_id: UUID,
    patch: TicketPatch,
    pool=Depends(get_pool),
):
    fields = patch.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="no patch fields supplied")

    set_parts: list[str] = []
    args: list[Any] = []
    for col in ("status", "owner_team", "contact"):
        if col in fields:
            args.append(fields[col])
            set_parts.append(f"{col} = ${len(args)}")

    # closed_at follows status: set it on a transition into a terminal status,
    # clear it otherwise. updated_at always bumps.
    if "status" in fields:
        if fields["status"] in TICKET_CLOSED_STATUSES:
            set_parts.append("closed_at = NOW()")
        else:
            set_parts.append("closed_at = NULL")
    set_parts.append("updated_at = NOW()")

    args.append(ticket_id)
    async with pool.acquire() as con:
        updated = await con.fetchrow(
            f"UPDATE tickets t SET {', '.join(set_parts)} WHERE t.id = ${len(args)} "
            "RETURNING t.id",
            *args,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="ticket not found")
        row = await con.fetchrow(
            f"SELECT {_TICKET_COLS} {_TICKET_FROM} WHERE t.id = $1", ticket_id
        )
    return _row_to_ticket(row)


# --------------------------------------------------------------------------- #
# Owners (asset_owners)
# --------------------------------------------------------------------------- #

_OWNER_COLS = "id, name, match, team, contact, priority, enabled, created_at"


def _row_to_owner(row) -> OwnerOut:
    d = dict(row)
    if isinstance(d.get("match"), str):
        d["match"] = json.loads(d["match"])
    elif d.get("match") is None:
        d["match"] = {}
    return OwnerOut.model_validate(d)


@owners_router.get("", response_model=list[OwnerOut])
async def list_owners(
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
        SELECT {_OWNER_COLS}
          FROM asset_owners
          {where}
         ORDER BY priority ASC, created_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [_row_to_owner(r) for r in rows]


@owners_router.post(
    "",
    response_model=OwnerOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope_admin)],
)
async def create_owner(body: OwnerIn, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            INSERT INTO asset_owners (name, match, team, contact, priority, enabled)
            VALUES ($1, $2::jsonb, $3, $4, $5, $6)
            RETURNING {_OWNER_COLS}
            """,
            body.name,
            json.dumps(body.match or {}),
            body.team,
            body.contact,
            body.priority,
            body.enabled,
        )
    return _row_to_owner(row)


@owners_router.patch(
    "/{owner_id}",
    response_model=OwnerOut,
    dependencies=[Depends(require_scope_admin)],
)
async def patch_owner(owner_id: UUID, patch: OwnerPatch, pool=Depends(get_pool)):
    fields = patch.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="no patch fields supplied")

    set_parts: list[str] = []
    args: list[Any] = []
    for col in ("name", "team", "contact", "priority", "enabled"):
        if col in fields:
            args.append(fields[col])
            set_parts.append(f"{col} = ${len(args)}")
    if "match" in fields:
        args.append(json.dumps(fields["match"] or {}))
        set_parts.append(f"match = ${len(args)}::jsonb")

    args.append(owner_id)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            UPDATE asset_owners
               SET {", ".join(set_parts)}
             WHERE id = ${len(args)}
         RETURNING {_OWNER_COLS}
            """,
            *args,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="owner not found")
    return _row_to_owner(row)


@owners_router.delete(
    "/{owner_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope_admin)],
)
async def delete_owner(owner_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        res = await con.execute("DELETE FROM asset_owners WHERE id = $1", owner_id)
    if res.rsplit(" ", 1)[-1] == "0":
        raise HTTPException(status_code=404, detail="owner not found")
    return None


# --------------------------------------------------------------------------- #
# SLA policies
# --------------------------------------------------------------------------- #


@sla_router.get("", response_model=list[SlaPolicyOut])
async def list_sla_policies(pool=Depends(get_pool)):
    order = "ARRAY['critical','high','medium','low','info']"
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT severity, hours FROM sla_policies "
            f"ORDER BY array_position({order}::text[], severity)"
        )
    return [SlaPolicyOut.model_validate(dict(r)) for r in rows]


@sla_router.patch("/{severity}", response_model=SlaPolicyOut)
async def patch_sla_policy(
    severity: Severity,
    patch: SlaPolicyPatch,
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE sla_policies SET hours = $2 WHERE severity = $1
            RETURNING severity, hours
            """,
            severity,
            patch.hours,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="sla policy not found")
    return SlaPolicyOut.model_validate(dict(row))
