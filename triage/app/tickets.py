"""Ticket creation + SLA sweep.

``TicketManager`` runs one triage pass:

  1. fetch open findings at/above ``TRIAGE_MIN_SEVERITY`` that have no ticket
     yet (the ``tickets.finding_id`` UNIQUE constraint is the dedupe backstop);
  2. resolve each finding's owner from its asset via ``asset_owners`` rules;
  3. look up ``sla_policies[severity].hours`` and set
     ``sla_due = finding.first_seen + hours``;
  4. insert the ticket (``system`` from the owner rule, else ``internal``),
     publish ``ticket_opened``;
  5. for a non-internal system, POST the ticket JSON to the configured target —
     on success record external id/url, on failure fall back to ``internal``
     with a note;
  6. sweep: mark still-open tickets past ``sla_due`` breached and publish
     ``ticket_breached``.

The manager works against a db-like object (duck-typed) and a publish callable,
so its logic is unit-testable with fakes — no live Postgres or Redis.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Optional

from .config import Config
from .dispatch import TicketDispatcher
from .owners import resolve_owner

log = logging.getLogger("triage.tickets")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A publisher takes an event dict and fans it out (Redis stream, test spy, …).
Publisher = Callable[[dict[str, Any]], Awaitable[None]]


async def _noop_publish(_event: dict[str, Any]) -> None:  # pragma: no cover
    return None


def severities_at_least(min_severity: str) -> list[str]:
    """All severities >= ``min_severity`` (unknown → everything)."""
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [s for s, rank in SEVERITY_ORDER.items() if rank >= floor]


def compute_sla_due(first_seen: Optional[datetime], hours: Optional[int]) -> Optional[datetime]:
    """``first_seen + hours``; ``None`` when either input is missing."""
    if first_seen is None or hours is None:
        return None
    return first_seen + timedelta(hours=int(hours))


class TicketManager:
    def __init__(
        self,
        db: Any,
        cfg: Config,
        dispatcher: TicketDispatcher,
        publish: Optional[Publisher] = None,
    ) -> None:
        self.db = db
        self.cfg = cfg
        self.dispatcher = dispatcher
        self._publish = publish or _noop_publish

    # ------------------------------------------------------------------
    async def run_pass(self) -> dict[str, Any]:
        """One full triage pass: create tickets, then sweep SLA breaches."""
        severities = severities_at_least(self.cfg.min_severity)
        findings = await self.db.open_findings_without_ticket(severities)
        owners = await self.db.enabled_owners()
        policies = await self.db.sla_policies()

        created = 0
        dedupe_skipped = 0
        dispatched = 0
        dispatch_failed = 0
        unowned = 0

        for finding in findings:
            result = await self._triage_one(finding, owners, policies)
            if result == "created":
                created += 1
            elif result == "dedupe":
                dedupe_skipped += 1
            # Per-finding outcome flags set by _triage_one.
            if finding.get("_dispatched"):
                dispatched += 1
            if finding.get("_dispatch_failed"):
                dispatch_failed += 1
            if finding.get("_unowned"):
                unowned += 1

        breached = await self.sla_sweep()

        counts = {
            "findings_considered": len(findings),
            "tickets_created": created,
            "dedupe_skipped": dedupe_skipped,
            "dispatched": dispatched,
            "dispatch_failed": dispatch_failed,
            "unowned": unowned,
            "breached": breached,
        }
        return counts

    # ------------------------------------------------------------------
    async def _triage_one(
        self,
        finding: dict[str, Any],
        owners: list[dict[str, Any]],
        policies: dict[str, Any],
    ) -> str:
        """Create (and maybe dispatch) one ticket. Returns 'created'/'dedupe'."""
        asset = {
            "kind": finding.get("asset_kind"),
            "value": finding.get("asset_value"),
            "metadata": finding.get("asset_metadata") or {},
        }
        owner = resolve_owner(asset, owners)
        if owner is None:
            finding["_unowned"] = True
        owner_team = owner["team"] if owner else None
        contact = owner.get("contact") if owner else None
        system = (owner.get("system") if owner else None) or "internal"

        severity = finding.get("severity")
        hours = policies.get(severity)
        sla_due = compute_sla_due(finding.get("first_seen"), hours)

        ticket = await self.db.insert_ticket({
            "finding_id": finding["finding_id"],
            "title": finding.get("title") or "Untitled finding",
            "severity": severity,
            "owner_team": owner_team,
            "contact": contact,
            "system": system,
            "sla_hours": hours,
            "sla_due": sla_due,
            "metadata": {},
        })
        if ticket is None:
            # UNIQUE(finding_id) conflict → a ticket already exists for it.
            return "dedupe"

        await self._publish({
            "event": "ticket_opened",
            "ticket_id": ticket["id"],
            "finding_id": ticket["finding_id"],
            "severity": ticket.get("severity"),
            "owner_team": owner_team,
            "system": system,
            "sla_due": sla_due.isoformat() if sla_due else None,
        })

        if system != "internal":
            result = await self.dispatcher.dispatch(ticket, system, contact)
            if result.get("ok"):
                finding["_dispatched"] = True
                await self.db.set_ticket_external(
                    ticket["id"],
                    result.get("external_id"),
                    result.get("external_url"),
                )
            else:
                finding["_dispatch_failed"] = True
                note = result.get("note") or "dispatch failed"
                log.warning("ticket %s dispatch failed: %s", ticket["id"], note)
                await self.db.mark_ticket_internal(ticket["id"], note)

        return "created"

    # ------------------------------------------------------------------
    async def sla_sweep(self) -> int:
        """Mark open, past-due tickets breached; publish ``ticket_breached``."""
        rows = await self.db.breach_open_tickets_past_due()
        for r in rows:
            await self._publish({
                "event": "ticket_breached",
                "ticket_id": r["id"],
                "finding_id": r.get("finding_id"),
                "severity": r.get("severity"),
                "owner_team": r.get("owner_team"),
                "sla_due": r["sla_due"].isoformat()
                if r.get("sla_due") and hasattr(r["sla_due"], "isoformat")
                else r.get("sla_due"),
            })
        return len(rows)

    # ------------------------------------------------------------------
    async def resolve_owners(self) -> dict[str, Any]:
        """Re-evaluate ``owner_team``/``contact`` for existing open tickets."""
        owners = await self.db.enabled_owners()
        rows = await self.db.open_tickets_with_asset()
        updated = 0
        for t in rows:
            asset = {
                "kind": t.get("asset_kind"),
                "value": t.get("asset_value"),
                "metadata": t.get("asset_metadata") or {},
            }
            owner = resolve_owner(asset, owners)
            new_team = owner["team"] if owner else None
            new_contact = owner.get("contact") if owner else None
            if new_team != t.get("owner_team") or new_contact != t.get("contact"):
                await self.db.update_ticket_owner(t["id"], new_team, new_contact)
                updated += 1
        return {"tickets": len(rows), "updated": updated}
