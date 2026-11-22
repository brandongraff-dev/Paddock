"""Two-way ticket sync glue: apply inbound changes, deliver outbound with links.

* ``apply_inbound(pool, integration, updates, ...)`` -- the inbound half.
  Resolves each ``InboundUpdate`` to a finding via ``integration_links``,
  changes the finding status (degrading statuses the DB doesn't allow yet),
  appends a note, records the external status on the link, writes an audit
  row as ``integration:<kind>:<name>``, and emits a follow-up event marked
  with ``data["origin"]`` so the originating ticket system is not echoed.
* ``deliver_ticket(pool, integration, event, http=...)`` -- outbound helper
  for the delivery worker: builds the connector from the integration row,
  ``bind()``s it (link table + ``allow_private``) and delivers.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional
from uuid import UUID

from . import links
from .base import SEVERITIES, DeliveryResult, Event, InboundUpdate, get_connector_class

log = logging.getLogger(__name__)

# Preferred status first, then what to fall back to when the findings CHECK
# constraint doesn't (yet) allow it. Another stream adds accepted /
# false_positive; until then accepted degrades to the legacy accepted_risk.
STATUS_FALLBACKS: dict[str, tuple[str, ...]] = {
    "open": ("open",),
    "triaged": ("triaged",),
    "fixed": ("fixed",),
    "accepted": ("accepted", "accepted_risk", "wontfix"),
    "false_positive": ("false_positive", "accepted", "accepted_risk"),
}
_ACCEPTED_LIKE = {"accepted", "accepted_risk", "wontfix", "false_positive"}
MAX_NOTES = 50
MAX_NOTE_LEN = 4000


def origin_marker(integration: Mapping[str, Any], external_id: Optional[str]) -> dict[str, Any]:
    return {
        "integration_id": str(integration["id"]),
        "kind": integration.get("kind"),
        "name": integration.get("name"),
        "external_id": external_id,
    }


def actor_for(integration: Mapping[str, Any]) -> str:
    return f"integration:{integration.get('kind')}:{integration.get('name')}"


async def allowed_finding_statuses(con: Any) -> Optional[set[str]]:
    """Status values the ``findings.status`` CHECK constraint permits.

    ``None`` means no such constraint was found (anything goes)."""
    rows = await con.fetch(
        """
        SELECT pg_get_constraintdef(c.oid) AS def
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
         WHERE t.relname = 'findings' AND c.contype = 'c'
           AND pg_get_constraintdef(c.oid) ILIKE '%status%'
        """
    )
    found: Optional[set[str]] = None
    for r in rows:
        d = r["def"]
        # Only the allow-list constraint (`status IN (...)` / `= ANY (ARRAY[...])`).
        # Other constraints that merely mention status -- e.g. the lifecycle rule
        # "status NOT IN ('accepted','false_positive') OR reason present" -- name
        # values that are *conditionally* allowed and must not be intersected.
        if re.search(r"\bNOT\b|<>", d, re.I) or not re.search(r"status\)?(::text)?\s*(=\s*ANY|IN)\b", d, re.I):
            continue
        vals = set(re.findall(r"'([a-z_]+)'", d))
        if vals:
            found = vals if found is None else (found & vals)
    return found


def resolve_status(desired: Optional[str], allowed: Optional[set[str]]) -> Optional[str]:
    if not desired:
        return None
    for cand in STATUS_FALLBACKS.get(desired, (desired,)):
        if allowed is None or cand in allowed:
            return cand
    return None


def event_type_for(new: str, old: Optional[str]) -> str:
    if new == "fixed":
        return "finding.resolved"
    if new in _ACCEPTED_LIKE:
        return "finding.accepted"
    if new == "open" and old and old != "open":
        return "finding.reopened"
    return "finding.updated"


@dataclass
class InboundResult:
    received: int = 0
    applied: int = 0
    ignored: int = 0
    events: list[Event] = field(default_factory=list)
    details: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"received": self.received, "applied": self.applied, "ignored": self.ignored,
                "results": self.details}


async def _resolve_link(con: Any, integration_id: UUID, upd: InboundUpdate) -> Optional[links.Link]:
    link = await links.get_by_external(con, integration_id, upd.external_id)
    if link is not None:
        return link
    # Adopt an unlinked ticket that carries a paddock-<finding> marker -- but
    # never re-point a finding that is already linked to another ticket.
    if not upd.finding_id:
        return None
    try:
        fid = UUID(str(upd.finding_id))
    except ValueError:
        return None
    if await links.get_by_finding(con, integration_id, fid) is not None:
        return None
    if not await con.fetchval("SELECT 1 FROM findings WHERE id = $1", fid):
        return None
    return await links.upsert(con, integration_id, fid, upd.external_id,
                              getattr(upd, "external_url", None), None)


async def apply_inbound(
    pool: Any,
    integration: Mapping[str, Any],
    updates: Iterable[InboundUpdate],
    *,
    request_id: Optional[str] = None,
    ip: Optional[str] = None,
    path: Optional[str] = None,
) -> InboundResult:
    from .. import audit

    res = InboundResult()
    iid = UUID(str(integration["id"]))
    actor = actor_for(integration)
    sync_status = bool((integration.get("config") or {}).get("sync_inbound_status", True))
    audits: list[dict[str, Any]] = []
    async with pool.acquire() as con:
        allowed = await allowed_finding_statuses(con)
        for upd in updates:
            res.received += 1
            async with con.transaction():
                link = await _resolve_link(con, iid, upd)
                if link is None:
                    res.ignored += 1
                    res.details.append({"external_id": upd.external_id, "result": "unlinked"})
                    continue
                fid = UUID(link.finding_id)
                row = await con.fetchrow(
                    "SELECT id, status, severity, title, asset_id, metadata FROM findings "
                    "WHERE id = $1 FOR UPDATE", fid,
                )
                ext_status = getattr(upd, "external_status", None) or upd.status
                await links.set_external_status(con, iid, upd.external_id, ext_status)
                if row is None:
                    res.ignored += 1
                    res.details.append({"external_id": upd.external_id, "result": "finding_missing"})
                    continue
                old = row["status"]
                new = resolve_status(upd.status, allowed) if sync_status else None
                degraded = bool(upd.status and new and new != upd.status)
                changed = bool(new and new != old)
                origin = origin_marker(integration, upd.external_id)
                now = datetime.now(timezone.utc).isoformat()
                patch: dict[str, Any] = {}
                notes = []
                if changed:
                    patch["status_origin"] = {**origin, "at": now, "from": old, "to": new}
                    notes.append(f"Status {old} -> {new} from {integration.get('kind')} "
                                 f"{upd.external_id} ({ext_status or upd.status})"
                                 + (f" by {upd.actor}" if upd.actor else ""))
                elif upd.status and not new and sync_status:
                    notes.append(f"{integration.get('kind')} {upd.external_id} reported "
                                 f"'{upd.status}', which this database cannot store; status unchanged")
                if upd.comment:
                    notes.append(str(upd.comment)[:MAX_NOTE_LEN])
                if not changed and not notes:
                    res.ignored += 1
                    res.details.append({"external_id": upd.external_id, "finding_id": str(fid),
                                        "result": "no_change"})
                    continue
                meta = row["metadata"]
                if isinstance(meta, str):
                    meta = json.loads(meta or "{}")
                existing = list((meta or {}).get("integration_notes") or [])
                for text in notes:
                    existing.append({"at": now, "source": actor, "external_id": upd.external_id,
                                     "actor": upd.actor, "text": text})
                patch["integration_notes"] = existing[-MAX_NOTES:]
                if changed:
                    # Dismissals (accepted / false_positive) must carry a reason
                    # (schema 019 constraint): record where the decision came from.
                    reason = (f"{integration.get('kind')} {upd.external_id}: "
                              f"{ext_status or upd.status}"
                              + (f" by {upd.actor}" if upd.actor else "")
                              + (f" - {str(upd.comment)[:200]}" if upd.comment else ""))
                    await con.execute(
                        "UPDATE findings SET status = $2, metadata = metadata || $3::jsonb, "
                        "status_reason = $4, status_by = $5, status_changed_at = NOW(), "
                        "fix_verified_at = NULL WHERE id = $1",
                        fid, new, json.dumps(patch), reason, actor,
                    )
                else:
                    await con.execute(
                        "UPDATE findings SET metadata = metadata || $2::jsonb WHERE id = $1",
                        fid, json.dumps(patch),
                    )
            res.applied += 1
            res.details.append({"external_id": upd.external_id, "finding_id": str(fid),
                                "result": "status_changed" if changed else "noted",
                                **({"status": new} if changed else {}),
                                **({"degraded_from": upd.status} if degraded and changed else {})})
            audits.append({
                "resource_id": str(fid),
                "details": {
                    "integration_id": str(iid), "external_id": upd.external_id,
                    "external_status": ext_status, "from": old, "to": new if changed else old,
                    "requested": upd.status, "comment": bool(upd.comment), "remote_actor": upd.actor,
                },
            })
            if changed:
                sev = row["severity"] if row["severity"] in SEVERITIES else None
                res.events.append(Event(
                    type=event_type_for(new, old),
                    title=row["title"],
                    summary=f"Status changed to {new} from {integration.get('kind')} {upd.external_id}",
                    severity=sev,
                    data={"finding_id": str(fid), "asset_id": str(row["asset_id"]), "status": new,
                          "previous_status": old, "title": row["title"], "origin": origin},
                ))
    for a in audits:
        try:
            await audit.record(
                pool, action="update", actor=actor, actor_role="integration",
                resource_type="findings", resource_id=a["resource_id"], method="POST",
                path=path, status=200, ip=ip, request_id=request_id, details=a["details"],
            )
        except Exception:  # noqa: BLE001 -- the change is committed; never fail on audit
            log.exception("inbound_audit_failed")
    return res


async def emit_events(pool: Any, events: Iterable[Event]) -> int:
    """Hand follow-up events to the integrations core (if it is installed)."""
    try:
        from . import service  # type: ignore[attr-defined]
    except ImportError:
        return 0
    emit = getattr(service, "emit", None)
    if emit is None:
        return 0
    sent = 0
    for ev in events:
        try:
            await emit(pool, ev)
            sent += 1
        except Exception:  # noqa: BLE001 -- best-effort fan-out
            log.exception("inbound_emit_failed", extra={"event_type": ev.type})
    return sent


async def deliver_ticket(pool: Any, integration: Mapping[str, Any], event: Event, *, http: Any) -> DeliveryResult:
    """Deliver ``event`` through a TICKET integration row, with link persistence."""
    from .secrets import decrypt_secrets

    cls = get_connector_class(str(integration["kind"]))
    config = integration.get("config") or {}
    if isinstance(config, str):
        config = json.loads(config)
    conn = cls(config, decrypt_secrets(integration.get("secrets")), http)
    bind = getattr(conn, "bind", None)
    if bind is not None:
        bind(integration_id=integration["id"], pool=pool,
             allow_private=bool(integration.get("allow_private", False)))
    return await conn.deliver(event)
