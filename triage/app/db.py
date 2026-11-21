"""Asyncpg connection pool + helpers for the triage tables.

triage owns writes to ``tickets``. It reads/evaluates ``asset_owners`` and
``sla_policies`` and reads ``findings`` / ``assets`` (and, transitively,
chains/attack_paths via the ticket FKs). It never writes the tables it reads.
All queries go through one process-wide pool.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional
from uuid import UUID

import asyncpg

log = logging.getLogger("triage.db")

# Tickets considered "open" (an SLA clock still applies).
ACTIVE_STATUSES = ("open", "acknowledged", "in_progress")
# Tickets whose SLA clock has stopped.
CLOSED_STATUSES = ("resolved", "closed", "wontfix")


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Install JSON codecs so we can pass dicts/lists directly."""
    await conn.set_type_codec(
        "jsonb",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "json",
        encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads,
        schema="pg_catalog",
    )


def _clean(row: Optional[asyncpg.Record]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, UUID):
            d[k] = str(v)
    return d


class Database:
    """Thin wrapper around an asyncpg pool."""

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self, min_size: int | None = None, max_size: int | None = None) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=min_size or self._min,
            max_size=max_size or self._max,
            init=_init_connection,
            command_timeout=60,
        )
        log.info("db: pool connected")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("db pool not initialised; call connect()")
        return self._pool

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn:
            yield conn

    # ---- generic helpers ----------------------------------------------------

    async def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def fetchrow(self, sql: str, *args: Any) -> Optional[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetchrow(sql, *args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self.acquire() as conn:
            return await conn.execute(sql, *args)

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ---- asset_owners -------------------------------------------------------

    async def enabled_owners(self) -> list[dict[str, Any]]:
        """Enabled ownership rules, priority ASC (lower wins).

        A rule may carry an optional ``system`` inside its ``match`` blob; we
        lift it to a top-level key so ``resolve_owner`` can read it without the
        schema needing a dedicated column.
        """
        rows = await self.fetch(
            "SELECT id::text, name, match, team, contact, priority, enabled "
            "FROM asset_owners WHERE enabled "
            "ORDER BY priority ASC, created_at ASC"
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            d = _clean(r) or {}
            match = d.get("match") or {}
            if isinstance(match, dict):
                d["system"] = match.get("system")
            out.append(d)
        return out

    # ---- sla_policies -------------------------------------------------------

    async def sla_policies(self) -> dict[str, int]:
        rows = await self.fetch("SELECT severity, hours FROM sla_policies")
        return {r["severity"]: int(r["hours"]) for r in rows}

    # ---- findings -> tickets ------------------------------------------------

    async def open_findings_without_ticket(
        self, severities: list[str]
    ) -> list[dict[str, Any]]:
        """Open findings at the given severities that have no ticket yet."""
        rows = await self.fetch(
            """
            SELECT f.id::text          AS finding_id,
                   f.severity          AS severity,
                   f.title             AS title,
                   f.first_seen        AS first_seen,
                   f.asset_id::text    AS asset_id,
                   a.kind              AS asset_kind,
                   a.value             AS asset_value,
                   a.metadata          AS asset_metadata
              FROM findings f
              JOIN assets a ON a.id = f.asset_id
         LEFT JOIN tickets t ON t.finding_id = f.id
             WHERE f.status = 'open'
               AND f.severity = ANY($1::text[])
               AND t.id IS NULL
             ORDER BY f.first_seen
            """,
            severities,
        )
        return [_clean(r) for r in rows]  # type: ignore[misc]

    async def insert_ticket(self, data: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Insert a ticket; ``None`` if one already exists for the finding."""
        row = await self.fetchrow(
            """
            INSERT INTO tickets
                (finding_id, title, severity, owner_team, contact, system,
                 sla_hours, sla_due, metadata)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            ON CONFLICT (finding_id) DO NOTHING
            RETURNING id::text, finding_id::text, title, severity, owner_team,
                      contact, system, external_id, external_url, status,
                      sla_hours, sla_due, breached, opened_at
            """,
            data["finding_id"],
            data["title"],
            data["severity"],
            data.get("owner_team"),
            data.get("contact"),
            data.get("system", "internal"),
            data.get("sla_hours"),
            data.get("sla_due"),
            data.get("metadata") or {},
        )
        return _clean(row)

    async def set_ticket_external(
        self, ticket_id: str, external_id: Optional[str], external_url: Optional[str]
    ) -> None:
        await self.execute(
            "UPDATE tickets SET external_id = $2, external_url = $3, "
            "updated_at = NOW() WHERE id = $1::uuid",
            ticket_id, external_id, external_url,
        )

    async def mark_ticket_internal(self, ticket_id: str, note: str) -> None:
        """Downgrade a ticket to ``internal`` after a failed dispatch, w/ note."""
        await self.execute(
            "UPDATE tickets SET system = 'internal', updated_at = NOW(), "
            "metadata = metadata || jsonb_build_object('dispatch_note', $2::text) "
            "WHERE id = $1::uuid",
            ticket_id, note,
        )

    # ---- SLA sweep ----------------------------------------------------------

    async def breach_open_tickets_past_due(self) -> list[dict[str, Any]]:
        """Mark still-open, past-due tickets breached; return the newly-marked."""
        rows = await self.fetch(
            """
            UPDATE tickets
               SET breached = TRUE, updated_at = NOW()
             WHERE status <> ALL($1::text[])
               AND breached = FALSE
               AND sla_due IS NOT NULL
               AND sla_due < NOW()
            RETURNING id::text, finding_id::text, title, severity, owner_team, sla_due
            """,
            list(CLOSED_STATUSES),
        )
        return [_clean(r) for r in rows]  # type: ignore[misc]

    # ---- owner re-resolution ------------------------------------------------

    async def open_tickets_with_asset(self) -> list[dict[str, Any]]:
        rows = await self.fetch(
            """
            SELECT t.id::text       AS id,
                   t.owner_team     AS owner_team,
                   t.contact        AS contact,
                   a.kind           AS asset_kind,
                   a.value          AS asset_value,
                   a.metadata       AS asset_metadata
              FROM tickets t
              JOIN findings f ON f.id = t.finding_id
              JOIN assets a   ON a.id = f.asset_id
             WHERE t.status <> ALL($1::text[])
            """,
            list(CLOSED_STATUSES),
        )
        return [_clean(r) for r in rows]  # type: ignore[misc]

    async def update_ticket_owner(
        self, ticket_id: str, owner_team: Optional[str], contact: Optional[str]
    ) -> None:
        await self.execute(
            "UPDATE tickets SET owner_team = $2, contact = $3, updated_at = NOW() "
            "WHERE id = $1::uuid",
            ticket_id, owner_team, contact,
        )

    # ---- stats --------------------------------------------------------------

    async def stats(self) -> dict[str, Any]:
        total = await self.fetchval("SELECT COUNT(*) FROM tickets")
        open_n = await self.fetchval(
            "SELECT COUNT(*) FROM tickets WHERE status = ANY($1::text[])",
            list(ACTIVE_STATUSES),
        )
        breached_n = await self.fetchval(
            "SELECT COUNT(*) FROM tickets WHERE breached "
            "AND status <> ALL($1::text[])",
            list(CLOSED_STATUSES),
        )
        by_team_rows = await self.fetch(
            "SELECT COALESCE(owner_team, '(unowned)') AS team, COUNT(*) AS n "
            "FROM tickets WHERE status = ANY($1::text[]) GROUP BY team",
            list(ACTIVE_STATUSES),
        )
        by_status_rows = await self.fetch(
            "SELECT status, COUNT(*) AS n FROM tickets GROUP BY status"
        )
        rules = await self.fetchval("SELECT COUNT(*) FROM asset_owners WHERE enabled")
        return {
            "tickets_total": int(total or 0),
            "open": int(open_n or 0),
            "breached": int(breached_n or 0),
            "by_team": {r["team"]: int(r["n"]) for r in by_team_rows},
            "by_status": {r["status"]: int(r["n"]) for r in by_status_rows},
            "enabled_rules": int(rules or 0),
        }
