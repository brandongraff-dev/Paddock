"""Asyncpg connection pool + helpers for the changewatch tables.

changewatch owns writes to ``surface_changes`` and ``alert_deliveries`` and the
``intel_cursors`` row where ``source = 'changewatch'``. It reads ``assets``,
``findings`` and ``alert_rules`` but never writes them. All queries go through
one process-wide pool.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Optional
from uuid import UUID

import asyncpg

from . import tenancy

log = logging.getLogger("changewatch.db")


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
        await tenancy.check_role(self._pool)
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
        """A pooled connection inside a transaction that carries the current
        tenant (``set_config('app.tenant_id', ..., true)``): row-level security
        pins every statement to it and nothing outlives the transaction."""
        async with self.pool.acquire() as conn:
            async with tenancy.scoped(conn):
                yield conn

    @asynccontextmanager
    async def acquire_platform(self) -> AsyncIterator[asyncpg.Connection]:
        """Like :meth:`acquire` but as the platform tenant: the only tenant
        allowed to write global catalogues (``@paddock:global`` tables)."""
        with tenancy.platform_context():
            async with self.acquire() as conn:
                yield conn

    # ---- generic helpers (used by detect.py) --------------------------------

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

    # ---- intel_cursors ------------------------------------------------------

    async def get_cursor(self, source: str) -> Optional[dict[str, Any]]:
        row = await self.fetchrow(
            "SELECT source, last_synced, last_cursor, stats FROM intel_cursors WHERE source=$1",
            source,
        )
        return _clean(row)

    async def get_since(self, source: str, fallback_days: int = 1) -> datetime:
        """The cursor timestamp to diff against, or a sane default."""
        cur = await self.get_cursor(source)
        if cur and cur.get("last_synced"):
            return cur["last_synced"]
        return datetime.now(timezone.utc) - timedelta(days=fallback_days)

    async def set_cursor(
        self,
        source: str,
        last_synced: datetime,
        stats: Optional[dict[str, Any]] = None,
    ) -> None:
        await self.execute(
            """
            INSERT INTO intel_cursors (source, last_synced, stats)
            VALUES ($1, $2, COALESCE($3, '{}'::jsonb))
            ON CONFLICT (source) DO UPDATE SET
                last_synced = EXCLUDED.last_synced,
                stats       = intel_cursors.stats || COALESCE(EXCLUDED.stats, '{}'::jsonb)
            """,
            source, last_synced, stats or {},
        )

    # ---- surface_changes ----------------------------------------------------

    async def insert_change(
        self,
        change: dict[str, Any],
        dedupe_window: Optional[timedelta],
    ) -> Optional[dict[str, Any]]:
        """Insert a surface_change, deduped on ``detail->>'dedupe'``.

        ``dedupe_window`` bounds how far back the existence check looks: a
        finite window for cursor-based change types (guards overlapping passes),
        or ``None`` to dedupe forever (NOW()-based types like asset_removed /
        cert_expiring that would otherwise re-fire every run). Returns the
        inserted row, or ``None`` if a duplicate already exists.
        """
        detail = change.get("detail") or {}
        dedupe = detail.get("dedupe")
        ct = change["change_type"]

        if dedupe is not None:
            if dedupe_window is None:
                exists = await self.fetchval(
                    "SELECT 1 FROM surface_changes "
                    "WHERE change_type=$1 AND detail->>'dedupe'=$2 LIMIT 1",
                    ct, dedupe,
                )
            else:
                exists = await self.fetchval(
                    "SELECT 1 FROM surface_changes "
                    "WHERE change_type=$1 AND detail->>'dedupe'=$2 "
                    "AND detected_at > NOW() - $3::interval LIMIT 1",
                    ct, dedupe, dedupe_window,
                )
            if exists:
                return None

        row = await self.fetchrow(
            """
            INSERT INTO surface_changes
                (change_type, asset_id, asset_kind, asset_value, severity, summary, detail)
            VALUES ($1, $2::uuid, $3, $4, $5, $6, $7::jsonb)
            RETURNING id::text, change_type, asset_id::text, asset_kind,
                      asset_value, severity, summary, detail, detected_at
            """,
            ct,
            change.get("asset_id"),
            change.get("asset_kind"),
            change.get("asset_value"),
            change.get("severity", "info"),
            change["summary"],
            detail,
        )
        return _clean(row)

    # ---- alert_rules / alert_deliveries -------------------------------------

    async def enabled_rules(self) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT id::text, name, enabled, match, channel, target, last_fired "
            "FROM alert_rules WHERE enabled ORDER BY created_at"
        )
        return [_clean(r) for r in rows]  # type: ignore[misc]

    async def record_delivery(
        self,
        rule_id: str,
        change_id: Optional[str],
        status: str,
        channel: str,
        response: Optional[str],
    ) -> dict[str, Any]:
        row = await self.fetchrow(
            """
            INSERT INTO alert_deliveries (rule_id, change_id, status, channel, response)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5)
            RETURNING id::text, rule_id::text, change_id::text, status, channel,
                      response, delivered_at
            """,
            rule_id, change_id, status, channel, response,
        )
        return _clean(row)  # type: ignore[return-value]

    async def bump_last_fired(self, rule_id: str) -> None:
        await self.execute(
            "UPDATE alert_rules SET last_fired = NOW() WHERE id = $1::uuid",
            rule_id,
        )

    # ---- stats --------------------------------------------------------------

    async def stats(self) -> dict[str, Any]:
        total = await self.fetchval("SELECT COUNT(*) FROM surface_changes")
        by_type_rows = await self.fetch(
            "SELECT change_type, COUNT(*) AS n FROM surface_changes GROUP BY change_type"
        )
        delivery_rows = await self.fetch(
            "SELECT status, COUNT(*) AS n FROM alert_deliveries GROUP BY status"
        )
        rules = await self.fetchval("SELECT COUNT(*) FROM alert_rules WHERE enabled")
        return {
            "changes_total": int(total or 0),
            "changes_by_type": {r["change_type"]: int(r["n"]) for r in by_type_rows},
            "deliveries": {r["status"]: int(r["n"]) for r in delivery_rows},
            "enabled_rules": int(rules or 0),
        }
