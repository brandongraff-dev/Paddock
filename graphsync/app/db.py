"""Asyncpg connection pool + read helpers for the source graph.

graphsync is a READER of Postgres: it reads `assets`, `asset_edges`,
`findings`, and the `neo4j_sync` row of `intel_cursors`. The only thing it
writes in Postgres is its own sync cursor (last_synced / stats) — all graph
mutation happens in Neo4j, never here.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import asyncpg

log = logging.getLogger(__name__)

CURSOR_SOURCE = "neo4j_sync"


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Install JSON codecs so we receive dicts/lists directly."""
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


class Database:
    """Thin wrapper around an asyncpg pool (read-only against the graph)."""

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self._min,
            max_size=self._max,
            init=_init_connection,
            command_timeout=60,
        )
        log.info("db: pool connected (%s/%s)", self._min, self._max)

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

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # graph readers
    # ------------------------------------------------------------------
    async def fetch_assets(self, since: datetime | None) -> list[dict[str, Any]]:
        """Assets changed since `since` (first_seen OR last_seen), or all."""
        sql = (
            "SELECT id::text AS id, kind, value, metadata, "
            "       first_seen, last_seen "
            "FROM assets"
        )
        async with self.acquire() as conn:
            if since is None:
                rows = await conn.fetch(sql + " ORDER BY id")
            else:
                rows = await conn.fetch(
                    sql + " WHERE last_seen > $1 OR first_seen > $1 ORDER BY id",
                    since,
                )
        return [dict(r) for r in rows]

    async def fetch_edges(self, since: datetime | None) -> list[dict[str, Any]]:
        """Edges changed since `since`, or all."""
        sql = (
            "SELECT src_id::text AS src, dst_id::text AS dst, kind, "
            "       first_seen, last_seen "
            "FROM asset_edges"
        )
        async with self.acquire() as conn:
            if since is None:
                rows = await conn.fetch(sql + " ORDER BY src, dst, kind")
            else:
                rows = await conn.fetch(
                    sql + " WHERE last_seen > $1 OR first_seen > $1 "
                    "ORDER BY src, dst, kind",
                    since,
                )
        return [dict(r) for r in rows]

    async def fetch_open_findings(
        self, since: datetime | None, asset_ids: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Open findings, optionally restricted to `asset_ids` and/or changed
        since `since`. Severity + KEV flag only — no exploitation data."""
        clauses = ["status = 'open'"]
        params: list[Any] = []
        if since is not None:
            params.append(since)
            clauses.append(f"(last_seen > ${len(params)} OR first_seen > ${len(params)})")
        if asset_ids is not None:
            params.append(asset_ids)
            clauses.append(f"asset_id::text = ANY(${len(params)}::text[])")
        where = " AND ".join(clauses)
        sql = (
            "SELECT id::text AS id, asset_id::text AS asset_id, severity, "
            "       rule_source, metadata "
            f"FROM findings WHERE {where} ORDER BY asset_id, id"
        )
        async with self.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def fetch_findings_for_assets(
        self, asset_ids: list[str]
    ) -> list[dict[str, Any]]:
        """All open findings for the given asset ids (no time filter)."""
        if not asset_ids:
            return []
        return await self.fetch_open_findings(since=None, asset_ids=asset_ids)

    # ------------------------------------------------------------------
    # sync cursor (the only thing we write)
    # ------------------------------------------------------------------
    async def get_cursor(self) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT source, last_synced, last_cursor, stats "
                "FROM intel_cursors WHERE source = $1",
                CURSOR_SOURCE,
            )
        return dict(row) if row else None

    async def set_cursor(
        self,
        last_synced: datetime | None = None,
        stats: dict[str, Any] | None = None,
    ) -> None:
        async with self.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO intel_cursors (source, last_synced, stats)
                VALUES ($1, $2, COALESCE($3, '{}'::jsonb))
                ON CONFLICT (source) DO UPDATE SET
                    last_synced = COALESCE(EXCLUDED.last_synced, intel_cursors.last_synced),
                    stats       = intel_cursors.stats || COALESCE(EXCLUDED.stats, '{}'::jsonb)
                """,
                CURSOR_SOURCE,
                last_synced or datetime.now(timezone.utc),
                stats or {},
            )

    async def counters(self) -> dict[str, int]:
        async with self.acquire() as conn:
            assets = await conn.fetchval("SELECT COUNT(*) FROM assets")
            edges = await conn.fetchval("SELECT COUNT(*) FROM asset_edges")
            findings = await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE status = 'open'"
            )
        return {
            "assets": int(assets or 0),
            "edges": int(edges or 0),
            "open_findings": int(findings or 0),
        }
