"""Asyncpg connection pool + helpers for the threat-intel tables.

We own writes to ``ti_feeds``, ``ti_indicators``, ``ti_matches``. We READ
(never write) ``assets`` and ``findings`` for matching. The matched-asset
``threat_intel`` finding is written through the orchestrator HTTP API, not
here (so the orchestrator owns finding upsert + event emission).
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import asyncpg

from . import tenancy

log = logging.getLogger(__name__)


async def _init_connection(conn: asyncpg.Connection) -> None:
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
    """Thin wrapper around an asyncpg pool."""

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
        await tenancy.check_role(self._pool)
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

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # ti_indicators
    # ------------------------------------------------------------------
    async def upsert_indicator(
        self, record: dict[str, Any], *, feed_id: str | None = None
    ) -> dict[str, Any]:
        """Insert or update an indicator (conflict on (type, value)).

        Returns {"id": <uuid str>, "inserted": bool}. If a ``stix_id`` collides
        with a different row, we retry without it (dedupe is by type+value).
        """
        async def _run(conn, stix_id):
            return await conn.fetchrow(
                """
                INSERT INTO ti_indicators (
                    stix_id, type, value, pattern, labels, malware,
                    threat_actor, confidence, valid_from, valid_until,
                    feed_id, source
                )
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                ON CONFLICT (type, value) DO UPDATE SET
                    stix_id      = COALESCE(EXCLUDED.stix_id, ti_indicators.stix_id),
                    pattern      = COALESCE(EXCLUDED.pattern, ti_indicators.pattern),
                    labels       = EXCLUDED.labels,
                    malware      = EXCLUDED.malware,
                    threat_actor = COALESCE(EXCLUDED.threat_actor, ti_indicators.threat_actor),
                    confidence   = GREATEST(ti_indicators.confidence, EXCLUDED.confidence),
                    valid_from   = COALESCE(EXCLUDED.valid_from, ti_indicators.valid_from),
                    valid_until  = COALESCE(EXCLUDED.valid_until, ti_indicators.valid_until),
                    feed_id      = COALESCE(EXCLUDED.feed_id, ti_indicators.feed_id),
                    source       = COALESCE(EXCLUDED.source, ti_indicators.source)
                RETURNING id, (xmax = 0) AS inserted
                """,
                stix_id,
                record["type"],
                record["value"],
                record.get("pattern"),
                list(record.get("labels") or []),
                list(record.get("malware") or []),
                record.get("threat_actor"),
                int(record.get("confidence") or 50),
                record.get("valid_from"),
                record.get("valid_until"),
                feed_id,
                record.get("source"),
            )

        async with self.acquire() as conn:
            try:
                row = await _run(conn, record.get("stix_id"))
            except asyncpg.UniqueViolationError:
                row = await _run(conn, None)
        return {"id": str(row["id"]), "inserted": bool(row["inserted"])}

    async def list_indicators(
        self,
        *,
        type: str | None = None,
        label: str | None = None,
        q: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if type is not None:
            args.append(type)
            clauses.append(f"i.type = ${len(args)}")
        if label is not None:
            args.append(label)
            clauses.append(f"${len(args)} = ANY(i.labels)")
        if q is not None:
            args.append(f"%{q}%")
            clauses.append(f"i.value ILIKE ${len(args)}")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        args.extend([limit, offset])
        sql = f"""
            SELECT i.id, i.stix_id, i.type, i.value, i.pattern, i.labels,
                   i.malware, i.threat_actor, i.confidence, i.valid_from,
                   i.valid_until, i.feed_id, i.source, i.created_at,
                   f.name AS feed_name
              FROM ti_indicators i
              LEFT JOIN ti_feeds f ON f.id = i.feed_id
              {where}
             ORDER BY i.created_at DESC
             LIMIT ${len(args) - 1} OFFSET ${len(args)}
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(sql, *args)
        return [self._ind_row(r) for r in rows]

    async def count_indicators(
        self, *, type: str | None = None, label: str | None = None, q: str | None = None
    ) -> int:
        clauses: list[str] = []
        args: list[Any] = []
        if type is not None:
            args.append(type)
            clauses.append(f"type = ${len(args)}")
        if label is not None:
            args.append(label)
            clauses.append(f"${len(args)} = ANY(labels)")
        if q is not None:
            args.append(f"%{q}%")
            clauses.append(f"value ILIKE ${len(args)}")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        async with self.acquire() as conn:
            n = await conn.fetchval(f"SELECT COUNT(*) FROM ti_indicators {where}", *args)
        return int(n or 0)

    @staticmethod
    def _ind_row(r: asyncpg.Record) -> dict[str, Any]:
        d = dict(r)
        d["id"] = str(d["id"])
        if d.get("feed_id") is not None:
            d["feed_id"] = str(d["feed_id"])
        d["labels"] = list(d.get("labels") or [])
        d["malware"] = list(d.get("malware") or [])
        return d

    # ------------------------------------------------------------------
    # read-only reads of owner's own surface (assets / findings)
    # ------------------------------------------------------------------
    async def list_match_assets(
        self, *, kinds: list[str], limit: int = 50000
    ) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, kind, value
                  FROM assets
                 WHERE kind = ANY($1::text[])
                 LIMIT $2
                """,
                kinds, limit,
            )
        return [{"id": str(r["id"]), "kind": r["kind"], "value": r["value"]} for r in rows]

    async def list_findings_with_evidence(self, *, limit: int = 50000) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, asset_id, evidence
                  FROM findings
                 WHERE evidence IS NOT NULL
                   AND evidence <> '{}'::jsonb
                 LIMIT $1
                """,
                limit,
            )
        out = []
        for r in rows:
            out.append({
                "id": str(r["id"]),
                "asset_id": str(r["asset_id"]) if r["asset_id"] else None,
                "evidence": r["evidence"],
            })
        return out

    # ------------------------------------------------------------------
    # ti_matches
    # ------------------------------------------------------------------
    async def upsert_match(
        self,
        *,
        indicator_id: str,
        subject_type: str,
        subject_id: str | None,
        matched_value: str,
        severity: str,
        finding_id: str | None = None,
    ) -> bool:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO ti_matches (
                    indicator_id, subject_type, subject_id, matched_value,
                    severity, finding_id
                )
                VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT (indicator_id, subject_id) DO UPDATE SET
                    matched_value = EXCLUDED.matched_value,
                    severity      = EXCLUDED.severity,
                    finding_id    = COALESCE(EXCLUDED.finding_id, ti_matches.finding_id),
                    matched_at    = NOW()
                RETURNING (xmax = 0) AS inserted
                """,
                indicator_id, subject_type, subject_id, matched_value,
                severity, finding_id,
            )
        return bool(row and row["inserted"])

    async def list_matches(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Matches joined to indicator + a subject summary (asset or finding)."""
        async with self.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT m.id, m.indicator_id, m.subject_type, m.subject_id,
                       m.matched_value, m.severity, m.finding_id, m.matched_at,
                       i.type AS indicator_type, i.value AS indicator_value,
                       i.labels AS indicator_labels, i.malware AS indicator_malware,
                       i.threat_actor AS indicator_threat_actor,
                       i.confidence AS indicator_confidence,
                       a.kind AS asset_kind, a.value AS asset_value,
                       fa.id AS finding_asset_id, fa.value AS finding_asset_value,
                       f.title AS finding_title, f.severity AS finding_severity
                  FROM ti_matches m
                  JOIN ti_indicators i ON i.id = m.indicator_id
                  LEFT JOIN assets a ON a.id = m.subject_id AND m.subject_type = 'asset'
                  LEFT JOIN findings f ON f.id = m.subject_id AND m.subject_type = 'finding'
                  LEFT JOIN assets fa ON fa.id = f.asset_id
                 ORDER BY array_position(
                            ARRAY['info','low','medium','high','critical'], m.severity
                          ) DESC,
                          m.matched_at DESC
                 LIMIT $1 OFFSET $2
                """,
                limit, offset,
            )
        return [self._match_row(r) for r in rows]

    async def count_matches(self) -> int:
        async with self.acquire() as conn:
            n = await conn.fetchval("SELECT COUNT(*) FROM ti_matches")
        return int(n or 0)

    @staticmethod
    def _match_row(r: asyncpg.Record) -> dict[str, Any]:
        d = dict(r)
        for k in ("id", "indicator_id", "subject_id", "finding_id", "finding_asset_id"):
            if d.get(k) is not None:
                d[k] = str(d[k])
        d["indicator_labels"] = list(d.get("indicator_labels") or [])
        d["indicator_malware"] = list(d.get("indicator_malware") or [])
        return d

    # ------------------------------------------------------------------
    # ti_feeds
    # ------------------------------------------------------------------
    async def insert_feed(
        self,
        *,
        name: str,
        kind: str,
        url: str | None = None,
        collection: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO ti_feeds (name, kind, url, collection, enabled)
                VALUES ($1,$2,$3,$4,$5)
                ON CONFLICT (name) DO UPDATE SET
                    kind = EXCLUDED.kind,
                    url = EXCLUDED.url,
                    collection = EXCLUDED.collection,
                    enabled = EXCLUDED.enabled
                RETURNING id, name, kind, url, collection, enabled, last_poll,
                          last_status, indicator_count, created_at
                """,
                name, kind, url, collection, enabled,
            )
        return self._feed_row(row)

    async def get_feed(self, feed_id: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, name, kind, url, collection, enabled, last_poll,
                       last_status, indicator_count, created_at
                  FROM ti_feeds WHERE id = $1
                """,
                feed_id,
            )
        return self._feed_row(row) if row else None

    async def list_feeds(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        where = "WHERE enabled" if enabled_only else ""
        async with self.acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT id, name, kind, url, collection, enabled, last_poll,
                       last_status, indicator_count, created_at
                  FROM ti_feeds {where}
                 ORDER BY created_at DESC
                """
            )
        return [self._feed_row(r) for r in rows]

    async def delete_feed(self, feed_id: str) -> bool:
        async with self.acquire() as conn:
            result = await conn.execute("DELETE FROM ti_feeds WHERE id = $1", feed_id)
        return result.endswith(" 1")

    async def record_feed_poll(
        self, feed_id: str, *, status: str, ingested: int = 0,
        last_poll: datetime | None = None,
    ) -> None:
        async with self.acquire() as conn:
            await conn.execute(
                """
                UPDATE ti_feeds
                   SET last_poll = $2,
                       last_status = $3,
                       indicator_count = indicator_count + $4
                 WHERE id = $1
                """,
                feed_id,
                last_poll or datetime.now(timezone.utc),
                status[:500],
                int(ingested),
            )

    @staticmethod
    def _feed_row(r: asyncpg.Record) -> dict[str, Any]:
        d = dict(r)
        d["id"] = str(d["id"])
        return d

    # ------------------------------------------------------------------
    # stats
    # ------------------------------------------------------------------
    async def stats(self) -> dict[str, Any]:
        async with self.acquire() as conn:
            by_type_rows = await conn.fetch(
                "SELECT type, COUNT(*) AS c FROM ti_indicators GROUP BY type"
            )
            indicators = await conn.fetchval("SELECT COUNT(*) FROM ti_indicators")
            matches = await conn.fetchval("SELECT COUNT(*) FROM ti_matches")
            feeds = await conn.fetchval("SELECT COUNT(*) FROM ti_feeds")
        return {
            "indicators": int(indicators or 0),
            "matches": int(matches or 0),
            "feeds": int(feeds or 0),
            "by_type": {r["type"]: int(r["c"]) for r in by_type_rows},
        }
