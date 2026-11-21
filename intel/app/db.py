"""Asyncpg connection pool + helpers for the intel tables.

We own writes to `cves`, `cve_matches`, `intel_cursors`. Everything else
(findings, assets) goes through the orchestrator HTTP API.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Iterable

import asyncpg

log = logging.getLogger(__name__)


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
    # cves
    # ------------------------------------------------------------------
    async def upsert_cve(self, record: dict[str, Any]) -> bool:
        """Insert or update a CVE row.

        Returns True if the row was inserted or genuinely updated (modified_at
        advanced), False if the stored record was already as fresh. Used by
        the linker to decide whether to re-match.
        """
        sql = """
        INSERT INTO cves (
            id, published_at, modified_at, cvss_v3, cvss_v3_vector, cvss_v2,
            description, refs, cpe_affected, cwe_ids, updated_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW())
        ON CONFLICT (id) DO UPDATE SET
            published_at   = COALESCE(EXCLUDED.published_at, cves.published_at),
            modified_at    = GREATEST(cves.modified_at, EXCLUDED.modified_at),
            cvss_v3        = COALESCE(EXCLUDED.cvss_v3, cves.cvss_v3),
            cvss_v3_vector = COALESCE(EXCLUDED.cvss_v3_vector, cves.cvss_v3_vector),
            cvss_v2        = COALESCE(EXCLUDED.cvss_v2, cves.cvss_v2),
            description    = COALESCE(EXCLUDED.description, cves.description),
            refs           = EXCLUDED.refs,
            cpe_affected   = EXCLUDED.cpe_affected,
            cwe_ids        = EXCLUDED.cwe_ids,
            updated_at     = NOW()
        WHERE EXCLUDED.modified_at IS NULL
           OR cves.modified_at IS NULL
           OR EXCLUDED.modified_at >= cves.modified_at
        RETURNING xmax = 0 AS inserted
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                record["id"],
                record.get("published_at"),
                record.get("modified_at"),
                record.get("cvss_v3"),
                record.get("cvss_v3_vector"),
                record.get("cvss_v2"),
                record.get("description"),
                record.get("refs") or [],
                record.get("cpe_affected") or [],
                record.get("cwe_ids") or [],
            )
            return row is not None

    async def update_epss(self, cve_id: str, epss: float, percentile: float) -> bool:
        """Update EPSS score. UPDATE-only — won't insert unknown CVEs."""
        async with self.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE cves
                   SET epss = $2,
                       epss_percentile = $3,
                       updated_at = NOW()
                 WHERE id = $1
                """,
                cve_id, epss, percentile,
            )
        return result.endswith(" 1")

    async def mark_kev(self, cve_id: str, added_at: datetime | None) -> bool:
        async with self.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE cves
                   SET known_exploited = TRUE,
                       kev_added_at = COALESCE($2, kev_added_at, NOW()),
                       updated_at = NOW()
                 WHERE id = $1
                """,
                cve_id, added_at,
            )
        return result.endswith(" 1")

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM cves WHERE id = $1", cve_id)
        return dict(row) if row else None

    async def candidate_cves_for(
        self, vendor: str, product: str, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Find CVEs whose cpe_affected contains the given vendor+product.

        Uses a JSONB `@>` containment with the GIN index on cpe_affected.
        """
        # cpe_affected looks like: [{"vendor":"nginx","product":"nginx", ...}, ...]
        needle = [{"vendor": vendor.lower(), "product": product.lower()}]
        async with self.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, cvss_v3, cvss_v3_vector, cvss_v2, epss, epss_percentile,
                       known_exploited, description, refs, cpe_affected,
                       published_at, modified_at
                  FROM cves
                 WHERE cpe_affected @> $1::jsonb
                 ORDER BY COALESCE(cvss_v3, 0) DESC
                 LIMIT $2
                """,
                needle, limit,
            )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # cve_matches
    # ------------------------------------------------------------------
    async def upsert_match(
        self, cve_id: str, asset_id: str, confidence: int, matcher: str
    ) -> bool:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO cve_matches (cve_id, asset_id, confidence, matcher)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (cve_id, asset_id) DO UPDATE
                   SET confidence = GREATEST(cve_matches.confidence, EXCLUDED.confidence),
                       matcher    = EXCLUDED.matcher,
                       matched_at = NOW()
                RETURNING xmax = 0 AS inserted
                """,
                cve_id, asset_id, int(confidence), matcher,
            )
        return bool(row and row["inserted"])

    async def matches_for_cve(self, cve_id: str) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                "SELECT cve_id, asset_id, confidence, matcher FROM cve_matches WHERE cve_id=$1",
                cve_id,
            )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # intel_cursors
    # ------------------------------------------------------------------
    async def get_cursor(self, source: str) -> dict[str, Any] | None:
        async with self.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT source, last_synced, last_cursor, stats FROM intel_cursors WHERE source=$1",
                source,
            )
        return dict(row) if row else None

    async def set_cursor(
        self,
        source: str,
        last_synced: datetime | None = None,
        last_cursor: str | None = None,
        stats: dict[str, Any] | None = None,
    ) -> None:
        async with self.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO intel_cursors (source, last_synced, last_cursor, stats)
                VALUES ($1, $2, $3, COALESCE($4, '{}'::jsonb))
                ON CONFLICT (source) DO UPDATE SET
                    last_synced = COALESCE(EXCLUDED.last_synced, intel_cursors.last_synced),
                    last_cursor = COALESCE(EXCLUDED.last_cursor, intel_cursors.last_cursor),
                    stats       = intel_cursors.stats || COALESCE(EXCLUDED.stats, '{}'::jsonb)
                """,
                source,
                last_synced or datetime.now(timezone.utc),
                last_cursor,
                stats or {},
            )

    async def counters(self) -> dict[str, int]:
        async with self.acquire() as conn:
            cves = await conn.fetchval("SELECT COUNT(*) FROM cves")
            matches = await conn.fetchval("SELECT COUNT(*) FROM cve_matches")
            kev = await conn.fetchval("SELECT COUNT(*) FROM cves WHERE known_exploited")
        return {"cves": int(cves or 0), "matches": int(matches or 0), "kev": int(kev or 0)}

    async def all_cursors(self) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                "SELECT source, last_synced, last_cursor, stats FROM intel_cursors ORDER BY source"
            )
        return [dict(r) for r in rows]
