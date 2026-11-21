"""Asyncpg access to the shared CVE feed.

otdiscovery only *reads* from ``cves`` (owned by the intel service) to match
discovered devices. It writes no asset/finding rows directly -- those go through
the orchestrator HTTP API. The DB is optional: when it is unreachable the
service still ingests and projects devices; CVE matching simply yields nothing.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import asyncpg

log = logging.getLogger("otdiscovery.db")


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb", encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads, schema="pg_catalog",
    )
    await conn.set_type_codec(
        "json", encoder=lambda v: json.dumps(v, default=str),
        decoder=json.loads, schema="pg_catalog",
    )


class Database:
    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 4) -> None:
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
            command_timeout=30,
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

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    async def cve_candidates(
        self, vendor_tokens: set[str], limit: int = 500
    ) -> list[dict[str, Any]]:
        """Coarse prefilter: CVEs whose affected CPE vendor matches a token.

        Returns rows for the precise Python matcher to re-check. An ILIKE
        prefilter keeps multi-word CPE vendors (``rockwell_automation``)
        reachable from a single token (``rockwell``).
        """
        if not vendor_tokens:
            return []
        patterns = [f"%{t}%" for t in vendor_tokens if t]
        sql = """
            SELECT id, cvss_v3, epss, description, refs, cpe_affected,
                   known_exploited, cwe_ids
              FROM cves c
             WHERE EXISTS (
                SELECT 1 FROM jsonb_array_elements(c.cpe_affected) e
                 WHERE e->>'vendor' ILIKE ANY($1::text[])
             )
             LIMIT $2
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(sql, patterns, limit)
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for col in ("refs", "cpe_affected"):
                if isinstance(d.get(col), str):
                    d[col] = json.loads(d[col])
            if d.get("cvss_v3") is not None:
                d["cvss_v3"] = float(d["cvss_v3"])
            if d.get("epss") is not None:
                d["epss"] = float(d["epss"])
            out.append(d)
        return out
