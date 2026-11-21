"""Asyncpg pool + helpers for the codeanalysis tables.

This service WRITES reachability columns on ``sbom_component_vulns`` and rows
in ``code_findings``. Unified ``findings`` go through the orchestrator HTTP API
(never written directly). SBOM / project rows are owned by ``sca`` and only
READ here. All queries share one pool. Mirrors ``sca/app/db.py``.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional
from uuid import UUID

import asyncpg

log = logging.getLogger("codeanalysis.db")


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

    # ------------------------------------------------------------------
    # projects / SBOM (read-only here)
    # ------------------------------------------------------------------
    async def get_project(self, name: str) -> Optional[dict[str, Any]]:
        row = await self.fetchrow(
            """
            SELECT id::text, name, asset_id::text, source_ref, ecosystems
            FROM sca_projects WHERE name = $1
            """,
            name,
        )
        return _clean(row)

    async def fetch_project_vulns(self, project_name: str) -> list[dict[str, Any]]:
        """All dependency vulns for a project, joined to their component."""
        rows = await self.fetch(
            """
            SELECT v.id::text       AS vuln_id,
                   v.osv_id         AS osv_id,
                   v.cve_id         AS cve_id,
                   v.summary        AS summary,
                   v.refs           AS refs,
                   v.severity       AS severity,
                   v.reachability   AS reachability,
                   c.ecosystem      AS ecosystem,
                   c.name           AS name,
                   c.version        AS version
            FROM sbom_component_vulns v
            JOIN sbom_components c ON c.id = v.component_id
            JOIN sca_projects p    ON p.id = c.project_id
            WHERE p.name = $1
            ORDER BY c.name, v.osv_id
            """,
            project_name,
        )
        return [_clean(r) for r in rows]  # type: ignore[misc]

    async def update_reachability(self, vuln_id: str, reachability: str,
                                  reachable_symbol: Optional[str],
                                  call_path: list[Any]) -> bool:
        res = await self.execute(
            """
            UPDATE sbom_component_vulns
            SET reachability     = $2,
                reachable_symbol = $3,
                call_path        = $4::jsonb
            WHERE id = $1::uuid
            """,
            vuln_id, reachability, reachable_symbol, call_path or [],
        )
        return res.endswith("1")

    # ------------------------------------------------------------------
    # code_findings (owned here)
    # ------------------------------------------------------------------
    async def upsert_code_finding(self, *, project_id: Optional[str],
                                  asset_id: Optional[str], engine: str, rule: str,
                                  message: str, severity: str, file: str,
                                  start_line: Optional[int], end_line: Optional[int],
                                  source: Optional[str], sink: Optional[str],
                                  dataflow: list[Any], cwe: Optional[str],
                                  metadata: dict[str, Any],
                                  finding_id: Optional[str] = None) -> dict[str, Any]:
        row = await self.fetchrow(
            """
            INSERT INTO code_findings
                (project_id, asset_id, finding_id, engine, rule, message, severity,
                 file, start_line, end_line, source, sink, dataflow, cwe, metadata)
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13::jsonb, $14, $15::jsonb)
            ON CONFLICT (project_id, rule, file, start_line) DO UPDATE SET
                message   = EXCLUDED.message,
                severity  = EXCLUDED.severity,
                end_line  = EXCLUDED.end_line,
                source    = EXCLUDED.source,
                sink      = EXCLUDED.sink,
                dataflow  = EXCLUDED.dataflow,
                cwe       = EXCLUDED.cwe,
                metadata  = code_findings.metadata || EXCLUDED.metadata,
                engine    = EXCLUDED.engine,
                detected_at = NOW()
            RETURNING id::text, (xmax = 0) AS inserted
            """,
            project_id, asset_id, finding_id, engine, rule, message, severity,
            file, start_line, end_line, source, sink, dataflow or [], cwe, metadata or {},
        )
        return _clean(row)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    async def stats(self) -> dict[str, Any]:
        async with self.acquire() as conn:
            code_findings = await conn.fetchval("SELECT COUNT(*) FROM code_findings")
            by_sev = await conn.fetch(
                "SELECT severity, COUNT(*) AS n FROM code_findings GROUP BY severity"
            )
            reach = await conn.fetch(
                "SELECT reachability, COUNT(*) AS n FROM sbom_component_vulns GROUP BY reachability"
            )
        return {
            "code_findings": int(code_findings or 0),
            "code_findings_by_severity": {r["severity"]: int(r["n"]) for r in by_sev},
            "reachability": {r["reachability"]: int(r["n"]) for r in reach},
        }
