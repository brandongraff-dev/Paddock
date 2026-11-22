"""Asyncpg pool + helpers for the brain tables.

We own writes to `finding_clusters` and `nl_queries`. We READ open findings
for triage, and we execute validated NL-queries in a strictly READ-ONLY
transaction against the three ask_* views only.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import asyncpg

from . import tenancy

log = logging.getLogger("brain.db")


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
    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 8) -> None:
        self.dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: asyncpg.Pool | None = None

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

    async def ping(self) -> bool:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("db ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # triage: read open findings, write finding_clusters
    # ------------------------------------------------------------------
    async def open_findings(self, limit: int = 5000) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT f.id, f.rule_id, f.rule_source, f.severity, f.title,
                       f.cvss, f.epss, a.value AS asset_value, a.kind AS asset_kind
                  FROM findings f
                  LEFT JOIN assets a ON a.id = f.asset_id
                 WHERE f.status = 'open'
                 ORDER BY f.first_seen DESC
                 LIMIT $1
                """,
                limit,
            )
        return [dict(r) for r in rows]

    async def replace_clusters(
        self, clusters: list[dict[str, Any]], engine: str
    ) -> int:
        """Replace the stored clusters for one engine with a fresh set.

        Runs in a single transaction so readers never see an empty table.
        """
        async with self.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM finding_clusters WHERE engine = $1", engine
                )
                n = 0
                for c in clusters:
                    await conn.execute(
                        """
                        INSERT INTO finding_clusters
                            (label, summary, severity, finding_ids, engine, metadata)
                        VALUES ($1, $2, $3, $4::uuid[], $5, $6::jsonb)
                        """,
                        c["label"],
                        c.get("summary"),
                        c.get("severity"),
                        [str(x) for x in c.get("finding_ids", [])],
                        engine,
                        c.get("metadata") or {},
                    )
                    n += 1
        return n

    async def count_clusters(self) -> int:
        async with self.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM finding_clusters") or 0)

    async def list_clusters(self, limit: int = 200) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, label, summary, severity, finding_ids, engine, created_at "
                "FROM finding_clusters ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("created_at"), datetime):
                d["created_at"] = d["created_at"].isoformat()
            d["finding_ids"] = [str(x) for x in (d.get("finding_ids") or [])]
            out.append(d)
        return out

    # ------------------------------------------------------------------
    # nl_queries: audit every NL-query attempt
    # ------------------------------------------------------------------
    async def log_nl_query(
        self,
        question: str,
        generated_sql: str | None,
        engine: str,
        ok: bool,
        row_count: int | None,
        error: str | None,
        asked_by: str | None,
    ) -> None:
        async with self.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO nl_queries
                    (question, generated_sql, engine, ok, row_count, error, asked_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                question, generated_sql, engine, ok, row_count, error, asked_by,
            )

    async def count_queries(self) -> int:
        async with self.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM nl_queries") or 0)

    async def recent_queries(self, limit: int = 20) -> list[dict[str, Any]]:
        async with self.acquire() as conn:
            rows = await conn.fetch(
                "SELECT question, engine, ok, row_count, asked_at "
                "FROM nl_queries ORDER BY asked_at DESC LIMIT $1",
                limit,
            )
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("asked_at"), datetime):
                d["asked_at"] = d["asked_at"].isoformat()
            out.append(d)
        return out

    # ------------------------------------------------------------------
    # The ONLY path that runs NL-query SQL. READ ONLY, timed, row-capped.
    # ------------------------------------------------------------------
    async def run_readonly_select(
        self, sql: str, stmt_timeout_ms: int, max_rows: int
    ) -> tuple[list[str], list[list[Any]]]:
        """Execute ``sql`` inside a READ-ONLY transaction with a statement
        timeout, returning (columns, rows). The caller MUST have run the SQL
        through `guard.validate()` first — this method does no validation.
        """
        if tenancy.current_tenant_id() is None:
            # LLM-written SQL must never run without a tenant (strict mode, unbound).
            raise PermissionError("no tenant bound: refusing to run NL-query SQL")
        # A TOP-LEVEL read-only transaction (asyncpg ignores `readonly` on a
        # nested one, so this must not go through acquire()) that also carries
        # the tenant (SET LOCAL): the SQL below can only ever see this tenant's
        # rows, with the service role's read-only grants on top.
        async with self.pool.acquire() as conn:
            async with tenancy.scoped(conn, readonly=True):
                await conn.execute(f"SET LOCAL statement_timeout = {int(stmt_timeout_ms)}")
                records = await conn.fetch(sql)
                # Defence in depth behind guard.validate() (which denies
                # set_config): if the statement managed to move the tenant GUC
                # mid-flight, the rows it read may belong to another tenant --
                # discard them instead of returning anything.
                if await conn.fetchval("SELECT current_setting('app.tenant_id', true)") != tenancy.current_tenant_id():
                    raise PermissionError("tenant context changed during NL-query; result discarded")

        if not records:
            return [], []
        columns = list(records[0].keys())
        rows: list[list[Any]] = []
        for rec in records[:max_rows]:
            row = []
            for v in rec.values():
                if v is None or isinstance(v, (str, int, float, bool)):
                    row.append(v)
                elif hasattr(v, "isoformat"):  # datetime / date
                    row.append(v.isoformat())
                else:  # UUID, Decimal, and anything else → string
                    row.append(str(v))
            rows.append(row)
        return columns, rows
