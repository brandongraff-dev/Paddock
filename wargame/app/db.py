"""Thin async wrapper around asyncpg. One pool per process."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional, Sequence
from uuid import UUID

import asyncpg

from . import tenancy

log = logging.getLogger(__name__)


class Database:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self, min_size: int = 1, max_size: int = 10) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            dsn=self._dsn,
            min_size=min_size,
            max_size=max_size,
            init=self._init_conn,
        )
        await tenancy.check_role(self._pool)

    @staticmethod
    async def _init_conn(conn: asyncpg.Connection) -> None:
        # JSON(B) <-> dict transparently
        await conn.set_type_codec(
            "jsonb",
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )
        await conn.set_type_codec(
            "json",
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("db not connected; call connect() first")
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

    async def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def fetchrow(
        self, sql: str, *args: Any
    ) -> Optional[asyncpg.Record]:
        async with self.acquire() as conn:
            return await conn.fetchrow(sql, *args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self.acquire() as conn:
            return await conn.execute(sql, *args)


# Convenience dataclasses -----------------------------------------------------


def record_to_dict(r: Optional[asyncpg.Record]) -> Optional[dict[str, Any]]:
    if r is None:
        return None
    d = dict(r)
    for k, v in list(d.items()):
        if isinstance(v, UUID):
            d[k] = str(v)
    return d


def records_to_dicts(
    rows: Sequence[asyncpg.Record],
) -> list[dict[str, Any]]:
    return [record_to_dict(r) for r in rows]  # type: ignore[misc]
