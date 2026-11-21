"""asyncpg pool lifecycle and small query helpers.

Pool is created at app startup via the FastAPI lifespan and stashed on
`app.state.pool`. Routers reach it through the `get_pool` dependency. In
tests we construct a pool directly from a pytest-postgresql fixture and
attach it the same way, so routers do not care where the pool came from.
"""
from __future__ import annotations

import logging
from typing import Any

import asyncpg
from fastapi import Request

from .config import settings

logger = logging.getLogger(__name__)


def _coerce_dsn(url: str) -> str:
    """Turn a SQLAlchemy-style DSN into one asyncpg accepts.

    docker-compose uses `postgresql+asyncpg://...`; asyncpg wants
    `postgresql://...` (no driver segment, no query-string driver hints).
    """
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + url[len("postgresql+asyncpg://") :]
    if url.startswith("postgres+asyncpg://"):
        return "postgres://" + url[len("postgres+asyncpg://") :]
    return url


async def create_pool(dsn: str | None = None) -> asyncpg.Pool:
    dsn = _coerce_dsn(dsn or settings.database_url)
    pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        command_timeout=30,
    )
    assert pool is not None
    return pool


async def close_pool(pool: asyncpg.Pool) -> None:
    await pool.close()


def get_pool(request: Request) -> asyncpg.Pool:
    """FastAPI dependency: current request's app.state.pool."""
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise RuntimeError("database pool not initialised on app.state.pool")
    return pool


async def fetch_one(pool: asyncpg.Pool, sql: str, *args: Any) -> asyncpg.Record | None:
    async with pool.acquire() as con:
        return await con.fetchrow(sql, *args)


async def fetch_all(pool: asyncpg.Pool, sql: str, *args: Any) -> list[asyncpg.Record]:
    async with pool.acquire() as con:
        return await con.fetch(sql, *args)


async def execute(pool: asyncpg.Pool, sql: str, *args: Any) -> str:
    async with pool.acquire() as con:
        return await con.execute(sql, *args)
