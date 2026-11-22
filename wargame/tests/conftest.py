"""Shared test fixtures for the Proving Ground service.

Pure tests (guard, backends, scenarios) need no infrastructure. The DB-backed
persistence tests use TEST_DATABASE_URL (or DATABASE_URL) and skip cleanly when
neither is set, mirroring the correlation suite.
"""
from __future__ import annotations

import os
import uuid
from typing import AsyncIterator, Optional

import pytest
import pytest_asyncio

from app.config import _asyncpg_dsn
from app.db import Database


def _test_dsn() -> Optional[str]:
    raw = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not raw:
        return None
    return _asyncpg_dsn(raw)


@pytest_asyncio.fixture
async def db() -> AsyncIterator[Database]:
    dsn = _test_dsn()
    if dsn is None:
        pytest.skip("no TEST_DATABASE_URL / DATABASE_URL set")
    d = Database(dsn)
    try:
        await d.connect(min_size=1, max_size=4)
    except Exception as e:
        pytest.skip(f"test postgres unreachable: {e}")
    try:
        await d.execute("SELECT 1 FROM wargame_runs LIMIT 1")
    except Exception:
        schema_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "schema")
        )
        for fname in sorted(os.listdir(schema_dir)):
            if fname.endswith(".sql"):
                with open(os.path.join(schema_dir, fname)) as f:
                    try:
                        await d.execute(f.read())
                    except Exception:
                        pass
    try:
        yield d
    finally:
        await d.close()


@pytest_asyncio.fixture
async def clean_db(db: Database) -> AsyncIterator[Database]:
    async with db.acquire() as conn:
        await conn.execute(
            "TRUNCATE wargame_proofs, wargame_runs RESTART IDENTITY CASCADE"
        )
    yield db


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

async def mk_asset(db: Database, kind: str, value: str, metadata: Optional[dict] = None) -> str:
    aid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO assets (id, kind, value, canonical, source, metadata) "
        "VALUES ($1::uuid, $2, $3, $4, 'test', $5::jsonb)",
        aid, kind, value, value.lower(), metadata or {},
    )
    return aid
