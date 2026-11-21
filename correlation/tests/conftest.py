"""Shared test fixtures.

The chain/graph tests need a working Postgres. We use `TEST_DATABASE_URL`
(or fall back to `DATABASE_URL`) and skip the DB-backed suite cleanly
when neither is set or reachable. Loader/narrative tests run without
any infra.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
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


# Function-scoped (not session-scoped): under pytest-asyncio>=1.0 each test
# runs on its own event loop, so a session-scoped pool would be bound to a
# stale loop ("another operation is in progress" / "attached to a different
# loop"). Mirrors the orchestrator suite's function-scoped pool. The schema
# bootstrap below is idempotent, so the per-test connect stays cheap.
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
    # Ensure the required tables exist; apply schema if not.
    try:
        await d.execute("SELECT 1 FROM assets LIMIT 1")
    except Exception:
        schema_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "schema"
        )
        schema_dir = os.path.abspath(schema_dir)
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
    """Truncate the tables correlation touches between tests."""
    async with db.acquire() as conn:
        await conn.execute(
            "TRUNCATE finding_chains, findings, asset_edges, assets "
            "RESTART IDENTITY CASCADE"
        )
    yield db


# ----------------------------------------------------------------------------
# Seed helpers
# ----------------------------------------------------------------------------

async def mk_asset(
    db: Database,
    kind: str,
    value: str,
    metadata: Optional[dict] = None,
    source: str = "test",
) -> str:
    aid = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO assets (id, kind, value, canonical, source, metadata)
        VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb)
        """,
        aid,
        kind,
        value,
        value.lower(),
        source,
        metadata or {},
    )
    return aid


async def mk_edge(
    db: Database,
    src: str,
    dst: str,
    kind: str,
    metadata: Optional[dict] = None,
) -> None:
    await db.execute(
        """
        INSERT INTO asset_edges (src_id, dst_id, kind, metadata)
        VALUES ($1::uuid, $2::uuid, $3, $4::jsonb)
        """,
        src,
        dst,
        kind,
        metadata or {},
    )


async def mk_finding(
    db: Database,
    asset_id: str,
    rule_id: str,
    rule_source: str = "nuclei",
    severity: str = "high",
    cvss: Optional[float] = None,
    epss: Optional[float] = None,
    metadata: Optional[dict] = None,
    evidence: Optional[dict] = None,
    status: str = "open",
    last_seen: Optional[datetime] = None,
) -> str:
    fid = str(uuid.uuid4())
    ts = last_seen or datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO findings (
          id, asset_id, rule_id, rule_source, severity, title, description,
          cvss, epss, status, metadata, evidence, first_seen, last_seen
        ) VALUES (
          $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb,
          $12::jsonb, $13, $14
        )
        """,
        fid,
        asset_id,
        rule_id,
        rule_source,
        severity,
        rule_id,
        rule_id,
        cvss,
        epss,
        status,
        metadata or {},
        evidence or {},
        ts,
        ts,
    )
    return fid
