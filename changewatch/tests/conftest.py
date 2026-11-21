"""Shared test fixtures.

The detection suite needs a working Postgres: it uses ``TEST_DATABASE_URL``
(falling back to ``DATABASE_URL``) and skips cleanly when neither is set or
reachable — mirroring intel/correlation. The alert suite is pure-Python
(a fake in-memory DB + a fake async poster) and always runs.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

import pytest
import pytest_asyncio

from app.config import _normalize_dsn
from app.db import Database


def _test_dsn() -> Optional[str]:
    raw = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not raw:
        return None
    return _normalize_dsn(raw)


# Session-scoped pool => session-scoped event loop (pytest-asyncio >= 0.24),
# otherwise asyncpg raises "attached to a different loop".
@pytest_asyncio.fixture(scope="session", loop_scope="session")
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
        await d.execute("SELECT 1 FROM surface_changes LIMIT 1")
    except Exception:
        schema_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "schema")
        )
        if os.path.isdir(schema_dir):
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
    """Truncate every table changewatch reads or writes between tests."""
    async with db.acquire() as conn:
        await conn.execute(
            "TRUNCATE surface_changes, alert_deliveries, alert_rules, "
            "findings, asset_edges, assets RESTART IDENTITY CASCADE"
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
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
    source: str = "test",
) -> str:
    aid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO assets (id, kind, value, canonical, source, metadata, first_seen, last_seen)
        VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7, $8)
        """,
        aid, kind, value, value.lower(), source,
        # app/db.py registers a jsonb codec: pass the dict, not json.dumps()
        # (which would double-encode it into a JSON *string*).
        metadata or {},
        first_seen or now,
        last_seen or now,
    )
    return aid


async def mk_edge(
    db: Database,
    src: str,
    dst: str,
    kind: str,
    first_seen: Optional[datetime] = None,
    metadata: Optional[dict] = None,
) -> None:
    now = datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO asset_edges (src_id, dst_id, kind, first_seen, last_seen, metadata)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)
        """,
        src, dst, kind, first_seen or now, now, metadata or {},  # jsonb codec encodes (see mk_asset)
    )


async def mk_finding(
    db: Database,
    asset_id: str,
    rule_id: str,
    rule_source: str = "nuclei",
    severity: str = "high",
    status: str = "open",
    title: Optional[str] = None,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
) -> str:
    fid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO findings (
          id, asset_id, rule_id, rule_source, severity, title, description,
          status, first_seen, last_seen
        ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        fid, asset_id, rule_id, rule_source, severity,
        title or rule_id, rule_id, status,
        first_seen or now, last_seen or now,
    )
    return fid


# ----------------------------------------------------------------------------
# Fakes for the (network-free, DB-free) alert suite
# ----------------------------------------------------------------------------

class FakeAlertDB:
    """In-memory stand-in exposing just the methods AlertDispatcher calls."""

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self._rules = rules
        self.deliveries: list[dict[str, Any]] = []
        self.bumped: list[str] = []

    async def enabled_rules(self) -> list[dict[str, Any]]:
        return [r for r in self._rules if r.get("enabled", True)]

    async def record_delivery(self, rule_id, change_id, status, channel, response):
        row = {
            "rule_id": rule_id,
            "change_id": change_id,
            "status": status,
            "channel": channel,
            "response": response,
        }
        self.deliveries.append(row)
        return row

    async def bump_last_fired(self, rule_id: str) -> None:
        self.bumped.append(rule_id)


class FakePoster:
    """Records POSTs instead of hitting the network."""

    def __init__(self, ok: bool = True, status: int = 200, body: str = "ok") -> None:
        self.ok = ok
        self.status = status
        self.body = body
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, url, payload, headers, timeout_s):
        self.calls.append({
            "url": url, "payload": payload, "headers": headers, "timeout_s": timeout_s,
        })
        return self.ok, self.status, self.body
