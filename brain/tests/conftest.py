"""Shared fixtures.

All guard, fallback, triage-clustering and ask-flow tests run WITHOUT a key,
network, or database — the LLM is mocked and the DB is a fake. The one
DB-backed execution test uses the real pool via `db` and skips cleanly when
TEST_DATABASE_URL (or DATABASE_URL) is not set / reachable.
"""
from __future__ import annotations

import os
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


@pytest_asyncio.fixture
async def db() -> AsyncIterator[Database]:
    dsn = _test_dsn()
    if dsn is None:
        pytest.skip("no TEST_DATABASE_URL / DATABASE_URL set")
    d = Database(dsn)
    try:
        await d.connect(min_size=1, max_size=2)
        if not await d.ping():
            pytest.skip("test postgres unreachable")
    except Exception as e:
        pytest.skip(f"test postgres unreachable: {e}")
    try:
        yield d
    finally:
        await d.close()


class FakeDB:
    """In-memory stand-in for Database used by the ask-flow tests.

    Records every nl_queries audit write and returns a canned result set
    from run_readonly_select — no real database involved.
    """

    def __init__(self, columns=None, rows=None, raise_on_run: bool = False) -> None:
        self._columns = columns if columns is not None else ["asset_value"]
        self._rows = rows if rows is not None else [["host.example.com"]]
        self._raise_on_run = raise_on_run
        self.logged: list[dict[str, Any]] = []
        self.ran_sql: list[str] = []

    async def log_nl_query(self, question, generated_sql, engine, ok,
                           row_count, error, asked_by) -> None:
        self.logged.append({
            "question": question, "generated_sql": generated_sql,
            "engine": engine, "ok": ok, "row_count": row_count,
            "error": error, "asked_by": asked_by,
        })

    async def run_readonly_select(self, sql, stmt_timeout_ms, max_rows):
        self.ran_sql.append(sql)
        if self._raise_on_run:
            raise RuntimeError("boom")
        return self._columns, self._rows[:max_rows]


class FakeLLM:
    """Stand-in LLM with a settable enabled flag and canned returns."""

    def __init__(self, enabled: bool = False, sql: Optional[str] = None,
                 clusters_out=None) -> None:
        self._enabled = enabled
        self._sql = sql
        self._clusters_out = clusters_out

    def is_enabled(self) -> bool:
        return self._enabled

    async def nl_to_sql(self, question, schema_desc):
        return self._sql

    async def summarize_clusters(self, clusters):
        return self._clusters_out
