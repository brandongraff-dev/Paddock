"""DB-backed execution test. Skips cleanly without TEST_DATABASE_URL.

Proves the real read-only path: a validated SELECT over an ask_* view runs
inside a READ ONLY transaction, and a write attempt in that transaction is
refused by Postgres."""
from __future__ import annotations

import asyncpg
import pytest

from app.config import Config
from app.ask import answer
from tests.conftest import FakeLLM

CFG = Config(anthropic_api_key=None, max_rows=10, stmt_timeout_ms=4000)


async def test_readonly_select_executes(db):
    res = await answer(db, FakeLLM(enabled=False), CFG, "how many open findings by severity", None)
    assert res["ok"] is True
    assert isinstance(res["columns"], list)
    assert isinstance(res["rows"], list)
    assert "LIMIT 10" in res["generated_sql"].upper()


async def test_transaction_is_read_only(db):
    # A write inside the read-only transaction must be refused by Postgres.
    with pytest.raises(asyncpg.PostgresError):
        await db.run_readonly_select(
            "INSERT INTO nl_queries (question, engine, ok) VALUES ('x','x',true)",
            4000, 10,
        )


async def test_row_cap_enforced(db):
    # Row cap applies even if the SELECT would return more.
    cols, rows = await db.run_readonly_select(
        "SELECT severity FROM ask_findings", 4000, 3
    )
    assert len(rows) <= 3
