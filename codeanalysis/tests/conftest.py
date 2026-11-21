"""Shared fixtures.

Pure-Python suites (call graphs, grading, taint scanner, normalization, semgrep
runner) need no database. The DB helper suite uses ``TEST_DATABASE_URL``
(falling back to ``DATABASE_URL``) and skips cleanly when neither is set or
reachable -- mirroring sca / intel / changewatch.
"""
from __future__ import annotations

import json
import os
import pathlib
from typing import Any, AsyncIterator, Optional

import pytest
import pytest_asyncio

from app.config import _normalize_dsn
from app.db import Database

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def load_json_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


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
        await d.connect(min_size=1, max_size=4)
    except Exception as e:
        pytest.skip(f"test postgres unreachable: {e}")
    try:
        await d.execute("SELECT 1 FROM code_findings LIMIT 1")
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
