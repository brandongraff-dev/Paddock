"""Shared fixtures.

Pure-Python suites (parsers, OSV mapping, risk detectors, finding builder) need
no database. The DB helper suite uses ``TEST_DATABASE_URL`` (falling back to
``DATABASE_URL``) and skips cleanly when neither is set or reachable --
mirroring intel / changewatch.
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


@pytest_asyncio.fixture(scope="session")
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
        await d.execute("SELECT 1 FROM sca_projects LIMIT 1")
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


# ---------------------------------------------------------------------------
# Fake aiohttp session for OSV tests (no network)
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    async def __aenter__(self) -> "_FakeResp":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            import aiohttp
            raise aiohttp.ClientError(f"status {self.status}")

    async def json(self) -> Any:
        return self._payload


class FakeOsvSession:
    """Serves a canned querybatch body and per-id vuln details."""

    def __init__(self, batch: Any, vulns: dict[str, Any]) -> None:
        self._batch = batch
        self._vulns = vulns
        self.posts: list[Any] = []
        self.gets: list[str] = []

    def post(self, url: str, json: Any = None, **_: Any) -> _FakeResp:
        self.posts.append(json)
        return _FakeResp(self._batch)

    def get(self, url: str, **_: Any) -> _FakeResp:
        self.gets.append(url)
        vid = url.rstrip("/").rsplit("/", 1)[-1]
        payload = self._vulns.get(vid)
        if payload is None:
            return _FakeResp({}, status=404)
        return _FakeResp(payload)


@pytest.fixture
def fake_osv_session() -> FakeOsvSession:
    return FakeOsvSession(
        batch=load_json_fixture("osv_querybatch.json"),
        vulns={
            "GHSA-xxxx-yyyy-zzzz": load_json_fixture("osv_vuln_ghsa.json"),
            "MAL-2023-0001": load_json_fixture("osv_vuln_mal.json"),
        },
    )
