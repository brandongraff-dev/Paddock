"""Shared in-memory fakes for the Postgres reader and the Neo4j wrapper."""
from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from app.neo import Neo4jUnavailable


class FakeDB:
    """In-memory stand-in for app.db.Database."""

    def __init__(
        self,
        assets: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self.assets = assets or []
        self.edges = edges or []
        self.findings = findings or []
        self.cursor: dict[str, Any] | None = None
        self.cursor_writes: list[dict[str, Any]] = []

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def ping(self) -> bool:
        return True

    async def fetch_assets(self, since: datetime | None) -> list[dict[str, Any]]:
        return list(self.assets)

    async def fetch_edges(self, since: datetime | None) -> list[dict[str, Any]]:
        return list(self.edges)

    async def fetch_open_findings(
        self, since: datetime | None, asset_ids: list[str] | None = None
    ) -> list[dict[str, Any]]:
        rows = self.findings
        if asset_ids is not None:
            rows = [f for f in rows if f["asset_id"] in set(asset_ids)]
        return list(rows)

    async def fetch_findings_for_assets(self, asset_ids: list[str]) -> list[dict[str, Any]]:
        return await self.fetch_open_findings(None, asset_ids)

    async def get_cursor(self) -> dict[str, Any] | None:
        return self.cursor

    async def set_cursor(self, last_synced=None, stats=None) -> None:
        self.cursor = {"source": "neo4j_sync", "last_synced": last_synced, "stats": stats or {}}
        self.cursor_writes.append({"last_synced": last_synced, "stats": stats})


class FakeNeo:
    """In-memory stand-in for app.neo.NeoClient."""

    def __init__(self, *, up: bool = True, apoc: bool = False) -> None:
        self._up = up
        self._apoc = apoc
        self.assets: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self.wiped = 0
        self.schema_calls = 0
        self.read_calls: list[tuple[str, dict[str, Any]]] = []

    def available(self) -> bool:
        return self._up

    def reason(self):
        return None if self._up else "connection refused"

    def driver_installed(self) -> bool:
        return True

    async def ping(self) -> bool:
        return self._up

    async def has_apoc(self, *, recheck: bool = False) -> bool:
        return self._apoc

    async def close(self) -> None: ...

    def _guard(self) -> None:
        if not self._up:
            raise Neo4jUnavailable("connection refused")

    async def ensure_schema(self) -> None:
        self._guard()
        self.schema_calls += 1

    async def wipe(self) -> None:
        self._guard()
        self.wiped += 1
        self.assets.clear()
        self.findings.clear()
        self.edges.clear()

    async def merge_assets(self, rows) -> None:
        self._guard()
        self.assets.extend(rows)

    async def merge_findings(self, rows) -> None:
        self._guard()
        self.findings.extend(rows)

    async def merge_edges(self, rows) -> None:
        self._guard()
        self.edges.extend(rows)

    async def run_read(self, cypher, params):
        self._guard()
        self.read_calls.append((cypher, params))
        return []


@pytest.fixture
def fake_db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def fake_neo() -> FakeNeo:
    return FakeNeo()
