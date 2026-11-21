"""Shared fixtures + in-memory stand-ins for Database and OrchestratorClient."""
from __future__ import annotations

import json
import pathlib
import uuid
from datetime import datetime
from typing import Any

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    path = FIXTURES / name
    if name.endswith(".json"):
        return json.loads(path.read_text())
    return path.read_text()


class FakeDB:
    """In-memory substitute for app.db.Database used in unit tests."""

    def __init__(self) -> None:
        # value-keyed by (type, value) to mimic the UNIQUE constraint
        self.indicators: dict[tuple[str, str], dict[str, Any]] = {}
        self.assets: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.matches: list[dict[str, Any]] = []
        self.feeds: dict[str, dict[str, Any]] = {}
        self.feed_polls: list[dict[str, Any]] = []

    # --- indicators ---
    async def upsert_indicator(self, record: dict[str, Any], *, feed_id: str | None = None) -> dict[str, Any]:
        key = (record["type"], record["value"])
        existing = self.indicators.get(key)
        if existing is None:
            iid = str(uuid.uuid4())
            row = {"id": iid, "feed_id": feed_id, **record}
            self.indicators[key] = row
            return {"id": iid, "inserted": True}
        existing.update({k: v for k, v in record.items() if v is not None})
        if feed_id:
            existing["feed_id"] = feed_id
        return {"id": existing["id"], "inserted": False}

    async def list_indicators(self, *, type=None, label=None, q=None, limit=100, offset=0):
        rows = list(self.indicators.values())
        return rows[offset:offset + limit]

    # --- read-only surface ---
    async def list_match_assets(self, *, kinds, limit=50000):
        return [a for a in self.assets if a["kind"] in kinds][:limit]

    async def list_findings_with_evidence(self, *, limit=50000):
        return [f for f in self.findings if f.get("evidence")][:limit]

    # --- matches ---
    async def upsert_match(self, *, indicator_id, subject_type, subject_id,
                           matched_value, severity, finding_id=None):
        for m in self.matches:
            if m["indicator_id"] == indicator_id and m["subject_id"] == subject_id:
                m.update({"matched_value": matched_value, "severity": severity,
                          "finding_id": finding_id or m.get("finding_id")})
                return False
        self.matches.append({
            "indicator_id": indicator_id, "subject_type": subject_type,
            "subject_id": subject_id, "matched_value": matched_value,
            "severity": severity, "finding_id": finding_id,
        })
        return True

    # --- feeds ---
    async def insert_feed(self, *, name, kind, url=None, collection=None, enabled=True):
        fid = str(uuid.uuid4())
        row = {"id": fid, "name": name, "kind": kind, "url": url,
               "collection": collection, "enabled": enabled, "indicator_count": 0,
               "last_poll": None, "last_status": None}
        self.feeds[fid] = row
        return row

    async def get_feed(self, feed_id):
        return self.feeds.get(feed_id)

    async def list_feeds(self, *, enabled_only=False):
        rows = list(self.feeds.values())
        return [r for r in rows if r["enabled"]] if enabled_only else rows

    async def record_feed_poll(self, feed_id, *, status, ingested=0, last_poll=None):
        self.feed_polls.append({"feed_id": feed_id, "status": status, "ingested": ingested})
        if feed_id in self.feeds:
            self.feeds[feed_id]["last_status"] = status
            self.feeds[feed_id]["indicator_count"] += ingested
            self.feeds[feed_id]["last_poll"] = last_poll

    # --- seed helpers for tests ---
    def seed_asset(self, kind: str, value: str) -> str:
        aid = str(uuid.uuid4())
        self.assets.append({"id": aid, "kind": kind, "value": value})
        return aid

    def seed_finding(self, asset_id: str, evidence: dict[str, Any]) -> str:
        fid = str(uuid.uuid4())
        self.findings.append({"id": fid, "asset_id": asset_id, "evidence": evidence})
        return fid

    async def seed_indicator(self, **record) -> str:
        record.setdefault("confidence", 50)
        res = await self.upsert_indicator(record)
        return res["id"]


class FakeOrchestrator:
    def __init__(self) -> None:
        self.posted_findings: list[dict[str, Any]] = []

    async def ensure(self) -> None: ...
    async def close(self) -> None: ...

    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        items = []
        for f in findings:
            self.posted_findings.append(f)
            items.append({
                "id": str(uuid.uuid4()),
                "asset_id": f.get("asset_id"),
                "rule_id": f.get("rule_id"),
                "rule_source": f.get("rule_source"),
            })
        return {"inserted": len(items), "updated": 0, "items": items}


@pytest.fixture
def fake_db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def fake_orch() -> FakeOrchestrator:
    return FakeOrchestrator()
