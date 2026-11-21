"""DB-backed smoke tests. Skipped unless TEST_DATABASE_URL points at a schema'd
postgres (001-010 applied). Kept thin — the heavy logic is tested pure above.
"""
from __future__ import annotations

import os

import pytest

from app.config import _normalize_dsn
from app.db import Database

TEST_DSN = os.environ.get("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not TEST_DSN, reason="set TEST_DATABASE_URL to run DB-backed tests"
)


async def _db() -> Database:
    db = Database(_normalize_dsn(TEST_DSN or ""))
    await db.connect()
    return db


async def test_ping_and_reads() -> None:
    db = await _db()
    try:
        assert await db.ping() is True
        open_rows = await db.fetch_open_feature_rows()
        assert isinstance(open_rows, list)
        labeled = await db.fetch_labeled_feature_rows()
        assert isinstance(labeled, list)
        hosts = await db.fetch_host_subject_rows()
        assert isinstance(hosts, list)
        counters = await db.counters()
        assert set(counters) >= {"risk_scores", "anomalies_open", "labeled_samples"}
    finally:
        await db.close()


async def test_model_versioning_roundtrip() -> None:
    db = await _db()
    try:
        v = await db.next_version("risk_ranker")
        assert v >= 1
        await db.insert_model(
            kind="risk_ranker", version=v, algo="heuristic_prior",
            n_samples=0, metrics={"mode": "heuristic_prior"},
            feature_importance={"kev": 0.22}, cold_start=True, notes="test",
        )
        active = await db.active_model("risk_ranker")
        assert active is not None and active["version"] == v
        assert active["active"] is True
    finally:
        await db.close()
