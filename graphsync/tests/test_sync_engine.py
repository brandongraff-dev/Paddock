"""Sync engine flow with in-memory fakes (no live Neo4j)."""
from __future__ import annotations

from app import queries
from app.sync import SyncEngine

from .conftest import FakeDB, FakeNeo


def _graph() -> FakeDB:
    assets = [
        {"id": "endpoint", "kind": "endpoint", "value": "https://x/", "metadata": {"public": True}},
        {"id": "svc", "kind": "service", "value": "nginx", "metadata": {}},
        {"id": "db", "kind": "technology", "value": "PostgreSQL 14", "metadata": {}},
    ]
    edges = [
        {"src": "endpoint", "dst": "svc", "kind": "hosts"},
        {"src": "svc", "dst": "db", "kind": "runs"},
    ]
    findings = [
        {"id": "f1", "asset_id": "svc", "severity": "critical", "rule_source": "cve_match",
         "metadata": {"kev": True}},
    ]
    return FakeDB(assets=assets, edges=edges, findings=findings)


async def test_full_sync_wipes_and_merges() -> None:
    db = _graph()
    neo = FakeNeo()
    engine = SyncEngine(db, neo)
    summary = await engine.run(full=True)

    assert summary["mode"] == "full"
    assert summary["assets"] == 3
    assert summary["edges"] == 4           # 2 undirected -> 4 directed
    assert summary["findings"] == 1
    assert neo.wiped == 1
    assert neo.schema_calls == 1

    # svc has a KEV finding -> cost 2; inbound edges to svc weigh 2.
    by_id = {a["id"]: a for a in neo.assets}
    assert by_id["svc"]["cost"] == 10 - queries.BONUS_KEV
    assert by_id["svc"]["kev"] is True
    assert by_id["db"]["crown"] is True
    assert by_id["endpoint"]["entry"] is True

    into_svc = [e for e in neo.edges if e["dst"] == "svc"]
    assert into_svc and all(e["weight"] == float(10 - queries.BONUS_KEV) for e in into_svc)
    # cursor advanced.
    assert db.cursor is not None


async def test_incremental_sync_no_wipe() -> None:
    db = _graph()
    neo = FakeNeo()
    engine = SyncEngine(db, neo)
    summary = await engine.run(full=False)
    assert summary["mode"] == "incremental"
    assert neo.wiped == 0
    assert neo.schema_calls == 1
    assert len(neo.assets) == 3


async def test_sync_propagates_unavailable() -> None:
    db = _graph()
    neo = FakeNeo(up=False)
    engine = SyncEngine(db, neo)
    import pytest
    from app.neo import Neo4jUnavailable
    with pytest.raises(Neo4jUnavailable):
        await engine.run(full=True)
