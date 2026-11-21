"""Degrade behaviour: service stays up and query routes return
{available: false} when Neo4j is unreachable."""
from __future__ import annotations

import json

from aiohttp.test_utils import make_mocked_request

from app import config as config_module
from app.main import GraphSyncService
from app.neo import Neo4jUnavailable
from app.sync import SyncEngine

from .conftest import FakeDB, FakeNeo


def _svc(neo: FakeNeo) -> GraphSyncService:
    svc = GraphSyncService(config_module.load())
    svc.db = FakeDB()           # type: ignore[assignment]
    svc.neo = neo               # type: ignore[assignment]
    svc.sync = SyncEngine(svc.db, svc.neo)  # rebind to the fakes
    svc._ready = True
    return svc


def _body(resp) -> dict:
    return json.loads(resp.text)


async def test_healthz_always_ok_when_neo_down() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_healthz(make_mocked_request("GET", "/healthz"))
    assert resp.status == 200
    assert _body(resp) == {"status": "ok"}


async def test_readyz_reports_neo4j_down_but_stays_ready() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_readyz(make_mocked_request("GET", "/readyz"))
    assert resp.status == 200          # pg up -> ready, service still serves
    body = _body(resp)
    assert body["ready"] is True
    assert body["pg"] == "up"
    assert body["neo4j"] == "down"
    assert body["neo4j_reason"]


async def test_paths_degrades_when_neo_down() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_paths(make_mocked_request("GET", "/paths?source=a&target=b"))
    assert resp.status == 200
    body = _body(resp)
    assert body["available"] is False
    assert body["reason"]


async def test_blast_degrades_when_neo_down() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_blast(
        make_mocked_request("GET", "/blast/a1", match_info={"asset_id": "a1"})
    )
    assert resp.status == 200
    assert _body(resp)["available"] is False


async def test_neighborhood_degrades_when_neo_down() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_neighborhood(
        make_mocked_request("GET", "/neighborhood/a1", match_info={"asset_id": "a1"})
    )
    assert resp.status == 200
    assert _body(resp)["available"] is False


async def test_paths_degrades_if_read_fails_after_ping() -> None:
    """Ping passes but the read trips mid-query -> still a clean degrade."""
    class Flaky(FakeNeo):
        async def run_read(self, cypher, params):
            raise Neo4jUnavailable("session reset")

    svc = _svc(Flaky(up=True, apoc=False))
    resp = await svc._handle_paths(make_mocked_request("GET", "/paths?source=a&target=b"))
    assert resp.status == 200
    body = _body(resp)
    assert body["available"] is False
    assert "session reset" in body["reason"]


async def test_resync_degrades_without_5xx() -> None:
    svc = _svc(FakeNeo(up=False))
    resp = await svc._handle_resync(make_mocked_request("POST", "/resync"))
    assert resp.status == 200
    assert _body(resp)["available"] is False
