"""Graph BFS tests. Require a live Postgres (skipped otherwise)."""
from __future__ import annotations

import pytest

from app.engine.graph import Graph

from .conftest import mk_asset, mk_edge


pytestmark = pytest.mark.asyncio


async def test_neighbors_depth_one(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.0.0.1")
    svc = await mk_asset(clean_db, "service", "nginx")
    tech = await mk_asset(clean_db, "technology", "openssl-1.1")
    await mk_edge(clean_db, host, svc, "hosts")
    await mk_edge(clean_db, svc, tech, "runs")

    g = Graph(clean_db)
    hop1 = await g.neighbors(host, depth=1)
    hop2 = await g.neighbors(host, depth=2)
    assert {n["id"] for n in hop1} == {svc}
    assert {n["id"] for n in hop2} == {svc, tech}


async def test_neighbors_kind_filter(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.0.0.2")
    svc = await mk_asset(clean_db, "service", "nginx2")
    ep = await mk_asset(clean_db, "endpoint", "https://x/")
    await mk_edge(clean_db, host, svc, "hosts")
    await mk_edge(clean_db, host, ep, "resolves_to")

    g = Graph(clean_db)
    only_hosts = await g.neighbors(host, depth=1, kinds=("hosts",))
    assert {n["id"] for n in only_hosts} == {svc}


async def test_subgraph_returns_nodes_and_edges(clean_db):
    a = await mk_asset(clean_db, "ipv4", "10.0.0.3")
    b = await mk_asset(clean_db, "service", "a")
    c = await mk_asset(clean_db, "technology", "t")
    await mk_edge(clean_db, a, b, "hosts")
    await mk_edge(clean_db, b, c, "runs")

    g = Graph(clean_db)
    sg = await g.subgraph(a, depth=2)
    assert {n["id"] for n in sg["nodes"]} == {a, b, c}
    assert len(sg["edges"]) == 2


async def test_path_found(clean_db):
    a = await mk_asset(clean_db, "ipv4", "10.0.0.4")
    b = await mk_asset(clean_db, "service", "svc-path")
    c = await mk_asset(clean_db, "technology", "tech-path")
    await mk_edge(clean_db, a, b, "hosts")
    await mk_edge(clean_db, b, c, "runs")

    g = Graph(clean_db)
    p = await g.path(a, c)
    assert p is not None
    assert [e["kind"] for e in p] == ["hosts", "runs"]


async def test_path_not_found(clean_db):
    a = await mk_asset(clean_db, "ipv4", "10.0.0.5")
    b = await mk_asset(clean_db, "ipv4", "10.0.0.6")
    g = Graph(clean_db)
    assert await g.path(a, b) is None


async def test_public_exposure_detected_via_endpoint(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.0.0.7")
    ep = await mk_asset(clean_db, "endpoint", "https://pub/")
    await mk_edge(clean_db, ep, host, "resolves_to", metadata={"public": True})

    g = Graph(clean_db)
    assert await g.public_exposure(host) is True
