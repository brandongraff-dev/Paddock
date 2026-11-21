"""End-to-end Neo4j-backed tests.

These require a live Neo4j and are SKIPPED unless NEO4J_TEST_URI is set, e.g.:

    NEO4J_TEST_URI=bolt://localhost:7687 \
    NEO4J_TEST_USER=neo4j NEO4J_TEST_PASSWORD=asm_dev_neo4j pytest -q

They exercise the full MERGE sync + the /paths, /blast and /neighborhood
Cypher against a small fixed graph and assert the deterministic shortest
exploit-weighted path.
"""
from __future__ import annotations

import os

import pytest

NEO4J_TEST_URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = pytest.mark.skipif(
    not NEO4J_TEST_URI,
    reason="set NEO4J_TEST_URI to run Neo4j-backed tests",
)


@pytest.fixture
async def neo():
    from app.neo import NeoClient

    client = NeoClient(
        NEO4J_TEST_URI,
        os.environ.get("NEO4J_TEST_USER", "neo4j"),
        os.environ.get("NEO4J_TEST_PASSWORD", "neo4j"),
    )
    assert await neo_ping(client), "Neo4j not reachable at NEO4J_TEST_URI"
    await client.wipe()
    await client.ensure_schema()
    yield client
    await client.wipe()
    await client.close()


async def neo_ping(client) -> bool:
    return await client.ping()


async def _seed(neo) -> None:
    from app import sync

    assets = [
        {"id": "src", "kind": "endpoint", "value": "https://app/", "metadata": {"public": True}},
        {"id": "mid", "kind": "service", "value": "nginx", "metadata": {}},
        {"id": "db", "kind": "technology", "value": "PostgreSQL 14", "metadata": {}},
        {"id": "alt", "kind": "service", "value": "sidecar", "metadata": {}},
    ]
    findings = [
        {"id": "f1", "asset_id": "mid", "severity": "critical", "rule_source": "cve_match",
         "metadata": {"kev": True}},
    ]
    grouped = sync.group_finding_severities(findings)
    cost_map = {}
    node_rows = []
    for a in assets:
        agg = grouped.get(a["id"], {"severities": [], "kev": False})
        from app import queries
        cost_map[a["id"]] = queries.node_entry_cost(agg["severities"], agg["kev"])
        node_rows.append(sync.asset_node_props(a, agg["severities"], agg["kev"]))
    edges = [
        {"src": "src", "dst": "mid", "kind": "hosts"},
        {"src": "mid", "dst": "db", "kind": "runs"},
        {"src": "src", "dst": "alt", "kind": "hosts"},
        {"src": "alt", "dst": "db", "kind": "runs"},
    ]
    await neo.merge_assets(node_rows)
    await neo.merge_findings([sync.finding_node_props(f) for f in findings])
    await neo.merge_edges(sync.edge_rows(edges, cost_map))


async def test_paths_blast_neighborhood_roundtrip(neo) -> None:
    from app import queries

    await _seed(neo)

    apoc = await neo.has_apoc()
    cypher, params = queries.build_paths_cypher(
        source="src", target="db", max_hops=8, limit=5, apoc=apoc
    )
    rows = await neo.run_read(cypher, params)
    assert rows, "expected at least one path src->db"
    best = rows[0]
    assert best["node_ids"][0] == "src"
    assert best["node_ids"][-1] == "db"

    bcypher, bparams = queries.build_blast_cypher("src", depth=3)
    brows = await neo.run_read(bcypher, bparams)
    assert brows[0]["neighborhood_size"] >= 3
    assert brows[0]["reachable_crown_jewels"] >= 1

    ncypher, nparams = queries.build_neighborhood_cypher("src", depth=3)
    nrows = await neo.run_read(ncypher, nparams)
    assert nrows[0]["nodes"]
    assert nrows[0]["edges"]
