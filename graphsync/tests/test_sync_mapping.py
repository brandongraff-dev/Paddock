"""Postgres row -> Neo4j MERGE params mapping (pure; no live Neo4j)."""
from __future__ import annotations

from app import queries, sync


def test_asset_node_props_basic() -> None:
    row = {
        "id": "a1",
        "kind": "endpoint",
        "value": "https://app.example.com/login",
        "metadata": {"env": "prod", "blast_score": 42.5},
    }
    props = sync.asset_node_props(row, severities=["high"], kev=False)
    assert props["id"] == "a1"
    assert props["kind"] == "endpoint"
    assert props["value"] == "https://app.example.com/login"
    assert props["blast_score"] == 42.5
    assert props["env"] == "prod"
    assert props["entry"] is True          # endpoint is internet-facing
    assert props["crown"] is False
    assert props["max_severity"] == "high"
    assert props["kev"] is False
    # cost mirrors attackpath: 10 - BONUS_HIGH.
    assert props["cost"] == 10 - queries.BONUS_HIGH


def test_asset_node_props_crown_jewel_datastore() -> None:
    row = {
        "id": "db1",
        "kind": "technology",
        "value": "PostgreSQL 14.2",
        "metadata": {},
    }
    props = sync.asset_node_props(row, severities=[], kev=False)
    assert props["crown"] is True
    assert props["entry"] is False
    assert props["blast_score"] is None
    assert props["cost"] == 10


def test_asset_node_props_kev_cost() -> None:
    row = {"id": "x", "kind": "service", "value": "nginx", "metadata": {"sensitive": True}}
    props = sync.asset_node_props(row, severities=["critical"], kev=True)
    assert props["crown"] is True              # sensitive metadata
    assert props["kev"] is True
    assert props["cost"] == 10 - queries.BONUS_KEV


def test_finding_node_props_kev_detection() -> None:
    row = {"id": "f1", "asset_id": "a1", "severity": "critical",
           "rule_source": "cve_match", "metadata": {"kev": True}}
    props = sync.finding_node_props(row)
    assert props == {"id": "f1", "asset_id": "a1", "severity": "critical", "kev": True}

    row2 = {"id": "f2", "asset_id": "a1", "severity": "low",
            "rule_source": "nuclei", "metadata": {"known_exploited": True}}
    assert sync.finding_node_props(row2)["kev"] is True

    row3 = {"id": "f3", "asset_id": "a1", "severity": "low",
            "rule_source": "nuclei", "metadata": {}}
    assert sync.finding_node_props(row3)["kev"] is False


def test_group_finding_severities() -> None:
    findings = [
        {"id": "f1", "asset_id": "a", "severity": "high", "metadata": {}},
        {"id": "f2", "asset_id": "a", "severity": "low", "metadata": {"kev": True}},
        {"id": "f3", "asset_id": "b", "severity": "medium", "metadata": {}},
    ]
    grouped = sync.group_finding_severities(findings)
    assert grouped["a"]["kev"] is True
    assert set(grouped["a"]["severities"]) == {"high", "low"}
    assert grouped["b"] == {"severities": ["medium"], "kev": False}


def test_edge_rows_bidirectional_weighted() -> None:
    cost_map = {"a": 2, "b": 10}
    rows = sync.edge_rows([{"src": "a", "dst": "b", "kind": "hosts"}], cost_map)
    assert len(rows) == 2
    forward = next(r for r in rows if r["src"] == "a")
    backward = next(r for r in rows if r["src"] == "b")
    # weight = entry cost of the node you ARRIVE at.
    assert forward == {"src": "a", "dst": "b", "kind": "hosts", "weight": 10.0}
    assert backward == {"src": "b", "dst": "a", "kind": "hosts", "weight": 2.0}


def test_edge_rows_skips_self_loops() -> None:
    assert sync.edge_rows([{"src": "a", "dst": "a", "kind": "x"}], {"a": 5}) == []


def test_edge_rows_defaults_weight_for_unknown_endpoint() -> None:
    rows = sync.edge_rows([{"src": "a", "dst": "z", "kind": "runs"}], {"a": 3})
    forward = next(r for r in rows if r["src"] == "a")
    assert forward["weight"] == float(queries.BASE_ENTRY_COST)
