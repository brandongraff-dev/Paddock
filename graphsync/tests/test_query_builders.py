"""Blast + neighborhood Cypher builders."""
from __future__ import annotations

from app import queries


def test_blast_builder() -> None:
    cypher, params = queries.build_blast_cypher("asset-1", depth=3)
    assert params == {"asset_id": "asset-1"}
    assert "asset-1" not in cypher
    assert "$asset_id" in cypher
    assert "[:EDGE*1..3]" in cypher
    assert "reachable_crown_jewels" in cypher
    assert "neighborhood_size" in cypher
    assert "collect(DISTINCT f.severity) AS severities" in cypher


def test_blast_depth_clamped() -> None:
    cypher, _ = queries.build_blast_cypher("a", depth=999)
    assert f"[:EDGE*1..{queries.MAX_DEPTH_CAP}]" in cypher
    bad, _ = queries.build_blast_cypher("a", depth="evil")
    assert f"[:EDGE*1..{queries.DEFAULT_DEPTH}]" in bad
    assert "evil" not in bad


def test_neighborhood_builder_caps_and_dedupes() -> None:
    cypher, params = queries.build_neighborhood_cypher("asset-9", depth=2)
    assert params == {"asset_id": "asset-9"}
    assert "asset-9" not in cypher
    assert "[:EDGE*1..2]" in cypher
    # capped node slice + deduped undirected edge emission.
    assert f"[0..{queries.NEIGHBORHOOD_CAP}]" in cypher
    assert "x.id < y.id" in cypher
    assert "RETURN node_rows AS nodes" in cypher


def test_neighborhood_cap_is_bounded() -> None:
    cypher, _ = queries.build_neighborhood_cypher("a", depth=1, cap=10_000)
    assert f"[0..{queries.NEIGHBORHOOD_CAP}]" in cypher


def test_builders_deterministic() -> None:
    assert queries.build_blast_cypher("a", 2) == queries.build_blast_cypher("a", 2)
    assert queries.build_neighborhood_cypher("a", 2) == queries.build_neighborhood_cypher("a", 2)
