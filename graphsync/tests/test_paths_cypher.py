"""The /paths Cypher builder: generated Cypher + params for given inputs."""
from __future__ import annotations

from app import queries


def test_paths_source_target_params_are_parameterised() -> None:
    cypher, params = queries.build_paths_cypher(
        source="aaaa-source", target="bbbb-target", max_hops=8, limit=5
    )
    # User values live ONLY in params, never concatenated into the query text.
    assert params == {"limit": 5, "source": "aaaa-source", "target": "bbbb-target"}
    assert "aaaa-source" not in cypher
    assert "bbbb-target" not in cypher
    assert "$source" in cypher and "$target" in cypher and "$limit" in cypher


def test_paths_bound_is_inlined_and_clamped() -> None:
    cypher, _ = queries.build_paths_cypher(source="a", target="b", max_hops=8)
    assert "[:EDGE*1..8]" in cypher
    # Out-of-range bounds are clamped to the cap, never passed through raw.
    big, _ = queries.build_paths_cypher(source="a", target="b", max_hops=9999)
    assert f"[:EDGE*1..{queries.MAX_HOPS_CAP}]" in big
    # Non-numeric falls back to the default.
    bad, _ = queries.build_paths_cypher(source="a", target="b", max_hops="; DROP")
    assert f"[:EDGE*1..{queries.DEFAULT_MAX_HOPS}]" in bad
    assert "DROP" not in bad


def test_paths_plain_uses_allshortestpaths_and_deterministic_order() -> None:
    cypher, _ = queries.build_paths_cypher(source="a", target="b", apoc=False)
    assert "allShortestPaths" in cypher
    assert "reduce(c = 0.0, r IN relationships(p) | c + coalesce(r.weight, 1.0))" in cypher
    assert "ORDER BY total_cost ASC, hop_count ASC, node_ids ASC" in cypher


def test_paths_apoc_uses_dijkstra() -> None:
    cypher, _ = queries.build_paths_cypher(source="a", target="b", apoc=True)
    assert "apoc.algo.dijkstra(s, t, 'EDGE>', 'weight')" in cypher
    assert "ORDER BY total_cost ASC, hop_count ASC, node_ids ASC" in cypher


def test_paths_default_source_anchors_entry_nodes() -> None:
    cypher, params = queries.build_paths_cypher(source=None, target="b")
    assert "s.entry = true" in cypher
    assert "s <> t" in cypher
    assert params == {"limit": 10, "target": "b"}
    assert "source" not in params


def test_paths_default_target_anchors_crown_jewels() -> None:
    cypher, params = queries.build_paths_cypher(source="a", target=None)
    assert "t.crown = true" in cypher
    assert "$target" not in cypher
    assert params == {"limit": 10, "source": "a"}


def test_paths_source_kinds_parameterised() -> None:
    cypher, params = queries.build_paths_cypher(
        source=None, target=None, source_kinds=["endpoint", "ipv4"]
    )
    assert "s.kind IN $source_kinds" in cypher
    assert "s.entry = true" in cypher
    assert "t.crown = true" in cypher
    assert params["source_kinds"] == ["endpoint", "ipv4"]


def test_paths_is_deterministic_for_fixed_inputs() -> None:
    a = queries.build_paths_cypher(source="x", target="y", max_hops=6, limit=3)
    b = queries.build_paths_cypher(source="x", target="y", max_hops=6, limit=3)
    assert a == b
