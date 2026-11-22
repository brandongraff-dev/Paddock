"""Choke-point engine tests.

The core computation (`compute_choke_points`) is pure: it takes an in-memory
graph dict plus the current attack paths, so Dinic correctness, the min-cut
node-set recovery, determinism and greedy ranking are all covered without a
database. A DB-backed test exercises bulk loading, upsert and stale pruning
against seeded data; it skips cleanly when no TEST_DATABASE_URL /
DATABASE_URL is reachable.
"""
from __future__ import annotations

import pytest

from app.engine.attackpath import AttackPathEngine
from app.engine.chokepoint import (
    ChokePointEngine,
    action_hint,
    choke_fingerprint,
    compute_choke_points,
)

from .conftest import mk_asset, mk_edge, mk_finding


# ----------------------------------------------------------------------------
# In-memory graph builder (no DB) — same style as test_attackpath._graph
# ----------------------------------------------------------------------------

def _graph(
    nodes: dict[str, dict],
    edges: list[tuple[str, str, str]],
    findings: dict[str, list[dict]] | None = None,
    public_nets: tuple = (),
) -> dict:
    assets = {
        nid: {
            "id": nid,
            "kind": spec["kind"],
            "value": spec.get("value", nid),
            "metadata": spec.get("metadata", {}),
        }
        for nid, spec in nodes.items()
    }
    adj: dict[str, set[str]] = {nid: set() for nid in assets}
    edge_kind: dict[tuple[str, str], str] = {}
    for s, d, k in edges:
        adj[s].add(d)
        adj[d].add(s)
        key = (s, d) if s < d else (d, s)
        cur = edge_kind.get(key)
        if cur is None or k < cur:
            edge_kind[key] = k
    return {
        "assets": assets,
        "adj": {k: sorted(v) for k, v in adj.items()},
        "edge_kind": edge_kind,
        "findings_by_asset": findings or {},
        "public_nets": public_nets,
    }


def _finding(fid, severity="high", rule_source="nuclei", kev=False):
    md = {"kev": True} if kev else {}
    return {"id": fid, "severity": severity, "rule_source": rule_source, "metadata": md}


def _cut_set(result: list[dict]) -> set[str]:
    return {c["asset_id"] for c in result}


# ----------------------------------------------------------------------------
# Pure: Dinic min-cut correctness on hand-built graphs with a known answer
# ----------------------------------------------------------------------------

def test_single_bottleneck_cut_is_one_node():
    # s -> m -> t : the only route runs through m, so the min cut is {m}.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "svc"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    res = compute_choke_points(_graph(nodes, edges), [])
    assert _cut_set(res) == {"m"}
    assert len(res) == 1  # min-cut VALUE == 1


def test_diamond_cut_is_the_single_articulation_node():
    # s -> x -> {a, b} -> t : x is the one node that disconnects everything.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "x": {"kind": "service", "value": "gw"},
        "a": {"kind": "service", "value": "a"},
        "b": {"kind": "service", "value": "b"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [
        ("s", "x", "resolves_to"),
        ("x", "a", "runs"),
        ("x", "b", "runs"),
        ("a", "t", "references"),
        ("b", "t", "references"),
    ]
    res = compute_choke_points(_graph(nodes, edges), [])
    assert _cut_set(res) == {"x"}
    assert len(res) == 1


def test_two_disjoint_paths_need_two_cuts():
    # s -> a -> t and s -> b -> t are node-disjoint, so the min cut is {a, b}.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "a": {"kind": "service", "value": "a"},
        "b": {"kind": "service", "value": "b"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [
        ("s", "a", "resolves_to"),
        ("a", "t", "references"),
        ("s", "b", "resolves_to"),
        ("b", "t", "references"),
    ]
    res = compute_choke_points(_graph(nodes, edges), [])
    assert _cut_set(res) == {"a", "b"}
    assert len(res) == 2  # min-cut VALUE == 2


def test_direct_source_to_target_has_no_finite_cut():
    # Nothing to remove between the door and the jewel -> no choke points.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [("s", "t", "references")]
    assert compute_choke_points(_graph(nodes, edges), []) == []


def test_no_sources_or_targets_returns_empty():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "svc"},
    }
    edges = [("s", "m", "resolves_to")]
    # Has a source but no crown-jewel target.
    assert compute_choke_points(_graph(nodes, edges), []) == []


def test_source_and_target_are_never_cut():
    # Even though removing s or t would "disconnect", they are uncuttable;
    # the finite cut lives on the intermediate node m.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "svc"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    res = compute_choke_points(_graph(nodes, edges), [])
    ids = _cut_set(res)
    assert "s" not in ids and "t" not in ids


# ----------------------------------------------------------------------------
# Pure: greedy ranking
# ----------------------------------------------------------------------------

def test_greedy_ranks_highest_coverage_first():
    # m1 lies on two paths (to t1, t2); m2 lies on one (to t3). Both are in
    # the min cut (node-disjoint through m1 vs m2). Greedy must rank m1 first.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m1": {"kind": "service", "value": "m1"},
        "m2": {"kind": "service", "value": "m2"},
        "t1": {"kind": "secret_candidate", "value": "k1"},
        "t2": {"kind": "secret_candidate", "value": "k2"},
        "t3": {"kind": "secret_candidate", "value": "k3"},
    }
    edges = [
        ("s", "m1", "resolves_to"),
        ("m1", "t1", "references"),
        ("m1", "t2", "references"),
        ("s", "m2", "resolves_to"),
        ("m2", "t3", "references"),
    ]
    graph = _graph(nodes, edges)
    # Use the real engine to produce the attack paths we rank against.
    paths = AttackPathEngine(None).compute_paths(graph)
    assert len(paths) == 3

    res = compute_choke_points(graph, paths)
    assert _cut_set(res) == {"m1", "m2"}

    by_id = {c["asset_id"]: c for c in res}
    assert by_id["m1"]["cut_rank"] == 1
    assert by_id["m1"]["paths_cut"] == 2
    assert by_id["m2"]["cut_rank"] == 2
    assert by_id["m2"]["paths_cut"] == 1
    assert by_id["m1"]["total_paths"] == 3
    # Cumulative reduction: m1 closes 2/3, then m2 closes the last -> 100%.
    assert by_id["m1"]["reduction_pct"] == pytest.approx(66.67, abs=0.01)
    assert by_id["m2"]["reduction_pct"] == pytest.approx(100.0, abs=0.01)
    # The returned list is ordered by cut_rank.
    assert [c["asset_id"] for c in res] == ["m1", "m2"]


def test_ranking_tie_breaks_by_asset_id():
    # Two symmetric disjoint single-path cuts -> equal marginal coverage,
    # so ordering falls back to asset id (a before b).
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "a": {"kind": "service", "value": "a"},
        "b": {"kind": "service", "value": "b"},
        "t1": {"kind": "secret_candidate", "value": "k1"},
        "t2": {"kind": "secret_candidate", "value": "k2"},
    }
    edges = [
        ("s", "a", "resolves_to"),
        ("a", "t1", "references"),
        ("s", "b", "resolves_to"),
        ("b", "t2", "references"),
    ]
    graph = _graph(nodes, edges)
    paths = AttackPathEngine(None).compute_paths(graph)
    res = compute_choke_points(graph, paths)
    assert [c["asset_id"] for c in res] == ["a", "b"]
    assert res[0]["cut_rank"] == 1 and res[1]["cut_rank"] == 2


# ----------------------------------------------------------------------------
# Pure: determinism
# ----------------------------------------------------------------------------

def test_compute_is_deterministic():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "x": {"kind": "service", "value": "gw"},
        "a": {"kind": "service", "value": "a"},
        "b": {"kind": "service", "value": "b"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [
        ("s", "x", "resolves_to"),
        ("x", "a", "runs"),
        ("x", "b", "runs"),
        ("a", "t", "references"),
        ("b", "t", "references"),
    ]
    g1 = _graph(nodes, edges)
    g2 = _graph(nodes, edges)
    p1 = AttackPathEngine(None).compute_paths(g1)
    p2 = AttackPathEngine(None).compute_paths(g2)
    r1 = compute_choke_points(g1, p1)
    r2 = compute_choke_points(g2, p2)
    assert r1 == r2


# ----------------------------------------------------------------------------
# Pure: action hints, narrative safety, fingerprint
# ----------------------------------------------------------------------------

def test_action_hint_patch_for_kev_or_critical():
    asset = {"kind": "service", "value": "svc", "metadata": {}}
    assert action_hint(asset, [_finding("f", "high", kev=True)], 1) == "patch"
    assert action_hint(asset, [_finding("f", "critical")], 1) == "patch"


def test_action_hint_segment_for_network_node_on_multiple_paths():
    asset = {"kind": "ipv4", "value": "10.0.0.1", "metadata": {}}
    assert action_hint(asset, [], 3) == "segment"
    # On a single path, a bare network node is not an automatic segment.
    assert action_hint(asset, [], 1) == "review"


def test_action_hint_decommission_for_ownerless_low_value():
    asset = {
        "kind": "service",
        "value": "legacy",
        "metadata": {"business_value": "low"},
    }
    assert action_hint(asset, [], 1) == "decommission"


def test_action_hint_restrict_for_access_point():
    asset = {"kind": "port", "value": "443", "metadata": {"owner": "team"}}
    assert action_hint(asset, [], 1) == "restrict"


def test_narrative_is_sanitized_and_fingerprint_stable():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "token for /bin/sh dump"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    res = compute_choke_points(_graph(nodes, edges), [])
    c = res[0]
    assert "/bin/" not in c["narrative"].lower()
    assert "crown jewels" in c["narrative"].lower()
    assert c["fingerprint"] == choke_fingerprint("m")
    # Fingerprint is a stable per-asset hash.
    assert choke_fingerprint("m") == choke_fingerprint("m")
    assert choke_fingerprint("m") != choke_fingerprint("n")


# ----------------------------------------------------------------------------
# DB-backed (skipped without a reachable Postgres)
# ----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_db_run_persists_and_prunes(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app-cp.example.com/")
    m1 = await mk_asset(clean_db, "service", "cp-m1")
    m2 = await mk_asset(clean_db, "service", "cp-m2")
    t1 = await mk_asset(clean_db, "secret_candidate", "cp-k1")
    t2 = await mk_asset(clean_db, "secret_candidate", "cp-k2")
    t3 = await mk_asset(clean_db, "secret_candidate", "cp-k3")
    await mk_edge(clean_db, src, m1, "resolves_to")
    await mk_edge(clean_db, m1, t1, "references")
    await mk_edge(clean_db, m1, t2, "references")
    await mk_edge(clean_db, src, m2, "resolves_to")
    await mk_edge(clean_db, m2, t3, "references")
    await mk_finding(
        clean_db, asset_id=m1, rule_id="cve-cp", rule_source="cve_match",
        severity="critical", metadata={"kev": True},
    )

    eng = ChokePointEngine(clean_db)
    res = await eng.run()
    assert res["choke_points"] == 2
    assert res["inserted"] == 2
    assert await eng.count() == 2

    rows = await clean_db.fetch(
        "SELECT asset_id::text AS a, paths_cut, cut_rank, in_min_cut, "
        "action_hint, total_paths FROM choke_points ORDER BY cut_rank"
    )
    by_id = {r["a"]: r for r in rows}
    assert set(by_id) == {m1, m2}
    assert by_id[m1]["cut_rank"] == 1 and by_id[m1]["paths_cut"] == 2
    assert by_id[m2]["cut_rank"] == 2 and by_id[m2]["paths_cut"] == 1
    assert by_id[m1]["total_paths"] == 3
    assert by_id[m1]["in_min_cut"] is True
    # m1 carries a KEV/critical finding -> patch.
    assert by_id[m1]["action_hint"] == "patch"

    # Idempotent upsert: a second run inserts nothing new.
    res2 = await eng.run()
    assert res2["inserted"] == 0
    assert await eng.count() == 2

    # Remove m2's subtree so only the m1 cut remains; stale row is pruned.
    await clean_db.execute(
        "DELETE FROM asset_edges WHERE src_id = $1::uuid OR dst_id = $1::uuid",
        m2,
    )
    res3 = await eng.run()
    assert res3["choke_points"] == 1
    remaining = await clean_db.fetch("SELECT asset_id::text AS a FROM choke_points")
    assert {r["a"] for r in remaining} == {m1}


@pytest.mark.asyncio
async def test_db_empty_graph_clears_table(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app-cp2/")
    mid = await mk_asset(clean_db, "service", "cp2-m")
    tgt = await mk_asset(clean_db, "secret_candidate", "cp2-k")
    await mk_edge(clean_db, src, mid, "resolves_to")
    await mk_edge(clean_db, mid, tgt, "references")
    eng = ChokePointEngine(clean_db)
    await eng.run()
    assert await eng.count() == 1

    await clean_db.execute("DELETE FROM asset_edges")
    res = await eng.run()
    assert res["choke_points"] == 0
    assert await eng.count() == 0
