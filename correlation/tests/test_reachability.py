"""Reachability / crown-jewel exposure tests.

`compute_exposure` is pure, so most coverage is DB-free. DB-backed tests skip
cleanly without TEST_DATABASE_URL.
"""
from __future__ import annotations

import pytest

from app.engine.attackpath import MAX_HOPS, AttackPathEngine
from app.engine.reachability import ReachabilityEngine, compute_exposure

from .conftest import mk_asset, mk_edge, mk_finding
from .test_attackpath import _finding, _graph

EP = {"kind": "endpoint", "value": "https://app/"}
SVC = {"kind": "service", "value": "svc"}
JEWEL = {"kind": "secret_candidate", "value": "key"}


def _exposure(graph):
    paths = AttackPathEngine(db=None).compute_paths(graph)
    return compute_exposure(graph, paths), paths


def _by_id(rows):
    return {r["asset_id"]: r for r in rows}


def test_two_sources_reach_jewel():
    nodes = {"s1": EP, "s2": EP, "m": SVC, "t": JEWEL}
    edges = [("s1", "m", "resolves_to"), ("s2", "m", "resolves_to"), ("m", "t", "references")]
    rows, _ = _exposure(_graph(nodes, edges))
    assert len(rows) == 1
    r = rows[0]
    assert r["asset_id"] == "t"
    assert r["target_reason"] == "secret_candidate"
    assert r["reachable_source_count"] == 2
    assert r["open_path_count"] == 2
    assert r["min_hops"] == 2
    assert r["proven_closed"] is False


def test_isolated_jewel_is_proven_closed():
    nodes = {"s": EP, "m": SVC, "t": JEWEL, "iso": JEWEL}
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    r = _by_id(_exposure(_graph(nodes, edges))[0])["iso"]
    assert r["reachable_source_count"] == 0
    assert r["open_path_count"] == 0
    assert r["min_hops"] is None
    assert r["max_exploitability"] == 0
    assert r["kev_on_any_path"] is False
    assert r["proven_closed"] is True


def test_no_sources_means_all_jewels_closed():
    rows, _ = _exposure(_graph({"m": SVC, "t": JEWEL}, [("m", "t", "references")]))
    assert [r["proven_closed"] for r in rows] == [True]


def test_min_hops_picks_shortest_source():
    nodes = {
        "far": EP, "a": SVC, "b": SVC, "near": EP, "t": JEWEL,
    }
    edges = [
        ("far", "a", "x"), ("a", "b", "x"), ("b", "t", "x"),  # 3 hops
        ("near", "t", "x"),  # 1 hop
    ]
    r = _exposure(_graph(nodes, edges))[0][0]
    assert r["min_hops"] == 1
    assert r["reachable_source_count"] == 2


def test_hop_cap_makes_far_jewel_closed():
    nodes = {"s": EP}
    edges = []
    prev = "s"
    for i in range(10):
        nodes[f"n{i}"] = SVC
        edges.append((prev, f"n{i}", "runs"))
        prev = f"n{i}"
    nodes["t"] = JEWEL
    edges.append((prev, "t", "references"))
    r = _exposure(_graph(nodes, edges))[0][0]
    assert 11 > MAX_HOPS
    assert r["reachable_source_count"] == 0
    assert r["proven_closed"] is True


def test_kev_and_exploitability_propagate():
    nodes = {"s": EP, "t": JEWEL}
    findings = {"t": [_finding("f", "critical", rule_source="cve_match", kev=True)]}
    r = _exposure(_graph(nodes, [("s", "t", "references")], findings))[0][0]
    assert r["kev_on_any_path"] is True
    assert r["max_exploitability"] == 80.0
    assert r["open_path_count"] == 1


def test_jewel_that_is_also_source_excludes_itself():
    sens = {"kind": "endpoint", "value": "https://p/", "metadata": {"sensitive": True}}
    rows, _ = _exposure(_graph({"p": sens}, []))
    assert rows[0]["reachable_source_count"] == 0
    assert rows[0]["proven_closed"] is True


def test_deterministic_and_ordered():
    nodes = {"s": EP, "m": SVC, "t2": JEWEL, "t1": JEWEL, "t3": JEWEL}
    edges = [("s", "m", "x"), ("m", "t1", "x"), ("m", "t2", "x")]
    a, _ = _exposure(_graph(nodes, edges))
    b, _ = _exposure(_graph(nodes, edges))
    assert a == b
    assert [r["asset_id"] for r in a] == ["t1", "t2", "t3"]


# ----------------------------------------------------------------------------
# DB-backed
# ----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_db_run_writes_rows_and_prunes_stale(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app-rc/")
    mid = await mk_asset(clean_db, "service", "svc-rc")
    t1 = await mk_asset(clean_db, "secret_candidate", "key-rc1")
    t2 = await mk_asset(clean_db, "secret_candidate", "key-rc2")  # isolated
    await mk_edge(clean_db, src, mid, "resolves_to")
    await mk_edge(clean_db, mid, t1, "references")
    await mk_finding(
        clean_db, asset_id=mid, rule_id="cve-rc", rule_source="cve_match",
        severity="critical", metadata={"kev": True},
    )

    eng = ReachabilityEngine(clean_db)
    res = await eng.run()
    assert res["crown_jewels"] == 2
    assert res["exposed"] == 1
    assert await eng.count() == 2

    rows = {
        r["asset_id"]: r
        for r in await clean_db.fetch(
            "SELECT asset_id::text AS asset_id, reachable_source_count, "
            "open_path_count, min_hops, kev_on_any_path, proven_closed, "
            "max_exploitability FROM crown_jewel_exposure"
        )
    }
    assert rows[t1]["reachable_source_count"] == 1
    assert rows[t1]["open_path_count"] == 1
    assert rows[t1]["min_hops"] == 2
    assert rows[t1]["kev_on_any_path"] is True
    assert rows[t1]["proven_closed"] is False
    assert float(rows[t1]["max_exploitability"]) == 40.0
    assert rows[t2]["proven_closed"] is True
    assert rows[t2]["min_hops"] is None

    # Idempotent upsert: no duplicates.
    await eng.run()
    assert await eng.count() == 2

    # t2 stops being a crown jewel -> its row is pruned; closing t1 flips it.
    await clean_db.execute("DELETE FROM assets WHERE id = $1::uuid", t2)
    await clean_db.execute("DELETE FROM asset_edges WHERE dst_id = $1::uuid", t1)
    res = await eng.run()
    assert res["crown_jewels"] == 1 and res["exposed"] == 0
    left = await clean_db.fetch(
        "SELECT asset_id::text AS asset_id, proven_closed FROM crown_jewel_exposure"
    )
    assert [(r["asset_id"], r["proven_closed"]) for r in left] == [(t1, True)]


@pytest.mark.asyncio
async def test_db_no_jewels_clears_table(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app-rc2/")
    tgt = await mk_asset(clean_db, "secret_candidate", "key-rc3")
    await mk_edge(clean_db, src, tgt, "references")
    eng = ReachabilityEngine(clean_db)
    await eng.run()
    assert await eng.count() == 1
    await clean_db.execute("DELETE FROM assets WHERE id = $1::uuid", tgt)
    res = await eng.run()
    assert res == {"crown_jewels": 0, "exposed": 0, "elapsed_ms": res["elapsed_ms"]}
    assert await eng.count() == 0
