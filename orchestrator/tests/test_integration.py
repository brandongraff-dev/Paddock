"""Integration tests for the orchestrator additions six sibling services
needed to come online. Covers:

- scan lifecycle (PATCH + start/complete/fail aliases, parent-scan
  inheritance, idempotent re-posts, scan_started/completed/failed events)
- POST /v1/chains (upsert-by-anchor and upsert-by-fingerprint, 400 on
  unknown finding_ids, chain_detected event)
- GET  /v1/chains enrichment (anchor asset summary + finding severities)
- POST /v1/outbound/bulk
- /v1/assets/bulk sentinel-edge routing (mixed assets+edges in one call,
  edge_added event)
- /v1/edges/bulk dedicated endpoint
- /v1/assets/graph whole-surface view (degree + open_high_crit_count)
- /v1/scope/{id}/decisions
- /v1/findings paged response + rule_source/kev/q filters, legacy list path
- /v1/findings/{id} detail with asset + chains join
- /v1/findings/bulk asset_value upsert path
- /v1/scope metadata persistence + matched_entry_metadata on check
- scope_added / scope_removed events
"""
from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

async def _add_scope(client, kind="subdomain_wildcard", value="example.com", **extra):
    payload = {"kind": kind, "value": value, "added_by": "t", **extra}
    r = await client.post("/v1/scope", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


async def _seed_scan(client):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    r = await client.post(
        "/v1/scans",
        json={"kind": "passive_subdomains", "target": "api.example.com"},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _seed_asset(client, kind="domain", value="example.com"):
    r = await client.post(
        "/v1/assets/bulk",
        json={"items": [{"kind": kind, "value": value, "source": "seed"}]},
    )
    assert r.status_code == 200, r.text
    return r.json()["items"][0]


async def _seed_finding(client, asset_id, rule_id="r1", severity="high",
                        rule_source="manual", title="t", description="d"):
    r = await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_id": asset_id,
                    "rule_id": rule_id,
                    "rule_source": rule_source,
                    "severity": severity,
                    "title": title,
                    "description": description,
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["items"][0]


# --------------------------------------------------------------------------- #
# Scan lifecycle
# --------------------------------------------------------------------------- #

async def test_scan_patch_running_sets_started_at_and_emits_event(
    client, db_pool, fake_redis
):
    scan = await _seed_scan(client)
    r = await client.patch(
        f"/v1/scans/{scan['id']}",
        json={"status": "running", "worker_id": "worker-1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "running"
    assert body["started_at"] is not None
    assert body["finished_at"] is None
    assert body["worker_id"] == "worker-1"

    events = await fake_redis.xrange("stream:events")
    kinds = [json.loads(f["event"])["event"] for _sid, f in events]
    assert "scan_started" in kinds


async def test_scan_start_alias_and_idempotent(client, fake_redis):
    scan = await _seed_scan(client)
    r1 = await client.post(
        f"/v1/scans/{scan['id']}/start", json={"worker_id": "w-1"}
    )
    assert r1.status_code == 200
    started_at = r1.json()["started_at"]
    # Re-post: same status, started_at must not move.
    r2 = await client.post(
        f"/v1/scans/{scan['id']}/start", json={"worker_id": "w-1"}
    )
    assert r2.status_code == 200
    assert r2.json()["started_at"] == started_at
    # Only ONE scan_started event — the second PATCH is a no-op transition.
    events = await fake_redis.xrange("stream:events")
    starts = [
        e for _sid, e in events
        if json.loads(e["event"]).get("event") == "scan_started"
    ]
    assert len(starts) == 1


async def test_scan_complete_and_fail_aliases(client, fake_redis):
    scan = await _seed_scan(client)
    await client.post(f"/v1/scans/{scan['id']}/start", json={"worker_id": "w"})
    r = await client.post(
        f"/v1/scans/{scan['id']}/complete",
        json={"result_summary": {"assets_added": 3}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["finished_at"] is not None
    assert body["result_summary"]["assets_added"] == 3

    scan2 = await _seed_scan(client)
    rf = await client.post(
        f"/v1/scans/{scan2['id']}/fail", json={"error": "boom"}
    )
    assert rf.status_code == 200
    assert rf.json()["status"] == "failed"
    assert rf.json()["error"] == "boom"

    events = await fake_redis.xrange("stream:events")
    kinds = [json.loads(f["event"])["event"] for _sid, f in events]
    assert "scan_completed" in kinds and "scan_failed" in kinds


async def test_scan_patch_404(client):
    r = await client.patch(
        "/v1/scans/00000000-0000-0000-0000-000000000000",
        json={"status": "running"},
    )
    assert r.status_code == 404


async def test_child_scan_inherits_parent_scope_no_new_decision_row(
    client, db_pool
):
    parent = await _seed_scan(client)
    # Count decisions before: exactly 1 (parent creation).
    async with db_pool.acquire() as con:
        before = await con.fetchval("SELECT COUNT(*) FROM scope_decisions")
    r = await client.post(
        "/v1/scans",
        json={
            "kind": "nuclei_scan",
            "target": "sub.api.example.com",
            "parent_scan_id": parent["id"],
        },
    )
    assert r.status_code == 201, r.text
    child = r.json()
    assert child["parent_scan_id"] == parent["id"]
    async with db_pool.acquire() as con:
        after = await con.fetchval("SELECT COUNT(*) FROM scope_decisions")
    # No new decision row -- the parent's scope is inherited.
    assert after == before


async def test_child_scan_unknown_parent_still_scope_checks(client):
    # No scope added at all; with an unknown parent id we must still
    # perform scope-check and deny.
    r = await client.post(
        "/v1/scans",
        json={
            "kind": "nuclei_scan",
            "target": "evil.example.com",
            "parent_scan_id": "00000000-0000-0000-0000-000000000000",
        },
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Chains POST
# --------------------------------------------------------------------------- #

async def test_chain_post_insert_and_upsert_by_anchor(client, fake_redis):
    asset = await _seed_asset(client)
    f1 = await _seed_finding(client, asset["id"], rule_id="a1", severity="high")
    f2 = await _seed_finding(client, asset["id"], rule_id="a2", severity="critical")
    r1 = await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "exposed_git_plus_outdated",
            "severity": "critical",
            "title": "Exposed + outdated",
            "description": "Anchor chain",
            "finding_ids": [f1["id"], f2["id"]],
            "anchor_asset_id": asset["id"],
        },
    )
    assert r1.status_code == 201, r1.text
    chain_id = r1.json()["id"]

    # Second post — same (chain_rule_id, anchor_asset_id) — should UPDATE
    # the existing row, not insert a new one.
    r2 = await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "exposed_git_plus_outdated",
            "severity": "high",
            "title": "Updated title",
            "description": "Anchor chain",
            "finding_ids": [f1["id"], f2["id"]],
            "anchor_asset_id": asset["id"],
        },
    )
    assert r2.status_code == 201
    assert r2.json()["id"] == chain_id
    assert r2.json()["severity"] == "high"
    assert r2.json()["title"] == "Updated title"

    events = await fake_redis.xrange("stream:events")
    detected = [
        e for _sid, e in events
        if json.loads(e["event"]).get("event") == "chain_detected"
    ]
    # Only the insert emits; upsert does not.
    assert len(detected) == 1


async def test_chain_post_upsert_by_fingerprint_when_no_anchor(client):
    asset = await _seed_asset(client, kind="domain", value="x.example.com")
    f1 = await _seed_finding(client, asset["id"], rule_id="x1")
    f2 = await _seed_finding(client, asset["id"], rule_id="x2")
    fp = "deadbeef-fingerprint"
    r1 = await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "no_anchor_rule",
            "severity": "medium",
            "title": "FP chain",
            "description": "no anchor",
            "finding_ids": [f1["id"], f2["id"]],
            "metadata": {"fingerprint": fp},
        },
    )
    assert r1.status_code == 201, r1.text
    r2 = await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "no_anchor_rule",
            "severity": "high",
            "title": "FP chain updated",
            "description": "no anchor",
            "finding_ids": [f1["id"], f2["id"]],
            "metadata": {"fingerprint": fp},
        },
    )
    assert r2.status_code == 201
    assert r2.json()["id"] == r1.json()["id"]
    assert r2.json()["severity"] == "high"


async def test_chain_post_400_on_unknown_finding(client):
    asset = await _seed_asset(client, kind="domain", value="y.example.com")
    r = await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "r",
            "severity": "low",
            "title": "x",
            "description": "x",
            "finding_ids": ["00000000-0000-0000-0000-000000000000"],
            "anchor_asset_id": asset["id"],
        },
    )
    assert r.status_code == 400


async def test_chains_list_enriches_anchor_and_severities(client):
    asset = await _seed_asset(client, kind="domain", value="z.example.com")
    f1 = await _seed_finding(client, asset["id"], rule_id="z1", severity="high")
    f2 = await _seed_finding(client, asset["id"], rule_id="z2", severity="low")
    await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "r2",
            "severity": "high",
            "title": "t",
            "description": "d",
            "finding_ids": [f1["id"], f2["id"]],
            "anchor_asset_id": asset["id"],
        },
    )
    r = await client.get("/v1/chains")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["anchor_asset"]["id"] == asset["id"]
    assert sorted(rows[0]["finding_severities"]) == sorted(["high", "low"])


# --------------------------------------------------------------------------- #
# Outbound audit bulk
# --------------------------------------------------------------------------- #

async def test_outbound_bulk_inserts(client, db_pool):
    body = {
        "entries": [
            {
                "worker": "active-1",
                "target": "https://example.com/.git/HEAD",
                "tool": "http_probe",
                "method": "GET",
                "response_code": 200,
                "scope_matched": True,
                "started_at": 1731000000.1,
                "duration_ms": 55,
                "bytes_in": 1000,
                "bytes_out": 0,
            },
            {
                "worker": "active-2",
                "target": "https://example.com/",
                "tool": "tlsx",
                "method": "tls_handshake",
                "scope_matched": True,
                "started_at": 1731000001.2,
                "duration_ms": 42,
            },
        ]
    }
    r = await client.post("/v1/outbound/bulk", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == 2
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM outbound_log")
    assert n == 2


# --------------------------------------------------------------------------- #
# Edge routing (sentinel + dedicated)
# --------------------------------------------------------------------------- #

async def test_assets_bulk_routes_edge_sentinel_end_to_end(
    client, db_pool, fake_redis
):
    """The passive worker ships a mixed payload: real assets + _edge items.
    Expect edges in asset_edges, edge_added events, counters in response."""
    payload = {
        "items": [
            {"kind": "domain", "value": "example.com", "source": "seed"},
            {"kind": "subdomain", "value": "api.example.com", "source": "seed"},
            {
                "kind": "_edge",
                "value": "subdomain:api.example.com->domain:example.com:contains",
                "source": "ct_logs",
                "metadata": {
                    "src_kind": "subdomain",
                    "src_canonical": "api.example.com",
                    "dst_kind": "domain",
                    "dst_canonical": "example.com",
                    "edge_kind": "contains",
                },
            },
            {
                "kind": "_edge",
                "value": "orphan edge",
                "source": "ct_logs",
                "metadata": {
                    "src_kind": "subdomain",
                    "src_canonical": "missing.example.com",
                    "dst_kind": "domain",
                    "dst_canonical": "example.com",
                    "edge_kind": "contains",
                },
            },
        ]
    }
    r = await client.post("/v1/assets/bulk", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 2  # two real assets
    assert body["edges_inserted"] == 1
    assert body["edges_skipped_missing_endpoint"] == 1

    async with db_pool.acquire() as con:
        n_edges = await con.fetchval("SELECT COUNT(*) FROM asset_edges")
    assert n_edges == 1

    events = await fake_redis.xrange("stream:events")
    kinds = [json.loads(f["event"])["event"] for _sid, f in events]
    assert "edge_added" in kinds


async def test_edges_bulk_resolves_by_kind_canonical(client, db_pool):
    # Seed endpoints first.
    await client.post(
        "/v1/assets/bulk",
        json={
            "items": [
                {"kind": "subdomain", "value": "a.example.com", "source": "s"},
                {"kind": "domain", "value": "example.com", "source": "s"},
            ]
        },
    )
    r = await client.post(
        "/v1/edges/bulk",
        json={
            "edges": [
                {
                    "src_kind": "subdomain",
                    "src_canonical": "a.example.com",
                    "dst_kind": "domain",
                    "dst_canonical": "example.com",
                    "kind": "contains",
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["edges_inserted"] == 1
    assert body["edges_skipped_missing_endpoint"] == 0

    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM asset_edges")
    assert n == 1


# --------------------------------------------------------------------------- #
# Whole-surface graph
# --------------------------------------------------------------------------- #

async def test_assets_graph_surface(client, db_pool):
    # Build a small graph: domain <-contains- subdomain -resolves_to-> ipv4
    async with db_pool.acquire() as con:
        d = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('domain','example.com','example.com','s') RETURNING id"
        )
        s = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('subdomain','api.example.com','api.example.com','s') RETURNING id"
        )
        ip = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('ipv4','10.1.1.1','10.1.1.1','s') RETURNING id"
        )
        lonely = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('domain','lonely.example.com','lonely.example.com','s') RETURNING id"
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'contains')",
            d, s,
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'resolves_to')",
            s, ip,
        )
        # Open high finding on `s` so we see the glow-ring count.
        await con.execute(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description, status) VALUES "
            "($1,'r1','manual','high','t','d','open')",
            s,
        )
    r = await client.get("/v1/assets/graph", params={"limit": 3})
    assert r.status_code == 200, r.text
    body = r.json()
    ids = {n["id"] for n in body["nodes"]}
    # The top-N by degree should include s, d and ip (lonely has degree 0).
    assert str(s) in ids and str(d) in ids and str(ip) in ids
    assert str(lonely) not in ids
    # s has degree 2; verify open_high_crit_count on it.
    s_node = next(n for n in body["nodes"] if n["id"] == str(s))
    assert s_node["degree"] == 2
    assert s_node["open_high_crit_count"] == 1
    # edges returned are those connecting the included nodes.
    assert len(body["edges"]) == 2


async def test_assets_graph_limit_cap_is_enforced(client):
    # limit over 2000 is rejected by FastAPI validation (422).
    r = await client.get("/v1/assets/graph", params={"limit": 3000})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Scope decisions lookup, metadata, matched_entry_metadata
# --------------------------------------------------------------------------- #

async def test_scope_metadata_round_trips_and_matched_entry_metadata(client):
    entry = await _add_scope(
        client,
        "domain",
        "example.com",
        metadata={"politeness": {"concurrency": 1, "delay_ms": 500}},
    )
    assert entry["metadata"]["politeness"]["concurrency"] == 1

    # GET /v1/scope reflects it
    r_list = await client.get("/v1/scope")
    found = [e for e in r_list.json() if e["id"] == entry["id"]][0]
    assert found["metadata"]["politeness"]["delay_ms"] == 500

    # POST /v1/scope/check surfaces it in matched_entry_metadata
    rc = await client.post(
        "/v1/scope/check", json={"target": "example.com"}
    )
    body = rc.json()
    assert body["allow"] is True
    assert body["matched_entry_metadata"]["politeness"]["concurrency"] == 1


async def test_scope_decisions_lookup_newest_first(client):
    entry = await _add_scope(client, "domain", "example.com")
    # Generate a few decisions by hitting /scope/check.
    for _ in range(3):
        await client.post("/v1/scope/check", json={"target": "example.com"})
    r = await client.get(
        f"/v1/scope/{entry['id']}/decisions", params={"limit": 5}
    )
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 3
    # Sorted newest-first
    times = [row["decided_at"] for row in rows]
    assert times == sorted(times, reverse=True)
    assert all(row["decision"] == "allow" for row in rows)


async def test_scope_add_and_remove_emit_events(client, fake_redis):
    entry = await _add_scope(client, "domain", "example.com")
    r = await client.delete(f"/v1/scope/{entry['id']}")
    assert r.status_code == 200
    events = await fake_redis.xrange("stream:events")
    kinds = [json.loads(f["event"])["event"] for _sid, f in events]
    assert "scope_added" in kinds
    assert "scope_removed" in kinds


# --------------------------------------------------------------------------- #
# Findings extensions
# --------------------------------------------------------------------------- #

async def test_findings_paged_filters_and_q(client):
    a = await _seed_asset(client, kind="domain", value="ex1.example.com")
    b = await _seed_asset(client, kind="domain", value="ex2.example.com")
    await _seed_finding(
        client, a["id"], rule_id="h1", severity="high", rule_source="nuclei",
        title="SQL injection", description="d",
    )
    await _seed_finding(
        client, b["id"], rule_id="h2", severity="low", rule_source="header_check",
        title="Missing header", description="d",
    )
    # Default page
    r = await client.get("/v1/findings")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 2
    assert body["limit"] == 50
    assert body["offset"] == 0

    # rule_source filter
    r = await client.get("/v1/findings", params={"rule_source": "nuclei"})
    assert all(it["rule_source"] == "nuclei" for it in r.json()["items"])

    # q substring filter
    r = await client.get("/v1/findings", params={"q": "sql"})
    titles = [it["title"] for it in r.json()["items"]]
    assert "SQL injection" in titles
    assert "Missing header" not in titles


async def test_findings_legacy_list_path_returns_bare_list(client):
    a = await _seed_asset(client, kind="domain", value="legacy.example.com")
    await _seed_finding(client, a["id"], rule_id="L1")
    r = await client.get("/v1/findings/list")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert any(it["rule_id"] == "L1" for it in body)


async def test_findings_detail_joins_asset_and_chain(client):
    a = await _seed_asset(client, kind="domain", value="det.example.com")
    f = await _seed_finding(
        client, a["id"], rule_id="d1", severity="critical",
    )
    await client.post(
        "/v1/chains",
        json={
            "chain_rule_id": "det-rule",
            "severity": "critical",
            "title": "title",
            "description": "desc",
            "finding_ids": [f["id"]],
            "anchor_asset_id": a["id"],
        },
    )
    r = await client.get(f"/v1/findings/{f['id']}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["finding"]["id"] == f["id"]
    assert body["asset"]["id"] == a["id"]
    assert len(body["chains"]) == 1
    assert body["chains"][0]["chain_rule_id"] == "det-rule"


async def test_findings_bulk_accepts_asset_value_and_upserts_asset(
    client, db_pool
):
    # No asset pre-seeded; the finding should bring one into existence by
    # (kind, canonical(asset_value)) with kind defaulting to endpoint.
    r = await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_value": "https://login.example.com/auth",
                    "rule_id": "hdr-missing",
                    "rule_source": "header_check",
                    "severity": "medium",
                    "title": "No HSTS",
                    "description": "No HSTS header on login.",
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == 1
    async with db_pool.acquire() as con:
        n = await con.fetchval(
            "SELECT COUNT(*) FROM assets WHERE kind='endpoint'"
        )
    assert n == 1


async def test_findings_bulk_rejects_item_with_neither_asset_id_nor_value(client):
    r = await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "rule_id": "x",
                    "rule_source": "manual",
                    "severity": "low",
                    "title": "x",
                    "description": "x",
                }
            ]
        },
    )
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Surfaced fields: asset_value / asset_kind / blast_score on findings,
# blast_score on assets + graph nodes.
# --------------------------------------------------------------------------- #

async def test_findings_surface_asset_and_blast_score(client):
    """Findings carry the joined asset value/kind and their own blast_score
    across the paged envelope, the legacy bare list, and the detail endpoint."""
    asset = await _seed_asset(client, kind="domain", value="blast.example.com")
    r = await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_id": asset["id"],
                    "rule_id": "bs1",
                    "rule_source": "manual",
                    "severity": "high",
                    "title": "Blasted",
                    "description": "d",
                    "metadata": {"blast_score": 7.5},
                }
            ]
        },
    )
    assert r.status_code == 200, r.text

    # Paged envelope.
    rp = await client.get("/v1/findings", params={"asset_id": asset["id"]})
    assert rp.status_code == 200, rp.text
    item = next(it for it in rp.json()["items"] if it["rule_id"] == "bs1")
    assert item["asset_value"] == "blast.example.com"
    assert item["asset_kind"] == "domain"
    assert item["blast_score"] == 7.5

    # Legacy bare list.
    rl = await client.get("/v1/findings/list", params={"asset_id": asset["id"]})
    assert rl.status_code == 200, rl.text
    item_l = next(it for it in rl.json() if it["rule_id"] == "bs1")
    assert item_l["asset_value"] == "blast.example.com"
    assert item_l["asset_kind"] == "domain"
    assert item_l["blast_score"] == 7.5

    # Detail.
    rd = await client.get(f"/v1/findings/{item['id']}")
    assert rd.status_code == 200, rd.text
    f = rd.json()["finding"]
    assert f["asset_value"] == "blast.example.com"
    assert f["asset_kind"] == "domain"
    assert f["blast_score"] == 7.5


async def test_findings_blast_score_null_when_absent(client):
    """A finding without a numeric blast_score in metadata surfaces null, but
    still carries its joined asset value/kind."""
    asset = await _seed_asset(client, kind="domain", value="noblast.example.com")
    await _seed_finding(client, asset["id"], rule_id="nb1")
    r = await client.get("/v1/findings", params={"asset_id": asset["id"]})
    item = next(it for it in r.json()["items"] if it["rule_id"] == "nb1")
    assert item["blast_score"] is None
    assert item["asset_value"] == "noblast.example.com"
    assert item["asset_kind"] == "domain"


async def test_assets_blast_score_from_own_metadata(client):
    """GET /v1/assets and GET /v1/assets/{id} surface the asset's own
    metadata.blast_score."""
    r = await client.post(
        "/v1/assets/bulk",
        json={
            "items": [
                {
                    "kind": "domain",
                    "value": "own.example.com",
                    "source": "seed",
                    "metadata": {"blast_score": 9.1},
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    aid = r.json()["items"][0]["id"]

    rl = await client.get("/v1/assets", params={"canonical": "own.example.com"})
    assert rl.status_code == 200, rl.text
    row = next(a for a in rl.json() if a["id"] == aid)
    assert row["blast_score"] == 9.1

    # get-one returns a depth-1 subgraph; the root node carries blast_score.
    rg = await client.get(f"/v1/assets/{aid}")
    assert rg.status_code == 200, rg.text
    root = next(n for n in rg.json()["nodes"] if n["id"] == aid)
    assert root["blast_score"] == 9.1


async def test_assets_blast_score_fallback_from_open_findings(client):
    """When the asset has no own blast_score, GET /v1/assets falls back to the
    MAX blast_score among its OPEN findings; null when there is none."""
    asset = await _seed_asset(client, kind="domain", value="fallback.example.com")
    await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_id": asset["id"],
                    "rule_id": "fb1",
                    "rule_source": "manual",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "metadata": {"blast_score": 3.0},
                },
                {
                    "asset_id": asset["id"],
                    "rule_id": "fb2",
                    "rule_source": "manual",
                    "severity": "critical",
                    "title": "t",
                    "description": "d",
                    "metadata": {"blast_score": 8.0},
                },
            ]
        },
    )
    rl = await client.get("/v1/assets", params={"canonical": "fallback.example.com"})
    assert rl.status_code == 200, rl.text
    row = next(a for a in rl.json() if a["id"] == asset["id"])
    assert row["blast_score"] == 8.0  # MAX of the two open findings

    # An asset with neither own blast_score nor scored findings -> null.
    bare = await _seed_asset(client, kind="domain", value="bare.example.com")
    rl2 = await client.get("/v1/assets", params={"canonical": "bare.example.com"})
    row2 = next(a for a in rl2.json() if a["id"] == bare["id"])
    assert row2["blast_score"] is None


async def test_assets_graph_nodes_include_blast_score(client, db_pool):
    """Graph nodes carry blast_score (own-metadata case and fallback case)
    alongside the existing degree / open_high_crit_count."""
    async with db_pool.acquire() as con:
        d = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source,metadata) VALUES "
            "('domain','g.example.com','g.example.com','s',"
            "'{\"blast_score\": 5.5}'::jsonb) RETURNING id"
        )
        s = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('subdomain','api.g.example.com','api.g.example.com','s') RETURNING id"
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'contains')",
            d, s,
        )
        # Open finding with a blast_score on `s` -> populates s via fallback.
        await con.execute(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description, status, metadata) VALUES "
            "($1,'r1','manual','high','t','d','open','{\"blast_score\": 4.25}'::jsonb)",
            s,
        )
    r = await client.get("/v1/assets/graph", params={"limit": 10})
    assert r.status_code == 200, r.text
    nodes = {n["id"]: n for n in r.json()["nodes"]}
    assert "blast_score" in nodes[str(d)]
    assert nodes[str(d)]["blast_score"] == 5.5   # own metadata
    assert nodes[str(s)]["blast_score"] == 4.25  # fallback from open finding


async def test_findings_kev_filter_from_metadata(client, db_pool):
    a = await _seed_asset(client, kind="domain", value="kev.example.com")
    # non-KEV
    await _seed_finding(client, a["id"], rule_id="k1", severity="high")
    # KEV via metadata
    await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_id": a["id"],
                    "rule_id": "k2",
                    "rule_source": "cve_match",
                    "severity": "critical",
                    "title": "t",
                    "description": "d",
                    "metadata": {"kev": True},
                }
            ]
        },
    )
    r = await client.get("/v1/findings", params={"kev": "true"})
    assert r.status_code == 200, r.text
    ids = {it["rule_id"] for it in r.json()["items"]}
    assert "k2" in ids
    assert "k1" not in ids
