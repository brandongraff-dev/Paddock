"""Asset endpoints: bulk upsert dedupe + event publish, BFS graph,
and the findings bulk upsert (co-located because it shares test fixtures).
"""
from __future__ import annotations

import json

import pytest


async def test_asset_bulk_upsert_dedupes_by_canonical(client, db_pool, fake_redis):
    payload = {
        "items": [
            {"kind": "domain", "value": "Example.COM", "source": "ct"},
            # Same canonical, different case/value -- should dedupe:
            {"kind": "domain", "value": "example.com.", "source": "wayback",
             "metadata": {"seen_by": "wayback"}},
        ]
    }
    r = await client.post("/v1/assets/bulk", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 1
    assert body["updated"] == 1

    # DB has exactly one row with the merged metadata.
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT canonical, metadata FROM assets WHERE kind='domain'"
        )
    assert len(rows) == 1
    md = rows[0]["metadata"]
    if isinstance(md, str):
        md = json.loads(md)
    assert md.get("seen_by") == "wayback"

    # One `asset_added` event on stream:events, no second one for the update.
    entries = await fake_redis.xrange("stream:events")
    assert len(entries) == 1
    _sid, fields = entries[0]
    event = json.loads(fields["event"])
    assert event["event"] == "asset_added"


async def test_asset_graph_bfs(client, db_pool):
    # Build a tiny graph: root -resolves_to-> ip, ip -hosts-> port
    async with db_pool.acquire() as con:
        root = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('subdomain','api.example.com','api.example.com','seed') "
            "RETURNING id"
        )
        ip = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('ipv4','10.0.0.5','10.0.0.5','seed') RETURNING id"
        )
        port = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('port','10.0.0.5:443','10.0.0.5:443','seed') RETURNING id"
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'resolves_to')",
            root,
            ip,
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'hosts')",
            ip,
            port,
        )

    r = await client.get(f"/v1/assets/{root}/graph", params={"depth": 2})
    assert r.status_code == 200
    body = r.json()
    ids = {n["id"] for n in body["nodes"]}
    assert str(root) in ids and str(ip) in ids and str(port) in ids
    assert len(body["edges"]) == 2
    assert body["truncated"] is False


async def test_asset_graph_depth_1_limits_reach(client, db_pool):
    async with db_pool.acquire() as con:
        root = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('subdomain','a.example.com','a.example.com','seed') "
            "RETURNING id"
        )
        ip = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('ipv4','10.0.0.9','10.0.0.9','seed') RETURNING id"
        )
        far = await con.fetchval(
            "INSERT INTO assets (kind,value,canonical,source) "
            "VALUES ('port','10.0.0.9:80','10.0.0.9:80','seed') RETURNING id"
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'resolves_to')",
            root,
            ip,
        )
        await con.execute(
            "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES ($1,$2,'hosts')",
            ip,
            far,
        )

    r = await client.get(f"/v1/assets/{root}/graph", params={"depth": 1})
    body = r.json()
    ids = {n["id"] for n in body["nodes"]}
    assert str(far) not in ids


async def test_findings_bulk_insert_then_update(client, db_pool, fake_redis):
    # Need an asset first.
    r = await client.post(
        "/v1/assets/bulk",
        json={"items": [{"kind": "domain", "value": "example.com", "source": "seed"}]},
    )
    asset_id = r.json()["items"][0]["id"]

    body1 = {
        "items": [
            {
                "asset_id": asset_id,
                "rule_id": "exposed-git",
                "rule_source": "exposed_file",
                "severity": "high",
                "title": "Exposed .git",
                "description": "A .git directory is reachable.",
                "evidence": {"path": "/.git/HEAD"},
            }
        ]
    }
    r1 = await client.post("/v1/findings/bulk", json=body1)
    assert r1.status_code == 200
    assert r1.json()["inserted"] == 1 and r1.json()["updated"] == 0

    # Second call: same (asset_id, rule_id, rule_source) => update, no new event.
    body2 = {
        "items": [
            {
                **body1["items"][0],
                "evidence": {"path": "/.git/HEAD", "size": 41},
                "severity": "critical",
            }
        ]
    }
    r2 = await client.post("/v1/findings/bulk", json=body2)
    assert r2.json()["inserted"] == 0 and r2.json()["updated"] == 1
    item = r2.json()["items"][0]
    assert item["severity"] == "critical"

    # Only one `finding_opened` event total.
    events = await fake_redis.xrange("stream:events")
    opened = [e for _sid, e in events if "finding_opened" in e.get("event", "")]
    assert len(opened) == 1


async def test_patch_finding_sets_status(client, db_pool):
    # seed
    r = await client.post(
        "/v1/assets/bulk",
        json={"items": [{"kind": "domain", "value": "patch.example.com", "source": "s"}]},
    )
    aid = r.json()["items"][0]["id"]
    r = await client.post(
        "/v1/findings/bulk",
        json={
            "items": [
                {
                    "asset_id": aid,
                    "rule_id": "r1",
                    "rule_source": "manual",
                    "severity": "low",
                    "title": "x",
                    "description": "x",
                }
            ]
        },
    )
    fid = r.json()["items"][0]["id"]

    r = await client.patch(
        f"/v1/findings/{fid}",
        json={"status": "fixed", "notes": "patched upstream"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "fixed"
    md = r.json()["metadata"]
    assert md.get("notes") == "patched upstream"


async def test_healthz_and_readyz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    r2 = await client.get("/readyz")
    assert r2.status_code == 200
    data = r2.json()
    assert data["checks"]["db"] == "ok"
    assert data["checks"]["redis"] == "ok"
