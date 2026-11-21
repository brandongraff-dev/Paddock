"""Scan intake: refusal of offensive kinds, scope-deny => 403, happy path
=> 201 + enqueued on the correct Redis stream.
"""
from __future__ import annotations

import json

import pytest


async def _add_scope(client, kind, value):
    r = await client.post(
        "/v1/scope", json={"kind": kind, "value": value, "added_by": "t"}
    )
    assert r.status_code == 201, r.text


async def test_scan_out_of_scope_returns_403(client):
    r = await client.post(
        "/v1/scans", json={"kind": "passive_subdomains", "target": "evil.example.com"}
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["allow"] is False


async def test_scan_in_scope_enqueues_and_writes_row(client, db_pool, fake_redis):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    r = await client.post(
        "/v1/scans",
        json={
            "kind": "passive_subdomains",
            "target": "https://api.example.com/path",
            "config": {"depth": 2},
        },
    )
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "queued"
    assert scan["target"] == "api.example.com"

    # Row exists in `scans`
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM scans WHERE id = $1::uuid", scan["id"])
    assert row is not None
    assert row["kind"] == "passive_subdomains"

    # Stream has the job
    entries = await fake_redis.xrange("queue:passive")
    assert len(entries) == 1
    _sid, fields = entries[0]
    job = json.loads(fields["job"])
    assert job["scan_id"] == scan["id"]
    assert job["target"] == "api.example.com"


async def test_scan_kind_refused_without_scope_check(client, db_pool):
    # Offensive kind: refused *before* scope-check is called.
    r = await client.post(
        "/v1/scans", json={"kind": "exploit_launch", "target": "example.com"}
    )
    assert r.status_code == 400
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM scope_decisions")
    assert n == 0


async def test_scan_get_and_list(client):
    await _add_scope(client, "domain", "example.com")
    r = await client.post(
        "/v1/scans", json={"kind": "active_http_probe", "target": "example.com"}
    )
    scan_id = r.json()["id"]
    r2 = await client.get(f"/v1/scans/{scan_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == scan_id

    r3 = await client.get("/v1/scans", params={"target": "example.com"})
    assert r3.status_code == 200
    assert any(s["id"] == scan_id for s in r3.json())


async def test_active_kind_lands_on_active_queue(client, fake_redis):
    await _add_scope(client, "domain", "example.com")
    r = await client.post(
        "/v1/scans", json={"kind": "nuclei_scan", "target": "example.com"}
    )
    assert r.status_code == 201
    assert len(await fake_redis.xrange("queue:active")) == 1
    assert len(await fake_redis.xrange("queue:passive")) == 0
