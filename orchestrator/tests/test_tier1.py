"""Tier 1 endpoints: attack paths + change intelligence + alert rules.

Seeds `attack_paths`, `surface_changes`, `alert_rules`, `alert_deliveries`
directly (the compute services own the writes) and exercises the
orchestrator's read/CRUD/ack surface.
"""
from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _mk_asset(con, kind: str, value: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ($1,$2,$3,'seed') RETURNING id",
            kind,
            value,
            value.lower(),
        )
    )


async def _mk_finding(con, asset_id: str, severity: str, title: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description) VALUES ($1,$2,'manual',$3,$4,'desc') RETURNING id",
            asset_id,
            f"rule-{title}",
            severity,
            title,
        )
    )


async def _mk_path(
    con,
    *,
    source_id: str,
    target_id: str,
    hops: list[dict],
    length: int,
    total_cost: float,
    exploitability: float,
    severity: str,
    title: str,
    narrative: str = "internet -> staging -> secret",
    kev: bool = False,
    fingerprint: str,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO attack_paths (
                source_asset_id, target_asset_id, hops, length, total_cost,
                exploitability, severity, title, narrative, kev_on_path,
                fingerprint
            ) VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8,$9,$10,$11)
            RETURNING id
            """,
            source_id,
            target_id,
            json.dumps(hops),
            length,
            total_cost,
            exploitability,
            severity,
            title,
            narrative,
            kev,
            fingerprint,
        )
    )


async def _mk_change(
    con,
    *,
    change_type: str,
    severity: str = "info",
    summary: str = "something changed",
    asset_id: str | None = None,
    asset_kind: str | None = None,
    asset_value: str | None = None,
    acknowledged: bool = False,
    detected_offset_days: int = 0,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO surface_changes (
                change_type, asset_id, asset_kind, asset_value, severity,
                summary, detected_at, acknowledged
            ) VALUES (
                $1,$2,$3,$4,$5,$6, NOW() - ($7::int * INTERVAL '1 day'), $8
            ) RETURNING id
            """,
            change_type,
            asset_id,
            asset_kind,
            asset_value,
            severity,
            summary,
            detected_offset_days,
            acknowledged,
        )
    )


# --------------------------------------------------------------------------- #
# Attack paths
# --------------------------------------------------------------------------- #

async def test_attack_paths_list_shape_order_and_hop_enrichment(client, db_pool):
    async with db_pool.acquire() as con:
        src = await _mk_asset(con, "endpoint", "https://edge.example.com")
        mid = await _mk_asset(con, "subdomain", "staging.example.com")
        tgt = await _mk_asset(con, "secret_candidate", "leaked-aws-key")
        # Lower exploitability path.
        await _mk_path(
            con,
            source_id=src,
            target_id=tgt,
            hops=[{"asset_id": src, "max_severity": "info", "finding_ids": []}],
            length=1,
            total_cost=9.0,
            exploitability=10.0,
            severity="low",
            title="low path",
            fingerprint="fp-low",
        )
        # Higher exploitability path (should sort first).
        await _mk_path(
            con,
            source_id=src,
            target_id=tgt,
            hops=[
                {"asset_id": src, "max_severity": "info", "finding_ids": [],
                 "entry_cost": 0, "edge_kind_in": None},
                {"asset_id": mid, "max_severity": "high", "finding_ids": [],
                 "entry_cost": 4, "edge_kind_in": "resolves_to"},
                {"asset_id": tgt, "max_severity": "critical", "finding_ids": [],
                 "entry_cost": 1, "edge_kind_in": "exposes"},
            ],
            length=3,
            total_cost=5.0,
            exploitability=83.33,
            severity="critical",
            title="hot path",
            kev=True,
            fingerprint="fp-hot",
        )

    r = await client.get("/v1/attack-paths")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    assert [p["title"] for p in body["items"]] == ["hot path", "low path"]

    hot = body["items"][0]
    assert hot["source"]["value"] == "https://edge.example.com"
    assert hot["source"]["kind"] == "endpoint"
    assert hot["target"]["value"] == "leaked-aws-key"
    assert hot["kev_on_path"] is True
    assert hot["length"] == 3
    # Hops enriched with asset value/kind + max_severity carried through.
    mid_hop = hot["hops"][1]
    assert mid_hop["value"] == "staging.example.com"
    assert mid_hop["kind"] == "subdomain"
    assert mid_hop["max_severity"] == "high"
    assert mid_hop["edge_kind_in"] == "resolves_to"


async def test_attack_paths_severity_filter(client, db_pool):
    async with db_pool.acquire() as con:
        s = await _mk_asset(con, "endpoint", "e1")
        t = await _mk_asset(con, "secret_candidate", "k1")
        await _mk_path(con, source_id=s, target_id=t, hops=[{"asset_id": s}],
                       length=1, total_cost=1, exploitability=50,
                       severity="critical", title="crit", fingerprint="f1")
        await _mk_path(con, source_id=s, target_id=t, hops=[{"asset_id": s}],
                       length=1, total_cost=1, exploitability=40,
                       severity="medium", title="med", fingerprint="f2")

    r = await client.get("/v1/attack-paths", params={"severity": "critical"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"


async def test_attack_paths_kev_filter(client, db_pool):
    async with db_pool.acquire() as con:
        s = await _mk_asset(con, "endpoint", "e2")
        t = await _mk_asset(con, "secret_candidate", "k2")
        await _mk_path(con, source_id=s, target_id=t, hops=[{"asset_id": s}],
                       length=1, total_cost=1, exploitability=50, severity="high",
                       title="kev", kev=True, fingerprint="k-f1")
        await _mk_path(con, source_id=s, target_id=t, hops=[{"asset_id": s}],
                       length=1, total_cost=1, exploitability=40, severity="high",
                       title="nokev", kev=False, fingerprint="k-f2")

    r = await client.get("/v1/attack-paths", params={"kev": "true"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "kev"

    r2 = await client.get("/v1/attack-paths", params={"kev": "false"})
    assert r2.json()["total"] == 1
    assert r2.json()["items"][0]["title"] == "nokev"


async def test_attack_path_detail_enriches_hop_findings(client, db_pool):
    async with db_pool.acquire() as con:
        s = await _mk_asset(con, "endpoint", "e3")
        mid = await _mk_asset(con, "subdomain", "mid.example.com")
        t = await _mk_asset(con, "secret_candidate", "k3")
        f1 = await _mk_finding(con, mid, "high", "exposed-git")
        f2 = await _mk_finding(con, mid, "critical", "leaked-key")
        pid = await _mk_path(
            con,
            source_id=s,
            target_id=t,
            hops=[
                {"asset_id": s, "max_severity": "info", "finding_ids": []},
                {"asset_id": mid, "max_severity": "critical",
                 "finding_ids": [f1, f2]},
                {"asset_id": t, "max_severity": "critical", "finding_ids": []},
            ],
            length=3,
            total_cost=5,
            exploitability=70,
            severity="critical",
            title="detail path",
            fingerprint="detail-f",
        )

    r = await client.get(f"/v1/attack-paths/{pid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "detail path"
    hop = body["hops"][1]
    assert hop["value"] == "mid.example.com"
    assert len(hop["findings"]) == 2
    titles = {f["title"] for f in hop["findings"]}
    assert titles == {"exposed-git", "leaked-key"}
    for f in hop["findings"]:
        assert set(f) == {"id", "title", "severity"}


async def test_attack_path_detail_404(client):
    r = await client.get("/v1/attack-paths/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_attack_paths_recompute_falls_back_to_queue(
    client, fake_redis, monkeypatch
):
    # Point at an address that refuses fast so the sync call fails and we fall
    # back to the Redis job.
    from app import config as config_mod
    from app.routers import attackpaths as ap_mod

    monkeypatch.setattr(ap_mod.settings, "correlation_url", "http://127.0.0.1:9")

    r = await client.post("/v1/attack-paths/recompute")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["queued"] is True
    # A recompute job landed on the correlate queue stream.
    entries = await fake_redis.xrange("queue:correlate")
    assert len(entries) == 1
    job = json.loads(entries[0][1]["job"])
    assert job["op"] == "recompute_paths"


# --------------------------------------------------------------------------- #
# Changes
# --------------------------------------------------------------------------- #

async def test_changes_list_newest_first_and_envelope(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="subdomain_discovered",
                         summary="old", detected_offset_days=3)
        await _mk_change(con, change_type="port_opened",
                         summary="new", detected_offset_days=0)

    r = await client.get("/v1/changes")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    assert body["items"][0]["summary"] == "new"
    assert body["items"][1]["summary"] == "old"


async def test_changes_filter_type(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="secret_found", severity="high")
        await _mk_change(con, change_type="port_opened", severity="medium")

    r = await client.get("/v1/changes", params={"type": "secret_found"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["change_type"] == "secret_found"


async def test_changes_filter_severity(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="secret_found", severity="high")
        await _mk_change(con, change_type="port_opened", severity="medium")

    r = await client.get("/v1/changes", params={"severity": "high"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "high"


async def test_changes_filter_acknowledged(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="port_opened", acknowledged=True)
        await _mk_change(con, change_type="tech_detected", acknowledged=False)

    r = await client.get("/v1/changes", params={"acknowledged": "false"})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["change_type"] == "tech_detected"


async def test_changes_filter_since(client, db_pool):
    from datetime import datetime, timedelta, timezone

    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="ip_discovered",
                         summary="stale", detected_offset_days=10)
        await _mk_change(con, change_type="ip_discovered",
                         summary="recent", detected_offset_days=1)

    since = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    r = await client.get("/v1/changes", params={"since": since})
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["summary"] == "recent"


async def test_change_ack_flips_row_with_user_header(client, db_pool):
    async with db_pool.acquire() as con:
        cid = await _mk_change(con, change_type="port_opened", severity="medium")

    r = await client.post(f"/v1/changes/{cid}/ack", headers={"X-User": "alice"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["acknowledged"] is True
    assert body["ack_by"] == "alice"
    assert body["ack_at"] is not None

    # Default actor when no header.
    async with db_pool.acquire() as con:
        cid2 = await _mk_change(con, change_type="tech_detected")
    r2 = await client.post(f"/v1/changes/{cid2}/ack")
    assert r2.json()["ack_by"] == "operator"


async def test_change_ack_404(client):
    r = await client.post(
        "/v1/changes/00000000-0000-0000-0000-000000000000/ack"
    )
    assert r.status_code == 404


async def test_changes_summary_by_type_and_day(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_change(con, change_type="port_opened", severity="medium",
                         detected_offset_days=0)
        await _mk_change(con, change_type="port_opened", severity="high",
                         detected_offset_days=0)
        await _mk_change(con, change_type="secret_found", severity="critical",
                         detected_offset_days=1)
        # Outside a 7-day window -> excluded.
        await _mk_change(con, change_type="tech_detected", severity="low",
                         detected_offset_days=30)

    r = await client.get("/v1/changes/summary", params={"window_days": 7})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    assert body["by_type"]["port_opened"] == 2
    assert body["by_type"]["secret_found"] == 1
    assert "tech_detected" not in body["by_type"]
    # by_day rows carry a per-severity breakdown.
    assert len(body["by_day"]) == 2
    day_keys = set(body["by_day"][0])
    assert day_keys == {"day", "info", "low", "medium", "high", "critical"}
    totals = {d["day"]: d for d in body["by_day"]}
    some_day = max(totals)  # most recent day has the two port_opened rows
    assert totals[some_day]["medium"] + totals[some_day]["high"] >= 1


# --------------------------------------------------------------------------- #
# Alert rules
# --------------------------------------------------------------------------- #

async def test_alert_rule_crud_lifecycle(client):
    # Create (log channel needs no target).
    r = await client.post(
        "/v1/alert-rules",
        json={
            "name": "all-critical",
            "channel": "log",
            "match": {"min_severity": "critical"},
        },
    )
    assert r.status_code == 201, r.text
    rule = r.json()
    rid = rule["id"]
    assert rule["channel"] == "log"
    assert rule["enabled"] is True
    assert rule["match"] == {"min_severity": "critical"}

    # List.
    r = await client.get("/v1/alert-rules")
    assert r.status_code == 200
    assert any(x["id"] == rid for x in r.json())

    # Patch (disable + rename).
    r = await client.patch(
        f"/v1/alert-rules/{rid}", json={"enabled": False, "name": "renamed"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    assert r.json()["name"] == "renamed"

    # Delete.
    r = await client.delete(f"/v1/alert-rules/{rid}")
    assert r.status_code == 204
    r = await client.delete(f"/v1/alert-rules/{rid}")
    assert r.status_code == 404


async def test_alert_rule_webhook_requires_target(client):
    r = await client.post(
        "/v1/alert-rules",
        json={"name": "wh", "channel": "webhook"},
    )
    assert r.status_code == 422, r.text


async def test_alert_rule_rejects_bad_channel(client):
    r = await client.post(
        "/v1/alert-rules",
        json={"name": "bad", "channel": "email", "target": "https://x.example"},
    )
    assert r.status_code == 422


async def test_alert_rule_rejects_non_http_target(client):
    r = await client.post(
        "/v1/alert-rules",
        json={"name": "ftp", "channel": "webhook", "target": "ftp://x.example/u"},
    )
    assert r.status_code == 422


async def test_alert_rule_webhook_with_target_ok(client):
    r = await client.post(
        "/v1/alert-rules",
        json={
            "name": "wh-ok",
            "channel": "webhook",
            "target": "https://hooks.example.com/abc",
            "match": {"change_types": ["secret_found"]},
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["target"] == "https://hooks.example.com/abc"


async def test_alert_rule_patch_to_webhook_without_target_rejected(client):
    r = await client.post(
        "/v1/alert-rules", json={"name": "log-rule", "channel": "log"}
    )
    rid = r.json()["id"]
    # Switching an existing log rule to webhook with no target must fail.
    r = await client.patch(f"/v1/alert-rules/{rid}", json={"channel": "webhook"})
    assert r.status_code == 422


async def test_alert_rule_deliveries_list(client, db_pool):
    async with db_pool.acquire() as con:
        rid = await con.fetchval(
            "INSERT INTO alert_rules (name, channel, target) "
            "VALUES ('d','webhook','https://h.example/x') RETURNING id"
        )
        cid = await _mk_change(con, change_type="secret_found", severity="high")
        for stat, resp in (("sent", "200 OK"), ("failed", "timeout")):
            await con.execute(
                "INSERT INTO alert_deliveries (rule_id, change_id, status, "
                "channel, response) VALUES ($1,$2,$3,'webhook',$4)",
                rid,
                cid,
                stat,
                resp,
            )

    r = await client.get(f"/v1/alert-rules/{rid}/deliveries")
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 2
    assert {row["status"] for row in rows} == {"sent", "failed"}
    assert set(rows[0]) == {
        "id", "rule_id", "change_id", "status", "channel", "response",
        "delivered_at",
    }
