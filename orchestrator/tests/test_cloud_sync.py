"""DB-backed: cloud SOURCE sync -> scope suggestions -> accept/dismiss, and the
network-action evidence endpoint the approvals screen uses.

Vendor APIs are the ``cloud_fixtures`` MockTransports; nothing leaves the box.
"""
from __future__ import annotations

import base64
import json
import os

import httpx
import pytest

from app.integrations import runtime
from app.integrations import secrets as secrets_mod
from app.integrations.connectors import load_all
from app.integrations.connectors._gcp_auth import clear_token_cache
from tests import cloud_fixtures as fx
from tests.cloud_fixtures import fake_dns  # noqa: F401 (fixture)

load_all()


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    clear_token_cache()


async def _gcp_integration(pool, **cfg) -> str:
    async with pool.acquire() as con:
        return await con.fetchval(
            "INSERT INTO integrations (kind, name, enabled, config, secrets) "
            "VALUES ('gcp', 'gcp-prod', TRUE, $1::jsonb, $2) RETURNING id",
            json.dumps({"parents": ["projects/acme-prod"], "sync_interval_minutes": 60, **cfg}),
            secrets_mod.encrypt_secrets({"service_account_json": fx.sa_json()}))


def _factory(gcp: fx.Gcp):
    return lambda cfg: httpx.AsyncClient(transport=httpx.MockTransport(gcp))


async def _sync(pool, redis, iid, gcp=None):
    return await runtime.run_source_sync(pool, redis, iid, http_factory=_factory(gcp or fx.Gcp()))


async def test_gcp_sync_lands_assets_findings_and_pending_suggestions(db_pool, fake_redis, fake_dns):
    iid = await _gcp_integration(db_pool)
    res = await _sync(db_pool, fake_redis, iid)
    assert res["status"] == "ok" and not res["detail"], res
    assert res["counts"]["scope_suggestions"] >= 4
    async with db_pool.acquire() as con:
        assert await con.fetchval(
            "SELECT count(*) FROM findings WHERE rule_id = 'gcp.storage.bucket_public'") == 1
        sug = await con.fetch("SELECT kind, value, status, source FROM scope_suggestions "
                              "ORDER BY value")
        # NOTHING was added to scope by the sync
        assert await con.fetchval("SELECT count(*) FROM scope_entries") == 0
    assert {s["status"] for s in sug} == {"pending"} and {s["source"] for s in sug} == {"integration:gcp"}
    assert ("ipv4_cidr", "34.120.10.5/32") in {(s["kind"], s["value"]) for s in sug}

    # idempotent: a second sync upserts, never duplicates
    await _sync(db_pool, fake_redis, iid)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM scope_suggestions") == len(sug)


async def test_partial_failure_is_ok_with_warnings_and_visible_in_status(
        app, client, db_pool, fake_redis, fake_dns):
    from app.integrations.connectors import gcp as gcp_mod

    iid = await _gcp_integration(db_pool)
    res = await _sync(db_pool, fake_redis, iid, fx.Gcp(fail_types={gcp_mod.T_SQL: 403}))
    assert res["status"] == "ok" and res["detail"].startswith("partial:")
    assert res["counts"]["warnings"] == 1 and fx.SA_SECRET_MARK not in res["detail"]
    r = await client.get("/v1/integration-sync")
    st = r.json()[0]
    assert st["last_run"]["status"] == "ok" and st["last_run"]["counts"]["warnings"] == 1
    assert st["interval_minutes"] == 60 and st["next_run_at"] is not None
    assert st["pending_suggestions"] >= 1


async def test_total_failure_is_an_error_run_without_secrets(db_pool, fake_redis, fake_dns):
    iid = await _gcp_integration(db_pool)
    res = await _sync(db_pool, fake_redis, iid, fx.Gcp(token_status=401))
    assert res["status"] == "error" and "401" in res["detail"]
    assert fx.SA_SECRET_MARK not in res["detail"] and "PRIVATE KEY" not in res["detail"]


async def test_accept_goes_through_normal_scope_add_and_keeps_proof_gate(client, db_pool, fake_redis, fake_dns):
    iid = await _gcp_integration(db_pool)
    await _sync(db_pool, fake_redis, iid)
    r = await client.get("/v1/integration-sync/suggestions")
    assert r.status_code == 200
    items = r.json()
    dom = next(s for s in items if s["value"] == "acme-test.com")
    assert dom["integration_name"] == "gcp-prod" and dom["status"] == "pending"

    r = await client.post(f"/v1/integration-sync/suggestions/{dom['id']}/accept",
                          json={"auth_doc_ref": "LOA-77"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["suggestion"]["status"] == "accepted" and out["suggestion"]["scope_entry_id"]
    entry = out["scope_entry"]
    assert entry["kind"] == "domain" and entry["value"] == "acme-test.com"
    assert entry["auth_doc_ref"] == "LOA-77" and entry["metadata"]["suggested_by"] == "integration:gcp"
    assert "proof" in entry                                          # proof-of-control flow still applies
    r = await client.get(f"/v1/scope/{entry['id']}/proof")
    assert r.status_code == 200
    r = await client.post(f"/v1/scope/{entry['id']}/challenge")      # normal challenge endpoint works
    assert r.status_code == 200 and r.json()["dns_txt"]["value"]

    # decided once
    again = await client.post(f"/v1/integration-sync/suggestions/{dom['id']}/accept", json={})
    assert again.status_code == 409
    assert (await client.post(f"/v1/integration-sync/suggestions/{dom['id']}/dismiss", json={})).status_code == 409
    async with db_pool.acquire() as con:
        assert await con.fetchval(
            "SELECT count(*) FROM audit_log WHERE action = 'scope_suggestion_accept'") == 1

    # an accepted value that is already active scope is never re-suggested
    await _sync(db_pool, fake_redis, iid)
    r = await client.get("/v1/integration-sync/suggestions", params={"status": "all"})
    assert [s["status"] for s in r.json() if s["value"] == "acme-test.com"] == ["accepted"]


async def test_dismiss_sticks_across_syncs(client, db_pool, fake_redis, fake_dns):
    iid = await _gcp_integration(db_pool)
    await _sync(db_pool, fake_redis, iid)
    sug = next(s for s in (await client.get("/v1/integration-sync/suggestions")).json()
               if s["value"] == "34.120.10.5/32")
    r = await client.post(f"/v1/integration-sync/suggestions/{sug['id']}/dismiss", json={"reason": "not ours"})
    assert r.status_code == 200 and r.json()["status"] == "dismissed" and r.json()["decided_by"]
    await _sync(db_pool, fake_redis, iid)
    pending = (await client.get("/v1/integration-sync/suggestions")).json()
    assert "34.120.10.5/32" not in {s["value"] for s in pending}
    dismissed = (await client.get("/v1/integration-sync/suggestions", params={"status": "dismissed"})).json()
    assert [s["value"] for s in dismissed] == ["34.120.10.5/32"]
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM scope_entries") == 0     # dismiss never touches scope


async def test_accept_is_refused_when_scope_validation_refuses(client, db_pool):
    iid = await _gcp_integration(db_pool)
    async with db_pool.acquire() as con:
        sid = await con.fetchval(
            "INSERT INTO scope_suggestions (integration_id, source, kind, value) "
            "VALUES ($1, 'integration:gcp', 'ipv4_cidr', '10.0.0.0/8') RETURNING id", iid)
    r = await client.post(f"/v1/integration-sync/suggestions/{sid}/accept", json={})
    assert r.status_code == 422                                      # too broad: same refusal as a manual add
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM scope_suggestions WHERE id = $1", sid) == "pending"
        assert await con.fetchval("SELECT count(*) FROM scope_entries") == 0
    assert (await client.post("/v1/integration-sync/suggestions/999999/accept", json={})).status_code == 404
    assert (await client.get("/v1/integration-sync/suggestions", params={"status": "bogus"})).status_code == 422


async def test_suggestion_writes_need_admin(client, db_pool):
    from app.config import settings
    from app import auth as auth_svc

    iid = await _gcp_integration(db_pool)
    async with db_pool.acquire() as con:
        sid = await con.fetchval(
            "INSERT INTO scope_suggestions (integration_id, source, kind, value) "
            "VALUES ($1, 'integration:gcp', 'domain', 'x.example.com') RETURNING id", iid)
        uid = await con.fetchval("INSERT INTO app_users (username, role, clearance) VALUES ('v', 'viewer', "
                                 "'internal') RETURNING id")
        full, prefix, key_hash = auth_svc.generate_api_key()
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1, 'k', $2, $3, $4)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES["viewer"]))
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        h = {"Authorization": f"Bearer {full}"}
        assert (await client.get("/v1/integration-sync/suggestions", headers=h)).status_code == 200
        assert (await client.post(f"/v1/integration-sync/suggestions/{sid}/accept", json={},
                                  headers=h)).status_code == 403
        assert (await client.post(f"/v1/integration-sync/suggestions/{sid}/dismiss", json={},
                                  headers=h)).status_code == 403
    finally:
        settings.auth_mode = prev


async def test_network_action_evidence_endpoint(client, db_pool):
    mac = "00:1a:2b:3c:4d:5e"
    async with db_pool.acquire() as con:
        iid = await con.fetchval(
            "INSERT INTO integrations (kind, name, enabled, config, secrets, allow_private) "
            "VALUES ('unifi', 'unifi-hq', TRUE, '{}'::jsonb, $1, TRUE) RETURNING id",
            secrets_mod.encrypt_secrets({"api_key": "k"}))
    r = await client.post("/v1/assets/bulk", json={"items": [{
        "kind": "iot_device", "value": "10.5.0.20", "source": "sentry",
        "metadata": {"mac": mac, "vendor": "Hikvision", "type": "camera"}}]})
    assert r.status_code == 200, r.text
    r = await client.post("/v1/findings/bulk", json={"items": [{
        "asset_kind": "iot_device", "asset_value": "10.5.0.20", "rule_id": "device_lateral_scan",
        "rule_source": "policy", "severity": "high", "title": "Camera is scanning",
        "description": "d", "evidence": {"distinct_hosts": 40}}]})
    fid = r.json()["items"][0]["id"]
    r = await client.post("/v1/fleet/network-actions/from-finding",
                          json={"finding_id": fid, "integration_id": str(iid)})
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    r = await client.get(f"/v1/fleet/network-actions/{aid}/evidence")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["finding"]["rule_id"] == "device_lateral_scan"
    assert out["finding"]["evidence"] == {"distinct_hosts": 40}
    assert out["device"]["mac"] == mac and out["device"]["vendor"] == "Hikvision"
    assert (await client.get("/v1/fleet/network-actions/00000000-0000-0000-0000-000000000000/evidence")
            ).status_code == 404
