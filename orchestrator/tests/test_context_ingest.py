"""DB-backed tests: SOURCE ingest + scheduled sync, and the network quarantine
flow through the existing fleet approve gate. Vendor APIs are MockTransports.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from app.integrations import SourceBatch, netsafety
from app.integrations import secrets as secrets_mod
from app.integrations.connectors import load_all
from app.integrations.connectors._common import asset, edge, finding, merge_hint
from app.integrations.ingest import apply_source_batch
from app.integrations import runtime

load_all()

SECRET = "s3cr3t-DO-NOT-LEAK"
MAC = "00:1a:2b:3c:4d:5e"


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())


@pytest.fixture
def fake_dns(monkeypatch):
    def getaddrinfo(host, port, *a, **k):
        return [(2, 1, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(netsafety, "socket", types.SimpleNamespace(getaddrinfo=getaddrinfo))


async def _integration(pool, kind, config, secrets, *, allow_private=False, enabled=True):
    async with pool.acquire() as con:
        return await con.fetchval(
            "INSERT INTO integrations (kind, name, enabled, config, secrets, allow_private) "
            "VALUES ($1, $2, $3, $4::jsonb, $5, $6) RETURNING id",
            kind, f"{kind}-test", enabled, json.dumps(config),
            secrets_mod.encrypt_secrets(secrets), allow_private)


async def _asset(pool, kind, value):
    async with pool.acquire() as con:
        return await con.fetchrow(
            "SELECT id, metadata FROM assets WHERE kind = $1 AND canonical = $2", kind, value)


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #

async def test_ingest_merges_onto_existing_assets_and_routes_owners(db_pool, fake_redis):
    # Sentry already knows the device by IP + MAC; another tool tagged it.
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO assets (kind, value, canonical, source, metadata) VALUES "
            "('iot_device', '10.1.2.3', '10.1.2.3', 'otdiscovery', $1::jsonb)",
            json.dumps({"mac": MAC, "ips": ["10.1.2.3"], "tags": ["lobby"]}))
    hint = merge_hint(ips=["10.1.2.3"], hostnames=["cam-1"], macs=[MAC])
    item = asset("ipv4", "10.1.2.3", "integration:servicenow_cmdb",
                 {"owner_team": "Facilities", "tags": ["owner:Facilities"], "crown_jewel": True},
                 merge_on=hint)
    orphan = asset("subdomain", "-", "integration:servicenow_cmdb", {"owner": "x"},
                   merge_on=merge_hint(hostnames=["nowhere-host"]))
    orphan["merge_only"] = True
    batch = SourceBatch(
        assets=[item, orphan,
                asset("cloud_resource", "arn:aws:s3:::b1", "integration:aws", {"sensitive": True}),
                asset("cloud_resource", "arn:aws:iam::1:role/r", "integration:aws", {})],
        edges=[edge("cloud_resource", "arn:aws:iam::1:role/r", "cloud_resource",
                    "arn:aws:s3:::b1", "can_access")],
        findings=[finding("ipv4", "10.1.2.3", "cmdb.test", "low", "t", "d",
                          source="integration:servicenow_cmdb", merge_on=hint)],
        owners=[{"name": "servicenow_cmdb:Facilities", "match": {"tag": "owner:Facilities"},
                 "team": "Facilities", "contact": "fac@acme.com", "priority": 40}],
    )
    counts = await apply_source_batch(db_pool, fake_redis, batch, source="test")
    assert counts["assets_merged"] == 1 and counts["merge_targets"] == 1
    assert counts["assets_dropped"] == 1 and counts["edges_inserted"] == 1
    assert counts["findings_inserted"] == 1 and counts["owners_upserted"] == 1

    dev = await _asset(db_pool, "iot_device", "10.1.2.3")
    md = json.loads(dev["metadata"])
    assert md["owner_team"] == "Facilities" and md["crown_jewel"] is True
    assert sorted(md["tags"]) == ["lobby", "owner:Facilities"]          # unioned
    assert await _asset(db_pool, "ipv4", "10.1.2.3") is None             # merged, not duplicated
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT asset_id FROM findings WHERE rule_id = 'cmdb.test'") == dev["id"]
        assert await con.fetchval("SELECT count(*) FROM assets WHERE value = '-'") == 0

    # idempotent: a second run updates, never duplicates owner rules
    await apply_source_batch(db_pool, fake_redis, batch, source="test")
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM asset_owners") == 1
        md2 = json.loads(await con.fetchval("SELECT metadata FROM assets WHERE id = $1", dev["id"]))
    assert sorted(md2["tags"]) == ["lobby", "owner:Facilities"]


def _load_correlation_engine():
    pytest.importorskip("yaml")
    root = Path(__file__).resolve().parents[2] / "correlation" / "app"
    if "paddock_corr" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "paddock_corr", root / "__init__.py", submodule_search_locations=[str(root)])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["paddock_corr"] = mod
        spec.loader.exec_module(mod)
    return importlib.import_module("paddock_corr.engine.attackpath")


class _DbAdapter:
    """What the correlation engine expects from its Database: fetch() -> dicts, JSON decoded."""

    def __init__(self, pool):
        self.pool = pool

    async def fetch(self, sql, *args):
        async with self.pool.acquire() as con:
            rows = await con.fetch(sql, *args)
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("metadata"), str):
                d["metadata"] = json.loads(d["metadata"])
            out.append(d)
        return out


async def test_aws_batch_feeds_the_attack_path_engine(db_pool, fake_redis):
    """internet -> record -> LB -> instance -> role -> bucket, found by the REAL engine."""
    ap = _load_correlation_engine()
    S = "integration:aws"
    lb, inst = "arn:aws:elasticloadbalancing:r:1:loadbalancer/app/x/1", "arn:aws:ec2:r:1:instance/i-1"
    role, bucket = "arn:aws:iam::1:role/app", "arn:aws:s3:::crown"
    batch = SourceBatch(
        assets=[asset("subdomain", "app.acme-test.com", S, {"public": True}),
                asset("cloud_resource", lb, S, {"public": True}),
                asset("cloud_resource", inst, S, {}),
                asset("cloud_resource", role, S, {}),
                asset("cloud_resource", bucket, S, {"sensitive": True})],
        edges=[edge("subdomain", "app.acme-test.com", "cloud_resource", lb, "routes_to"),
               edge("cloud_resource", lb, "cloud_resource", inst, "routes_to"),
               edge("cloud_resource", inst, "cloud_resource", role, "has_role"),
               edge("cloud_resource", role, "cloud_resource", bucket, "can_access")],
    )
    await apply_source_batch(db_pool, fake_redis, batch, source=S)
    engine = ap.AttackPathEngine(_DbAdapter(db_pool))
    paths = engine.compute_paths(await engine._load_graph())
    chains = [[h["value"] for h in p["hops"]] for p in paths]
    assert [lb, inst, role, bucket] in chains or \
        ["app.acme-test.com", lb, inst, role, bucket] in chains, chains


# --------------------------------------------------------------------------- #
# Scheduled sync
# --------------------------------------------------------------------------- #

def _cs_factory(fail=False):
    def handler(req: httpx.Request):
        if fail:
            return httpx.Response(401, json={"errors": [f"secret {SECRET} rejected"]})
        if req.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "t"})
        if req.url.path == "/devices/queries/devices-scroll/v1":
            return httpx.Response(200, json={"resources": ["d1"],
                                             "meta": {"pagination": {"total": 1}}})
        if req.url.path == "/devices/entities/devices/v2":
            return httpx.Response(200, json={"resources": [{
                "device_id": "d1", "hostname": "web-01", "local_ip": "10.2.0.5",
                "device_policies": {}}]})
        return httpx.Response(404)
    return lambda cfg: httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_scheduled_source_sync_runs_on_interval(db_pool, fake_redis, fake_dns):
    iid = await _integration(db_pool, "crowdstrike",
                             {"client_id": "cid", "sync_interval_minutes": 60},
                             {"client_secret": SECRET})
    # ACTION integrations are never pulled
    await _integration(db_pool, "unifi", {"base_url": "https://10.0.0.1"}, {"api_key": "k"})
    assert await runtime.due_source_integrations(db_pool) == [iid]
    ran = await runtime.run_due_source_syncs(db_pool, fake_redis, http_factory=_cs_factory())
    assert ran == 1
    assert await runtime.due_source_integrations(db_pool) == []
    later = datetime.now(timezone.utc) + timedelta(minutes=61)
    assert await runtime.due_source_integrations(db_pool, later) == [iid]

    async with db_pool.acquire() as con:
        run = await con.fetchrow("SELECT status, counts FROM integration_sync_runs")
        ok_at = await con.fetchval("SELECT last_ok_at FROM integrations WHERE id = $1", iid)
        fid = await con.fetchval(
            "SELECT count(*) FROM findings WHERE rule_id = 'crowdstrike.prevention_policy_not_applied'")
        audit = await con.fetchval(
            "SELECT count(*) FROM audit_log WHERE action = 'integration_sync' AND resource_id = $1",
            str(iid))
    assert run["status"] == "ok" and json.loads(run["counts"])["assets_inserted"] == 1
    assert ok_at is not None and fid == 1 and audit == 1
    assert await _asset(db_pool, "ipv4", "10.2.0.5") is not None


async def test_failed_sync_records_scrubbed_error_and_claim_blocks_overlap(db_pool, fake_redis, fake_dns):
    iid = await _integration(db_pool, "crowdstrike", {"client_id": "cid"},
                             {"client_secret": SECRET})
    res = await runtime.run_source_sync(db_pool, fake_redis, iid, http_factory=_cs_factory(fail=True))
    assert res["status"] == "error" and "401" in res["detail"] and SECRET not in res["detail"]
    async with db_pool.acquire() as con:
        err = await con.fetchval("SELECT last_error FROM integrations WHERE id = $1", iid)
        assert SECRET not in err and "401" in err
        await con.execute("INSERT INTO integration_sync_runs (integration_id) VALUES ($1)", iid)
    res = await runtime.run_source_sync(db_pool, fake_redis, iid, http_factory=_cs_factory())
    assert res["status"] == "skipped"


async def test_kick_starts_one_background_sweep(db_pool, fake_redis, monkeypatch):
    import asyncio

    gate = asyncio.Event()
    calls = []

    async def runner(pool, r):
        calls.append(1)
        await gate.wait()
        return 0

    monkeypatch.setattr(runtime, "_sweep", None)
    assert runtime.kick_source_syncs(db_pool, fake_redis, runner=runner) is True
    assert runtime.kick_source_syncs(db_pool, fake_redis, runner=runner) is False
    gate.set()
    await asyncio.sleep(0)
    await runtime._sweep
    assert calls == [1]
    monkeypatch.setenv("PADDOCK_SOURCE_SYNC", "0")
    assert runtime.kick_source_syncs(db_pool, fake_redis, runner=runner) is False


async def test_sync_now_endpoint(app, client, db_pool, fake_dns):
    iid = await _integration(db_pool, "crowdstrike", {"client_id": "cid"},
                             {"client_secret": SECRET})
    app.state.integration_http_factory = _cs_factory()
    r = await client.post(f"/v1/integration-sync/{iid}")
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    r = await client.get("/v1/integration-sync")
    assert r.json()[0]["last_run"]["status"] == "ok"
    r = await client.get(f"/v1/integration-sync/{iid}/runs")
    assert len(r.json()) == 1 and r.json()[0]["trigger"] == "manual"


# --------------------------------------------------------------------------- #
# Network quarantine through the fleet approve gate
# --------------------------------------------------------------------------- #

def _unifi_factory(calls):
    def handler(req: httpx.Request):
        body = json.loads(req.content) if req.content else None
        calls.append((req.method, req.url.path, body))
        if req.url.path.endswith(f"/stat/user/{MAC}"):
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"_id": "u1", "mac": MAC}]})
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
    return lambda cfg: httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def self_approve(monkeypatch):
    monkeypatch.setenv("FLEET_ALLOW_SELF_APPROVE", "1")


async def _lateral_scan_finding(client):
    r = await client.post("/v1/assets/bulk", json={"items": [{
        "kind": "iot_device", "value": "10.5.0.20", "source": "otdiscovery",
        "metadata": {"mac": MAC.upper(), "vendor": "Hikvision", "type": "camera"}}]})
    assert r.status_code == 200, r.text
    r = await client.post("/v1/findings/bulk", json={"items": [{
        "asset_kind": "iot_device", "asset_value": "10.5.0.20", "rule_id": "device_lateral_scan",
        "rule_source": "policy", "severity": "high", "title": "Hikvision camera is scanning",
        "description": "d", "evidence": {"distinct_hosts": 40}}]})
    assert r.status_code == 200, r.text
    return r.json()["items"][0]["id"]


async def test_quarantine_flow_through_approve_gate(app, client, db_pool, self_approve):
    calls: list = []
    app.state.integration_http_factory = _unifi_factory(calls)
    iid = await _integration(db_pool, "unifi",
                             {"base_url": "https://10.0.0.1", "site": "default",
                              "protected_macs": ["aa:bb:cc:00:00:01"]},
                             {"api_key": SECRET}, allow_private=True)
    fid = await _lateral_scan_finding(client)

    r = await client.post("/v1/fleet/network-actions/from-finding",
                          json={"finding_id": fid, "integration_id": str(iid)})
    assert r.status_code == 201, r.text
    a = r.json()
    assert (a["status"], a["dry_run"], a["agent_id"], a["target"]) == ("proposed", True, None, MAC)
    assert a["action_type"] == "quarantine_device" and a["integration_id"] == str(iid)

    # Not approved yet -> nothing runs.
    r = await client.post(f"/v1/fleet/network-actions/{a['id']}/execute", json={})
    assert r.status_code == 409 and calls == []
    # Duplicate open proposal refused.
    r = await client.post("/v1/fleet/network-actions/from-finding",
                          json={"finding_id": fid, "integration_id": str(iid)})
    assert r.status_code == 409

    # A network decision without a reason is refused (server-side, not just in the UI).
    for verb in ("approve", "deny"):
        r = await client.post(f"/v1/fleet/actions/{a['id']}/{verb}", json={"note": "  "})
        assert r.status_code == 422 and "reason" in r.json()["detail"]

    # Approve WITHOUT apply_for_real -> execute is a read-only preview.
    r = await client.post(f"/v1/fleet/actions/{a['id']}/approve", json={"note": "preview first"})
    assert r.status_code == 200 and r.json()["dry_run"] is True
    r = await client.post(f"/v1/fleet/network-actions/{a['id']}/execute", json={})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] and out["dry_run"] and out["action"]["status"] == "approved"
    assert "block-sta" in out["planned"][0]
    assert not any(m == "POST" for m, _, _ in calls)

    # A real quarantine needs a fresh proposal approved with apply_for_real.
    r = await client.post("/v1/fleet/network-actions",
                          json={"integration_id": str(iid), "mac": MAC, "finding_id": fid})
    assert r.status_code == 201, r.text
    real_id = r.json()["id"]
    r = await client.post(f"/v1/fleet/actions/{real_id}/approve",
                          json={"apply_for_real": True, "note": "rogue device on POS VLAN"})
    assert r.json()["dry_run"] is False
    r = await client.post(f"/v1/fleet/network-actions/{real_id}/execute", json={})
    out = r.json()
    assert out["ok"] and not out["dry_run"] and out["action"]["status"] == "applied"
    assert out["action"]["result"]["revert"] == {"mode": "block", "mac": MAC}
    assert ("POST", "/proxy/network/api/s/default/cmd/stamgr",
            {"cmd": "block-sta", "mac": MAC}) in calls
    assert SECRET not in json.dumps(out)
    # Applied actions cannot be executed again.
    r = await client.post(f"/v1/fleet/network-actions/{real_id}/execute", json={})
    assert r.status_code == 409

    # Release = the fleet gate's first-class revert.
    r = await client.post(f"/v1/fleet/actions/{real_id}/revert", json={"note": "cleaned"})
    assert r.status_code == 201, r.text
    rev_id = r.json()["id"]
    r = await client.post(f"/v1/fleet/network-actions/{rev_id}/execute", json={})
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert ("POST", "/proxy/network/api/s/default/cmd/stamgr",
            {"cmd": "unblock-sta", "mac": MAC}) in calls
    r = await client.get("/v1/fleet/actions", params={"status": "reverted"})
    assert [x["id"] for x in r.json()["items"]] == [real_id]

    r = await client.get("/v1/fleet/network-actions")
    assert r.json()["total"] == 3
    async with db_pool.acquire() as con:
        acts = await con.fetch(
            "SELECT action, details FROM audit_log WHERE resource_type = 'fleet_action' "
            "AND resource_id = $1 ORDER BY id", real_id)
        # Agents never see network actions.
        assert await con.fetchval(
            "SELECT count(*) FROM agent_actions WHERE agent_id IS NOT NULL") == 0
    assert [x["action"] for x in acts] == ["propose", "approve", "apply", "reverted"]
    assert all(SECRET not in x["details"] for x in acts)


async def test_quarantine_guards(app, client, db_pool, self_approve, fake_dns):
    calls: list = []
    app.state.integration_http_factory = _unifi_factory(calls)
    unifi = await _integration(db_pool, "unifi",
                               {"base_url": "https://10.0.0.1",
                                "protected_macs": ["AA-BB-CC-00-00-01"]},
                               {"api_key": "k"}, allow_private=True)
    source = await _integration(db_pool, "crowdstrike", {"client_id": "c"}, {"client_secret": "s"})
    disabled = await _integration(db_pool, "meraki", {"network_id": "L_1"}, {"api_key": "k"},
                                  enabled=False)
    p = "/v1/fleet/network-actions"
    assert (await client.post(p, json={"integration_id": str(unifi),
                                       "mac": "aa:bb:cc:00:00:01"})).status_code == 422
    assert (await client.post(p, json={"integration_id": str(unifi),
                                       "mac": "01:00:5e:00:00:01"})).status_code == 422
    assert (await client.post(p, json={"integration_id": str(source), "mac": MAC})).status_code == 422
    assert (await client.post(p, json={"integration_id": str(disabled), "mac": MAC})).status_code == 409
    # extra fields (e.g. a smuggled host) are rejected
    assert (await client.post(p, json={"integration_id": str(unifi), "mac": MAC,
                                       "host": "10.0.0.9"})).status_code == 422

    # Only Sentry lateral-scan findings convert into proposals.
    r = await client.post("/v1/findings/bulk", json={"items": [{
        "asset_kind": "iot_device", "asset_value": "10.5.0.21", "rule_id": "weak_tls",
        "rule_source": "policy", "severity": "low", "title": "t", "description": "d"}]})
    other = r.json()["items"][0]["id"]
    r = await client.post(f"{p}/from-finding", json={"finding_id": other,
                                                      "integration_id": str(unifi)})
    assert r.status_code == 422
    # A lateral-scan finding on a device with no known MAC cannot be proposed.
    r = await client.post("/v1/findings/bulk", json={"items": [{
        "asset_kind": "iot_device", "asset_value": "10.5.0.22", "rule_id": "device_lateral_scan",
        "rule_source": "policy", "severity": "high", "title": "t", "description": "d"}]})
    r = await client.post(f"{p}/from-finding", json={"finding_id": r.json()["items"][0]["id"],
                                                      "integration_id": str(unifi)})
    assert r.status_code == 422 and "MAC" in r.json()["detail"]

    # A release cannot be "reverted" back into a quarantine without approval.
    r = await client.post(p, json={"integration_id": str(unifi), "mac": MAC,
                                   "action_type": "release_device"})
    rid = r.json()["id"]
    await client.post(f"/v1/fleet/actions/{rid}/approve",
                      json={"apply_for_real": True, "note": "cleared by owner"})
    r = await client.post(f"{p}/{rid}/execute", json={})
    assert r.json()["ok"] and r.json()["action"]["status"] == "applied"
    r = await client.post(f"/v1/fleet/actions/{rid}/revert", json={})
    r = await client.post(f"{p}/{r.json()['id']}/execute", json={})
    assert r.status_code == 409
    assert [c for c in calls if c[0] == "POST"] == [
        ("POST", "/proxy/network/api/s/default/cmd/stamgr", {"cmd": "unblock-sta", "mac": MAC})]
