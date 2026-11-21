"""Integrations core against a real Postgres: REST API, emit fan-out, the
delivery engine (backoff + dead-letter) and the stream:events worker."""
from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app import auth as auth_svc
from app.config import settings
from app.integrations import Event, service, worker
from app.integrations.settings import isettings

from .integrations_helpers import Recorder, fake_dns, secret_key  # noqa: F401

WEBHOOK = {"kind": "webhook", "name": "SOC intake", "config": {"url": "https://hooks.example.com/paddock"},
           "secrets": {"signing_secret": "whsec_supersecret"}, "events": ["finding.opened", "finding.resolved"],
           "min_severity": "medium"}
SLACK_URL = "https://hooks.slack.com/services/T0/B0/SLACKSECRET"


@pytest.fixture
def rec(app):
    r = Recorder()
    app.state.integrations_transport = r.transport
    return r


@pytest.fixture(autouse=True)
def _env(fake_dns, secret_key):  # noqa: F811
    yield


async def _create(client, body=None, **overrides):
    payload = {**(body or WEBHOOK), **overrides}
    r = await client.post("/v1/integrations", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


def _event(**kw):
    base = dict(type="finding.opened", title="Exposed admin panel", severity="high",
                data={"finding_id": str(uuid.uuid4()), "asset": "admin.example.com", "asset_kind": "subdomain"})
    base.update(kw)
    return Event(**base)


# --------------------------------------------------------------------------- #
# catalogue + CRUD
# --------------------------------------------------------------------------- #

async def test_catalog(client):
    r = await client.get("/v1/integrations/catalog")
    assert r.status_code == 200
    body = r.json()
    kinds = {c["kind"]: c for c in body["connectors"]}
    assert {"webhook", "slack", "teams", "pagerduty", "email"} <= set(kinds)
    assert kinds["slack"]["secret_fields"] == ["webhook_url"]
    assert kinds["slack"]["required_secrets"] == ["webhook_url"]
    assert "finding.opened" in {e["type"] for e in body["events"]}
    assert body["severities"][0] == "info" and "asset_kinds" in body["filters"]


async def test_create_redacts_and_encrypts(client, db_pool):
    out = await _create(client)
    assert out["secrets"] == {"signing_secret": "********"}
    assert out["status"] == "never" and out["config"]["url"].startswith("https://")
    assert "whsec_supersecret" not in json.dumps(out)
    blob = await db_pool.fetchval("SELECT secrets FROM integrations WHERE id = $1", uuid.UUID(out["id"]))
    assert blob.startswith("v1:") and "whsec" not in blob
    got = (await client.get(f"/v1/integrations/{out['id']}")).json()
    assert got["secrets"] == {"signing_secret": "********"} and got["created_by"] == "dev-admin"
    lst = (await client.get("/v1/integrations")).json()
    assert lst["total"] == 1 and "whsec_supersecret" not in json.dumps(lst)


@pytest.mark.parametrize("override,needle", [
    ({"kind": "nope"}, "unknown integration kind"),
    ({"events": ["finding.exploded"]}, "unknown event"),
    ({"min_severity": "urgent"}, "min_severity"),
    ({"secrets": {}}, "secrets.signing_secret: is required"),
    ({"secrets": {"signing_secret": "x", "token": "y"}}, "not a secret field"),
    ({"config": {}}, "config.url: is required"),
    ({"config": {"url": "https://lan.example.com/x"}}, "private address"),
    ({"config": {"url": "https://meta.example.com/x"}}, "protected address"),
    ({"config": {"url": "http://hooks.example.com/x"}}, "plain http"),
    ({"filters": {"colour": ["red"]}}, "unknown filter"),
])
async def test_create_validation(client, override, needle):
    r = await client.post("/v1/integrations", json={**WEBHOOK, **override})
    assert r.status_code == 422, r.text
    assert needle in json.dumps(r.json())
    assert "whsec_supersecret" not in r.text


async def test_private_url_allowed_with_opt_in_and_duplicates_conflict(client):
    out = await _create(client, config={"url": "https://lan.example.com/x"}, allow_private=True)
    assert out["allow_private"] is True
    r = await client.post("/v1/integrations", json={**WEBHOOK, "config": {"url": "https://lan.example.com/x"},
                                                     "allow_private": True})
    assert r.status_code == 409


async def test_patch_secret_semantics_and_fields(client, db_pool):
    body = {"kind": "email", "name": "mail", "config": {"host": "smtp.example.com", "from_addr": "p@example.com",
                                                        "to": ["a@example.com"]},
            "secrets": {"username": "u", "password": "pw1"}, "events": ["finding.opened"]}
    out = await _create(client, body)
    iid = out["id"]
    assert out["config"]["port"] == 587          # default filled
    from app.integrations import secrets as sm

    async def stored():
        return sm.decrypt_secrets(await db_pool.fetchval("SELECT secrets FROM integrations WHERE id=$1", uuid.UUID(iid)))

    r = await client.patch(f"/v1/integrations/{iid}", json={"secrets": {"username": "********", "password": "pw2"}})
    assert r.status_code == 200 and await stored() == {"username": "u", "password": "pw2"}
    r = await client.patch(f"/v1/integrations/{iid}", json={"secrets": {"password": ""}})
    assert r.json()["secrets"] == {"username": "********", "password": ""} and await stored() == {"username": "u"}
    r = await client.patch(f"/v1/integrations/{iid}", json={"name": "mail-2", "events": ["scan.failed"],
                                                           "min_severity": "high",
                                                           "filters": {"asset_kinds": ["domain"]},
                                                           "config": {**out["config"], "port": 465,
                                                                      "security": "tls"}})
    o = r.json()
    assert (o["name"], o["events"], o["min_severity"], o["filters"], o["config"]["port"]) == \
        ("mail-2", ["scan.failed"], "high", {"asset_kinds": ["domain"]}, 465)
    r = await client.patch(f"/v1/integrations/{iid}", json={"config": {"host": "smtp.example.com"}})
    assert r.status_code == 422


async def test_enable_disable_delete(client):
    iid = (await _create(client))["id"]
    assert (await client.post(f"/v1/integrations/{iid}/disable")).json()["status"] == "disabled"
    assert (await client.post(f"/v1/integrations/{iid}/enable")).json()["enabled"] is True
    assert (await client.delete(f"/v1/integrations/{iid}")).status_code == 200
    assert (await client.get(f"/v1/integrations/{iid}")).status_code == 404
    assert (await client.delete(f"/v1/integrations/{iid}")).status_code == 404


# --------------------------------------------------------------------------- #
# test button + delivery log + health
# --------------------------------------------------------------------------- #

async def test_test_endpoint_delivers_synchronously(client, rec):
    out = await _create(client, {"kind": "slack", "name": "sec-alerts", "secrets": {"webhook_url": SLACK_URL},
                                 "events": ["finding.opened"]})
    r = await client.post(f"/v1/integrations/{out['id']}/test")
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["ok"] is True and res["status_code"] == 200 and res["delivery_id"]
    assert str(rec.requests[0].url) == SLACK_URL
    assert "Paddock test event" in rec.json()["text"]
    log = (await client.get(f"/v1/integrations/{out['id']}/deliveries")).json()
    assert log["total"] == 1 and log["items"][0]["status"] == "sent"
    assert log["items"][0]["event_type"] == "integration.test"
    got = (await client.get(f"/v1/integrations/{out['id']}")).json()
    assert got["status"] == "ok" and got["last_ok_at"] and got["stats"]["sent_24h"] == 1
    assert "SLACKSECRET" not in json.dumps(got) + json.dumps(log) + json.dumps(res)


async def test_test_endpoint_failure_and_health(client, rec, app):
    rec.handler = lambda req: httpx.Response(500, text="upstream down")
    out = await _create(client)
    res = (await client.post(f"/v1/integrations/{out['id']}/test", json={"mode": "deliver"})).json()
    assert res["ok"] is False and res["status_code"] == 500 and "upstream down" in res["detail"]
    log = (await client.get(f"/v1/integrations/{out['id']}/deliveries")).json()
    assert log["items"][0]["status"] == "failed" and log["items"][0]["next_attempt_at"] is None  # never retried
    got = (await client.get(f"/v1/integrations/{out['id']}")).json()
    assert got["status"] == "error" and "HTTP 500" in got["last_error"]
    h = (await client.get("/v1/integrations/health")).json()
    assert h["status"] == "degraded" and h["integrations"]["error"] == 1 and h["secret_key_persistent"] is True
    # health mode runs connector.test() without writing to the delivery log
    rec.handler = lambda req: httpx.Response(200, text="ok")
    res = (await client.post(f"/v1/integrations/{out['id']}/test", json={"mode": "health"})).json()
    assert res["mode"] == "health" and res["ok"] is True
    assert (await client.get(f"/v1/integrations/{out['id']}/deliveries")).json()["total"] == 1
    assert (await client.get("/v1/integrations/health")).json()["status"] == "ok"


async def test_health_empty(client):
    h = (await client.get("/v1/integrations/health")).json()
    assert h["status"] == "empty" and h["integrations"]["total"] == 0


# --------------------------------------------------------------------------- #
# emit fan-out
# --------------------------------------------------------------------------- #

async def test_emit_matches_and_is_idempotent(client, db_pool):
    a = await _create(client)                                                           # medium+, opened/resolved
    b = await _create(client, name="crit-only", min_severity="critical")
    c = await _create(client, name="prod-only", filters={"tags": ["prod"]})
    d = await _create(client, name="off", enabled=False)
    e = await _create(client, name="scans", events=["scan.failed"])
    ev = _event()
    created = await service.fan_out(db_pool, ev)
    assert len(created) == 1
    await service.emit(db_pool, ev)                                                     # same event again
    rows = await db_pool.fetch("SELECT integration_id, status, payload FROM integration_deliveries")
    assert [str(r["integration_id"]) for r in rows] == [a["id"]]
    assert rows[0]["status"] == "pending" and json.loads(rows[0]["payload"])["id"] == ev.id
    await service.emit(db_pool, _event(severity="critical", data={"tags": ["prod"], "finding_id": "x"}))
    ids = {str(r["integration_id"]) for r in await db_pool.fetch("SELECT integration_id FROM integration_deliveries")}
    assert ids == {a["id"], b["id"], c["id"]}
    assert d["id"] not in ids and e["id"] not in ids


async def test_emit_never_raises(caplog):
    class Broken:
        async def fetch(self, *a):
            raise RuntimeError("db down")
    await service.emit(Broken(), _event())          # logged, swallowed
    assert any("integration_emit_failed" in r.message for r in caplog.records)


async def test_emit_accepts_a_connection(client, db_pool):
    await _create(client)
    async with db_pool.acquire() as con:
        async with con.transaction():
            await service.emit(con, _event())
    assert await db_pool.fetchval("SELECT COUNT(*) FROM integration_deliveries") == 1


# --------------------------------------------------------------------------- #
# delivery engine
# --------------------------------------------------------------------------- #

async def _due_now(pool):
    await pool.execute("UPDATE integration_deliveries SET next_attempt_at = NOW() - INTERVAL '1 second' "
                       "WHERE status IN ('pending', 'failed') AND next_attempt_at IS NOT NULL")


async def test_process_due_sends_and_marks_ok(client, db_pool):
    out = await _create(client)
    await service.emit(db_pool, _event())
    rec = Recorder(lambda req: httpx.Response(204))
    assert await service.process_due(db_pool, transport=rec.transport) == 1
    row = await db_pool.fetchrow("SELECT status, attempts, status_code, next_attempt_at FROM integration_deliveries")
    assert (row["status"], row["attempts"], row["status_code"], row["next_attempt_at"]) == ("sent", 1, 204, None)
    assert rec.requests[0].headers["Paddock-Event"] == "finding.opened"
    assert await db_pool.fetchval("SELECT last_ok_at IS NOT NULL FROM integrations WHERE id=$1", uuid.UUID(out["id"]))
    assert await service.process_due(db_pool, transport=rec.transport) == 0


async def test_retry_backoff_then_dead_letter(client, db_pool, monkeypatch):
    monkeypatch.setattr(isettings, "integrations_max_attempts", 3)
    await _create(client)
    await service.emit(db_pool, _event())
    rec = Recorder(lambda req: httpx.Response(503, text="busy"))
    assert await service.process_due(db_pool, transport=rec.transport) == 1
    row = await db_pool.fetchrow("SELECT status, attempts, next_attempt_at > NOW() + INTERVAL '20 seconds' AS later "
                                 "FROM integration_deliveries")
    assert (row["status"], row["attempts"], row["later"]) == ("failed", 1, True)
    assert await service.process_due(db_pool, transport=rec.transport) == 0     # not due yet
    for expected in ("failed", "dead"):
        await _due_now(db_pool)
        await service.process_due(db_pool, transport=rec.transport)
        assert await db_pool.fetchval("SELECT status FROM integration_deliveries") == expected
    row = await db_pool.fetchrow("SELECT attempts, detail, next_attempt_at FROM integration_deliveries")
    assert row["attempts"] == 3 and "gave up after 3" in row["detail"] and row["next_attempt_at"] is None
    assert len(rec.requests) == 3


async def test_non_retryable_goes_straight_to_dead_and_manual_retry(client, db_pool):
    out = await _create(client)
    await service.emit(db_pool, _event())
    await service.process_due(db_pool, transport=Recorder(lambda r: httpx.Response(400, text="bad")).transport)
    did = await db_pool.fetchval("SELECT id FROM integration_deliveries")
    assert await db_pool.fetchval("SELECT status FROM integration_deliveries") == "dead"
    r = await client.post(f"/v1/integrations/{out['id']}/deliveries/{did}/retry")
    assert r.status_code == 200 and r.json()["status"] == "pending"
    assert (await client.post(f"/v1/integrations/{out['id']}/deliveries/{did}/retry")).status_code == 409
    assert (await client.post(f"/v1/integrations/{out['id']}/deliveries/999999/retry")).status_code == 404
    await service.process_due(db_pool, transport=Recorder().transport)
    assert await db_pool.fetchval("SELECT status FROM integration_deliveries") == "sent"
    await client.post(f"/v1/integrations/{out['id']}/disable")
    assert (await client.post(f"/v1/integrations/{out['id']}/deliveries/{did}/retry")).status_code == 409


async def test_disabled_after_queueing_is_skipped(client, db_pool):
    out = await _create(client)
    await service.emit(db_pool, _event())
    await client.post(f"/v1/integrations/{out['id']}/disable")
    rec = Recorder()
    await service.process_due(db_pool, transport=rec.transport)
    assert await db_pool.fetchval("SELECT status FROM integration_deliveries") == "skipped" and not rec.requests


async def test_undecryptable_secrets_dead_letter_with_clear_message(client, db_pool, monkeypatch):
    import base64
    import os
    out = await _create(client)
    await service.emit(db_pool, _event())
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())   # rotated away
    await service.process_due(db_pool, transport=Recorder().transport)
    row = await db_pool.fetchrow("SELECT status, detail FROM integration_deliveries")
    assert row["status"] == "dead" and "PADDOCK_SECRET_KEY" in row["detail"]
    got = (await client.get(f"/v1/integrations/{out['id']}")).json()
    assert got["secrets_error"] and got["secrets"] == {"signing_secret": ""}


async def test_claim_uses_a_lease(client, db_pool):
    await _create(client)
    await service.emit(db_pool, _event())
    assert len(await service.claim_due(db_pool)) == 1
    assert await service.claim_due(db_pool) == []         # leased to the first claimer


async def test_deliveries_pagination_and_status_filter(client, db_pool):
    out = await _create(client)
    for _ in range(5):
        await service.emit(db_pool, _event())
    page = (await client.get(f"/v1/integrations/{out['id']}/deliveries", params={"limit": 2, "offset": 2})).json()
    assert page["total"] == 5 and len(page["items"]) == 2 and page["offset"] == 2
    assert page["items"][0]["title"] == "Exposed admin panel" and page["items"][0]["severity"] == "high"
    assert (await client.get(f"/v1/integrations/{out['id']}/deliveries",
                             params={"status": "sent"})).json()["total"] == 0
    assert (await client.get(f"/v1/integrations/{out['id']}/deliveries",
                             params={"status": "bogus"})).status_code == 422


# --------------------------------------------------------------------------- #
# stream:events -> worker -> deliveries
# --------------------------------------------------------------------------- #

async def _consume(db_pool, r):
    await worker.ensure_group(r, settings.events_stream, "integrations")
    return await worker.consume_once(db_pool, r, stream=settings.events_stream, group="integrations",
                                     consumer="t1", block_ms=None)


async def test_worker_end_to_end_from_findings_bulk(client, db_pool, fake_redis):
    await worker.ensure_group(fake_redis, settings.events_stream, "integrations")
    slack_i = await _create(client, {"kind": "slack", "name": "s", "secrets": {"webhook_url": SLACK_URL},
                                     "events": ["finding.opened", "asset.discovered"], "min_severity": "high"})
    body = {"items": [{"asset_value": "pay.example.com", "asset_kind": "subdomain", "rule_id": "exposed-env",
                       "rule_source": "exposed_file", "severity": "critical", "title": ".env file exposed",
                       "description": "Secrets readable", "impact": "Database credentials are public."},
                      {"asset_value": "pay.example.com", "asset_kind": "subdomain", "rule_id": "hsts",
                       "rule_source": "header_check", "severity": "low", "title": "No HSTS", "description": "d"}]}
    assert (await client.post("/v1/findings/bulk", json=body)).status_code == 200
    acked = await _consume(db_pool, fake_redis)
    assert acked == 3                                         # asset_added + 2x finding_opened
    rows = await db_pool.fetch("SELECT event_type, payload FROM integration_deliveries ORDER BY id")
    assert [r["event_type"] for r in rows] == ["asset.discovered", "finding.opened"]   # low finding gated out
    ev = json.loads(rows[1]["payload"])
    assert ev["title"] == ".env file exposed" and ev["summary"] == "Database credentials are public."
    assert ev["data"]["asset"] == "pay.example.com" and ev["data"]["asset_kind"] == "subdomain"
    assert ev["url"].endswith(f"/findings?focus={ev['data']['finding_id']}")
    pending = await fake_redis.xpending(settings.events_stream, "integrations")
    assert pending["pending"] == 0
    rec = Recorder()
    assert await service.process_due(db_pool, transport=rec.transport) == 2
    texts = [rec.json(i)["text"] for i in range(2)]
    assert any(".env file exposed" in t for t in texts)
    assert (await client.get(f"/v1/integrations/{slack_i['id']}")).json()["stats"]["sent_24h"] == 2


async def test_worker_dedupes_same_fact_from_two_publishers(client, db_pool, fake_redis):
    await _create(client, events=["scan.completed"])
    await worker.ensure_group(fake_redis, settings.events_stream, "integrations")
    sid = str(uuid.uuid4())
    await fake_redis.xadd(settings.events_stream, {"event": json.dumps(
        {"event": "scan_completed", "scan_id": sid, "kind": "http_probe", "target": "a.example"})})
    await fake_redis.xadd(settings.events_stream, {"event": "scan_completed", "scan_id": sid,
                                                   "kind": "http_probe", "target": "a.example", "ts": "1700000000"})
    await fake_redis.xadd(settings.events_stream, {"event": json.dumps({"event": "scope_added"})})
    assert await _consume(db_pool, fake_redis) == 3
    assert await db_pool.fetchval("SELECT COUNT(*) FROM integration_deliveries") == 1


async def test_worker_leaves_entry_pending_when_db_fails(fake_redis, monkeypatch):
    await worker.ensure_group(fake_redis, settings.events_stream, "integrations")
    await fake_redis.xadd(settings.events_stream, {"event": json.dumps(
        {"event": "scan_failed", "scan_id": "s", "kind": "k", "target": "t", "error": "e"})})

    async def broken(pool, event):
        raise RuntimeError("db down")
    monkeypatch.setattr(service, "fan_out", broken)
    acked = await worker.consume_once(None, fake_redis, stream=settings.events_stream, group="integrations",
                                      consumer="t1", block_ms=None)
    assert acked == 0
    assert (await fake_redis.xpending(settings.events_stream, "integrations"))["pending"] == 1


async def test_stream_mapper_enriches_closed_and_chain(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await con.fetchval("INSERT INTO assets (kind, value, canonical, source, metadata) VALUES "
                                 "('domain', 'shop.example', 'shop.example', 't', '{\"tags\": [\"pci\"]}') RETURNING id")
        fid = await con.fetchval("INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, "
                                 "assigned_to) VALUES ($1, 'r1', 'policy', 'high', 'Weak TLS', 'd', 'web-team') "
                                 "RETURNING id", aid)
        cid = await con.fetchval("INSERT INTO finding_chains (chain_rule_id, severity, title, description, "
                                 "impact_narrative, finding_ids, anchor_asset_id) VALUES ('c1', 'critical', "
                                 "'git + outdated lib + no WAF', 'd', 'Full source + RCE path', $1, $2) RETURNING id",
                                 [fid], aid)
    ev = await service.event_from_stream(db_pool, {"event": json.dumps(
        {"event": "finding_closed", "finding_id": str(fid), "status": "fixed"})}, "9-0")
    assert ev.type == "finding.resolved" and ev.title == "Resolved: Weak TLS" and ev.severity == "high"
    assert ev.data["owner"] == "web-team" and ev.data["tags"] == ["pci"] and ev.data["status"] == "fixed"
    ch = await service.event_from_stream(db_pool, {"event": json.dumps(
        {"event": "chain_detected", "chain_id": str(cid), "chain_rule_id": "c1", "severity": "critical"})}, "9-1")
    assert ch.type == "finding.opened" and ch.severity == "critical" and ch.data["finding_kind"] == "chain"
    assert ch.summary == "Full source + RCE path" and ch.data["asset"] == "shop.example"
    ap = await service.event_from_stream(db_pool, {"event": json.dumps(
        {"event": "attack_path_found", "fingerprint": "fp1", "source_asset_id": str(aid),
         "target_asset_id": str(aid), "severity": "high", "title": "Internet -> payments DB"})}, "9-2")
    assert ap.type == "attack_path.opened" and ap.data["asset"] == "shop.example → shop.example"


# --------------------------------------------------------------------------- #
# governance: RBAC, audit, secret key
# --------------------------------------------------------------------------- #

@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _key(pool, username, role):
    uid = await pool.fetchval("INSERT INTO app_users (username, role, clearance) VALUES ($1, $2, 'internal') "
                              "RETURNING id", username, role)
    full, prefix, key_hash = auth_svc.generate_api_key()
    scopes = sorted(auth_svc.ROLE_CAPABILITIES[role])
    await pool.execute("INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, $5)",
                       uid, f"k-{prefix}", prefix, key_hash, scopes)
    return {"Authorization": f"Bearer {full}"}


def test_rbac_table():
    rc = auth_svc.required_capability
    assert rc("GET", "/v1/integrations/catalog") == "read"
    assert rc("GET", "/v1/integrations/abc/deliveries") == "read"
    assert rc("POST", "/v1/integrations") == "admin"
    assert rc("PATCH", "/v1/integrations/abc") == "admin"
    assert rc("POST", "/v1/integrations/abc/test") == "admin"
    assert rc("POST", "/v1/integrations/abc/deliveries/1/retry") == "admin"


async def test_viewer_reads_analyst_cannot_write_admin_audited(enforce, client, db_pool):
    viewer = await _key(db_pool, "v1", "viewer")
    analyst = await _key(db_pool, "a1", "analyst")
    admin = await _key(db_pool, "adm1", "admin")
    assert (await client.get("/v1/integrations/catalog", headers=viewer)).status_code == 200
    assert (await client.post("/v1/integrations", json=WEBHOOK, headers=viewer)).status_code == 403
    assert (await client.post("/v1/integrations", json=WEBHOOK, headers=analyst)).status_code == 403
    r = await client.post("/v1/integrations", json=WEBHOOK, headers=admin)
    assert r.status_code == 201, r.text
    iid = r.json()["id"]
    assert (await client.post(f"/v1/integrations/{iid}/disable", headers=analyst)).status_code == 403
    rows = await db_pool.fetch("SELECT actor, action, resource_type, resource_id, details::text AS d, path "
                               "FROM audit_log WHERE resource_type = 'integrations' ORDER BY id")
    assert any(r["actor"] == "adm1" and r["action"] == "create" for r in rows)
    assert any(r["action"] == "deny" for r in rows)
    assert all("whsec_supersecret" not in (r["d"] or "") for r in rows)


async def test_enforce_refuses_to_store_secrets_without_persistent_key(enforce, client, db_pool, monkeypatch):
    admin = await _key(db_pool, "adm2", "admin")
    monkeypatch.delenv("PADDOCK_SECRET_KEY", raising=False)
    r = await client.post("/v1/integrations", json=WEBHOOK, headers=admin)
    assert r.status_code == 503 and "PADDOCK_SECRET_KEY" in r.text


# --------------------------------------------------------------------------- #
# worker x ticketing: the delivery engine binds TICKET connectors so links
# (and therefore two-way sync + idempotency) are persisted
# --------------------------------------------------------------------------- #

async def test_worker_delivers_ticket_and_persists_link(client, db_pool):
    from .ticketing_fakes import FakeJira

    jira = FakeJira()
    out = await _create(client, {
        "kind": "jira", "name": "sec-jira", "enabled": True,
        "config": {"base_url": jira.base, "project_key": "SEC", "email": "bot@example.com"},
        "secrets": {"api_token": "t0k3n"},
        "events": ["finding.opened", "finding.resolved"], "min_severity": "low",
    })
    fid = str(uuid.uuid4())
    await service.emit(db_pool, _event(data={"finding_id": fid, "asset": "admin.example.com"}))
    assert await service.process_due(db_pool, transport=jira.transport()) == 1
    status = await db_pool.fetchval("SELECT status FROM integration_deliveries")
    assert status == "sent"
    link = await db_pool.fetchrow(
        "SELECT external_id, external_url FROM integration_links WHERE integration_id=$1",
        uuid.UUID(out["id"]))
    assert link is not None and link["external_id"].startswith("SEC-")
    assert len(jira.issues) == 1

    # the same finding opening again (e.g. redelivered fact with a new event id)
    # must update the linked issue, not create a second one
    await service.emit(db_pool, _event(data={"finding_id": fid, "asset": "admin.example.com"}))
    await service.process_due(db_pool, transport=jira.transport())
    assert len(jira.issues) == 1
