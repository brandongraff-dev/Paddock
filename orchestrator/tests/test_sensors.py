"""Sentry sensor enrollment, credentials, heartbeat, idempotent uploads and the
silent-sensor monitor (schema 034, app/sensors.py, routers/sensors.py)."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import auth as auth_svc
from app import sensors as svc
from app import tenancy
from app.config import settings


@pytest.fixture(autouse=True)
def _reset_limiters():
    for lim in (svc.enroll_limiter, svc.enroll_fail_limiter, svc.heartbeat_limiter):
        lim.reset()
    yield
    for lim in (svc.enroll_limiter, svc.enroll_fail_limiter, svc.heartbeat_limiter):
        lim.reset()


async def _token(client, site="store-42", ttl=60):
    r = await client.post("/v1/sensors/tokens", json={"site": site, "ttl_minutes": ttl})
    assert r.status_code == 201, r.text
    return r.json()


async def _enroll(client, token=None, **kw):
    token = token or (await _token(client))["token"]
    return await client.post("/v1/sensors/enroll", json={
        "token": token, "hostname": "pi-1", "version": "0.2.0",
        "interfaces": [{"name": "eth1", "up": True, "speed_mbps": 1000}], **kw})


async def _enrolled(client):
    r = await _enroll(client)
    assert r.status_code == 201, r.text
    return r.json()


def _sh(cred):
    return {"X-Sensor-Token": cred}


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #

async def test_token_is_shown_once_and_stored_hashed(client, db_pool):
    t = await _token(client)
    assert t["token"].startswith("pet_") and t["state"] == "pending"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM sensor_enroll_tokens WHERE id = $1", uuid.UUID(t["id"]))
    assert t["token"] not in "".join(str(v) for v in row.values())
    assert row["token_hash"] == auth_svc.hash_api_key(t["token"])
    listed = (await client.get("/v1/sensors/tokens")).json()
    assert listed[0]["token_prefix"] == t["token_prefix"] and "token" not in listed[0]
    assert (row["expires_at"] - row["created_at"]) <= timedelta(minutes=61)


async def test_token_ttl_bounds_and_site_validation(client):
    assert (await client.post("/v1/sensors/tokens", json={"site": "x", "ttl_minutes": 1})).status_code == 422
    assert (await client.post("/v1/sensors/tokens", json={"site": "x", "ttl_minutes": 10**6})).status_code == 422
    assert (await client.post("/v1/sensors/tokens", json={"site": "a<script>"})).status_code == 422


async def test_token_is_single_use(client):
    t = await _token(client)
    first = await _enroll(client, t["token"])
    assert first.status_code == 201
    second = await _enroll(client, t["token"])
    assert second.status_code == 401
    state = [x for x in (await client.get("/v1/sensors/tokens")).json() if x["id"] == t["id"]][0]
    assert state["state"] == "used" and state["used_by_sensor"] == first.json()["sensor_id"]


async def test_concurrent_redemption_yields_exactly_one_sensor(client):
    t = await _token(client)
    rs = await asyncio.gather(*[_enroll(client, t["token"]) for _ in range(4)])
    codes = sorted(r.status_code for r in rs)
    assert codes.count(201) == 1 and codes.count(401) == 3
    assert len((await client.get("/v1/sensors")).json()) == 1


async def test_expired_token_is_rejected(client, db_pool):
    t = await _token(client)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensor_enroll_tokens SET expires_at = NOW() - interval '1 second'")
    assert (await _enroll(client, t["token"])).status_code == 401
    assert (await client.get("/v1/sensors/tokens")).json()[0]["state"] == "expired"


async def test_revoked_token_is_rejected_and_revoke_is_not_repeatable(client):
    t = await _token(client)
    assert (await client.delete(f"/v1/sensors/tokens/{t['id']}")).status_code == 204
    assert (await client.delete(f"/v1/sensors/tokens/{t['id']}")).status_code == 404
    assert (await _enroll(client, t["token"])).status_code == 401


async def test_used_token_cannot_be_revoked(client):
    t = await _token(client)
    await _enroll(client, t["token"])
    assert (await client.delete(f"/v1/sensors/tokens/{t['id']}")).status_code == 404


async def test_malformed_and_wrong_secret_tokens_get_the_same_generic_401(client):
    t = await _token(client)
    wrong = t["token"][:-3] + ("aaa" if not t["token"].endswith("aaa") else "bbb")
    for bad in ("garbage-token-value", wrong, "pst_" + t["token"][4:]):
        r = await _enroll(client, bad)
        assert r.status_code == 401
        assert r.json()["detail"] == "invalid, expired or already-used enrollment token"


async def test_enroll_failures_lock_out_and_window_limit(client):
    t = await _token(client)
    for _ in range(5):
        assert (await _enroll(client, "pet_deadbeef_" + "x" * 30)).status_code == 401
    r = await _enroll(client, t["token"])  # locked out: even the valid token is refused
    assert r.status_code == 429 and r.headers["retry-after"]
    svc.enroll_fail_limiter.reset()
    svc.enroll_limiter.reset()
    for _ in range(20):
        assert svc.enroll_limiter.hit("1.2.3.4")
    assert not svc.enroll_limiter.hit("1.2.3.4")
    assert svc.enroll_limiter.hit("5.6.7.8")  # per client


def test_limiter_window_expires():
    lim = svc.SlidingWindowLimiter(2, 10)
    assert lim.hit("k", now=100) and lim.hit("k", now=101) and not lim.hit("k", now=102)
    assert lim.hit("k", now=112)


# --------------------------------------------------------------------------- #
# enrollment, heartbeat, revocation
# --------------------------------------------------------------------------- #

async def test_enroll_registers_sensor_with_site_version_interfaces(client, db_pool):
    e = await _enrolled(client)
    assert e["credential"].startswith("pst_") and e["site"] == "store-42"
    s = (await client.get(f"/v1/sensors/{e['sensor_id']}")).json()
    assert s["version"] == "0.2.0" and s["interfaces"][0]["name"] == "eth1" and s["state"] == "online"
    async with db_pool.acquire() as con:
        h = await con.fetchval("SELECT cred_hash FROM sensors WHERE id = $1", uuid.UUID(e["sensor_id"]))
        actions = [r["action"] for r in await con.fetch("SELECT action FROM audit_log")]
    assert h == auth_svc.hash_api_key(e["credential"]) and e["credential"] != h
    assert "sensor.enroll" in actions and "sensor.token.create" in actions


async def test_heartbeat_records_health_and_clock_skew(client):
    e = await _enrolled(client)
    now = datetime.now(timezone.utc).timestamp()
    r = await client.post("/v1/sensors/heartbeat", headers=_sh(e["credential"]), json={
        "version": "0.2.1",
        "health": {"sent_at": now + 120, "packets_seen": 1000, "packets_dropped": 7,
                   "buffer_fill_pct": 91.5, "buffer_batches": 12, "iface": "eth1", "evil": "ignored"}})
    assert r.status_code == 200 and r.json()["server_time"] > 0
    s = (await client.get(f"/v1/sensors/{e['sensor_id']}")).json()
    assert s["version"] == "0.2.1" and s["state"] == "degraded"
    assert 100 < s["health"]["clock_skew_s"] < 140
    assert "evil" not in s["health"]
    joined = " ".join(s["warnings"])
    assert "dropped" in joined and "buffer" in joined and "clock" in joined


async def test_heartbeat_rejects_bad_credentials(client):
    assert (await client.post("/v1/sensors/heartbeat", json={})).status_code == 401
    bogus = "pst_00000000_" + "a" * 40
    assert (await client.post("/v1/sensors/heartbeat", headers=_sh(bogus), json={})).status_code == 401
    e = await _enrolled(client)
    tok = (await _token(client))["token"]  # an enrollment token is not a credential
    assert (await client.post("/v1/sensors/heartbeat", headers=_sh(tok), json={})).status_code == 401
    assert (await client.post("/v1/sensors/heartbeat", headers=_sh(e["credential"]), json={})).status_code == 200


async def test_revoked_sensor_credential_stops_working_immediately(client):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    assert (await client.post("/v1/sensors/heartbeat", headers=h, json={})).status_code == 200
    r = await client.post(f"/v1/sensors/{e['sensor_id']}/revoke")
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    assert (await client.post("/v1/sensors/heartbeat", headers=h, json={})).status_code == 403
    claim = await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "batch-0001"})
    assert claim.status_code == 403
    assert (await client.post(f"/v1/sensors/{e['sensor_id']}/revoke")).status_code == 404


async def test_patch_sensor(client):
    e = await _enrolled(client)
    r = await client.patch(f"/v1/sensors/{e['sensor_id']}", json={"name": "lobby", "silent_after_s": 120})
    assert r.status_code == 200 and r.json()["name"] == "lobby" and r.json()["silent_after_s"] == 120
    assert (await client.patch(f"/v1/sensors/{e['sensor_id']}", json={"silent_after_s": 5})).status_code == 422


# --------------------------------------------------------------------------- #
# idempotent uploads
# --------------------------------------------------------------------------- #

async def test_batch_claim_done_is_idempotent(client):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    c1 = (await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-0000001"})).json()
    assert c1["state"] == "new" and c1["tenant_id"]
    c2 = (await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-0000001"})).json()
    assert c2["state"] == "in_progress"  # a concurrent retry while the first is processing
    done = await client.post("/v1/sensors/ingest/done", headers=h, json={"batch_id": "b-0000001", "flows": 40})
    assert done.status_code == 200
    for _ in range(3):  # replays never double count
        again = (await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-0000001"})).json()
        assert again["state"] == "duplicate"
        await client.post("/v1/sensors/ingest/done", headers=h, json={"batch_id": "b-0000001", "flows": 40})
    s = (await client.get(f"/v1/sensors/{e['sensor_id']}")).json()
    assert s["batches_total"] == 1 and s["flows_total"] == 40 and s["duplicates_total"] == 3
    assert s["last_upload_at"] is not None


async def test_failed_batch_releases_the_claim(client):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-fail-001"})
    await client.post("/v1/sensors/ingest/done", headers=h, json={"batch_id": "b-fail-001", "ok": False})
    again = (await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-fail-001"})).json()
    assert again["state"] == "new"


async def test_stale_claim_can_be_retaken(client, db_pool):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-stale-01"})
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensor_batches SET claimed_at = NOW() - interval '10 minutes'")
    again = (await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-stale-01"})).json()
    assert again["state"] == "new"


async def test_batch_ids_are_per_sensor(client):
    a, b = await _enrolled(client), await _enrolled(client)
    for e in (a, b):
        c = (await client.post("/v1/sensors/ingest/claim", headers=_sh(e["credential"]),
                               json={"batch_id": "same-batch-id"})).json()
        assert c["state"] == "new"


async def test_claim_validates_batch_id(client):
    e = await _enrolled(client)
    r = await client.post("/v1/sensors/ingest/claim", headers=_sh(e["credential"]), json={"batch_id": "x'; drop"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# offline / online events
# --------------------------------------------------------------------------- #

@pytest.fixture
def events(monkeypatch):
    from app.integrations import service as isvc
    seen = []

    async def fake_emit(pool, event):
        seen.append(event)

    monkeypatch.setattr(isvc, "emit", fake_emit)
    return seen


async def test_silent_sensor_raises_offline_once_then_online_on_heartbeat(client, app, db_pool, events):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    pool = app.state.pool
    assert await svc.sweep_all_tenants(pool) == 0 and events == []  # fresh: fine
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensors SET last_seen_at = NOW() - interval '10 minutes'")
    assert await svc.sweep_all_tenants(pool) == 1
    assert await svc.sweep_all_tenants(pool) == 0  # no repeat alert
    assert [x.type for x in events] == ["sensor.offline"]
    off = events[0]
    assert off.severity == "high" and off.data["sensor"] == "pi-1" and off.data["site"] == "store-42"
    assert (await client.get(f"/v1/sensors/{e['sensor_id']}")).json()["state"] == "offline"
    assert (await client.post("/v1/sensors/heartbeat", headers=h, json={})).status_code == 200
    assert [x.type for x in events] == ["sensor.offline", "sensor.online"]
    assert (await client.get(f"/v1/sensors/{e['sensor_id']}")).json()["state"] == "online"


async def test_revoked_and_threshold_respecting_sensors_are_not_flagged(client, app, db_pool, events):
    a, b = await _enrolled(client), await _enrolled(client)
    await client.post(f"/v1/sensors/{b['sensor_id']}/revoke")
    await client.patch(f"/v1/sensors/{a['sensor_id']}", json={"silent_after_s": 3600})
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensors SET last_seen_at = NOW() - interval '10 minutes'")
    assert await svc.sweep_all_tenants(app.state.pool) == 0 and events == []


async def test_upload_also_revives_an_offline_sensor(client, app, db_pool, events):
    e = await _enrolled(client)
    h = _sh(e["credential"])
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensors SET last_seen_at = NOW() - interval '1 hour'")
    await svc.sweep_all_tenants(app.state.pool)
    await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-revive-1"})
    await client.post("/v1/sensors/ingest/done", headers=h, json={"batch_id": "b-revive-1", "flows": 3})
    assert [x.type for x in events] == ["sensor.offline", "sensor.online"]


def test_events_are_in_the_catalogue():
    from app.integrations.base import EVENT_TYPES
    assert "sensor.offline" in EVENT_TYPES and "sensor.online" in EVENT_TYPES


async def test_old_batch_ids_are_purged(client, app, db_pool):
    e = await _enrolled(client)
    await client.post("/v1/sensors/ingest/claim", headers=_sh(e["credential"]), json={"batch_id": "b-old-0001"})
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sensor_batches SET claimed_at = NOW() - interval '30 days'")
    await svc.sweep_all_tenants(app.state.pool)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM sensor_batches") == 0


# --------------------------------------------------------------------------- #
# RBAC (enforce) + tenancy
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
    async with pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash) VALUES ($1,$2,'restricted',NULL) RETURNING id",
            username, role)
        scopes = sorted(auth_svc.ROLE_CAPABILITIES.get(role, {"read"}))
        full, prefix, h = auth_svc.generate_api_key()
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1,$2,$3,$4,$5::text[])",
            uid, f"k-{prefix}", prefix, h, scopes)
    return {"Authorization": f"Bearer {full}"}


async def test_rbac_enroll_is_public_everything_else_is_governed(enforce, client, db_pool):
    admin, viewer = await _key(db_pool, "adm", "admin"), await _key(db_pool, "view", "viewer")
    assert (await client.post("/v1/sensors/tokens", json={"site": "s"})).status_code == 401
    assert (await client.post("/v1/sensors/tokens", json={"site": "s"}, headers=viewer)).status_code == 403
    assert (await client.get("/v1/sensors/tokens", headers=viewer)).status_code == 403
    t = (await client.post("/v1/sensors/tokens", json={"site": "s"}, headers=admin)).json()
    # a sensor has no user credential: the token IS the credential
    r = await client.post("/v1/sensors/enroll", json={"token": t["token"], "hostname": "h"})
    assert r.status_code == 201
    e = r.json()
    assert (await client.get("/v1/sensors")).status_code == 401
    assert (await client.get("/v1/sensors", headers=viewer)).status_code == 200
    assert (await client.post(f"/v1/sensors/{e['sensor_id']}/revoke", headers=viewer)).status_code == 403
    assert (await client.post("/v1/sensors/heartbeat", headers=_sh(e["credential"]), json={})).status_code == 200
    # the upload bracket needs a write-capable caller as well as the sensor's credential
    claim = {"batch_id": "b-rbac-0001"}
    assert (await client.post("/v1/sensors/ingest/claim", headers=_sh(e["credential"]), json=claim)).status_code == 401
    assert (await client.post("/v1/sensors/ingest/claim", headers={**viewer, **_sh(e["credential"])},
                              json=claim)).status_code == 403
    assert (await client.post("/v1/sensors/ingest/claim", headers={**admin, **_sh(e["credential"])},
                              json=claim)).status_code == 200


async def test_sensors_are_tenant_scoped_and_credential_lookup_crosses_tenants(app_pool, db_pool):
    other = str(uuid.uuid4())
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=other)
    with tenancy.tenant_context(other):
        full, _row = await svc.create_token(app_pool, site="b-site", label=None, ttl_minutes=30, actor="t")
    out = await svc.redeem_token(app_pool, full, hostname="b1", version="1", interfaces=[], name=None)
    assert out["tenant_id"] == other
    sensor = await svc.authenticate(app_pool, out["credential"])  # no tenant context needed
    assert str(sensor["tenant_id"]) == other
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM sensors") == 0
            assert await con.fetchval("SELECT COUNT(*) FROM sensor_enroll_tokens") == 0
    with tenancy.tenant_context(other):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM sensors") == 1


async def test_routine_sensor_traffic_is_not_audited_but_failures_are(client, db_pool):
    e = await _enrolled(client)
    h = _sh(e["credential"])

    async def n_audit():
        async with db_pool.acquire() as con:
            return await con.fetchval("SELECT COUNT(*) FROM audit_log")

    before = await n_audit()
    await client.post("/v1/sensors/heartbeat", headers=h, json={})
    await client.post("/v1/sensors/ingest/claim", headers=h, json={"batch_id": "b-audit-001"})
    await client.post("/v1/sensors/ingest/done", headers=h, json={"batch_id": "b-audit-001", "flows": 1})
    assert await n_audit() == before  # nothing per successful heartbeat / upload
    await client.post("/v1/sensors/heartbeat", headers=_sh("pst_00000000_" + "a" * 40), json={})
    assert await n_audit() > before  # a rejected credential is audited
    mid = await n_audit()
    await client.post(f"/v1/sensors/{e['sensor_id']}/revoke")
    assert await n_audit() > mid  # lifecycle changes always are
