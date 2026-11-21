"""Governance tests: auth, RBAC, ABAC classification, audit chain, provenance.

These run in AUTH_MODE=enforce (set per-test via the `enforce` fixture) so the
real credential + authorization paths are exercised. The rest of the suite runs
in the default AUTH_MODE=dev where a synthetic admin is injected.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from app import audit as audit_svc
from app import auth as auth_svc
from app.config import settings


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def enforce():
    """Force AUTH_MODE=enforce for the duration of a test."""
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _seed_user(pool, username, role, clearance, password=None):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO app_users (username, role, clearance, pw_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            username,
            role,
            clearance,
            auth_svc.hash_password(password) if password else None,
        )
    return row["id"]


async def _make_key(pool, user_id, scopes=("read",)):
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with pool.acquire() as con:
        await con.execute(
            """
            INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes)
            VALUES ($1, $2, $3, $4, $5::text[])
            """,
            user_id,
            f"key-{prefix}",
            prefix,
            key_hash,
            list(scopes),
        )
    return full


async def _seed_user_with_key(pool, username, role, clearance, scopes=None):
    uid = await _seed_user(pool, username, role, clearance)
    if scopes is None:
        scopes = tuple(sorted(auth_svc.ROLE_CAPABILITIES.get(role, {"read"})))
    key = await _make_key(pool, uid, scopes=scopes)
    return uid, key


def _hdr(key):
    return {"Authorization": f"Bearer {key}"}


async def _insert_asset(pool, value="ex.com", classification="internal"):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO assets (kind, value, canonical, source, classification)
            VALUES ('domain', $1, $1, 'test', $2)
            RETURNING id
            """,
            value,
            classification,
        )
    return row["id"]


async def _insert_finding(pool, asset_id, classification="internal", title="f"):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO findings (asset_id, rule_id, rule_source, severity,
                                  title, description, classification)
            VALUES ($1, $2, 'manual', 'high', $3, 'd', $4)
            RETURNING id
            """,
            asset_id,
            f"rule-{uuid.uuid4().hex[:8]}",
            title,
            classification,
        )
    return row["id"]


# --------------------------------------------------------------------------- #
# API key hashing / verify / revoke
# --------------------------------------------------------------------------- #

def test_api_key_format_and_hash_deterministic():
    full, prefix, key_hash = auth_svc.generate_api_key()
    assert full.startswith(f"pak_{prefix}_")
    assert len(key_hash) == 64
    assert auth_svc.hash_api_key(full) == key_hash
    # Raw key is never equal to its hash.
    assert full != key_hash


def test_api_key_hash_unique_per_key():
    a, _, ha = auth_svc.generate_api_key()
    b, _, hb = auth_svc.generate_api_key()
    assert a != b and ha != hb


def test_password_hash_roundtrip_and_reject():
    h = auth_svc.hash_password("hunter2")
    assert auth_svc.verify_password("hunter2", h)
    assert not auth_svc.verify_password("wrong", h)
    assert not auth_svc.verify_password("hunter2", None)


async def test_api_key_resolves_then_revoked_rejected(enforce, app, client, db_pool):
    uid, key = await _seed_user_with_key(db_pool, "svc", "admin", "restricted")
    # Works before revoke.
    r = await client.get("/v1/auth/me", headers=_hdr(key))
    assert r.status_code == 200
    assert r.json()["actor"] == "svc"
    # Revoke directly, then it is rejected.
    async with db_pool.acquire() as con:
        await con.execute("UPDATE api_keys SET revoked = TRUE WHERE user_id = $1", uid)
    r2 = await client.get("/v1/auth/me", headers=_hdr(key))
    assert r2.status_code == 401


async def test_apikey_create_endpoint_returns_raw_once(enforce, app, client, db_pool):
    await _seed_user(db_pool, "admin2", "admin", "restricted")
    _, admin_key = await _seed_user_with_key(db_pool, "adminkey", "admin", "restricted")
    r = await client.post(
        "/v1/auth/apikeys",
        headers=_hdr(admin_key),
        json={"name": "ci", "username": "admin2", "scopes": ["read", "write"]},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key"].startswith("pak_")
    assert body["prefix"] in body["api_key"]
    # The freshly-minted key authenticates.
    r2 = await client.get("/v1/auth/me", headers=_hdr(body["api_key"]))
    assert r2.status_code == 200


# --------------------------------------------------------------------------- #
# Login + JWT
# --------------------------------------------------------------------------- #

async def test_login_success_and_me(enforce, app, client, db_pool):
    await _seed_user(db_pool, "alice", "analyst", "internal", password="pw-alice")
    r = await client.post("/v1/auth/login", json={"username": "alice", "password": "pw-alice"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "analyst"
    assert body["clearance"] == "internal"
    assert body["expires_in"] > 0
    token = body["access_token"]
    me = await client.get("/v1/auth/me", headers=_hdr(token))
    assert me.status_code == 200
    assert me.json()["actor"] == "alice"
    assert "triage" in me.json()["capabilities"]


async def test_login_bad_password_rejected(enforce, app, client, db_pool):
    await _seed_user(db_pool, "bob", "viewer", "public", password="correct")
    r = await client.post("/v1/auth/login", json={"username": "bob", "password": "nope"})
    assert r.status_code == 401


async def test_login_unknown_user_rejected(enforce, app, client, db_pool):
    r = await client.post("/v1/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 401


async def test_enforce_mode_requires_credential(enforce, app, client):
    # No credential at all -> 401.
    r = await client.get("/v1/findings")
    assert r.status_code == 401


async def test_dev_mode_injects_admin(app, client):
    # Default dev mode: no credential still works (synthetic admin).
    r = await client.get("/v1/findings")
    assert r.status_code == 200
    me = await client.get("/v1/auth/me")
    assert me.json()["role"] == "admin"
    assert me.json()["kind"] == "dev"


# --------------------------------------------------------------------------- #
# RBAC role gates
# --------------------------------------------------------------------------- #

async def test_viewer_can_read(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "v", "viewer", "internal")
    r = await client.get("/v1/findings", headers=_hdr(key))
    assert r.status_code == 200


async def test_viewer_cannot_mutate(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool)
    fid = await _insert_finding(db_pool, aid)
    _, key = await _seed_user_with_key(db_pool, "v2", "viewer", "internal")
    r = await client.patch(
        f"/v1/findings/{fid}", headers=_hdr(key), json={"status": "triaged"}
    )
    assert r.status_code == 403


async def test_auditor_cannot_mutate(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool)
    fid = await _insert_finding(db_pool, aid)
    _, key = await _seed_user_with_key(db_pool, "aud", "auditor", "internal")
    r = await client.patch(
        f"/v1/findings/{fid}", headers=_hdr(key), json={"status": "triaged"}
    )
    assert r.status_code == 403


async def test_auditor_can_read_audit_analyst_cannot(enforce, app, client, db_pool):
    _, aud_key = await _seed_user_with_key(db_pool, "aud2", "auditor", "internal")
    _, ana_key = await _seed_user_with_key(db_pool, "ana2", "analyst", "internal")
    r_ok = await client.get("/v1/audit", headers=_hdr(aud_key))
    assert r_ok.status_code == 200
    r_no = await client.get("/v1/audit", headers=_hdr(ana_key))
    assert r_no.status_code == 403


async def test_analyst_can_triage(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool)
    fid = await _insert_finding(db_pool, aid)
    _, key = await _seed_user_with_key(db_pool, "ana", "analyst", "internal")
    r = await client.patch(
        f"/v1/findings/{fid}", headers=_hdr(key), json={"status": "triaged"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "triaged"


async def test_analyst_cannot_admin_scope(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "ana3", "analyst", "internal")
    r = await client.post(
        "/v1/scope",
        headers=_hdr(key),
        json={"kind": "domain", "value": "x.example", "added_by": "ana3"},
    )
    assert r.status_code == 403


async def test_admin_can_do_everything(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "adm", "admin", "restricted")
    # admin can add scope (admin) ...
    r = await client.post(
        "/v1/scope",
        headers=_hdr(key),
        json={"kind": "domain", "value": "y.example", "added_by": "adm"},
    )
    assert r.status_code == 201, r.text
    # ... and read the audit log (audit).
    r2 = await client.get("/v1/audit", headers=_hdr(key))
    assert r2.status_code == 200


async def test_service_key_can_ingest(enforce, app, client, db_pool, monkeypatch):
    # The env service key resolves to a synthetic service principal with write.
    monkeypatch.setattr(settings, "service_api_key", "svc-secret-123")
    r = await client.post(
        "/v1/findings/bulk",
        headers={"X-API-Key": "svc-secret-123"},
        json={"items": [{
            "asset_value": "svc.example.com",
            "rule_id": "r1",
            "rule_source": "manual",
            "severity": "low",
            "title": "t",
            "description": "d",
        }]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == 1


# --------------------------------------------------------------------------- #
# ABAC classification filtering
# --------------------------------------------------------------------------- #

def test_classification_rank_order():
    r = auth_svc.clearance_rank
    assert r("public") < r("internal") < r("confidential") < r("restricted")


async def test_confidential_finding_hidden_from_internal_clearance(
    enforce, app, client, db_pool
):
    aid = await _insert_asset(db_pool)
    conf_fid = await _insert_finding(db_pool, aid, classification="confidential", title="secret")
    pub_fid = await _insert_finding(db_pool, aid, classification="public", title="public")
    _, internal_key = await _seed_user_with_key(db_pool, "int", "analyst", "internal")

    r = await client.get("/v1/findings", headers=_hdr(internal_key))
    assert r.status_code == 200
    ids = {item["id"] for item in r.json()["items"]}
    assert str(pub_fid) in ids
    assert str(conf_fid) not in ids
    # Detail is a 404 (existence not disclosed).
    r_detail = await client.get(f"/v1/findings/{conf_fid}", headers=_hdr(internal_key))
    assert r_detail.status_code == 404


async def test_confidential_finding_visible_to_restricted_clearance(
    enforce, app, client, db_pool
):
    aid = await _insert_asset(db_pool)
    conf_fid = await _insert_finding(db_pool, aid, classification="confidential", title="secret")
    _, key = await _seed_user_with_key(db_pool, "res", "admin", "restricted")
    r = await client.get("/v1/findings", headers=_hdr(key))
    ids = {item["id"] for item in r.json()["items"]}
    assert str(conf_fid) in ids
    r_detail = await client.get(f"/v1/findings/{conf_fid}", headers=_hdr(key))
    assert r_detail.status_code == 200


async def test_restricted_asset_hidden_from_internal_clearance(
    enforce, app, client, db_pool
):
    restricted_aid = await _insert_asset(db_pool, value="secret.example", classification="restricted")
    public_aid = await _insert_asset(db_pool, value="open.example", classification="public")
    _, key = await _seed_user_with_key(db_pool, "int2", "viewer", "internal")
    r = await client.get("/v1/assets", headers=_hdr(key))
    values = {a["value"] for a in r.json()}
    assert "open.example" in values
    assert "secret.example" not in values
    # Asset detail for an over-classified asset is a 404.
    r_detail = await client.get(f"/v1/assets/{restricted_aid}", headers=_hdr(key))
    assert r_detail.status_code == 404


# --------------------------------------------------------------------------- #
# Audit chain: append + verify + tamper detection
# --------------------------------------------------------------------------- #

async def test_audit_chain_appends_and_links(db_pool):
    e1 = await audit_svc.record(db_pool, action="login", actor="a")
    e2 = await audit_svc.record(db_pool, action="create", actor="a", resource_type="scope")
    assert e1["prev_hash"] == audit_svc.GENESIS_HASH
    assert e2["prev_hash"] == e1["entry_hash"]
    assert e1["entry_hash"] != e2["entry_hash"]


async def test_audit_verify_ok_on_intact_chain(db_pool):
    for i in range(5):
        await audit_svc.record(db_pool, action="read", actor=f"u{i}")
    res = await audit_svc.verify(db_pool)
    assert res["ok"] is True
    assert res["checked"] == 5
    assert res["first_broken_id"] is None


async def test_audit_verify_detects_tampered_row(db_pool):
    ids = []
    for i in range(4):
        e = await audit_svc.record(db_pool, action="read", actor=f"u{i}")
        ids.append(e["id"])
    # Tamper: mutate a content column of the 2nd row without fixing hashes.
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE audit_log SET actor = 'mallory' WHERE id = $1", ids[1]
        )
    res = await audit_svc.verify(db_pool)
    assert res["ok"] is False
    assert res["first_broken_id"] == ids[1]


async def test_audit_verify_detects_deleted_row(db_pool):
    ids = []
    for i in range(4):
        e = await audit_svc.record(db_pool, action="read", actor=f"u{i}")
        ids.append(e["id"])
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM audit_log WHERE id = $1", ids[1])
    res = await audit_svc.verify(db_pool)
    # The row after the deleted one no longer links to its recorded prev_hash.
    assert res["ok"] is False
    assert res["first_broken_id"] == ids[2]


async def test_mutating_request_writes_audit_entry(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "adm4", "admin", "restricted")
    await client.post(
        "/v1/scope",
        headers=_hdr(key),
        json={"kind": "domain", "value": "audited.example", "added_by": "adm4"},
    )
    r = await client.get("/v1/audit?action=create", headers=_hdr(key))
    assert r.status_code == 200
    entries = r.json()["items"]
    assert any(e["path"] == "/v1/scope" and e["actor"] == "adm4" for e in entries)


async def test_denied_request_is_audited(enforce, app, client, db_pool):
    _, vkey = await _seed_user_with_key(db_pool, "vdeny", "viewer", "internal")
    _, akey = await _seed_user_with_key(db_pool, "areader", "auditor", "internal")
    # viewer attempts an admin action -> 403, audited as a deny.
    await client.post(
        "/v1/scope",
        headers=_hdr(vkey),
        json={"kind": "domain", "value": "z.example", "added_by": "vdeny"},
    )
    r = await client.get("/v1/audit?action=deny", headers=_hdr(akey))
    assert r.status_code == 200
    assert any(e["actor"] == "vdeny" and e["status"] == 403 for e in r.json()["items"])


async def test_audit_verify_endpoint(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "adm5", "admin", "restricted")
    # generate some audited activity
    await client.post(
        "/v1/scope",
        headers=_hdr(key),
        json={"kind": "domain", "value": "v.example", "added_by": "adm5"},
    )
    r = await client.get("/v1/audit/verify", headers=_hdr(key))
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["checked"] >= 1


async def test_justification_header_recorded(enforce, app, client, db_pool):
    _, key = await _seed_user_with_key(db_pool, "adm6", "admin", "restricted")
    await client.post(
        "/v1/scope",
        headers={**_hdr(key), "X-Justification": "IR-1234 incident response"},
        json={"kind": "domain", "value": "j.example", "added_by": "adm6"},
    )
    r = await client.get("/v1/audit?actor=adm6", headers=_hdr(key))
    entries = r.json()["items"]
    assert any(e["justification"] == "IR-1234 incident response" for e in entries)


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #

async def test_provenance_record_and_fetch(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool)
    _, key = await _seed_user_with_key(db_pool, "adm7", "admin", "restricted")
    r = await client.post(
        "/v1/provenance",
        headers=_hdr(key),
        json={
            "subject_type": "asset",
            "subject_id": str(aid),
            "source_service": "passive",
            "source_detail": "crt.sh",
            "method": "passive",
            "evidence": {"cert": "abc"},
            "confidence": 90,
        },
    )
    assert r.status_code == 201, r.text
    got = await client.get(
        f"/v1/provenance?subject_type=asset&subject_id={aid}", headers=_hdr(key)
    )
    assert got.status_code == 200
    rows = got.json()
    assert len(rows) == 1
    assert rows[0]["source_service"] == "passive"
    assert rows[0]["confidence"] == 90
    assert rows[0]["evidence"]["cert"] == "abc"


async def test_provenance_backfill_admin_only(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool, value="prov.example")
    await _insert_finding(db_pool, aid)
    _, analyst_key = await _seed_user_with_key(db_pool, "ana8", "analyst", "internal")
    _, admin_key = await _seed_user_with_key(db_pool, "adm8", "admin", "restricted")
    # analyst is forbidden
    r_no = await client.post("/v1/provenance/backfill", headers=_hdr(analyst_key))
    assert r_no.status_code == 403
    # admin backfills from source columns
    r = await client.post("/v1/provenance/backfill", headers=_hdr(admin_key))
    assert r.status_code == 200, r.text
    created = r.json()["created"]
    assert created.get("asset", 0) >= 1
    assert created.get("finding", 0) >= 1
    # lineage now present for the asset
    got = await client.get(
        f"/v1/provenance?subject_type=asset&subject_id={aid}", headers=_hdr(admin_key)
    )
    assert any(row["method"] == "import" for row in got.json())


async def test_provenance_backfill_idempotent(enforce, app, client, db_pool):
    aid = await _insert_asset(db_pool, value="idem.example")
    _, admin_key = await _seed_user_with_key(db_pool, "adm9", "admin", "restricted")
    first = await client.post("/v1/provenance/backfill", headers=_hdr(admin_key))
    assert first.json()["created"].get("asset", 0) >= 1
    second = await client.post("/v1/provenance/backfill", headers=_hdr(admin_key))
    # Nothing new on a second pass.
    assert second.json()["created"].get("asset", 0) == 0
