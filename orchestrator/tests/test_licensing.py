"""Editions / license keys / entitlements + usage metering (schema 024).

Every key here is signed with a THROWAWAY Ed25519 key generated per test
session -- the vendor private key never exists in this repository.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app import licensing as lic
from app.config import settings


def _pub_b64(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


@pytest.fixture(scope="module")
def vendor_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def trust(vendor_key, monkeypatch):
    """Trust the throwaway vendor key for the duration of a test."""
    monkeypatch.setattr(lic.license_settings, "license_public_keys", _pub_b64(vendor_key))
    monkeypatch.setattr(lic.license_settings, "license_key", None)
    monkeypatch.setattr(lic.license_settings, "license_file", None)
    monkeypatch.setattr(lic.license_settings, "license_cache_ttl_sec", 0.0)
    # Keep the otdiscovery probe fast and deterministic: nothing listens here.
    monkeypatch.setattr(settings, "otdiscovery_url", "http://127.0.0.1:9")
    return vendor_key


def _payload(**over):
    p = {
        "v": 1,
        "license_id": "lic-test-0001",
        "licensee": "Example Corp",
        "edition": "enterprise",
        "seats": 25,
        "sites": 3,
        "assets": 5000,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "features": [],
    }
    p.update(over)
    return p


# --------------------------------------------------------------------------- #
# Pure verification
# --------------------------------------------------------------------------- #

def test_roundtrip_and_edition_features(vendor_key):
    key = lic.sign_license(_payload(edition="team"), vendor_key)
    assert key.startswith("PDK1.")
    got = lic.verify_license_key(key, public_keys=[vendor_key.public_key()])
    assert got.status == "active"
    assert got.edition == "team"
    assert got.has("sso_saml")
    assert not got.has("scim")
    assert got.limits() == {"seats": 25, "sites": 3, "assets": 5000}


def test_explicit_features_add_to_edition_and_unknown_dropped(vendor_key):
    key = lic.sign_license(_payload(edition="team", features=["scim", "not_a_feature"]), vendor_key)
    got = lic.verify_license_key(key, public_keys=[vendor_key.public_key()])
    assert got.has("scim") and got.has("sso_saml")
    assert "not_a_feature" not in got.features


def test_edge_is_superset_of_enterprise():
    assert lic.edition_features("enterprise") <= lic.edition_features("edge")
    assert lic.edition_features("community") == frozenset()


def test_tampered_payload_rejected(vendor_key):
    key = lic.sign_license(_payload(edition="team"), vendor_key)
    head, body, sig = key.split(".")
    forged = lic.canonical_payload(_payload(edition="edge"))
    forged_key = ".".join([head, base64.urlsafe_b64encode(forged).decode().rstrip("="), sig])
    with pytest.raises(lic.LicenseError, match="signature"):
        lic.verify_license_key(forged_key, public_keys=[vendor_key.public_key()])


def test_wrong_vendor_key_rejected(vendor_key):
    key = lic.sign_license(_payload(), vendor_key)
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(lic.LicenseError):
        lic.verify_license_key(key, public_keys=[other])


def test_no_trusted_key_means_invalid(vendor_key, monkeypatch):
    monkeypatch.setattr(lic.license_settings, "license_public_keys", "")
    key = lic.sign_license(_payload(), vendor_key)
    with pytest.raises(lic.LicenseError, match="no trusted"):
        lic.verify_license_key(key)


@pytest.mark.parametrize("bad", ["", "garbage", "PDK1.a", "PDK2.aaaa.bbbb", "PDK1.!!!.???"])
def test_malformed_keys(bad, vendor_key):
    with pytest.raises(lic.LicenseError):
        lic.verify_license_key(bad, public_keys=[vendor_key.public_key()])


def test_expiry_grace_then_community(vendor_key):
    exp = datetime(2026, 6, 1, tzinfo=timezone.utc)
    key = lic.sign_license(_payload(expires_at=exp.isoformat()), vendor_key)
    pk = [vendor_key.public_key()]
    in_grace = lic.verify_license_key(key, public_keys=pk, now=exp + timedelta(days=3), grace_days=14)
    assert in_grace.status == "grace" and in_grace.has("scim")
    gone = lic.verify_license_key(key, public_keys=pk, now=exp + timedelta(days=30), grace_days=14)
    assert gone.status == "expired"
    assert gone.edition == "community"
    assert gone.licensed_edition == "enterprise"
    assert gone.features == frozenset()


def test_payload_validation(vendor_key):
    for bad in (_payload(edition="platinum"), _payload(seats=-1), _payload(license_id=""),
                _payload(features="scim"), _payload(expires_at="tomorrow")):
        with pytest.raises(lic.LicenseError):
            lic.sign_license(bad, vendor_key)


def test_require_feature_rejects_unknown_names():
    with pytest.raises(ValueError):
        lic.require_feature("sso_saml_typo")


def test_hex_public_key_accepted(vendor_key):
    raw = vendor_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    keys = lic.parse_public_keys([raw.hex(), "not-a-key"])
    assert len(keys) == 1


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

async def test_default_is_community(client, trust):
    r = await client.get("/v1/license")
    assert r.status_code == 200
    body = r.json()
    assert body["edition"] == "community"
    assert body["status"] == "community"
    assert body["features"] == []
    assert body["limits"] == {"seats": None, "sites": None, "assets": None}
    assert {f["name"] for f in body["catalogue"]} == set(lic.FEATURES)


async def test_upload_and_remove_license(client, trust):
    key = lic.sign_license(_payload(), trust)
    r = await client.post("/v1/license", json={"key": key})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["edition"] == "enterprise" and body["status"] == "active"
    assert body["source"] == "db"
    assert "scim" in body["features"]
    assert (await client.get("/v1/license")).json()["license_id"] == "lic-test-0001"

    r = await client.delete("/v1/license")
    assert r.status_code == 200
    assert r.json()["edition"] == "community"


async def test_upload_rejects_bad_and_expired(client, trust):
    r = await client.post("/v1/license", json={"key": "PDK1.not.valid-at-all"})
    assert r.status_code == 422
    old = lic.sign_license(_payload(expires_at="2020-01-01T00:00:00Z"), trust)
    r = await client.post("/v1/license", json={"key": old})
    assert r.status_code == 422
    assert (await client.get("/v1/license")).json()["edition"] == "community"


async def test_env_license_used_when_no_db_key(client, trust, monkeypatch):
    monkeypatch.setattr(lic.license_settings, "license_key", lic.sign_license(_payload(edition="team"), trust))
    body = (await client.get("/v1/license")).json()
    assert body["edition"] == "team" and body["source"] == "env"


async def test_invalid_env_license_degrades_to_community(client, trust, monkeypatch):
    monkeypatch.setattr(lic.license_settings, "license_key", "PDK1.bogus.bogus")
    body = (await client.get("/v1/license")).json()
    assert body["edition"] == "community"
    assert body["status"] == "invalid" and body["error"]


async def test_license_file(client, trust, monkeypatch, tmp_path):
    f = tmp_path / "paddock.lic"
    f.write_text(lic.sign_license(_payload(edition="edge"), trust) + "\n")
    monkeypatch.setattr(lic.license_settings, "license_file", str(f))
    body = (await client.get("/v1/license")).json()
    assert body["edition"] == "edge" and body["source"] == "file"
    assert "federation" in body["features"]


async def test_require_feature_dependency(app, trust):
    probe = APIRouter()

    @probe.get("/v1/_probe/scim", dependencies=[Depends(lic.require_feature("scim"))])
    async def _scim():
        return {"ok": True}

    app.include_router(probe)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/v1/_probe/scim")
        assert r.status_code == 402
        detail = r.json()["detail"]
        assert detail["error"] == "feature_not_licensed"
        assert detail["required_edition"] == "enterprise"
        assert detail["current_edition"] == "community"

        await c.post("/v1/license", json={"key": lic.sign_license(_payload(edition="team"), trust)})
        assert (await c.get("/v1/_probe/scim")).status_code == 402  # team lacks scim
        await c.post("/v1/license", json={"key": lic.sign_license(_payload(), trust)})
        assert (await c.get("/v1/_probe/scim")).json() == {"ok": True}


async def test_existing_features_are_not_gated(client, trust):
    """Community = everything that exists today. Spot-check core routes."""
    for path in ("/v1/findings", "/v1/assets", "/v1/scope", "/v1/attack-paths", "/v1/devices"):
        r = await client.get(path)
        assert r.status_code != 402, path


async def test_license_admin_only(client, db_pool, trust):
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        async with db_pool.acquire() as con:
            uid = await con.fetchval(
                "INSERT INTO app_users (username, role, clearance) VALUES ('v1', 'viewer', 'internal') RETURNING id"
            )
            full, prefix, h = auth_svc.generate_api_key()
            await con.execute(
                "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1,'k',$2,$3,ARRAY['read'])",
                uid, prefix, h,
            )
        hdr = {"Authorization": f"Bearer {full}"}
        assert (await client.get("/v1/license", headers=hdr)).status_code == 200
        key = lic.sign_license(_payload(), trust)
        assert (await client.post("/v1/license", json={"key": key}, headers=hdr)).status_code == 403
        assert (await client.delete("/v1/license", headers=hdr)).status_code == 403
        assert (await client.post("/v1/usage/snapshot", headers=hdr)).status_code == 403
        assert (await client.get("/v1/usage", headers=hdr)).status_code == 200
    finally:
        settings.auth_mode = prev


# --------------------------------------------------------------------------- #
# Usage metering
# --------------------------------------------------------------------------- #

async def _seed_usage(pool):
    async with pool.acquire() as con:
        for kind, value in [("domain", "ex.com"), ("subdomain", "a.ex.com"), ("ipv4", "192.0.2.1"),
                            ("port", "192.0.2.1:443"), ("technology", "nginx")]:
            await con.execute(
                "INSERT INTO assets (kind, value, canonical, source) VALUES ($1,$2,$2,'test')", kind, value
            )
        # stale asset: outside the monitored window
        await con.execute(
            "INSERT INTO assets (kind, value, canonical, source, last_seen) "
            "VALUES ('subdomain','old.ex.com','old.ex.com','test', NOW() - INTERVAL '90 days')"
        )
        await con.execute("INSERT INTO scans (kind, target, status) VALUES ('passive','ex.com','completed')")
        await con.execute(
            "INSERT INTO integrations (kind, name, enabled) VALUES ('slack','s1',TRUE), ('webhook','w1',FALSE)"
        )


async def test_usage_counts_and_lazy_snapshot(client, db_pool, trust):
    await _seed_usage(db_pool)
    r = await client.get("/v1/usage")
    assert r.status_code == 200, r.text
    u = r.json()
    assert u["monitored_assets"] == 3          # domain + subdomain + ipv4 (port/tech excluded, stale excluded)
    assert u["total_assets"] == 6
    assert u["assets_by_kind"]["subdomain"] == 2
    assert u["scans_this_month"] == 1
    assert u["integrations"] == 1
    assert u["users"] >= 0
    assert u["sites"] is None and u["sensors"] is None
    assert any("otdiscovery" in n for n in u["notes"])
    assert u["limits"]["assets"] == {"used": 3, "limit": None, "over": False}

    snaps = (await client.get("/v1/usage/snapshots")).json()
    assert len(snaps) == 1 and snaps[0]["monitored_assets"] == 3


async def test_usage_over_limit_reported_not_blocked(client, db_pool, trust):
    await _seed_usage(db_pool)
    await client.post("/v1/license", json={"key": lic.sign_license(_payload(assets=2), trust)})
    u = (await client.get("/v1/usage")).json()
    assert u["edition"] == "enterprise"
    assert u["limits"]["assets"] == {"used": 3, "limit": 2, "over": True}
    assert any("reported only" in n for n in u["notes"])
    # still not blocked
    assert (await client.post("/v1/scans", json={"kind": "passive", "target": "ex.com"})).status_code != 402


async def test_snapshot_endpoint_overwrites_today(client, db_pool, trust):
    s1 = (await client.post("/v1/usage/snapshot")).json()
    assert s1["monitored_assets"] == 0
    await _seed_usage(db_pool)
    s2 = (await client.post("/v1/usage/snapshot")).json()
    assert s2["day"] == s1["day"] and s2["monitored_assets"] == 3
    assert len((await client.get("/v1/usage/snapshots")).json()) == 1


async def test_usage_reads_otdiscovery_sensors(client, trust, monkeypatch):
    from app.routers import licensing as lic_router

    async def fake():
        return 2, 3, None

    monkeypatch.setattr(lic_router, "_otdiscovery_sites", fake)
    u = (await client.get("/v1/usage")).json()
    assert u["sites"] == 2 and u["sensors"] == 3
