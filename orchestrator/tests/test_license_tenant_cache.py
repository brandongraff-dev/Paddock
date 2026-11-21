"""The effective-license cache must be per tenant (found by the isolation sweep).

Regression: ``licensing.current_license`` cached ONE license per app for
``license_cache_ttl_sec``, so right after tenant A uploaded its key every other
tenant was served A's licensee / edition / features (and A could be served a
downgrade by B's request).
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import licensing as lic
from app.config import settings

from . import stress_world as sw


@pytest.fixture
def trusted_vendor(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    monkeypatch.setattr(lic.license_settings, "license_public_keys", pub)
    monkeypatch.setattr(lic.license_settings, "license_key", None)
    monkeypatch.setattr(lic.license_settings, "license_file", None)
    monkeypatch.setattr(lic.license_settings, "license_cache_ttl_sec", 300.0)  # a long TTL: the bug window
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", sw.SERVICE_KEY)
    return priv


async def test_license_cache_is_per_tenant(trusted_vendor, app, app_pool, db_pool, client):
    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client, generic=False)
    key = lic.sign_license({
        "v": 1, "license_id": "lic-tenant-a-only", "licensee": "Tenant A Secret Corp", "edition": "enterprise",
        "seats": 25, "sites": 3, "assets": 5000, "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(), "features": [],
    }, trusted_vendor)

    # B warms ITS cache (community), then A uploads, then both read.
    rb0 = await client.get("/v1/license", headers=w["b"].headers())
    assert rb0.status_code == 200 and rb0.json()["edition"] == "community"
    up = await client.post("/v1/license", headers=w["a"].headers(), json={"key": key})
    assert up.status_code == 200, up.text
    ra = await client.get("/v1/license", headers=w["a"].headers())
    rb = await client.get("/v1/license", headers=w["b"].headers())
    rm = await client.get("/v1/license", headers=w["m"].headers())
    assert ra.json()["edition"] == "enterprise"
    for r in (rb, rm):
        assert r.json()["edition"] == "community"
        assert "Tenant A Secret Corp" not in r.text and "lic-tenant-a-only" not in r.text
    # and the other order: B reads first on a cold cache, A must still be enterprise
    lic.invalidate_cache(app)
    rb2 = await client.get("/v1/license", headers=w["b"].headers())
    ra2 = await client.get("/v1/license", headers=w["a"].headers())
    assert rb2.json()["edition"] == "community" and ra2.json()["edition"] == "enterprise"
