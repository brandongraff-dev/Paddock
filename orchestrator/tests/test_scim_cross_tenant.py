"""SCIM bearer tokens are tenant-bound: tenant B's token never reaches A's
users / groups, and both tenants can own a group with the SAME displayName
(schema 036 made scim_groups.display_name unique per tenant)."""
from __future__ import annotations

import uuid

import pytest

from app.config import settings

from . import stress_world as sw

SCIM = "application/scim+json"


@pytest.fixture
def stress_settings(monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", sw.SERVICE_KEY)
    yield


async def _scim_token(client, tenant) -> dict:
    r = await client.post("/v1/auth/sso/admin/scim-tokens", headers=tenant.headers(), json={"name": "scim"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}", "Content-Type": SCIM}


async def test_scim_tokens_cannot_cross_tenants(stress_settings, app, app_pool, db_pool, client):
    w = await sw.build_world(db_pool=db_pool, app_pool=app_pool, app=app, client=client, generic=False)
    ha, hb = await _scim_token(client, w["a"]), await _scim_token(client, w["b"])
    schema = ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    # Same displayName in both tenants must both be creatable.
    ga = await client.post("/scim/v2/Groups", headers=ha, json={"schemas": schema, "displayName": "Admins zqamark"})
    gb = await client.post("/scim/v2/Groups", headers=hb, json={"schemas": schema, "displayName": "Admins zqbmark"})
    assert ga.status_code == 201 and gb.status_code == 201, (ga.text, gb.text)
    same_a = await client.post("/scim/v2/Groups", headers=ha, json={"schemas": schema, "displayName": "Shared"})
    same_b = await client.post("/scim/v2/Groups", headers=hb, json={"schemas": schema, "displayName": "Shared"})
    assert same_a.status_code == 201 and same_b.status_code == 201, (same_a.text, same_b.text)
    # A duplicate INSIDE one tenant is still refused.
    dup = await client.post("/scim/v2/Groups", headers=ha, json={"schemas": schema, "displayName": "Shared"})
    assert dup.status_code == 409

    gid_a = ga.json()["id"]
    for method, url in (("GET", f"/scim/v2/Groups/{gid_a}"), ("DELETE", f"/scim/v2/Groups/{gid_a}"),
                        ("GET", f"/scim/v2/Groups/{uuid.uuid4()}")):
        r = await client.request(method, url, headers=hb)
        assert r.status_code == 404, (method, url, r.status_code, r.text)
    r = await client.patch(f"/scim/v2/Groups/{gid_a}", headers=hb, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "pwned"}]})
    assert r.status_code == 404
    r = await client.put(f"/scim/v2/Groups/{gid_a}", headers=hb, json={"schemas": schema, "displayName": "pwned"})
    assert r.status_code == 404

    for path in ("/scim/v2/Groups", "/scim/v2/Users"):
        lb = await client.get(path, headers=hb)
        assert lb.status_code == 200
        assert "zqamark" not in lb.text.lower() and "admin-a" not in lb.text.lower()
        la = await client.get(path, headers=ha)
        assert "zqbmark" not in la.text.lower() and "admin-b" not in la.text.lower()
    # A's group survived B's attempts.
    assert (await client.get(f"/scim/v2/Groups/{gid_a}", headers=ha)).status_code == 200
    # B's SCIM token is no key to anything else.
    assert (await client.get("/v1/findings", headers=hb)).status_code in (401, 403)
