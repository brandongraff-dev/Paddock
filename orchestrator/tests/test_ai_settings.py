"""Settings -> System -> AI features: the optional Anthropic key.

The unit tests need no database. The route tests need Postgres (the `client`
fixture) and cover who may read, write and fetch the key.
"""
from __future__ import annotations

import base64
import os

import pytest

from app import ai_settings, auth as auth_svc, service_routes
from app.config import settings
from app.integrations import secrets as secrets_mod

KEY = "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" * 2
SVC = "svc-secret-ai-123"


# ---------------------------------------------------------------- no database

def test_clean_key_accepts_real_shapes_and_trims_copy_paste_debris():
    assert ai_settings.clean_key(KEY) == KEY
    assert ai_settings.clean_key(f'  "{KEY}"\n') == KEY
    assert ai_settings.clean_key(f"'{KEY}'") == KEY


@pytest.mark.parametrize("bad", ["", "hunter2", "sk-ant-", "sk-ant-short", "sk-proj-" + "a" * 40,
                                 "sk-ant-" + "a" * 30 + " " + "b" * 5, "sk-ant-" + "a" * 500])
def test_clean_key_rejects_anything_else_with_a_plain_message(bad):
    with pytest.raises(Exception) as e:
        ai_settings.clean_key(bad)
    assert getattr(e.value, "status_code", None) == 422
    assert "Anthropic API key" in e.value.detail


def test_hint_never_reveals_more_than_four_characters():
    assert ai_settings.hint_for(KEY) == "…" + KEY[-4:]
    assert KEY[:-4] not in ai_settings.hint_for(KEY)


def test_roundtrip_and_purpose_binding(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    blob = secrets_mod.encrypt_secrets({"anthropic_api_key": KEY}, aad=ai_settings.AAD)
    assert KEY not in blob and blob.startswith("v1:")
    assert secrets_mod.decrypt_secrets(blob, aad=ai_settings.AAD)["anthropic_api_key"] == KEY
    # an integration credential blob cannot be swapped in, nor the reverse
    with pytest.raises(Exception):
        secrets_mod.decrypt_secrets(blob)
    other = secrets_mod.encrypt_secrets({"anthropic_api_key": KEY})
    with pytest.raises(Exception):
        secrets_mod.decrypt_secrets(other, aad=ai_settings.AAD)


def test_integration_secrets_are_unchanged_by_the_new_aad_parameter(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    assert secrets_mod.decrypt_secrets(secrets_mod.encrypt_secrets({"t": "x"})) == {"t": "x"}


def test_route_permissions():
    cap = auth_svc.required_capability
    assert cap("GET", "/v1/system/ai") == "admin"
    assert cap("PUT", "/v1/system/ai") == "admin"
    assert cap("DELETE", "/v1/system/ai") == "admin"
    assert cap("GET", "/v1/system/ai/credential") == "write"       # + the route insists on the service key
    for role in ("viewer", "analyst", "auditor"):
        assert "write" not in auth_svc.ROLE_CAPABILITIES[role]


def test_strict_tenancy_allow_list_includes_only_the_credential_read():
    assert service_routes.permitted("GET", "/v1/system/ai/credential")
    assert not service_routes.permitted("PUT", "/v1/system/ai")
    assert not service_routes.permitted("GET", "/v1/system/ai")


# ------------------------------------------------------------- with Postgres

@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(settings, "service_api_key", SVC)
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(ai_settings.system_mod, "_probe_service", _fake_probe)


async def _fake_probe(_url: str) -> str:
    return "up"


async def test_admin_saves_key_which_is_never_echoed_and_only_the_service_key_can_read_it(enforce, client, db_pool):
    from .test_governance import _hdr, _seed_user_with_key

    _, admin = await _seed_user_with_key(db_pool, "ada", "admin", "public")
    _, viewer = await _seed_user_with_key(db_pool, "vera", "viewer", "public")

    assert (await client.get("/v1/system/ai")).status_code == 401
    assert (await client.get("/v1/system/ai", headers=_hdr(viewer))).status_code == 403
    assert (await client.put("/v1/system/ai", headers=_hdr(viewer), json={"api_key": KEY})).status_code == 403

    r = await client.get("/v1/system/ai", headers=_hdr(admin))
    assert r.status_code == 200 and r.json()["configured"] is False and r.json()["editable"] is True

    bad = await client.put("/v1/system/ai", headers=_hdr(admin), json={"api_key": "nope"})
    assert bad.status_code == 422 and "Anthropic API key" in bad.text

    r = await client.put("/v1/system/ai", headers=_hdr(admin), json={"api_key": f" {KEY}\n"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True and body["hint"] == "…" + KEY[-4:] and body["updated_by"]
    assert KEY not in r.text and KEY not in (await client.get("/v1/system/ai", headers=_hdr(admin))).text

    # at rest: ciphertext only
    async with db_pool.acquire() as con:
        stored = await con.fetchval("SELECT anthropic_secret FROM ai_settings")
        audit = await con.fetch("SELECT * FROM audit_log")
    assert stored.startswith("v1:") and KEY not in stored and KEY[-12:] not in stored
    assert all(KEY not in repr(dict(a)) for a in audit), "the key must never reach the audit trail"

    # the credential route: not for users, not even admins, not anonymous
    assert (await client.get("/v1/system/ai/credential")).status_code == 401
    assert (await client.get("/v1/system/ai/credential", headers=_hdr(viewer))).status_code == 403
    assert (await client.get("/v1/system/ai/credential", headers=_hdr(admin))).status_code == 403
    r = await client.get("/v1/system/ai/credential", headers={"X-API-Key": SVC})
    assert r.status_code == 200 and r.json() == {"api_key": KEY}
    assert r.headers["cache-control"] == "no-store"


async def test_remove_key_and_missing_key(enforce, client, db_pool):
    from .test_governance import _hdr, _seed_user_with_key

    _, admin = await _seed_user_with_key(db_pool, "ada", "admin", "public")
    assert (await client.get("/v1/system/ai/credential", headers={"X-API-Key": SVC})).json() == {"api_key": None}
    assert (await client.put("/v1/system/ai", headers=_hdr(admin), json={"api_key": KEY})).status_code == 200
    r = await client.delete("/v1/system/ai", headers=_hdr(admin))
    assert r.status_code == 200 and r.json()["configured"] is False
    assert (await client.get("/v1/system/ai/credential", headers={"X-API-Key": SVC})).json() == {"api_key": None}


async def test_refuses_to_store_without_a_persistent_secret_key(enforce, client, db_pool, monkeypatch):
    from .test_governance import _hdr, _seed_user_with_key

    monkeypatch.delenv("PADDOCK_SECRET_KEY")
    _, admin = await _seed_user_with_key(db_pool, "ada", "admin", "public")
    r = await client.put("/v1/system/ai", headers=_hdr(admin), json={"api_key": KEY})
    assert r.status_code == 503 and "PADDOCK_SECRET_KEY" in r.text
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM ai_settings") == 0
