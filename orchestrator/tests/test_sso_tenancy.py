"""SSO browser login for providers of NON-default tenants.

The unauthenticated flow (start / callback / ACS / SLS / exchange) only knows a
provider slug. Every test here serves the app through the non-superuser
``paddock_app`` pool (RLS enforced) in BOTH suite modes, so a provider owned by
tenant B is invisible unless the flow resolves the slug's tenant first.
"""
from __future__ import annotations

import httpx
import jwt
import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.identity import oidc
from app.identity import saml as saml_mod
from app.routers import sso as sso_router

from ._identity_fakes import SPA_VERIFIER, FakeIdP, callback, oidc_provider_body, s256, start
from .stress_world import seed_admin

T_B = "00000000-0000-0000-0000-0000000000b2"
DEFAULT = tenancy.DEFAULT_TENANT_ID


def _h(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture(autouse=True)
def _reset_limiter():
    sso_router._starts.clear()
    yield
    sso_router._starts.clear()


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    oidc.reset_caches()
    oidc.set_transport(httpx.MockTransport(fake.handler))

    async def _no_dns(url, *, allow_private):
        return None

    monkeypatch.setattr(oidc, "check_url", _no_dns)
    yield fake
    oidc.set_transport(None)
    oidc.reset_caches()


@pytest_asyncio.fixture
async def world(app, app_pool, db_pool, client, monkeypatch):
    """Default tenant + tenant B, each with an admin API key, enforce mode,
    app served through the RLS-enforced pool."""
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    monkeypatch.setattr(sso_router.secret_box, "has_persistent_key", lambda: True)
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="tenant-b", name="Tenant B", tenant_id=T_B)
    key_d = await seed_admin(db_pool, DEFAULT, "admin-d")
    key_b = await seed_admin(db_pool, T_B, "admin-b")
    return {"d": key_d, "b": key_b}


async def _create_oidc(client, key, slug, **over):
    r = await client.post("/v1/auth/sso/admin/providers", headers=_h(key), json=oidc_provider_body(slug, **over))
    assert r.status_code == 201, r.text
    return r.json()


async def _oidc_login(client, idp, slug, **claims):
    q = await start(client, slug)
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"], **claims)
    return await callback(client, slug, code=code, state=q["state"])


async def _exchange(client, code, verifier=SPA_VERIFIER):
    return await client.post("/v1/auth/sso/exchange", json={"code": code, "verifier": verifier})


# --------------------------------------------------------------------------- #
# OIDC
# --------------------------------------------------------------------------- #

async def test_oidc_login_in_second_tenant_end_to_end(world, client, db_pool, idp):
    await _create_oidc(client, world["b"], "okta-b")
    # the provider is B's, not the default tenant's
    async with db_pool.acquire() as con:
        assert str(await con.fetchval("SELECT tenant_id FROM identity_providers WHERE slug='okta-b'")) == T_B

    out = await _oidc_login(client, idp, "okta-b")
    assert "error" not in out and "code" in out, out
    r = await _exchange(client, out["code"])
    assert r.status_code == 200, r.text
    tok = r.json()
    assert jwt.decode(tok["access_token"], options={"verify_signature": False})["tid"] == T_B
    assert tok["username"] == "alice@example.com" and tok["role"] == "analyst"

    me = await client.get("/v1/auth/me", headers=_h(tok["access_token"]))
    assert me.status_code == 200 and me.json()["tenant_id"] == T_B

    async with db_pool.acquire() as con:
        u = await con.fetchrow("SELECT tenant_id, provisioned_by FROM app_users WHERE username = 'alice@example.com'")
        link = await con.fetchrow("SELECT tenant_id FROM user_identities")
        audit_tenants = {str(r["tenant_id"]) for r in await con.fetch(
            "SELECT tenant_id FROM audit_log WHERE action = 'login' AND resource_type = 'sso'")}
        left = await con.fetchval("SELECT count(*) FROM sso_login_states")
    assert str(u["tenant_id"]) == T_B and u["provisioned_by"] == "sso:okta-b"
    assert str(link["tenant_id"]) == T_B
    assert audit_tenants == {T_B}
    assert left == 0

    # the code is single use, and the issued session works only in tenant B
    assert (await _exchange(client, out["code"])).status_code == 400
    assert (await client.get("/v1/findings", headers=_h(tok["access_token"]))).status_code == 200


async def test_exchange_code_is_bound_to_its_tenant(world, client, idp):
    await _create_oidc(client, world["b"], "okta-b")
    out = await _oidc_login(client, idp, "okta-b")
    head, _, tail = out["code"].partition(".")
    assert head == T_B.replace("-", "")
    # re-pointing the code at another tenant finds nothing (and a malformed
    # prefix is refused outright)
    forged = DEFAULT.replace("-", "") + "." + tail
    assert (await _exchange(client, forged)).status_code == 400
    assert (await _exchange(client, "zz" * 16 + "." + tail)).status_code == 400
    # the genuine code was not burned by those attempts
    assert (await _exchange(client, out["code"])).status_code == 200


async def test_callback_with_state_from_other_tenants_provider_is_refused(world, client, idp):
    await _create_oidc(client, world["d"], "okta")
    await _create_oidc(client, world["b"], "okta-b")
    q = await start(client, "okta")                       # state minted for tenant A's provider
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"])
    out = await callback(client, "okta-b", code=code, state=q["state"])
    assert out == {"error": "state_mismatch"}
    # the other direction too
    sso_router._starts.clear()
    qb = await start(client, "okta-b")
    codeb = idp.issue_code(nonce=qb["nonce"], code_challenge=qb["code_challenge"])
    assert await callback(client, "okta", code=codeb, state=qb["state"]) == {"error": "state_mismatch"}


async def test_unknown_slug_and_cross_tenant_disabled_provider(world, client, idp):
    await _create_oidc(client, world["b"], "okta-b", enabled=False)
    r = await client.get("/v1/auth/sso/okta-b/start", params={"spa_challenge": s256(SPA_VERIFIER)})
    assert r.status_code == 404
    r = await client.get("/v1/auth/sso/nope/start", params={"spa_challenge": s256(SPA_VERIFIER)})
    assert r.status_code == 404


async def test_jit_username_collision_across_tenants_is_refused(world, client, db_pool, idp):
    # tenant A already owns alice@example.com
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, email, role, clearance, tenant_id) "
            "VALUES ('alice@example.com', 'alice@example.com', 'viewer', 'internal', $1)", DEFAULT)
    await _create_oidc(client, world["b"], "okta-b")
    out = await _oidc_login(client, idp, "okta-b")
    assert out == {"error": "account_conflict"}
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT tenant_id, role, provisioned_by FROM app_users WHERE username = 'alice@example.com'")
        assert await con.fetchval("SELECT count(*) FROM user_identities") == 0
        detail = await con.fetchval(
            "SELECT details::text FROM audit_log WHERE action='login' AND resource_id='okta-b' "
            "ORDER BY id DESC LIMIT 1")
    # A's account is untouched, nothing was created in B
    assert len(rows) == 1 and str(rows[0]["tenant_id"]) == DEFAULT and rows[0]["role"] == "viewer"
    assert "another organization" in detail


async def test_same_email_in_other_tenant_cannot_be_taken_over(world, client, db_pool, idp):
    """Even a verified-email match only ever looks inside the provider's tenant."""
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, email, role, clearance, tenant_id) "
            "VALUES ('legacy-alice', 'alice@example.com', 'admin', 'restricted', $1)", DEFAULT)
    await _create_oidc(client, world["b"], "okta-b")
    out = await _oidc_login(client, idp, "okta-b")
    assert "code" in out
    tok = (await _exchange(client, out["code"])).json()
    assert tok["username"] == "alice@example.com" and tok["role"] == "analyst"   # a NEW tenant-B user
    async with db_pool.acquire() as con:
        legacy = await con.fetchrow("SELECT role, last_login FROM app_users WHERE username = 'legacy-alice'")
    assert legacy["role"] == "admin" and legacy["last_login"] is None


async def test_providers_list_is_per_tenant(world, client, idp):
    await _create_oidc(client, world["d"], "okta")
    await _create_oidc(client, world["b"], "okta-b")
    default = (await client.get("/v1/auth/sso/providers")).json()
    assert [p["slug"] for p in default["providers"]] == ["okta"]
    b = (await client.get("/v1/auth/sso/providers", params={"tenant": "tenant-b"})).json()
    assert [p["slug"] for p in b["providers"]] == ["okta-b"]
    gone = (await client.get("/v1/auth/sso/providers", params={"tenant": "nope"})).json()
    assert gone == {"providers": [], "sso_required": False}


async def test_provider_slug_is_globally_unique(world, client, idp):
    await _create_oidc(client, world["d"], "okta")
    r = await client.post("/v1/auth/sso/admin/providers", headers=_h(world["b"]), json=oidc_provider_body("okta"))
    assert r.status_code == 409


# --------------------------------------------------------------------------- #
# SSO-required gating per tenant
# --------------------------------------------------------------------------- #

async def _seed_pw_user(db_pool, tenant, username):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, 'viewer', 'internal', $2, $3)", username, auth_svc.hash_password("pw"), tenant)


async def _login(client, username, password="pw"):
    return await client.post("/v1/auth/login", json={"username": username, "password": password})


async def test_sso_required_is_enforced_per_tenant(world, client, db_pool):
    await _create_oidc(client, world["b"], "okta-b")     # SSO can only be required once a provider exists
    await _create_oidc(client, world["d"], "okta")
    await _seed_pw_user(db_pool, T_B, "bob-b")
    await _seed_pw_user(db_pool, DEFAULT, "dan-d")
    r = await client.put("/v1/auth/sso/admin/settings", headers=_h(world["b"]),
                         json={"sso_required": True, "break_glass_users": ["admin-b"]})
    assert r.status_code == 200, r.text
    # tenant B requires SSO: its users are blocked, its break-glass admin is not,
    assert (await _login(client, "bob-b")).status_code == 403
    ok = await _login(client, "admin-b", "pw-admin-b")
    assert ok.status_code == 200
    assert jwt.decode(ok.json()["access_token"], options={"verify_signature": False})["tid"] == T_B
    # ... and tenant A (default), which does not, is unaffected.
    assert (await _login(client, "dan-d")).status_code == 200

    # Inverse: A requires SSO, B does not.
    await client.put("/v1/auth/sso/admin/settings", headers=_h(world["b"]), json={"sso_required": False})
    r = await client.put("/v1/auth/sso/admin/settings", headers=_h(world["d"]),
                         json={"sso_required": True, "break_glass_users": ["admin-d"]})
    assert r.status_code == 200, r.text
    assert (await _login(client, "dan-d")).status_code == 403
    assert (await _login(client, "bob-b")).status_code == 200
    assert (await _login(client, "admin-d", "pw-admin-d")).status_code == 200
    # the public provider list reports each tenant's own policy
    assert (await client.get("/v1/auth/sso/providers")).json()["sso_required"] is True
    assert (await client.get("/v1/auth/sso/providers", params={"tenant": "tenant-b"})).json()["sso_required"] is False


# --------------------------------------------------------------------------- #
# OIDC logout + SCIM in tenant B
# --------------------------------------------------------------------------- #

async def test_logout_in_second_tenant_revokes_session(world, client, idp):
    await _create_oidc(client, world["b"], "okta-b")
    out = await _oidc_login(client, idp, "okta-b")
    tok = (await _exchange(client, out["code"])).json()["access_token"]
    assert (await client.get("/v1/auth/me", headers=_h(tok))).status_code == 200
    r = await client.post("/v1/auth/sso/logout", headers=_h(tok))
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert (await client.get("/v1/auth/me", headers=_h(tok))).status_code == 401


async def test_scim_in_second_tenant_still_works(world, client, db_pool):
    r = await client.post("/v1/auth/sso/admin/scim-tokens", headers=_h(world["b"]), json={"name": "scim"})
    assert r.status_code == 201, r.text
    hdr = {"Authorization": f"Bearer {r.json()['token']}", "Content-Type": "application/scim+json"}
    # per-tenant identity_settings drives SCIM defaults
    r = await client.put("/v1/auth/sso/admin/settings", headers=_h(world["b"]),
                         json={"scim_default_role": "analyst"})
    assert r.status_code == 200, r.text
    u = await client.post("/scim/v2/Users", headers=hdr, json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scim-user@b.example", "active": True,
        "emails": [{"value": "scim-user@b.example", "primary": True}],
    })
    assert u.status_code == 201, u.text
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT tenant_id, role FROM app_users WHERE username = 'scim-user@b.example'")
        s_b = await con.fetchval("SELECT scim_default_role FROM identity_settings WHERE tenant_id = $1", T_B)
        s_d = await con.fetchval("SELECT scim_default_role FROM identity_settings WHERE tenant_id = $1", DEFAULT)
    assert str(row["tenant_id"]) == T_B and row["role"] == "analyst"
    assert s_b == "analyst" and s_d != "analyst"         # identity_settings is per tenant
    lst = await client.get("/scim/v2/Users", headers=hdr)
    assert lst.status_code == 200 and "scim-user@b.example" in lst.text


# --------------------------------------------------------------------------- #
# SAML
# --------------------------------------------------------------------------- #

saml = pytest.mark.skipif(
    not saml_mod.SAML_AVAILABLE, reason=f"python3-saml unavailable: {saml_mod.SAML_IMPORT_ERROR}",
)


@pytest_asyncio.fixture
async def saml_b(world, client):
    from .test_identity_saml import FakeSamlIdP

    test_idp = FakeSamlIdP()
    r = await client.post("/v1/auth/sso/admin/providers", headers=_h(world["b"]), json={
        "slug": "corp-saml", "kind": "saml", "display_name": "Corp SAML",
        "saml_metadata_xml": test_idp.metadata(),
        "role_mappings": [{"group": "paddock-analysts", "role": "analyst"}],
    })
    assert r.status_code == 201, r.text
    return test_idp


@saml
async def test_saml_login_in_second_tenant_end_to_end(world, client, db_pool, saml_b):
    from .test_identity_saml import _post, _start

    req_id, relay = await _start(client)
    out = await _post(client, saml_b.response(in_response_to=req_id), relay)
    assert "code" in out and out["next"] == "/graph", out
    r = await _exchange(client, out["code"])
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["username"] == "erin@corp.example" and tok["role"] == "analyst"
    assert jwt.decode(tok["access_token"], options={"verify_signature": False})["tid"] == T_B
    me = await client.get("/v1/auth/me", headers=_h(tok["access_token"]))
    assert me.status_code == 200 and me.json()["tenant_id"] == T_B
    async with db_pool.acquire() as con:
        tenants = {str(r["tenant_id"]) for r in await con.fetch(
            "SELECT tenant_id FROM app_users WHERE username = 'erin@corp.example' "
            "UNION ALL SELECT tenant_id FROM user_identities UNION ALL SELECT tenant_id FROM sso_replay_cache")}
    assert tenants == {T_B}
    # SP metadata is served for a non-default tenant's provider too
    assert (await client.get("/v1/auth/sso/corp-saml/metadata")).status_code == 200


@saml
async def test_saml_acs_with_state_of_other_tenants_provider_is_refused(world, client, saml_b, idp):
    from .test_identity_saml import _post

    await _create_oidc(client, world["d"], "okta")
    q = await start(client, "okta")                     # RelayState minted for tenant A's provider
    resp = saml_b.response(in_response_to="_whatever")
    assert await _post(client, resp, q["state"]) == {"error": "state_mismatch"}


@saml
async def test_saml_jit_collision_across_tenants_is_refused(world, client, db_pool, saml_b):
    from .test_identity_saml import _post, _start

    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, role, clearance, tenant_id) "
            "VALUES ('erin@corp.example', 'viewer', 'internal', $1)", DEFAULT)
    req_id, relay = await _start(client)
    assert await _post(client, saml_b.response(in_response_to=req_id), relay) == {"error": "account_conflict"}
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM app_users WHERE username = 'erin@corp.example'") == 1


@saml
async def test_saml_sls_in_second_tenant(world, client, db_pool, saml_b):
    from .test_identity_saml import _post, _start
    from .test_identity_saml_hardening import (
        idp_message,
        logout_request_xml,
        logout_response_xml,
        parse_query,
        request_id_of,
    )

    async def login():
        req_id, relay = await _start(client)
        out = await _post(client, saml_b.response(in_response_to=req_id), relay)
        tok = (await _exchange(client, out["code"])).json()["access_token"]
        return _h(tok), saml_b.last_session_index

    # IdP-initiated LogoutRequest ends the session of tenant B's user
    hdr, sidx = await login()
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200
    q = idp_message("SAMLRequest", logout_request_xml("erin@corp.example", sidx), saml_b, relay="/after")
    r = await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")
    assert r.status_code == 302, r.text
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 401

    # SP-initiated: the logout state is bound to B and consumed by B's /sls
    await db_pool.execute("UPDATE app_users SET sessions_revoked_at = NULL")
    await db_pool.execute(
        "UPDATE identity_providers SET config = jsonb_set(config, '{idp_slo_url}', '\"https://idp.saml.example/slo\"')")
    hdr, _ = await login()
    r = await client.post("/v1/auth/sso/logout", headers=hdr)
    assert r.status_code == 200, r.text
    url = r.json()["idp_logout_url"]
    assert url
    parts = parse_query(url)
    q = idp_message("SAMLResponse", logout_response_xml(request_id_of(parts["SAMLRequest"])), saml_b,
                    relay=parts["RelayState"])
    ok = await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")
    assert ok.status_code == 303, ok.text
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")).status_code == 400
    # unknown provider slug
    assert (await client.get("/v1/auth/sso/nope/sls?SAMLRequest=abc")).status_code == 404
