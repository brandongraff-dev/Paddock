"""SSO logout ends Paddock sessions (JWT watermark) and, where the IdP offers
it, hands back the IdP logout URL. OIDC flavour; SAML SLO lives in
test_identity_saml_hardening.py."""
from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from app.config import settings
from app.identity import oidc
from app.routers import sso as sso_router

from ._identity_fakes import ISSUER, SPA_VERIFIER, FakeIdP, full_login, oidc_provider_body


@pytest.fixture(autouse=True)
def _reset():
    sso_router._starts.clear()
    yield
    sso_router._starts.clear()


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    oidc.reset_caches()

    def handler(request: httpx.Request) -> httpx.Response:
        r = fake.handler(request)
        if str(request.url).endswith("/.well-known/openid-configuration"):
            doc = r.json()
            doc["end_session_endpoint"] = ISSUER + "/v1/logout"
            return httpx.Response(200, json=doc)
        return r

    oidc.set_transport(httpx.MockTransport(handler))

    async def _no_dns(url, *, allow_private):
        return None

    monkeypatch.setattr(oidc, "check_url", _no_dns)
    yield fake
    oidc.set_transport(None)
    oidc.reset_caches()


@pytest_asyncio.fixture
async def session(client, idp):
    r = await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body())
    assert r.status_code == 201, r.text
    out = await full_login(client, idp)
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        tok = await client.post("/v1/auth/sso/exchange", json={"code": out["code"], "verifier": SPA_VERIFIER})
        assert tok.status_code == 200, tok.text
        yield {"Authorization": f"Bearer {tok.json()['access_token']}"}
    finally:
        settings.auth_mode = prev


async def test_oidc_logout_revokes_the_session_and_returns_idp_logout_url(client, session):
    assert (await client.get("/v1/auth/me", headers=session)).status_code == 200
    r = await client.post("/v1/auth/sso/logout", headers=session)
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] is True
    url = r.json()["idp_logout_url"]
    assert url.startswith(ISSUER + "/v1/logout?") and "client_id=paddock-client" in url
    assert (await client.get("/v1/auth/me", headers=session)).status_code == 401
    # a second logout with the dead token is simply unauthenticated
    assert (await client.post("/v1/auth/sso/logout", headers=session)).status_code == 401


async def test_logout_is_audited(client, db_pool, session):
    await client.post("/v1/auth/sso/logout", headers=session)
    async with db_pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT actor, resource_id, details FROM audit_log WHERE action = 'logout' ORDER BY id DESC LIMIT 1")
    assert row["actor"] == "alice@example.com" and row["resource_id"] == "okta"
    assert "success" in str(row["details"])


async def test_logout_only_ends_the_callers_own_sessions(client, db_pool, idp, session):
    out = await full_login(client, idp, sub="00u-bob", email="bob@example.com")
    tok = await client.post("/v1/auth/sso/exchange", json={"code": out["code"], "verifier": SPA_VERIFIER})
    bob = {"Authorization": f"Bearer {tok.json()['access_token']}"}
    await client.post("/v1/auth/sso/logout", headers=session)
    assert (await client.get("/v1/auth/me", headers=session)).status_code == 401
    assert (await client.get("/v1/auth/me", headers=bob)).status_code == 200


async def test_logout_refuses_non_session_principals(client, db_pool, session):
    """API keys / service principals have no interactive session to end."""
    settings_mode = settings.auth_mode
    settings.auth_mode = "dev"            # synthetic dev admin: kind == "dev"
    try:
        r = await client.post("/v1/auth/sso/logout")
    finally:
        settings.auth_mode = settings_mode
    assert r.status_code == 400
