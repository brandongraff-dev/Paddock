"""OIDC SSO: a fake IdP (RSA key, discovery + JWKS + token endpoint over
httpx.MockTransport) drives the real /v1/auth/sso flow end to end."""
from __future__ import annotations

import time

import httpx
import jwt
import pytest
import pytest_asyncio

from app import auth as auth_svc
from app.config import settings
from app.identity import mapping, oidc
from app.identity import store as id_store
from app.routers import sso as sso_router

from ._identity_fakes import (
    CLIENT_ID,
    ISSUER,
    SPA_VERIFIER,
    FakeIdP,
    callback,
    full_login,
    new_key,
    oidc_provider_body,
    start,
)


@pytest.fixture(autouse=True)
def _reset_start_limiter():
    sso_router._starts.clear()
    yield
    sso_router._starts.clear()


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    oidc.reset_caches()
    oidc.set_transport(httpx.MockTransport(fake.handler))

    async def _no_dns(url, *, allow_private):  # the fake host doesn't resolve
        return None

    monkeypatch.setattr(oidc, "check_url", _no_dns)
    yield fake
    oidc.set_transport(None)
    oidc.reset_caches()


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


@pytest_asyncio.fixture
async def okta(client, idp):
    r = await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body())
    assert r.status_code == 201, r.text
    return r.json()


async def _user(pool, username):
    async with pool.acquire() as con:
        return await con.fetchrow("SELECT * FROM app_users WHERE username = $1", username)


async def _exchange(client, code, verifier=SPA_VERIFIER):
    body = {"code": code}
    if verifier:
        body["verifier"] = verifier
    return await client.post("/v1/auth/sso/exchange", json=body)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #

async def test_happy_path_jit_mapping_exchange_and_me(client, db_pool, idp, okta, enforce):
    q = await start(client)
    # PKCE S256 + state + nonce are always sent; never the implicit flow.
    assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
    assert q["client_id"] == CLIENT_ID and q["state"] and q["nonce"]
    assert q["redirect_uri"] == "http://localhost:8080/v1/auth/sso/okta/callback"
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"])
    out = await callback(client, "okta", code=code, state=q["state"])
    assert "error" not in out and out["next"] == "/findings"
    # client_secret_basic + PKCE verifier were sent to the token endpoint
    assert idp.token_requests[-1]["auth"].startswith("Basic ")
    assert "code_verifier" in idp.token_requests[-1]["form"]

    u = await _user(db_pool, "alice@example.com")
    assert u["role"] == "analyst" and u["clearance"] == "confidential"
    assert u["pw_hash"] is None and u["provisioned_by"] == "sso:okta"

    r = await _exchange(client, out["code"])
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["role"] == "analyst" and tok["username"] == "alice@example.com"
    me = await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {tok['access_token']}"})
    assert me.status_code == 200 and me.json()["actor"] == "alice@example.com"

    # the one-time code is single use
    assert (await _exchange(client, out["code"])).status_code == 400

    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT actor, details FROM audit_log WHERE action = 'login' AND resource_type = 'sso'"
        )
    assert any('"success"' in str(r["details"]) and r["actor"] == "alice@example.com" for r in rows)
    # no secret / token material in the audit trail
    async with db_pool.acquire() as con:
        blob = " ".join(str(r["details"]) for r in await con.fetch("SELECT details FROM audit_log"))
    assert "s3cret" not in blob and out["code"] not in blob


async def test_exchange_requires_the_spa_verifier(client, idp, okta):
    out = await full_login(client, idp)
    assert (await _exchange(client, out["code"], verifier=None)).status_code == 400
    # ...and the failed attempt burned the code
    assert (await _exchange(client, out["code"])).status_code == 400


async def test_exchange_with_wrong_verifier(client, idp, okta):
    out = await full_login(client, idp)
    assert (await _exchange(client, out["code"], verifier="y" * 50)).status_code == 400


async def test_expired_exchange_code(client, db_pool, idp, okta):
    out = await full_login(client, idp)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE sso_exchange_codes SET expires_at = NOW() - INTERVAL '1 second'")
    assert (await _exchange(client, out["code"])).status_code == 400


# --------------------------------------------------------------------------- #
# ID token validation failures
# --------------------------------------------------------------------------- #

async def _login_with_token(client, idp, build):
    q = await start(client)
    tok = build(q["nonce"])
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"], id_token=tok)
    return await callback(client, "okta", code=code, state=q["state"])


async def _no_users_created(pool):
    async with pool.acquire() as con:
        return await con.fetchval("SELECT count(*) FROM app_users WHERE provisioned_by LIKE 'sso:%'") == 0


async def test_bad_signature_rejected(client, db_pool, idp, okta):
    attacker = new_key()
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n), key=attacker))
    assert out == {"error": "invalid_token"}
    assert await _no_users_created(db_pool)


async def test_wrong_audience_rejected(client, db_pool, idp, okta):
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n, aud="someone-else")))
    assert out == {"error": "invalid_token"}
    assert await _no_users_created(db_pool)


async def test_multi_audience_requires_azp(client, idp, okta):
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n, aud=[CLIENT_ID, "other"])))
    assert out == {"error": "invalid_token"}
    out = await _login_with_token(
        client, idp, lambda n: idp.mint(idp.claims(n, aud=[CLIENT_ID, "other"], azp="other")),
    )
    assert out == {"error": "invalid_token"}
    out = await _login_with_token(
        client, idp, lambda n: idp.mint(idp.claims(n, aud=[CLIENT_ID, "other"], azp=CLIENT_ID)),
    )
    assert "code" in out


async def test_wrong_issuer_rejected(client, idp, okta):
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n, iss="https://evil.example")))
    assert out == {"error": "invalid_token"}


async def test_expired_token_rejected(client, idp, okta):
    past = int(time.time()) - 3600
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n, iat=past, exp=past + 60)))
    assert out == {"error": "invalid_token"}


async def test_nonce_mismatch_rejected(client, idp, okta):
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims("not-the-nonce")))
    assert out == {"error": "invalid_token"}
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(None)))
    assert out == {"error": "invalid_token"}


async def test_alg_none_and_hs256_rejected(client, idp, okta):
    out = await _login_with_token(
        client, idp, lambda n: jwt.encode(idp.claims(n), None, algorithm="none", headers={"kid": idp.kid}),
    )
    assert out == {"error": "invalid_token"}
    # HS256 "signed" with the public key (classic alg-confusion) -- even if
    # the IdP were to advertise it.
    idp.algs = ["RS256", "HS256"]
    oidc.reset_caches()
    out = await _login_with_token(
        client, idp, lambda n: jwt.encode(idp.claims(n), "x" * 32, algorithm="HS256", headers={"kid": idp.kid}),
    )
    assert out == {"error": "invalid_token"}


async def test_replayed_callback_is_rejected(client, idp, okta):
    q = await start(client)
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"])
    first = await callback(client, "okta", code=code, state=q["state"])
    assert "code" in first
    # the browser/attacker replays the exact same redirect: state is gone
    again = await callback(client, "okta", code=code, state=q["state"])
    assert again == {"error": "state_mismatch"}


async def test_nonce_replay_cache(db_pool):
    from datetime import datetime, timedelta, timezone

    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert await id_store.remember_once(db_pool, "oidc:x:nonce", exp) is True
    assert await id_store.remember_once(db_pool, "oidc:x:nonce", exp) is False


async def test_state_mismatch_and_cookie_binding(client, idp, okta):
    q = await start(client)
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"])
    # forged state
    assert await callback(client, "okta", code=code, state="forged") == {"error": "state_mismatch"}
    # right state, but delivered to a different browser (no binding cookie):
    q = await start(client)
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"])
    client.cookies.clear()
    assert await callback(client, "okta", code=code, state=q["state"]) == {"error": "state_mismatch"}


async def test_idp_error_is_reported_generically(client, idp, okta):
    q = await start(client)
    r = await client.get(
        "/v1/auth/sso/okta/callback",
        params={"state": q["state"], "error": "access_denied", "error_description": "<script>"},
    )
    assert r.status_code == 303
    assert r.headers["location"].endswith("/sso/callback?error=idp_error")


async def test_pkce_verifier_mismatch_fails_at_token_endpoint(client, idp, okta):
    q = await start(client)
    code = idp.issue_code(nonce=q["nonce"], code_challenge="not-the-challenge")
    assert await callback(client, "okta", code=code, state=q["state"]) == {"error": "idp_error"}


async def test_jwks_rotation_refetches_once(client, idp, okta):
    assert "code" in await full_login(client, idp)
    hits = idp.jwks_hits
    idp.rotate()  # IdP rolls its signing key; our cached JWKS is now stale
    assert "code" in await full_login(client, idp, sub="00u-bob", email="bob@example.com")
    assert idp.jwks_hits == hits + 1
    # a garbage kid doesn't trigger a refetch storm (rate-limited)
    out = await _login_with_token(client, idp, lambda n: idp.mint(idp.claims(n), kid="unknown"))
    assert out == {"error": "invalid_token"}
    assert idp.jwks_hits == hits + 1


async def test_discovery_issuer_must_match(client, idp):
    body = oidc_provider_body(slug="mismatch", issuer="https://idp.example.test/other")
    r = await client.post("/v1/auth/sso/admin/providers", json=body)
    assert r.status_code == 201
    r = await client.get("/v1/auth/sso/mismatch/start", params={"spa_challenge": "a" * 43})
    assert r.status_code == 303 and r.headers["location"].endswith("error=provider_unavailable")


async def test_ssrf_guard_on_issuer():
    oidc.reset_caches()
    with pytest.raises(oidc.OIDCError) as ei:
        await oidc.discover("https://169.254.169.254/latest", allow_private=True)
    assert ei.value.code == "provider_unavailable"


# --------------------------------------------------------------------------- #
# Mapping, JIT, linking, domain allow-list
# --------------------------------------------------------------------------- #

async def test_group_mapping_first_match_and_default(client, db_pool, idp, okta):
    await full_login(client, idp, groups=["paddock-analysts", "paddock-admins"])
    u = await _user(db_pool, "alice@example.com")
    assert (u["role"], u["clearance"]) == ("admin", "restricted")  # first mapping in list wins
    await full_login(client, idp, sub="00u-carol", email="carol@example.com", groups=["unrelated"])
    c = await _user(db_pool, "carol@example.com")
    assert (c["role"], c["clearance"]) == ("viewer", "internal")


async def test_role_resync_on_login_and_break_glass_protected(client, db_pool, idp, okta):
    await full_login(client, idp, groups=["paddock-admins"])
    assert (await _user(db_pool, "alice@example.com"))["role"] == "admin"
    await full_login(client, idp, groups=["paddock-analysts"])  # demoted in the IdP
    assert (await _user(db_pool, "alice@example.com"))["role"] == "analyst"

    # A break-glass account can never be claimed by an IdP identity (it is the
    # way back in when the IdP is down or compromised).
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET email = 'root@example.com' WHERE username = 'admin'")
    out = await full_login(client, idp, sub="00u-root", email="root@example.com", groups=["nothing"])
    assert out == {"error": "account_conflict"}
    out = await full_login(client, idp, sub="00u-root2", email=None, preferred_username="admin")
    assert out == {"error": "account_conflict"}
    adm = await _user(db_pool, "admin")
    assert adm["role"] == "admin"
    async with db_pool.acquire() as con:
        assert await con.fetchval(
            "SELECT count(*) FROM user_identities WHERE user_id = $1", adm["id"]
        ) == 0


async def test_require_mapping_denies_unmapped(client, db_pool, idp, okta):
    r = await client.patch(f"/v1/auth/sso/admin/providers/{okta['id']}", json={"require_mapping": True})
    assert r.status_code == 200 and r.json()["require_mapping"] is True
    out = await full_login(client, idp, groups=["nope"])
    assert out == {"error": "no_mapping"}
    assert await _user(db_pool, "alice@example.com") is None


async def test_nested_and_namespaced_group_claims():
    claims = {
        "realm_access": {"roles": ["kc-admin"]},
        "https://paddock.example/groups": ["auth0-admins"],
    }
    assert mapping.extract_groups(claims, "realm_access.roles") == ["kc-admin"]
    assert mapping.extract_groups(claims, "https://paddock.example/groups") == ["auth0-admins"]


async def test_domain_allow_list(client, db_pool, idp, okta):
    await client.patch(f"/v1/auth/sso/admin/providers/{okta['id']}", json={"allowed_domains": ["Example.COM"]})
    assert "code" in await full_login(client, idp)
    out = await full_login(client, idp, sub="00u-mallory", email="mallory@evil.example")
    assert out == {"error": "domain_not_allowed"}
    assert await _user(db_pool, "mallory@evil.example") is None


def test_google_hosted_domain_must_be_allowed():
    assert mapping.domain_allowed("a@corp.com", ["corp.com"], hosted_domain="corp.com")
    assert not mapping.domain_allowed("a@corp.com", ["corp.com"], hosted_domain="gmail.com")
    assert not mapping.domain_allowed(None, ["corp.com"])
    assert mapping.domain_allowed("x@any.org", [])


async def test_jit_disabled(client, idp, okta):
    await client.patch(f"/v1/auth/sso/admin/providers/{okta['id']}", json={"jit_provisioning": False})
    assert await full_login(client, idp) == {"error": "provisioning_disabled"}


async def test_email_linking_requires_verified_email(client, db_pool, idp, okta):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, email, role) VALUES ('alice', 'alice@example.com', 'viewer')"
        )
    out = await full_login(client, idp, email_verified=False)
    assert out == {"error": "account_conflict"}
    out = await full_login(client, idp, email_verified=True)
    assert "code" in out
    async with db_pool.acquire() as con:
        n = await con.fetchval(
            "SELECT count(*) FROM user_identities i JOIN app_users u ON u.id = i.user_id WHERE u.username = 'alice'"
        )
    assert n == 1


async def test_entra_links_scim_user_by_oid_not_email(client, db_pool, idp):
    body = oidc_provider_body(slug="entra", preset="entra", display_name="Microsoft")
    assert (await client.post("/v1/auth/sso/admin/providers", json=body)).status_code == 201
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, email, role, provisioned_by, external_id) "
            "VALUES ('dana@corp.example', 'dana@corp.example', 'analyst', 'scim', 'oid-123')"
        )
    # email claim is present but Entra emails are never trusted for linking;
    # the immutable oid links to the SCIM-provisioned account.
    out = await full_login(
        client, idp, "entra", sub="pairwise-sub", oid="oid-123", email="dana@corp.example", email_verified=None,
    )
    assert "code" in out
    r = await _exchange(client, out["code"])
    assert r.json()["username"] == "dana@corp.example"


async def test_disabled_user_cannot_sso(client, db_pool, idp, okta):
    await full_login(client, idp)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET active = FALSE WHERE username = 'alice@example.com'")
    assert await full_login(client, idp) == {"error": "user_disabled"}


# --------------------------------------------------------------------------- #
# SSO-required + public endpoints + admin
# --------------------------------------------------------------------------- #

async def _set_pw(pool, username, pw, role="analyst"):
    async with pool.acquire() as con:
        await con.execute(
            "INSERT INTO app_users (username, role, pw_hash) VALUES ($1, $2, $3) "
            "ON CONFLICT (username) DO UPDATE SET pw_hash = EXCLUDED.pw_hash",
            username, role, auth_svc.hash_password(pw),
        )


async def test_sso_required_disables_password_login_except_break_glass(client, db_pool, idp):
    await _set_pw(db_pool, "admin", "bg-pass", role="admin")
    await _set_pw(db_pool, "nel", "nel-pass")
    # can't require SSO without an enabled IdP (lock-out guard)
    r = await client.put("/v1/auth/sso/admin/settings", json={"sso_required": True})
    assert r.status_code == 409
    assert (await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body())).status_code == 201
    r = await client.put("/v1/auth/sso/admin/settings", json={"sso_required": True, "break_glass_users": []})
    assert r.status_code == 409  # must keep a break-glass user
    r = await client.put("/v1/auth/sso/admin/settings", json={"sso_required": True})
    assert r.status_code == 200 and r.json()["sso_required"] is True

    r = await client.post("/v1/auth/login", json={"username": "nel", "password": "nel-pass"})
    assert r.status_code == 403
    # same answer for a user that doesn't exist: no enumeration
    r = await client.post("/v1/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 403
    r = await client.post("/v1/auth/login", json={"username": "admin", "password": "bg-pass"})
    assert r.status_code == 200

    pub = (await client.get("/v1/auth/sso/providers")).json()
    assert pub["sso_required"] is True


async def test_public_providers_unauthenticated_and_admin_endpoints_gated(client, db_pool, idp, okta, enforce):
    r = await client.get("/v1/auth/sso/providers")
    assert r.status_code == 200
    body = r.json()
    assert body["providers"] == [{
        "slug": "okta", "kind": "oidc", "preset": "okta", "display_name": "Okta",
        "start_url": "/v1/auth/sso/okta/start",
    }]
    assert "client" not in str(body)  # no config leaks
    # start + exchange are public too
    await start(client)
    assert (await client.post("/v1/auth/sso/exchange", json={"code": "x" * 20})).status_code == 400
    # admin CRUD is not
    assert (await client.get("/v1/auth/sso/admin/providers")).status_code == 401
    from .test_governance import _hdr, _seed_user_with_key

    _, viewer = await _seed_user_with_key(db_pool, "v", "viewer", "internal")
    assert (await client.get("/v1/auth/sso/admin/providers", headers=_hdr(viewer))).status_code == 403
    assert (await client.get("/v1/auth/sso/admin/settings", headers=_hdr(viewer))).status_code == 403


def test_rbac_rules_for_identity_routes():
    rc = auth_svc.required_capability
    # public login flow
    assert rc("GET", "/v1/auth/sso/providers") is None
    assert rc("GET", "/v1/auth/sso/okta/start") is None
    assert rc("GET", "/v1/auth/sso/okta/callback") is None
    assert rc("GET", "/v1/auth/sso/corp/metadata") is None
    assert rc("POST", "/v1/auth/sso/corp/acs") is None
    assert rc("POST", "/v1/auth/sso/exchange") is None
    # only the listed verbs are public; everything else stays deny-closed
    assert rc("POST", "/v1/auth/sso/okta/callback") == "admin"
    assert rc("DELETE", "/v1/auth/sso/okta/start") == "admin"
    # admin config, including a would-be provider called "admin"
    assert rc("GET", "/v1/auth/sso/admin/providers") == "admin"
    assert rc("GET", "/v1/auth/sso/admin/start") == "admin"
    assert rc("DELETE", "/v1/auth/sso/admin/scim-tokens/abc") == "admin"
    # SCIM: only the scim capability, which no role has
    assert rc("PATCH", "/scim/v2/Users/abc") == "scim"
    assert rc("GET", "/scim/v2") == "scim"
    assert not any("scim" in caps for caps in auth_svc.ROLE_CAPABILITIES.values())


async def test_disabled_provider_hidden_and_unusable(client, idp, okta):
    await client.patch(f"/v1/auth/sso/admin/providers/{okta['id']}", json={"enabled": False})
    assert (await client.get("/v1/auth/sso/providers")).json()["providers"] == []
    assert (await client.get("/v1/auth/sso/okta/start")).status_code == 404


async def test_admin_crud_never_returns_secret_and_is_audited(client, db_pool, idp):
    r = await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body())
    p = r.json()
    assert p["has_client_secret"] is True and "s3cret" not in r.text
    assert p["redirect_uri"].endswith("/v1/auth/sso/okta/callback")
    async with db_pool.acquire() as con:
        blob = await con.fetchval("SELECT secrets FROM identity_providers WHERE id = $1", p["id"])
    assert blob.startswith("v1:") and "s3cret" not in blob  # AES-GCM at rest

    r = await client.patch(f"/v1/auth/sso/admin/providers/{p['id']}", json={"client_secret": ""})
    assert r.json()["has_client_secret"] is False
    r = await client.post(f"/v1/auth/sso/admin/providers/{p['id']}/test")
    assert r.json()["ok"] is True and r.json()["jwks_keys"] == 1
    assert (await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body())).status_code == 409
    bad = oidc_provider_body(slug="admin")
    assert (await client.post("/v1/auth/sso/admin/providers", json=bad)).status_code == 422
    insecure = oidc_provider_body(slug="plain", issuer="http://idp.example.test")
    assert (await client.post("/v1/auth/sso/admin/providers", json=insecure)).status_code == 422
    assert (await client.delete(f"/v1/auth/sso/admin/providers/{p['id']}")).status_code == 204
    async with db_pool.acquire() as con:
        acts = [
            (r["action"], r["resource_type"]) for r in await con.fetch(
                "SELECT action, resource_type FROM audit_log WHERE resource_type = 'identity_provider'"
            )
        ]
        details = " ".join(str(r["details"]) for r in await con.fetch("SELECT details FROM audit_log"))
    assert ("create", "identity_provider") in acts
    assert ("update", "identity_provider") in acts
    assert ("delete", "identity_provider") in acts
    assert "s3cret" not in details


async def test_enforce_mode_refuses_secrets_without_persistent_key(client, db_pool, idp, enforce, monkeypatch):
    from .test_governance import _hdr, _seed_user_with_key

    monkeypatch.delenv("PADDOCK_SECRET_KEY", raising=False)
    _, key = await _seed_user_with_key(db_pool, "boss", "admin", "restricted")
    r = await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body(), headers=_hdr(key))
    assert r.status_code == 409
    monkeypatch.setenv("PADDOCK_SECRET_KEY", "A" * 43)
    r = await client.post("/v1/auth/sso/admin/providers", json=oidc_provider_body(), headers=_hdr(key))
    assert r.status_code == 201


def test_return_to_sanitised():
    f = sso_router._safe_return_to
    assert f("/findings?x=1") == "/findings?x=1"
    for bad in ("https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)", "", None, "/a\nb"):
        assert f(bad) == "/"


async def test_start_requires_well_formed_spa_challenge(client, idp, okta):
    r = await client.get("/v1/auth/sso/okta/start", params={"spa_challenge": "short"})
    assert r.status_code == 400
    r = await client.get("/v1/auth/sso/okta/start")  # no challenge: login-CSRF guard
    assert r.status_code == 400


async def test_start_is_rate_limited_per_ip(client, db_pool, idp, okta):
    for _ in range(sso_router._START_MAX_PER_MIN):
        await start(client)
    r = await client.get("/v1/auth/sso/okta/start", params={"spa_challenge": "a" * 43})
    assert r.status_code == 429
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM sso_login_states") == sso_router._START_MAX_PER_MIN


def test_extra_auth_params_cannot_override_protocol():
    from pydantic import ValidationError

    from app.identity.models import OIDCConfig

    with pytest.raises(ValidationError):
        OIDCConfig(issuer=ISSUER, client_id="c", extra_auth_params={"redirect_uri": "https://evil"})
    assert OIDCConfig(issuer=ISSUER, client_id="c", scopes=["email"]).scopes[0] == "openid"
