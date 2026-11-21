"""Entra ID group overage: the token says "groups omitted" and Paddock asks
Microsoft Graph (a fake one over httpx.MockTransport) for transitiveMemberOf.

Failure mode under test: any Graph problem leaves the groups UNRESOLVED --
no role mapping is applied, require_mapping providers deny, existing users
keep (never gain) a role.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import pytest_asyncio

from app.identity import graph, oidc
from app.integrations import netsafety
from app.integrations.pinned import PinnedTransport
from app.routers import sso as sso_router

from ._identity_fakes import SPA_VERIFIER, FakeIdP, callback, oidc_provider_body, start

ADMIN_GROUP = "aaaaaaaa-0000-4000-8000-000000000001"
ANALYST_GROUP = "aaaaaaaa-0000-4000-8000-000000000002"
OID = "bbbbbbbb-0000-4000-8000-0000000000aa"
TID = "cccccccc-0000-4000-8000-0000000000bb"
GRAPH = "https://graph.microsoft.com"
LOGIN = "https://login.microsoftonline.com"

OVERAGE = {"groups": None, "_claim_names": {"groups": "src1"},
           "_claim_sources": {"src1": {"endpoint": "https://graph.windows.net/x/users/y/getMemberObjects"}},
           "oid": OID, "tid": TID}


class FakeGraph:
    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.groups: list[str] = [ANALYST_GROUP]
        self.page_size = 1000
        self.status = 200
        self.app_token = "app-token-1"
        self.token_calls = 0
        self.next_link_override: str | None = None
        self.loop = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        if url.netloc == "login.microsoftonline.com":
            self.token_calls += 1
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert form["grant_type"] == "client_credentials" and form["scope"] == GRAPH + "/.default"
            assert form["client_secret"] == "s3cret-client-secret"
            if self.status != 200:
                return httpx.Response(self.status, json={"error": "invalid_client"})
            return httpx.Response(200, json={"access_token": self.app_token, "expires_in": 3600})
        assert url.netloc == "graph.microsoft.com", url.netloc
        self.calls.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"code": "Authorization_RequestDenied"}},
                                  headers={"retry-after": "0"})
        q = parse_qs(url.query)
        skip = int(q.get("skip", ["0"])[0])
        page = self.groups[skip: skip + self.page_size]
        body: dict = {"value": [{"@odata.type": "#microsoft.graph.group", "id": g} for g in page]}
        if self.loop:
            body["@odata.nextLink"] = str(request.url)
        elif self.next_link_override:
            body["@odata.nextLink"] = self.next_link_override
        elif skip + self.page_size < len(self.groups):
            body["@odata.nextLink"] = f"{GRAPH}{url.path}?$select=id&$top=999&skip={skip + self.page_size}"
        return httpx.Response(200, json=body)


@pytest.fixture(autouse=True)
def _reset():
    sso_router._starts.clear()
    graph.clear_caches()
    yield
    graph.set_transport(None)
    graph.clear_caches()
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


@pytest.fixture
def fgraph():
    g = FakeGraph()
    graph.set_transport(httpx.MockTransport(g.handler))
    return g


async def _create(client, **over):
    oidc_over = over.pop("oidc", {})
    body = oidc_provider_body(
        slug="entra", preset="entra",
        role_mappings=[{"group": ADMIN_GROUP, "role": "admin", "clearance": "restricted"},
                       {"group": ANALYST_GROUP, "role": "analyst", "clearance": "confidential"}],
        **over,
    )
    body["oidc"] = {**body["oidc"], **oidc_over}
    r = await client.post("/v1/auth/sso/admin/providers", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def _login(client, idp, **claims):
    q = await start(client, "entra")
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"], **{**OVERAGE, **claims})
    return await callback(client, "entra", code=code, state=q["state"])


async def _user(pool, name="alice@example.com"):
    async with pool.acquire() as con:
        return await con.fetchrow("SELECT * FROM app_users WHERE username = $1", name)


async def _last_login_audit(pool):
    async with pool.acquire() as con:
        return str((await con.fetchrow(
            "SELECT details FROM audit_log WHERE action = 'login' AND resource_id = 'entra' ORDER BY id DESC LIMIT 1"
        ))["details"])


# --------------------------------------------------------------------------- #
# detection helpers
# --------------------------------------------------------------------------- #

def test_overage_detection_and_helpers():
    assert graph.oidc_overage({"_claim_names": {"groups": "src1"}})
    assert graph.oidc_overage({"hasgroups": True}) and graph.oidc_overage({"hasgroups": "true"})
    assert not graph.oidc_overage({"groups": ["x"]})
    assert not graph.oidc_overage({"_claim_names": {"other": "src1"}})
    assert graph.saml_overage({graph.GROUPS_LINK_ATTR: ["https://graph.windows.net/..."]})
    assert not graph.saml_overage({"groups": ["x"]})
    assert graph.saml_object_id({graph.OID_ATTR: [OID]}) == OID
    assert graph.saml_object_id({graph.OID_ATTR: ["../../etc"]}) is None
    assert graph.tenant_from_issuer(f"{LOGIN}/{TID}/v2.0") == TID
    assert graph.tenant_from_issuer("https://x.example") is None


# --------------------------------------------------------------------------- #
# OIDC: delegated (user's access token)
# --------------------------------------------------------------------------- #

async def test_overage_delegated_maps_roles_from_graph_with_paging(client, db_pool, idp, fgraph):
    await _create(client)
    fgraph.groups = ["dddddddd-0000-4000-8000-00000000000%d" % i for i in range(3)] + [ADMIN_GROUP]
    fgraph.page_size = 2
    out = await _login(client, idp)
    assert "code" in out, out
    u = await _user(db_pool)
    assert (u["role"], u["clearance"]) == ("admin", "restricted")
    assert len(fgraph.calls) == 2                                       # two pages followed
    first = fgraph.calls[0]
    assert first.url.path == "/v1.0/me/transitiveMemberOf/microsoft.graph.group"
    assert first.url.params["$select"] == "id"                          # ids only, never display names
    assert first.headers["authorization"].startswith("Bearer at-")      # the user's own access token
    assert "graph.windows.net" not in str(first.url)                    # the claim-source link is never followed
    assert "groups_unresolved\": false" in (await _last_login_audit(db_pool)).lower()


async def test_overage_hasgroups_variant(client, db_pool, idp, fgraph):
    await _create(client)
    fgraph.groups = [ADMIN_GROUP]
    out = await _login(client, idp, _claim_names=None, _claim_sources=None, hasgroups=True)
    assert "code" in out
    assert (await _user(db_pool))["role"] == "admin"


async def test_overage_ignores_partial_groups_claim(client, db_pool, idp, fgraph):
    """A groups claim next to an overage marker is not trusted; only Graph is."""
    await _create(client)
    fgraph.groups = [ANALYST_GROUP]
    await _login(client, idp, groups=[ADMIN_GROUP])
    assert (await _user(db_pool))["role"] == "analyst"


async def test_overage_cache_serves_second_login_without_calling_graph(client, db_pool, idp, fgraph):
    await _create(client)
    await _login(client, idp)
    assert len(fgraph.calls) == 1
    fgraph.groups = [ADMIN_GROUP]           # changed in Entra, but within the cache TTL
    await _login(client, idp)
    assert len(fgraph.calls) == 1
    assert (await _user(db_pool))["role"] == "analyst"
    graph.clear_caches()
    await _login(client, idp)
    assert len(fgraph.calls) == 2 and (await _user(db_pool))["role"] == "admin"


async def test_overage_cache_can_be_disabled(client, idp, fgraph, monkeypatch):
    monkeypatch.setenv("PADDOCK_GRAPH_GROUP_CACHE_SEC", "0")
    await _create(client)
    await _login(client, idp)
    await _login(client, idp)
    assert len(fgraph.calls) == 2


@pytest.mark.parametrize("failure", ["forbidden", "server_error", "throttled"])
async def test_graph_failure_never_grants_and_never_caches(client, db_pool, idp, fgraph, failure):
    await _create(client)
    fgraph.groups = [ADMIN_GROUP]
    fgraph.status = {"forbidden": 403, "server_error": 500, "throttled": 429}[failure]
    out = await _login(client, idp)
    # not require_mapping: login proceeds with the provider's baseline role only
    assert "code" in out, out
    u = await _user(db_pool)
    assert (u["role"], u["clearance"]) == ("viewer", "internal")
    audit = await _last_login_audit(db_pool)
    assert "groups_unresolved" in audit and "graph_" in audit
    # failure was not cached: next login with Graph healthy resolves properly
    fgraph.status = 200
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "admin"


async def test_graph_failure_denies_when_mapping_required(client, db_pool, idp, fgraph):
    await _create(client, require_mapping=True)
    fgraph.status = 403
    out = await _login(client, idp)
    assert out == {"error": "groups_unavailable"}
    assert await _user(db_pool) is None


async def test_graph_failure_keeps_existing_role_and_does_not_upgrade(client, db_pool, idp, fgraph):
    await _create(client)
    fgraph.groups = [ANALYST_GROUP]
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "analyst"
    graph.clear_caches()
    fgraph.groups = [ADMIN_GROUP]
    fgraph.status = 500
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "analyst"      # neither upgraded to admin nor reset
    async with db_pool.acquire() as con:                     # and stored groups were not blanked
        assert await con.fetchval("SELECT groups FROM user_identities LIMIT 1") == [ANALYST_GROUP]


async def test_delegated_without_access_token_is_unresolved(client, db_pool, idp, fgraph, monkeypatch):
    await _create(client)
    real = idp.handler

    def no_access_token(request):
        r = real(request)
        if str(request.url).endswith("/v1/token"):
            body = r.json()
            body.pop("access_token")
            return httpx.Response(200, json=body)
        return r

    oidc.set_transport(httpx.MockTransport(no_access_token))
    fgraph.groups = [ADMIN_GROUP]
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "viewer" and fgraph.calls == []


@pytest.mark.parametrize("mode", ["off_host_nextlink", "loop", "too_many_pages"])
async def test_hostile_paging_is_refused(client, db_pool, idp, fgraph, mode):
    await _create(client)
    fgraph.groups = [ADMIN_GROUP]
    if mode == "off_host_nextlink":
        fgraph.next_link_override = "https://evil.example/v1/steal"
    elif mode == "loop":
        fgraph.loop = True
    else:
        fgraph.groups = ["g%d" % i for i in range(graph.MAX_PAGES * 2 + 5)] + [ADMIN_GROUP]
        fgraph.page_size = 2
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "viewer"
    assert all(c.url.host == "graph.microsoft.com" for c in fgraph.calls)


async def test_graph_overage_off_ignores_markers(client, db_pool, idp, fgraph):
    await _create(client, oidc={"graph_overage": "off"})
    await _login(client, idp)
    assert fgraph.calls == [] and (await _user(db_pool))["role"] == "viewer"


# --------------------------------------------------------------------------- #
# OIDC: application credentials
# --------------------------------------------------------------------------- #

async def test_overage_app_mode_uses_client_credentials_and_caches_token(client, db_pool, idp, fgraph):
    await _create(client, oidc={"graph_mode": "app"})
    fgraph.groups = [ADMIN_GROUP]
    await _login(client, idp)
    assert (await _user(db_pool))["role"] == "admin"
    assert fgraph.token_calls == 1
    call = fgraph.calls[0]
    assert call.url.path == f"/v1.0/users/{OID}/transitiveMemberOf/microsoft.graph.group"
    assert call.headers["authorization"] == "Bearer app-token-1"
    # second user, groups cached per subject but the app token is reused
    await _login(client, idp, sub="00u-bob", email="bob@example.com")
    assert fgraph.token_calls == 1 and len(fgraph.calls) == 2


async def test_app_mode_rejects_bad_oid_and_missing_credentials(client, db_pool, idp, fgraph):
    await _create(client, oidc={"graph_mode": "app"})
    await _login(client, idp, oid="../../v1.0/me")
    assert (await _user(db_pool))["role"] == "viewer" and fgraph.calls == []
    # token endpoint refuses the app credentials
    fgraph.status = 401
    await _login(client, idp, sub="u2", email="u2@example.com")
    assert (await _user(db_pool, "u2@example.com"))["role"] == "viewer"


# --------------------------------------------------------------------------- #
# the Graph client itself
# --------------------------------------------------------------------------- #

async def test_graph_requests_use_the_pinned_transport_and_refuse_internal_hosts():
    graph.set_transport(None)
    c = graph._client(graph.GraphConfig())
    assert isinstance(c._transport, PinnedTransport)
    await c.aclose()

    async def internal(host, port):
        return ["127.0.0.1"]

    netsafety.set_resolver(internal)
    try:
        with pytest.raises(graph.GraphError) as ei:
            await graph.resolve_groups(graph.GraphConfig(), cache_scope="p", subject="s", access_token="t")
        assert ei.value.code == "graph_unreachable"
    finally:
        netsafety.set_resolver(None)


async def test_resolve_groups_validation():
    with pytest.raises(graph.GraphError) as ei:
        await graph.resolve_groups(graph.GraphConfig(mode="app"), cache_scope="p", subject="s", oid=OID)
    assert ei.value.code == "graph_not_configured"
    with pytest.raises(graph.GraphError) as ei:
        await graph.resolve_groups(graph.GraphConfig(mode="bogus"), cache_scope="p", subject="s")
    assert ei.value.code == "graph_misconfigured"
    with pytest.raises(graph.GraphError):
        await graph.resolve_groups(graph.GraphConfig(base_url="http://graph.example"),
                                   cache_scope="p", subject="s", access_token="t")


async def test_oidc_config_rejects_non_https_graph_urls(client, idp):
    body = oidc_provider_body(slug="bad", preset="entra")
    body["oidc"]["graph_base_url"] = "http://graph.example"
    assert (await client.post("/v1/auth/sso/admin/providers", json=body)).status_code == 422
