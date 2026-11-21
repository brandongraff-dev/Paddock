"""SAML hardening: SP-signed AuthnRequests, encrypted assertions, IdP metadata
URL fetch, single logout (SP- and IdP-initiated), Entra groups.link overage."""
from __future__ import annotations

import base64
import json
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote, urlsplit

import httpx
import pytest
import xmlsec
import pytest_asyncio

from app.config import settings
from app.identity import graph
from app.identity import saml as saml_mod
from app.integrations import netsafety
from app.routers import sso as sso_router

from ._identity_fakes import SPA_VERIFIER, s256
from .test_identity_graph import ADMIN_GROUP, ANALYST_GROUP, OID, FakeGraph
from .test_identity_saml import (
    ACS,
    IDP_ENTITY,
    IDP_SSO,
    SP_ENTITY,
    FakeSamlIdP,
    _keypair,
    _post,
    _start,
    _ts,
)

pytestmark = pytest.mark.skipif(
    not saml_mod.SAML_AVAILABLE, reason=f"python3-saml unavailable: {saml_mod.SAML_IMPORT_ERROR}",
)

if saml_mod.SAML_AVAILABLE:
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

IDP_SLO = "https://idp.saml.example/slo"
SLS = "http://localhost:8080/v1/auth/sso/corp-saml/sls"
PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def _reset():
    sso_router._starts.clear()
    graph.clear_caches()
    yield
    graph.set_transport(None)
    graph.clear_caches()
    netsafety.set_resolver(None)
    sso_router._starts.clear()


@pytest.fixture
def test_idp():
    return FakeSamlIdP()


@pytest.fixture
def enforce():
    """Call the returned function AFTER provisioning (admin calls need dev mode)."""
    prev = settings.auth_mode

    def turn_on():
        settings.auth_mode = "enforce"

    try:
        yield turn_on
    finally:
        settings.auth_mode = prev


@pytest.fixture
def sp_pair():
    return saml_mod.generate_sp_keypair("corp-saml")


def saml_body(idp: FakeSamlIdP, sp_cert: str | None = None, sp_key: str | None = None, **saml_over):
    cfg = {"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": idp.cert,
           "idp_slo_url": IDP_SLO, **saml_over}
    if sp_cert:
        cfg["sp_x509_cert"] = sp_cert
    body = {"slug": "corp-saml", "kind": "saml", "display_name": "Corp SAML", "saml": cfg,
            "role_mappings": [{"group": "paddock-admins", "role": "admin", "clearance": "restricted"},
                              {"group": "paddock-analysts", "role": "analyst"}]}
    if sp_key:
        body["sp_private_key"] = sp_key
    return body


@pytest_asyncio.fixture
async def corp(client, test_idp):
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp))
    assert r.status_code == 201, r.text
    return r.json()


def parse_query(url_or_query: str) -> dict[str, str]:
    q = urlsplit(url_or_query).query if "?" in url_or_query else url_or_query
    return {k: unquote(v) for k, v in (p.split("=", 1) for p in q.split("&"))}


def verify_redirect_signature(url: str, cert: str) -> dict[str, str]:
    """Verify the Redirect-binding signature over the octets that were signed."""
    raw = dict(p.split("=", 1) for p in urlsplit(url).query.split("&"))
    kind = "SAMLRequest" if "SAMLRequest" in raw else "SAMLResponse"
    signed = "&".join(f"{k}={raw[k]}" for k in (kind, "RelayState", "SigAlg") if k in raw)
    assert OneLogin_Saml2_Utils.validate_binary_sign(
        signed, base64.b64decode(unquote(raw["Signature"])), saml_mod.pem_cert(cert), unquote(raw["SigAlg"]),
    ), "bad redirect signature"
    return {k: unquote(v) for k, v in raw.items()}


def request_id_of(saml_request_b64: str) -> str:
    xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request_b64).decode()
    return xml.split(' ID="', 1)[1].split('"', 1)[0]


# =========================================================================== #
# SP key: signed AuthnRequests
# =========================================================================== #

async def test_authn_request_is_signed_with_sp_key(client, db_pool, test_idp, sp_pair):
    cert, key = sp_pair
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(
        test_idp, cert, key, sign_authn_requests=True))
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["has_sp_private_key"] is True and "PRIVATE KEY" not in r.text   # never echoed
    assert out["config"]["sign_authn_requests"] is True

    resp = await client.get("/v1/auth/sso/corp-saml/start", params={"spa_challenge": s256(SPA_VERIFIER)})
    assert resp.status_code == 302
    parts = verify_redirect_signature(resp.headers["location"], cert)
    assert parts["SigAlg"].endswith("rsa-sha256")
    other_cert, _ = saml_mod.generate_sp_keypair("other")
    with pytest.raises(AssertionError):
        verify_redirect_signature(resp.headers["location"], other_cert)

    md = (await client.get("/v1/auth/sso/corp-saml/metadata")).text
    assert 'AuthnRequestsSigned="true"' in md and "<ds:X509Certificate>" in md
    # encrypted at rest: neither the config nor the secrets column holds the PEM
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT config::text AS c, secrets FROM identity_providers WHERE slug = 'corp-saml'")
    assert "PRIVATE KEY" not in row["c"] and "PRIVATE KEY" not in str(row["secrets"]) and row["secrets"]


async def test_unsigned_authn_request_when_signing_is_off(client, test_idp, corp):
    resp = await client.get("/v1/auth/sso/corp-saml/start", params={"spa_challenge": s256(SPA_VERIFIER)})
    assert "Signature=" not in resp.headers["location"]


async def test_sp_key_validation(client, test_idp, sp_pair):
    cert, key = sp_pair
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp, cert, None, sign_authn_requests=True))
    assert r.status_code == 422                                       # signing needs the key
    _, other_key = saml_mod.generate_sp_keypair("other")
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp, cert, other_key))
    assert r.status_code == 422 and "match" in r.text                 # key must match the cert
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp, cert, "not a key"))
    assert r.status_code == 422


async def test_generate_sp_keypair_endpoint_and_patch_keeps_cert(client, test_idp):
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp))
    pid = r.json()["id"]
    k = await client.post(f"/v1/auth/sso/admin/providers/{pid}/saml-sp-keypair")
    assert k.status_code == 200 and "BEGIN CERTIFICATE" in k.json()["sp_x509_cert"]
    assert "PRIVATE" not in k.text
    got = (await client.get(f"/v1/auth/sso/admin/providers/{pid}")).json()
    assert got["has_sp_private_key"] and got["config"]["sp_x509_cert"] == k.json()["sp_x509_cert"]
    p = await client.patch(f"/v1/auth/sso/admin/providers/{pid}", json={"saml": {
        "idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": test_idp.cert,
        "sign_authn_requests": True}})
    assert p.status_code == 200, p.text
    assert p.json()["config"]["sp_x509_cert"] == k.json()["sp_x509_cert"]   # PATCH does not drop the cert
    assert p.json()["config"]["idp_slo_url"] == IDP_SLO                      # nor other untouched fields
    t = (await client.post(f"/v1/auth/sso/admin/providers/{pid}/test")).json()
    assert t["ok"] and t["signs_requests"] and t["has_sp_private_key"]
    bad = await client.patch(f"/v1/auth/sso/admin/providers/{pid}", json={"sp_private_key": ""})
    assert bad.status_code == 422                                            # can't clear the key while signing


# =========================================================================== #
# Encrypted assertions
# =========================================================================== #

async def test_encrypted_assertion_is_decrypted_and_can_be_required(client, db_pool, test_idp, sp_pair):
    cert, key = sp_pair
    r = await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp, cert, key))
    assert r.status_code == 201, r.text
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(
        in_response_to=req_id, groups=("paddock-admins",), encrypt_for=cert), relay)
    assert "code" in out, out
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT role FROM app_users WHERE username = 'erin@corp.example'") == "admin"

    pid = r.json()["id"]
    p = await client.patch(f"/v1/auth/sso/admin/providers/{pid}", json={"saml": {
        "idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": test_idp.cert,
        "require_encrypted_assertions": True}})
    assert p.status_code == 200, p.text
    req_id, relay = await _start(client)
    assert await _post(client, test_idp.response(in_response_to=req_id), relay) == {"error": "invalid_assertion"}
    req_id, relay = await _start(client)
    assert "code" in await _post(client, test_idp.response(in_response_to=req_id, encrypt_for=cert), relay)


async def test_assertion_encrypted_for_another_key_is_rejected(client, test_idp, sp_pair):
    cert, key = sp_pair
    other_cert, _ = saml_mod.generate_sp_keypair("other")
    assert (await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp, cert, key))).status_code == 201
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, encrypt_for=other_cert), relay)
    assert out == {"error": "invalid_assertion"}


async def test_encrypted_assertion_without_sp_key_is_rejected(client, test_idp, sp_pair):
    cert, _ = sp_pair
    assert (await client.post("/v1/auth/sso/admin/providers", json=saml_body(test_idp))).status_code == 201
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, encrypt_for=cert), relay)
    assert out == {"error": "invalid_assertion"}


# =========================================================================== #
# IdP metadata URL
# =========================================================================== #

async def test_idp_metadata_url_is_fetched_safely(client, test_idp):
    async def public(host, port):
        return [PUBLIC]

    netsafety.set_resolver(public)
    url = "https://idp.saml.example/metadata"
    ok = await saml_mod.fetch_idp_metadata(
        url, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=test_idp.metadata())))
    assert saml_mod.parse_idp_metadata(ok)["idp_entity_id"] == IDP_ENTITY
    for bad in (httpx.Response(302, headers={"location": "http://169.254.169.254/"}),
                httpx.Response(500), httpx.Response(200, content=b"x" * 600_000)):
        with pytest.raises(saml_mod.SAMLError):
            await saml_mod.fetch_idp_metadata(url, transport=httpx.MockTransport(lambda r, b=bad: b))

    async def internal(host, port):
        return ["127.0.0.1"]

    netsafety.set_resolver(internal)
    with pytest.raises(saml_mod.SAMLError, match="refused"):
        await saml_mod.fetch_idp_metadata(url)
    with pytest.raises(saml_mod.SAMLError, match="refused"):
        await saml_mod.fetch_idp_metadata("http://idp.saml.example/metadata")
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "by-url", "kind": "saml", "display_name": "x", "idp_metadata_url": "https://127.0.0.1/metadata"})
    assert r.status_code == 422


# =========================================================================== #
# Single logout
# =========================================================================== #

def idp_message(kind: str, xml: str, idp: FakeSamlIdP, *, relay: str | None = None, sign: bool = True,
                key: str | None = None) -> str:
    """A Redirect-binding SAMLRequest/SAMLResponse query string, as an IdP sends it."""
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = comp.compress(xml.encode()) + comp.flush()
    parts = [f"{kind}={quote(base64.b64encode(deflated).decode(), safe='')}"]
    if relay is not None:
        parts.append(f"RelayState={quote(relay, safe='')}")
    if sign:
        alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        parts.append(f"SigAlg={quote(alg, safe='')}")
        sig = OneLogin_Saml2_Utils.sign_binary("&".join(parts), key or idp.key, xmlsec.Transform.RSA_SHA256)
        parts.append(f"Signature={quote(base64.b64encode(sig).decode(), safe='')}")
    return "&".join(parts)


def logout_request_xml(name_id: str, session_index: str | None, *, issuer: str = IDP_ENTITY) -> str:
    now = datetime.now(timezone.utc)
    idx = f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>" if session_index else ""
    return (
        '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_lr{uuid.uuid4().hex}" Version="2.0" IssueInstant="{_ts(now)}" Destination="{SLS}" '
        f'NotOnOrAfter="{_ts(now + timedelta(minutes=5))}">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>'
        f"{idx}</samlp:LogoutRequest>"
    )


def logout_response_xml(in_response_to: str) -> str:
    now = datetime.now(timezone.utc)
    return (
        '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_lo{uuid.uuid4().hex}" Version="2.0" IssueInstant="{_ts(now)}" Destination="{SLS}" '
        f'InResponseTo="{in_response_to}">'
        f"<saml:Issuer>{IDP_ENTITY}</saml:Issuer>"
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        "</samlp:LogoutResponse>"
    )


async def saml_session(client, idp: FakeSamlIdP, **resp_kw):
    """Log in via SAML and exchange for a Paddock JWT -> (headers, session_index)."""
    req_id, relay = await _start(client)
    out = await _post(client, idp.response(in_response_to=req_id, **resp_kw), relay)
    r = await client.post("/v1/auth/sso/exchange", json={"code": out["code"], "verifier": SPA_VERIFIER})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}, idp.last_session_index


async def test_login_records_idp_session_for_logout(client, db_pool, test_idp, corp):
    _, sidx = await saml_session(client, test_idp)
    async with db_pool.acquire() as con:
        sess = await con.fetchval("SELECT idp_session FROM user_identities LIMIT 1")
    sess = json.loads(sess) if isinstance(sess, str) else sess
    assert sess["name_id"] == "erin@corp.example" and sess["session_index"] == sidx


async def test_sp_initiated_logout_revokes_sessions_and_sends_signed_logout_request(
        client, db_pool, test_idp, sp_pair, enforce):
    cert, key = sp_pair
    assert (await client.post("/v1/auth/sso/admin/providers", json=saml_body(
        test_idp, cert, key, sign_authn_requests=True))).status_code == 201
    enforce()
    hdr, sidx = await saml_session(client, test_idp)
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200

    r = await client.post("/v1/auth/sso/logout", headers=hdr)
    assert r.status_code == 200, r.text
    url = r.json()["idp_logout_url"]
    assert url.startswith(IDP_SLO + "?")
    parts = verify_redirect_signature(url, cert)                       # signed by the SP
    xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(parts["SAMLRequest"]).decode()
    assert "erin@corp.example" in xml and f">{sidx}<" in xml and SP_ENTITY in xml

    # the Paddock session is dead immediately (JWT revocation watermark)
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 401
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT details FROM audit_log WHERE action = 'logout' ORDER BY id DESC LIMIT 1")
    assert '"user"' in str(row["details"]) and "initiator" in str(row["details"])

    # the IdP's signed LogoutResponse returns to /sls with our RelayState
    q = idp_message("SAMLResponse", logout_response_xml(request_id_of(parts["SAMLRequest"])), test_idp,
                    relay=parts["RelayState"])
    ok = await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")
    assert ok.status_code == 303, ok.text
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")).status_code == 400   # state is single use


@pytest.mark.parametrize("variant", ["unsigned", "other_request", "attacker_key"])
async def test_logout_response_must_be_signed_by_idp_and_answer_our_request(client, test_idp, corp, variant):
    hdr, _ = await saml_session(client, test_idp)
    parts = parse_query((await client.post("/v1/auth/sso/logout", headers=hdr)).json()["idp_logout_url"])
    assert "Signature" not in parts                                    # signing is off for this provider
    rid = request_id_of(parts["SAMLRequest"])
    xml = logout_response_xml("_someone-elses-request" if variant == "other_request" else rid)
    kw = {"sign": False} if variant == "unsigned" else {"key": _keypair("attacker")[0]} \
        if variant == "attacker_key" else {}
    q = idp_message("SAMLResponse", xml, test_idp, relay=parts["RelayState"], **kw)
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")).status_code == 400


async def test_logout_response_with_unknown_relay_state_is_refused(client, test_idp, corp):
    q = idp_message("SAMLResponse", logout_response_xml("_x"), test_idp, relay="never-issued")
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")).status_code == 400


async def test_idp_initiated_logout_request_revokes_sessions(client, test_idp, corp, enforce):
    enforce()
    hdr, sidx = await saml_session(client, test_idp)
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200
    q = idp_message("SAMLRequest", logout_request_xml("erin@corp.example", sidx), test_idp, relay="/after")
    r = await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")
    assert r.status_code == 302, r.text
    assert r.headers["location"].startswith(IDP_SLO + "?") and "SAMLResponse=" in r.headers["location"]
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 401


@pytest.mark.parametrize("variant", ["unsigned", "attacker_key", "wrong_issuer"])
async def test_idp_initiated_logout_request_must_be_signed_by_the_idp(client, test_idp, corp, enforce, variant):
    """Otherwise anyone could end any user's session by guessing an email."""
    enforce()
    hdr, sidx = await saml_session(client, test_idp)
    xml = logout_request_xml("erin@corp.example", sidx,
                             issuer="https://evil-idp.example" if variant == "wrong_issuer" else IDP_ENTITY)
    kw = {"sign": False} if variant == "unsigned" else {"key": _keypair("attacker")[0]} \
        if variant == "attacker_key" else {}
    q = idp_message("SAMLRequest", xml, test_idp, **kw)
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{q}")).status_code == 400
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200      # untouched


async def test_logout_request_for_other_session_or_unknown_user_changes_nothing(client, test_idp, corp, enforce):
    enforce()
    hdr, sidx = await saml_session(client, test_idp)
    other = idp_message("SAMLRequest", logout_request_xml("erin@corp.example", "_some-other-session"), test_idp)
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{other}")).status_code == 302
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200       # a different IdP session
    unknown = idp_message("SAMLRequest", logout_request_xml("nobody@corp.example", None), test_idp)
    assert (await client.get(f"/v1/auth/sso/corp-saml/sls?{unknown}")).status_code == 302   # no user oracle
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 200


async def test_sls_rejects_garbage_and_unknown_provider(client, corp):
    assert (await client.get("/v1/auth/sso/corp-saml/sls")).status_code == 400
    assert (await client.get("/v1/auth/sso/corp-saml/sls?SAMLRequest=%%%")).status_code == 400
    assert (await client.get("/v1/auth/sso/nope/sls?SAMLRequest=abc")).status_code == 404


async def test_logout_without_idp_slo_url_still_revokes_and_requires_a_session(client, test_idp, enforce):
    body = saml_body(test_idp)
    body["saml"].pop("idp_slo_url")
    assert (await client.post("/v1/auth/sso/admin/providers", json=body)).status_code == 201
    enforce()
    hdr, _ = await saml_session(client, test_idp)
    r = await client.post("/v1/auth/sso/logout", headers=hdr)
    assert r.status_code == 200 and r.json() == {"revoked": True, "idp_logout_url": None}
    assert (await client.get("/v1/auth/me", headers=hdr)).status_code == 401
    # no credential -> 401; the public /sls and login routes stay open
    assert (await client.post("/v1/auth/sso/logout")).status_code == 401


# =========================================================================== #
# Entra groups.link overage over SAML
# =========================================================================== #

LINK = {graph.GROUPS_LINK_ATTR: ("https://graph.windows.net/t/users/u/getMemberObjects",), graph.OID_ATTR: (OID,)}


async def _graph_provider(client, idp, **over):
    body = saml_body(idp, graph_tenant_id="contoso.onmicrosoft.com", graph_client_id="app-1", **over)
    body["graph_client_secret"] = "s3cret-client-secret"
    body["role_mappings"] = [{"group": ADMIN_GROUP, "role": "admin", "clearance": "restricted"},
                             {"group": ANALYST_GROUP, "role": "analyst"}]
    r = await client.post("/v1/auth/sso/admin/providers", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["has_graph_client_secret"] is True and "s3cret" not in r.text
    return r.json()


async def test_saml_groups_link_overage_resolved_via_graph_app_credentials(client, db_pool, test_idp):
    await _graph_provider(client, test_idp)
    g = FakeGraph()
    g.groups = [ADMIN_GROUP]
    graph.set_transport(httpx.MockTransport(g.handler))
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, groups=(), extra_attrs=LINK), relay)
    assert "code" in out, out
    async with db_pool.acquire() as con:
        u = await con.fetchrow("SELECT role, clearance FROM app_users WHERE username = 'erin@corp.example'")
    assert (u["role"], u["clearance"]) == ("admin", "restricted")
    assert g.calls[0].url.path == f"/v1.0/users/{OID}/transitiveMemberOf/microsoft.graph.group"
    assert g.calls[0].headers["authorization"] == "Bearer app-token-1"
    assert all(c.url.host == "graph.microsoft.com" for c in g.calls)       # never the legacy link in the claim


async def test_saml_overage_failure_never_grants(client, db_pool, test_idp):
    await _graph_provider(client, test_idp)
    g = FakeGraph()
    g.groups = [ADMIN_GROUP]
    g.status = 403
    graph.set_transport(httpx.MockTransport(g.handler))
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(
        in_response_to=req_id, groups=(ADMIN_GROUP,), extra_attrs=LINK), relay)   # partial claim is ignored
    assert "code" in out
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT role FROM app_users WHERE username = 'erin@corp.example'") == "viewer"
    # mapping required: deny
    pid = (await client.get("/v1/auth/sso/admin/providers")).json()[0]["id"]
    assert (await client.patch(f"/v1/auth/sso/admin/providers/{pid}", json={"require_mapping": True})).status_code == 200
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, groups=(), extra_attrs=LINK), relay)
    assert out == {"error": "groups_unavailable"}


async def test_saml_overage_without_graph_credentials_is_unresolved(client, db_pool, test_idp, corp):
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, groups=(), extra_attrs=LINK), relay)
    assert "code" in out
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT role FROM app_users WHERE username = 'erin@corp.example'") == "viewer"
