"""SAML 2.0 SP: a self-signed test IdP signs real assertions (xmlsec via
python3-saml) and posts them to the ACS."""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.identity import saml as saml_mod
from app.routers import sso as sso_router

from ._identity_fakes import SPA_VERIFIER, s256

pytestmark = pytest.mark.skipif(
    not saml_mod.SAML_AVAILABLE, reason=f"python3-saml unavailable: {saml_mod.SAML_IMPORT_ERROR}",
)

if saml_mod.SAML_AVAILABLE:
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

IDP_ENTITY = "https://idp.saml.example/metadata"
IDP_SSO = "https://idp.saml.example/sso"
SP_ENTITY = "http://localhost:8080/v1/auth/sso/corp-saml/metadata"
ACS = "http://localhost:8080/v1/auth/sso/corp-saml/acs"


def _keypair(cn: str = "test-idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeSamlIdP:
    def __init__(self) -> None:
        self.key, self.cert = _keypair()

    def response(
        self,
        *,
        in_response_to: str,
        name_id: str = "erin@corp.example",
        groups: tuple[str, ...] = ("paddock-analysts",),
        audience: str = SP_ENTITY,
        destination: str = ACS,
        issuer: str = IDP_ENTITY,
        sign: bool = True,
        key: str | None = None,
        cert: str | None = None,
        not_on_or_after: datetime | None = None,
        tamper: bool = False,
        assertion_id: str | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        later = not_on_or_after or now + timedelta(minutes=5)
        aid = assertion_id or f"_a{uuid.uuid4().hex}"
        attrs = "".join(
            f'<saml:AttributeValue xsi:type="xs:string">{g}</saml:AttributeValue>' for g in groups
        )
        assertion = (
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" '
            f'ID="{aid}" Version="2.0" IssueInstant="{_ts(now)}">'
            f"<saml:Issuer>{issuer}</saml:Issuer>"
            "<saml:Subject>"
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData NotOnOrAfter="{_ts(later)}" Recipient="{destination}" '
            f'InResponseTo="{in_response_to}"/>'
            "</saml:SubjectConfirmation></saml:Subject>"
            f'<saml:Conditions NotBefore="{_ts(now - timedelta(minutes=1))}" NotOnOrAfter="{_ts(later)}">'
            f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>"
            "</saml:Conditions>"
            f'<saml:AuthnStatement AuthnInstant="{_ts(now)}" SessionIndex="_s{uuid.uuid4().hex[:8]}">'
            "<saml:AuthnContext><saml:AuthnContextClassRef>"
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
            '<saml:AttributeStatement><saml:Attribute Name="groups">'
            f"{attrs}</saml:Attribute></saml:AttributeStatement>"
            "</saml:Assertion>"
        )
        if sign:
            signed = OneLogin_Saml2_Utils.add_sign(assertion, key or self.key, cert or self.cert)
            assertion = signed.decode() if isinstance(signed, bytes) else signed
            assertion = assertion.split("?>", 1)[1] if assertion.startswith("<?xml") else assertion
        if tamper:
            assertion = assertion.replace(name_id, "mallory@corp.example")
        resp = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="{_ts(now)}" '
            f'Destination="{destination}" InResponseTo="{in_response_to}">'
            f"<saml:Issuer>{issuer}</saml:Issuer>"
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f"{assertion}</samlp:Response>"
        )
        return base64.b64encode(resp.encode()).decode()

    def metadata(self) -> str:
        cert_b64 = saml_mod.normalize_cert(self.cert)
        return (
            '<?xml version="1.0"?>'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'entityID="{IDP_ENTITY}">'
            '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>"
            "</ds:KeyInfo></md:KeyDescriptor>"
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
            '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{IDP_SSO}"/>'
            "</md:IDPSSODescriptor></md:EntityDescriptor>"
        )


@pytest.fixture(autouse=True)
def _reset_start_limiter():
    sso_router._starts.clear()
    yield
    sso_router._starts.clear()


@pytest.fixture
def test_idp():
    return FakeSamlIdP()


@pytest_asyncio.fixture
async def corp(client, test_idp):
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "corp-saml",
        "kind": "saml",
        "display_name": "Corp SAML",
        "saml_metadata_xml": test_idp.metadata(),
        "role_mappings": [
            {"group": "paddock-admins", "role": "admin", "clearance": "restricted"},
            {"group": "paddock-analysts", "role": "analyst"},
        ],
    })
    assert r.status_code == 201, r.text
    return r.json()


async def _start(client):
    r = await client.get(
        "/v1/auth/sso/corp-saml/start", params={"return_to": "/graph", "spa_challenge": s256(SPA_VERIFIER)},
    )
    assert r.status_code == 302, r.text
    loc = urlsplit(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == IDP_SSO
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    req_xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(q["SAMLRequest"]).decode()
    req_id = req_xml.split('ID="', 1)[1].split('"', 1)[0]
    assert ACS in req_xml and SP_ENTITY in req_xml
    return req_id, q["RelayState"]


async def _post(client, saml_response: str, relay_state: str | None):
    form = {"SAMLResponse": saml_response}
    if relay_state is not None:
        form["RelayState"] = relay_state
    r = await client.post("/v1/auth/sso/corp-saml/acs", data=form)
    assert r.status_code == 303, r.text
    return {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}


async def test_saml_happy_path(client, db_pool, test_idp, corp):
    assert corp["saml_acs_url"] == ACS and corp["saml_entity_id"] == SP_ENTITY
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id), relay)
    assert "code" in out and out["next"] == "/graph", out
    # the code alone is useless (this is what defeats SAML login-CSRF) ...
    assert (await client.post("/v1/auth/sso/exchange", json={"code": out["code"]})).status_code == 400
    # ... and a failed redemption burns it; log in again and redeem properly
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id), relay)
    r = await client.post("/v1/auth/sso/exchange", json={"code": out["code"], "verifier": SPA_VERIFIER})
    assert r.status_code == 200
    assert r.json()["username"] == "erin@corp.example" and r.json()["role"] == "analyst"
    async with db_pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT details FROM audit_log WHERE action = 'login' AND resource_id = 'corp-saml' ORDER BY id DESC LIMIT 1"
        )
    assert '"saml"' in str(row["details"]) and '"success"' in str(row["details"])


async def test_saml_admin_mapping(client, db_pool, test_idp, corp):
    req_id, relay = await _start(client)
    out = await _post(client, test_idp.response(in_response_to=req_id, groups=("paddock-admins",)), relay)
    async with db_pool.acquire() as con:
        u = await con.fetchrow("SELECT role, clearance FROM app_users WHERE username = 'erin@corp.example'")
    assert "code" in out and (u["role"], u["clearance"]) == ("admin", "restricted")


@pytest.mark.parametrize("variant", ["unsigned", "tampered", "wrong_key", "wrong_audience",
                                     "wrong_destination", "wrong_issuer", "expired", "wrong_in_response_to"])
async def test_saml_rejections(client, db_pool, test_idp, corp, variant):
    req_id, relay = await _start(client)
    other_key, other_cert = _keypair("attacker")
    kw = {
        "unsigned": {"sign": False},
        "tampered": {"tamper": True},
        "wrong_key": {"key": other_key, "cert": other_cert},
        "wrong_audience": {"audience": "https://someone-else.example/sp"},
        "wrong_destination": {"destination": "https://evil.example/acs"},
        "wrong_issuer": {"issuer": "https://evil-idp.example"},
        "expired": {"not_on_or_after": datetime.now(timezone.utc) - timedelta(minutes=10)},
        "wrong_in_response_to": {},
    }[variant]
    irt = "_not-our-request" if variant == "wrong_in_response_to" else req_id
    out = await _post(client, test_idp.response(in_response_to=irt, **kw), relay)
    assert out == {"error": "invalid_assertion"}, (variant, out)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM app_users WHERE provisioned_by = 'sso:corp-saml'") == 0


async def test_saml_replay_and_unsolicited(client, test_idp, corp):
    req_id, relay = await _start(client)
    resp = test_idp.response(in_response_to=req_id)
    assert "code" in await _post(client, resp, relay)
    assert await _post(client, resp, relay) == {"error": "state_mismatch"}  # RelayState consumed
    # IdP-initiated (no RelayState) is refused
    assert await _post(client, resp, None) == {"error": "state_mismatch"}


async def test_saml_assertion_id_replay_cache(client, test_idp, corp):
    req1, relay1 = await _start(client)
    resp1 = test_idp.response(in_response_to=req1, assertion_id="_fixed-assertion-id")
    assert "code" in await _post(client, resp1, relay1)
    # a fresh login whose IdP (buggy or hostile) re-uses an assertion ID
    req2, relay2 = await _start(client)
    resp2 = test_idp.response(in_response_to=req2, assertion_id="_fixed-assertion-id")
    assert await _post(client, resp2, relay2) == {"error": "replay"}


async def test_saml_garbage_response(client, corp):
    _, relay = await _start(client)
    assert await _post(client, base64.b64encode(b"<nope").decode(), relay) == {"error": "invalid_assertion"}
    _, relay = await _start(client)
    assert await _post(client, "%%%not-base64", relay) == {"error": "invalid_assertion"}


async def test_sp_metadata(client, corp):
    r = await client.get("/v1/auth/sso/corp-saml/metadata")
    assert r.status_code == 200 and "samlmetadata+xml" in r.headers["content-type"]
    assert f'entityID="{SP_ENTITY}"' in r.text and ACS in r.text
    assert 'WantAssertionsSigned="true"' in r.text


async def test_saml_config_validation(client, test_idp):
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "bad-saml", "kind": "saml", "display_name": "Bad",
        "saml_metadata_xml": "<not-metadata/>",
    })
    assert r.status_code == 422
    r = await client.post("/v1/auth/sso/admin/providers", json={
        "slug": "manual", "kind": "saml", "display_name": "Manual",
        "saml": {"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": test_idp.cert},
    })
    assert r.status_code == 201
    assert r.json()["config"]["idp_x509_cert"] == test_idp.cert
