"""SAML 2.0 service provider, built on OneLogin's ``python3-saml`` (xmlsec).

What the library enforces for us in ``strict`` mode (verified by
tests/test_identity_saml.py with a self-signed test IdP):

* the assertion is signed by the configured IdP certificate (we set
  ``wantAssertionsSigned``; message signatures optional per provider),
  with deprecated algorithms (SHA-1) rejected;
* XML signature-wrapping defences (the signed element must be the one
  consumed; duplicate / unexpected elements are refused);
* ``Destination`` / ``Recipient`` == our ACS URL, ``Audience`` == our SP
  entity id, ``Issuer`` == the IdP entity id;
* ``NotBefore`` / ``NotOnOrAfter`` on conditions + subject confirmation;
* ``InResponseTo`` == the AuthnRequest ID we issued (SP-initiated only:
  unsolicited / IdP-initiated responses are rejected).

On top of that we add a replay cache keyed by assertion ID (see
``routers/sso.py``). python3-saml is synchronous and CPU-bound, so callers
run these helpers in a thread pool.

Optional on top (all per provider, see docs/SSO.md):

* SP-signed AuthnRequests / LogoutRequests: an SP key pair (cert in the
  provider config, private key encrypted with the secrets module);
* encrypted assertions: decrypted with that same SP private key; can be made
  mandatory (``require_encrypted_assertions``);
* single logout (Redirect binding): SP-initiated (``POST /v1/auth/sso/logout``)
  and IdP-initiated LogoutRequests at ``/{slug}/sls`` -- the latter are only
  honoured when signed by the pinned IdP certificate (otherwise anyone could
  force-logout any user). IdP-initiated *login* stays refused.

If ``python3-saml`` / ``xmlsec`` cannot be imported the SAML endpoints
answer 501 with a pointer to docs/SSO.md instead of failing at import time.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

try:  # pragma: no cover - exercised implicitly by every SAML test
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.constants import OneLogin_Saml2_Constants
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    SAML_AVAILABLE = True
    SAML_IMPORT_ERROR: str | None = None
except Exception as _exc:  # noqa: BLE001
    SAML_AVAILABLE = False
    SAML_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"

from ..config import settings

POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_MAX_METADATA_BYTES = 512 * 1024


class SAMLError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _require() -> None:
    if not SAML_AVAILABLE:
        raise SAMLError("saml_unavailable", SAML_IMPORT_ERROR or "python3-saml not installed")


def sp_urls(slug: str) -> dict[str, str]:
    base = settings.sso_base_url.rstrip("/")
    return {
        "entity_id": f"{base}/v1/auth/sso/{slug}/metadata",
        "acs_url": f"{base}/v1/auth/sso/{slug}/acs",
        "metadata_url": f"{base}/v1/auth/sso/{slug}/metadata",
        "sls_url": f"{base}/v1/auth/sso/{slug}/sls",
    }


def normalize_cert(pem_or_b64: str) -> str:
    """Accept PEM or bare base64; return bare base64 (what python3-saml wants)."""
    lines = [
        ln.strip() for ln in pem_or_b64.strip().splitlines()
        if ln.strip() and "-----" not in ln
    ]
    return "".join(lines)


def pem_cert(pem_or_b64: str) -> str:
    b64 = normalize_cert(pem_or_b64)
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"


def build_settings(
    slug: str, cfg: dict[str, Any], sp_private_key: str | None = None, *, require_signed_messages: bool = False,
) -> dict[str, Any]:
    urls = sp_urls(slug)
    sp_cert = normalize_cert(cfg["sp_x509_cert"]) if cfg.get("sp_x509_cert") else ""
    sign = bool(cfg.get("sign_authn_requests"))
    out: dict[str, Any] = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": urls["entity_id"],
            "assertionConsumerService": {"url": urls["acs_url"], "binding": POST_BINDING},
            "singleLogoutService": {"url": urls["sls_url"], "binding": REDIRECT_BINDING},
            "NameIDFormat": cfg.get("name_id_format")
            or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": sp_cert,
            "privateKey": (sp_private_key or "").strip(),
        },
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {"url": cfg["idp_sso_url"], "binding": REDIRECT_BINDING},
            "x509cert": normalize_cert(cfg["idp_x509_cert"]),
        },
        "security": {
            "authnRequestsSigned": sign,
            "logoutRequestSigned": sign,
            "logoutResponseSigned": sign,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": bool(cfg.get("require_encrypted_assertions")),
            "wantMessagesSigned": bool(cfg.get("want_messages_signed", False)) or require_signed_messages,
            "wantNameId": True,
            "wantAttributeStatement": False,
            "requestedAuthnContext": False,
            "rejectDeprecatedAlgorithm": True,
            "allowRepeatAttributeName": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }
    if cfg.get("idp_slo_url"):
        out["idp"]["singleLogoutService"] = {"url": cfg["idp_slo_url"], "binding": REDIRECT_BINDING}
    return out


def _request_data(
    slug: str, post: dict[str, str] | None = None, *, which: str = "acs_url",
    get: dict[str, str] | None = None, query_string: str = "",
) -> dict[str, Any]:
    """python3-saml derives "the current URL" from this dict and checks the
    response's Destination against it -- so we build it from the CONFIGURED
    ACS / SLS URL, never from the incoming Host header."""
    p = urlsplit(sp_urls(slug)[which])
    https = p.scheme == "https"
    data: dict[str, Any] = {
        "https": "on" if https else "off",
        "http_host": p.hostname or "",
        "server_port": str(p.port or (443 if https else 80)),
        "script_name": p.path,
        "get_data": get or {},
        "post_data": post or {},
    }
    if query_string:
        # sign-verify the bytes the IdP actually signed (IdPs differ in
        # percent-encoding case), not a re-encoding of the parsed values.
        data["query_string"] = query_string
        data["validate_signature_from_qs"] = True
    return data


def parse_idp_metadata(xml: str) -> dict[str, str]:
    _require()
    try:
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml, required_sso_binding=REDIRECT_BINDING)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("bad_metadata", f"could not parse IdP metadata: {type(exc).__name__}") from exc
    idp = data.get("idp") or {}
    cert = idp.get("x509cert")
    if not cert:
        multi = (idp.get("x509certMulti") or {}).get("signing") or []
        cert = multi[0] if multi else None
    sso = (idp.get("singleSignOnService") or {}).get("url")
    if not (idp.get("entityId") and sso and cert):
        raise SAMLError("bad_metadata", "metadata lacks entityID, a Redirect SSO URL or a signing cert")
    out = {"idp_entity_id": idp["entityId"], "idp_sso_url": sso, "idp_x509_cert": cert}
    slo = (idp.get("singleLogoutService") or {}).get("url")
    if slo:
        out["idp_slo_url"] = slo
    nid = (data.get("sp") or {}).get("NameIDFormat")
    if nid:
        out["name_id_format"] = nid
    return out


async def fetch_idp_metadata(url: str, *, allow_private: bool = False, transport: Any = None) -> str:
    """Download IdP metadata through the DNS-pinned transport: https only,
    public addresses only (unless allow_private), no redirects, size-capped."""
    import httpx

    from ..integrations import netsafety
    from ..integrations.pinned import PinnedTransport

    try:
        await netsafety.validate_outbound_url(url, allow_private=allow_private)
        async with httpx.AsyncClient(
            transport=transport or PinnedTransport(allow_private=allow_private),
            timeout=httpx.Timeout(10.0), follow_redirects=False,
        ) as c:
            r = await c.get(url, headers={"Accept": "application/samlmetadata+xml, application/xml, text/xml"})
    except netsafety.UnsafeURL as exc:
        raise SAMLError("bad_metadata", f"metadata URL refused: {exc}") from exc
    except httpx.HTTPError as exc:
        raise SAMLError("bad_metadata", f"metadata URL unreachable: {type(exc).__name__}") from exc
    if r.status_code != 200:
        raise SAMLError("bad_metadata", f"metadata URL returned HTTP {r.status_code}")
    if len(r.content) > _MAX_METADATA_BYTES:
        raise SAMLError("bad_metadata", "metadata document too large")
    return r.text


def generate_sp_keypair(slug: str, *, days: int = 3650) -> tuple[str, str]:
    """A fresh self-signed SP signing/encryption pair -> (cert_pem, key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"paddock-sp-{slug}")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5)).not_valid_after(now + _dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode(),
    )


def _check_keypair(cfg: dict[str, Any], key_pem: str | None) -> None:
    """The private key must exist and match the SP certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    need = cfg.get("sign_authn_requests") or cfg.get("require_encrypted_assertions")
    if not cfg.get("sp_x509_cert") or not key_pem:
        if need:
            raise SAMLError("bad_config", "signing / encrypted assertions need sp_x509_cert and sp_private_key")
        return
    try:
        cert = x509.load_pem_x509_certificate(pem_cert(cfg["sp_x509_cert"]).encode())
        key = serialization.load_pem_private_key(key_pem.strip().encode(), password=None)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("bad_config", f"SP certificate / private key unreadable: {type(exc).__name__}") from exc
    pub = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(*pub) != key.public_key().public_bytes(*pub):
        raise SAMLError("bad_config", "sp_private_key does not match sp_x509_cert")


def validate_config(slug: str, cfg: dict[str, Any], sp_private_key: str | None = None) -> None:
    _require()
    _check_keypair(cfg, sp_private_key)
    try:
        OneLogin_Saml2_Settings(build_settings(slug, cfg, sp_private_key), sp_validation_only=False)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("bad_config", f"invalid SAML settings: {exc}") from exc


def sp_metadata(slug: str, cfg: dict[str, Any], sp_private_key: str | None = None) -> str:
    _require()
    s = OneLogin_Saml2_Settings(build_settings(slug, cfg, sp_private_key), sp_validation_only=True)
    md = s.get_sp_metadata()
    errors = s.validate_metadata(md)
    if errors:
        raise SAMLError("bad_config", f"generated SP metadata invalid: {errors}")
    return md.decode("utf-8") if isinstance(md, bytes) else md


def start_login(slug: str, cfg: dict[str, Any], relay_state: str, sp_private_key: str | None = None) -> tuple[str, str]:
    """Return (redirect_url, authn_request_id). Signed when the provider says so."""
    _require()
    _check_keypair(cfg, sp_private_key)
    auth = OneLogin_Saml2_Auth(_request_data(slug), build_settings(slug, cfg, sp_private_key))
    url = auth.login(return_to=relay_state, set_nameid_policy=True)
    return url, auth.get_last_request_id()


@dataclass
class SAMLResult:
    name_id: str
    name_id_format: str | None
    attributes: dict[str, list[str]]
    assertion_id: str | None
    not_on_or_after: int | None
    session_index: str | None
    name_id_nq: str | None = None
    name_id_spnq: str | None = None


def process_response(
    slug: str, cfg: dict[str, Any], *, saml_response: str, relay_state: str, request_id: str,
    sp_private_key: str | None = None,
) -> SAMLResult:
    _require()
    auth = OneLogin_Saml2_Auth(
        _request_data(slug, {"SAMLResponse": saml_response, "RelayState": relay_state}),
        build_settings(slug, cfg, sp_private_key),
    )
    try:
        auth.process_response(request_id=request_id)
    except Exception as exc:  # noqa: BLE001 -- malformed XML, bad base64, undecryptable, ...
        raise SAMLError("invalid_assertion", f"unprocessable SAMLResponse: {type(exc).__name__}") from exc
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or ",".join(errors) or "not authenticated"
        raise SAMLError("invalid_assertion", reason[:300])
    name_id = auth.get_nameid()
    if not name_id:
        raise SAMLError("invalid_assertion", "assertion has no NameID")
    attrs = {k: [str(v) for v in (vals or [])] for k, vals in (auth.get_attributes() or {}).items()}
    return SAMLResult(
        name_id=name_id,
        name_id_format=auth.get_nameid_format(),
        attributes=attrs,
        assertion_id=auth.get_last_assertion_id(),
        not_on_or_after=auth.get_last_assertion_not_on_or_after(),
        session_index=auth.get_session_index(),
        name_id_nq=auth.get_nameid_nq(),
        name_id_spnq=auth.get_nameid_spnq(),
    )


# --------------------------------------------------------------------------- #
# Single logout (HTTP-Redirect binding)
# --------------------------------------------------------------------------- #

def slo_supported(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("idp_slo_url"))


def build_logout_request(
    slug: str, cfg: dict[str, Any], *, name_id: str, session_index: str | None,
    name_id_format: str | None, relay_state: str, sp_private_key: str | None = None,
    name_id_nq: str | None = None, name_id_spnq: str | None = None,
) -> tuple[str, str]:
    """SP-initiated SLO: (redirect_url to the IdP, LogoutRequest ID)."""
    _require()
    if not slo_supported(cfg):
        raise SAMLError("slo_unsupported", "the IdP has no single-logout URL configured")
    auth = OneLogin_Saml2_Auth(_request_data(slug, which="sls_url"), build_settings(slug, cfg, sp_private_key))
    url = auth.logout(
        return_to=relay_state, name_id=name_id, session_index=session_index,
        nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq,
    )
    return url, auth.get_last_request_id()


@dataclass
class SLSResult:
    kind: str                       # "request" (IdP-initiated) | "response" (to our request)
    redirect_url: str | None = None  # where to send the browser (the LogoutResponse for a request)
    name_id: str | None = None
    session_indexes: list[str] = field(default_factory=list)


def process_sls(
    slug: str, cfg: dict[str, Any], *, query_string: str, request_id: str | None = None,
    sp_private_key: str | None = None,
) -> SLSResult:
    """Handle a message at the SingleLogoutService endpoint.

    Messages MUST be signed by the pinned IdP certificate: an unsigned
    LogoutRequest would let anyone on the internet end any user's session.
    """
    _require()
    get = dict(parse_qsl(query_string, keep_blank_values=True, max_num_fields=16))
    if "SAMLRequest" not in get and "SAMLResponse" not in get:
        raise SAMLError("invalid_binding", "no SAMLRequest or SAMLResponse (only HTTP-Redirect is supported)")
    if "Signature" not in get:
        raise SAMLError("invalid_logout", "single-logout messages must be signed")
    auth = OneLogin_Saml2_Auth(
        _request_data(slug, which="sls_url", get=get, query_string=query_string),
        build_settings(slug, cfg, sp_private_key, require_signed_messages=True),
    )
    try:
        url = auth.process_slo(keep_local_session=True, request_id=request_id)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("invalid_logout", f"unprocessable logout message: {type(exc).__name__}") from exc
    errors = auth.get_errors()
    if errors:
        raise SAMLError("invalid_logout", (auth.get_last_error_reason() or ",".join(errors))[:300])
    if "SAMLResponse" in get:
        return SLSResult(kind="response")
    xml = auth.get_last_request_xml()
    try:
        name_id = OneLogin_Saml2_Logout_Request.get_nameid(xml, auth.get_settings().get_sp_key())
        indexes = OneLogin_Saml2_Logout_Request.get_session_indexes(xml)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("invalid_logout", f"logout request unreadable: {type(exc).__name__}") from exc
    return SLSResult(kind="request", redirect_url=url, name_id=name_id, session_indexes=list(indexes or []))


EMAIL_NAMEID_FORMAT = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    if not SAML_AVAILABLE
    else OneLogin_Saml2_Constants.NAMEID_EMAIL_ADDRESS
)
