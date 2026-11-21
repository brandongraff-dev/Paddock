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

If ``python3-saml`` / ``xmlsec`` cannot be imported the SAML endpoints
answer 501 with a pointer to docs/SSO.md instead of failing at import time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

try:  # pragma: no cover - exercised implicitly by every SAML test
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.constants import OneLogin_Saml2_Constants
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    SAML_AVAILABLE = True
    SAML_IMPORT_ERROR: str | None = None
except Exception as _exc:  # noqa: BLE001
    SAML_AVAILABLE = False
    SAML_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"

from ..config import settings

POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


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
    }


def normalize_cert(pem_or_b64: str) -> str:
    """Accept PEM or bare base64; return bare base64 (what python3-saml wants)."""
    lines = [
        ln.strip() for ln in pem_or_b64.strip().splitlines()
        if ln.strip() and "-----" not in ln
    ]
    return "".join(lines)


def build_settings(slug: str, cfg: dict[str, Any]) -> dict[str, Any]:
    urls = sp_urls(slug)
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": urls["entity_id"],
            "assertionConsumerService": {"url": urls["acs_url"], "binding": POST_BINDING},
            "NameIDFormat": cfg.get("name_id_format")
            or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {"url": cfg["idp_sso_url"], "binding": REDIRECT_BINDING},
            "x509cert": normalize_cert(cfg["idp_x509_cert"]),
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": bool(cfg.get("want_messages_signed", False)),
            "wantNameId": True,
            "wantAttributeStatement": False,
            "requestedAuthnContext": False,
            "rejectDeprecatedAlgorithm": True,
            "allowRepeatAttributeName": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _request_data(slug: str, post: dict[str, str] | None = None) -> dict[str, Any]:
    """python3-saml derives "the current URL" from this dict and checks the
    response's Destination against it -- so we build it from the CONFIGURED
    ACS URL, never from the incoming Host header."""
    p = urlsplit(sp_urls(slug)["acs_url"])
    https = p.scheme == "https"
    return {
        "https": "on" if https else "off",
        "http_host": p.hostname or "",
        "server_port": str(p.port or (443 if https else 80)),
        "script_name": p.path,
        "get_data": {},
        "post_data": post or {},
    }


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
    nid = (data.get("sp") or {}).get("NameIDFormat")
    if nid:
        out["name_id_format"] = nid
    return out


def validate_config(slug: str, cfg: dict[str, Any]) -> None:
    _require()
    try:
        OneLogin_Saml2_Settings(build_settings(slug, cfg), sp_validation_only=False)
    except Exception as exc:  # noqa: BLE001
        raise SAMLError("bad_config", f"invalid SAML settings: {exc}") from exc


def sp_metadata(slug: str, cfg: dict[str, Any]) -> str:
    _require()
    s = OneLogin_Saml2_Settings(build_settings(slug, cfg), sp_validation_only=True)
    md = s.get_sp_metadata()
    errors = s.validate_metadata(md)
    if errors:
        raise SAMLError("bad_config", f"generated SP metadata invalid: {errors}")
    return md.decode("utf-8") if isinstance(md, bytes) else md


def start_login(slug: str, cfg: dict[str, Any], relay_state: str) -> tuple[str, str]:
    """Return (redirect_url, authn_request_id)."""
    _require()
    auth = OneLogin_Saml2_Auth(_request_data(slug), build_settings(slug, cfg))
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


def process_response(
    slug: str, cfg: dict[str, Any], *, saml_response: str, relay_state: str, request_id: str,
) -> SAMLResult:
    _require()
    auth = OneLogin_Saml2_Auth(
        _request_data(slug, {"SAMLResponse": saml_response, "RelayState": relay_state}),
        build_settings(slug, cfg),
    )
    try:
        auth.process_response(request_id=request_id)
    except Exception as exc:  # noqa: BLE001 -- malformed XML, bad base64, ...
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
    )


EMAIL_NAMEID_FORMAT = (
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    if not SAML_AVAILABLE
    else OneLogin_Saml2_Constants.NAMEID_EMAIL_ADDRESS
)
