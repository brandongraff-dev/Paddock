"""OpenID Connect relying party: discovery, JWKS, PKCE, code exchange, ID tokens.

Security properties (each has a test in tests/test_identity_oidc.py):

* Authorization-code flow only, always with PKCE (S256), ``state`` and
  ``nonce``. The implicit / hybrid flows are never requested.
* Discovery (``<issuer>/.well-known/openid-configuration``) must echo the
  configured issuer; every endpoint it returns passes the outbound-URL SSRF
  guard (``integrations.netsafety``) before Paddock talks to it.
* ID tokens: asymmetric algorithms only (``none`` / ``HS*`` are rejected even
  if the IdP advertises them), signature verified against the IdP's JWKS
  (cached; an unknown ``kid`` triggers one rate-limited refetch so key
  rotation just works), ``iss`` exact, ``aud`` contains our client id,
  ``azp`` checked when present or when ``aud`` has several values,
  ``exp``/``iat``/``nbf`` with bounded leeway, and ``nonce`` compared in
  constant time.
* No token, code or secret is ever logged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

from ..integrations import netsafety
from ..integrations.pinned import PinnedTransport

ALLOWED_ALGS = frozenset({
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
})
DISCOVERY_TTL_SEC = 3600
JWKS_TTL_SEC = 3600
JWKS_FORCED_REFRESH_MIN_SEC = 30
_HTTP_TIMEOUT = httpx.Timeout(10.0)
_MAX_DOC_BYTES = 512 * 1024


class OIDCError(Exception):
    """A failed OIDC step. ``code`` is safe to show the user; ``detail`` is
    for server logs / the audit record (never contains secrets)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# Tests inject an httpx.MockTransport here; production uses the default.
_transport: httpx.AsyncBaseTransport | None = None


def set_transport(transport: httpx.AsyncBaseTransport | None) -> None:
    global _transport
    _transport = transport


async def check_url(url: str, *, allow_private: bool) -> None:
    """SSRF guard for every IdP endpoint (overridable in tests)."""
    try:
        await netsafety.validate_outbound_url(url, allow_private=allow_private)
    except netsafety.UnsafeURL as exc:
        raise OIDCError("provider_unavailable", f"unsafe IdP URL: {exc}") from exc


def _client(allow_private: bool = False) -> httpx.AsyncClient:
    # Production: DNS-pinned transport (resolve once, validate, connect to that
    # IP, SNI/cert for the real hostname). Tests inject a MockTransport.
    return httpx.AsyncClient(
        transport=_transport or PinnedTransport(allow_private=allow_private),
        timeout=_HTTP_TIMEOUT, follow_redirects=False,
    )


async def _get_json(url: str, *, allow_private: bool, headers: dict[str, str] | None = None) -> dict:
    await check_url(url, allow_private=allow_private)
    try:
        async with _client(allow_private) as c:
            r = await c.get(url, headers={"Accept": "application/json", **(headers or {})})
    except httpx.HTTPError as exc:
        raise OIDCError("provider_unavailable", f"GET {_safe(url)} failed: {type(exc).__name__}") from exc
    if r.status_code != 200:
        raise OIDCError("provider_unavailable", f"GET {_safe(url)} -> HTTP {r.status_code}")
    if len(r.content) > _MAX_DOC_BYTES:
        raise OIDCError("provider_unavailable", f"GET {_safe(url)}: response too large")
    try:
        doc = r.json()
    except ValueError as exc:
        raise OIDCError("provider_unavailable", f"GET {_safe(url)}: not JSON") from exc
    if not isinstance(doc, dict):
        raise OIDCError("provider_unavailable", f"GET {_safe(url)}: not a JSON object")
    return doc


def _safe(url: str) -> str:
    """URL without query/fragment, for logs."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def reset_caches() -> None:
    _discovery_cache.clear()
    jwks_cache.clear()


async def discover(issuer: str, *, allow_private: bool = False) -> dict[str, Any]:
    key = issuer.rstrip("/")
    hit = _discovery_cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < DISCOVERY_TTL_SEC:
        return hit[1]
    doc = await _get_json(key + "/.well-known/openid-configuration", allow_private=allow_private)
    got = str(doc.get("issuer") or "")
    # Tolerate only a trailing-slash difference (Auth0's issuer ends in "/"),
    # then pin the IdP's exact spelling as the expected `iss`.
    if got.rstrip("/") != key:
        raise OIDCError("provider_unavailable", "discovery issuer does not match the configured issuer")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        val = doc.get(field)
        if not isinstance(val, str) or not val:
            raise OIDCError("provider_unavailable", f"discovery document lacks {field}")
        await check_url(val, allow_private=allow_private)
    if doc.get("userinfo_endpoint"):
        await check_url(str(doc["userinfo_endpoint"]), allow_private=allow_private)
    _discovery_cache[key] = (now, doc)
    return doc


# --------------------------------------------------------------------------- #
# JWKS (cached, rotation-aware)
# --------------------------------------------------------------------------- #

class JWKSCache:
    def __init__(self) -> None:
        self._sets: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._last_forced: dict[str, float] = {}

    def clear(self) -> None:
        self._sets.clear()
        self._last_forced.clear()

    async def _fetch(self, uri: str, allow_private: bool) -> list[dict[str, Any]]:
        doc = await _get_json(uri, allow_private=allow_private)
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise OIDCError("provider_unavailable", "JWKS has no keys array")
        keys = [k for k in keys if isinstance(k, dict)]
        self._sets[uri] = (time.monotonic(), keys)
        return keys

    @staticmethod
    def _pick(keys: list[dict[str, Any]], kid: str | None, alg: str) -> dict[str, Any] | None:
        cands = [
            k for k in keys
            if k.get("use", "sig") == "sig"
            and (k.get("alg") in (None, alg))
            and (kid is None or k.get("kid") == kid)
        ]
        if kid is None and len(cands) != 1:
            return None  # ambiguous without a kid: refuse rather than guess
        return cands[0] if cands else None

    async def get_key(self, uri: str, kid: str | None, alg: str, *, allow_private: bool) -> jwt.PyJWK:
        now = time.monotonic()
        hit = self._sets.get(uri)
        keys = hit[1] if hit and now - hit[0] < JWKS_TTL_SEC else await self._fetch(uri, allow_private)
        jwk = self._pick(keys, kid, alg)
        if jwk is None and now - self._last_forced.get(uri, -1e9) >= JWKS_FORCED_REFRESH_MIN_SEC:
            # Unknown kid: the IdP probably rotated. Refetch once (rate-limited
            # so a flood of garbage tokens can't hammer the IdP).
            self._last_forced[uri] = now
            keys = await self._fetch(uri, allow_private)
            jwk = self._pick(keys, kid, alg)
        if jwk is None:
            raise OIDCError("invalid_token", "no JWKS key matches the token's kid/alg")
        try:
            return jwt.PyJWK(jwk, algorithm=alg)
        except jwt.PyJWTError as exc:
            raise OIDCError("invalid_token", f"unusable JWKS key: {exc}") from exc


jwks_cache = JWKSCache()


# --------------------------------------------------------------------------- #
# Authorization request
# --------------------------------------------------------------------------- #

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)  # 64 chars, within RFC 7636's 43..128
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def authorization_url(
    discovery: dict[str, Any],
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    nonce: str,
    code_challenge: str,
    extra: dict[str, str] | None = None,
) -> str:
    params = {
        **(extra or {}),
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    ep = str(discovery["authorization_endpoint"])
    return ep + ("&" if "?" in ep else "?") + urlencode(params)


# --------------------------------------------------------------------------- #
# Token exchange
# --------------------------------------------------------------------------- #

async def exchange_code(
    discovery: dict[str, Any],
    *,
    client_id: str,
    client_secret: str | None,
    auth_method: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    allow_private: bool,
) -> dict[str, Any]:
    url = str(discovery["token_endpoint"])
    await check_url(url, allow_private=allow_private)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    auth = None
    if auth_method == "client_secret_basic" and client_secret:
        auth = httpx.BasicAuth(client_id, client_secret)
    else:
        form["client_id"] = client_id
        if auth_method == "client_secret_post" and client_secret:
            form["client_secret"] = client_secret
    try:
        async with _client(allow_private) as c:
            r = await c.post(url, data=form, auth=auth, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise OIDCError("provider_unavailable", f"token endpoint unreachable: {type(exc).__name__}") from exc
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200 or not isinstance(body, dict):
        err = body.get("error") if isinstance(body, dict) else None
        raise OIDCError("idp_error", f"token endpoint HTTP {r.status_code} ({err or 'no error code'})")
    if not body.get("id_token"):
        raise OIDCError("invalid_token", "token response has no id_token")
    return body


async def fetch_userinfo(discovery: dict[str, Any], access_token: str, *, allow_private: bool) -> dict:
    ep = discovery.get("userinfo_endpoint")
    if not ep:
        return {}
    return await _get_json(
        str(ep), allow_private=allow_private, headers={"Authorization": f"Bearer {access_token}"},
    )


# --------------------------------------------------------------------------- #
# ID token validation
# --------------------------------------------------------------------------- #

async def validate_id_token(
    id_token: str,
    *,
    discovery: dict[str, Any],
    client_id: str,
    nonce: str,
    leeway: int = 60,
    allow_private: bool = False,
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_token", "malformed ID token") from exc
    alg = str(header.get("alg") or "")
    advertised = discovery.get("id_token_signing_alg_values_supported") or ["RS256"]
    if alg not in ALLOWED_ALGS or alg not in advertised:
        raise OIDCError("invalid_token", f"ID token alg {alg!r} not allowed")
    key = await jwks_cache.get_key(
        str(discovery["jwks_uri"]), header.get("kid"), alg, allow_private=allow_private,
    )
    try:
        claims = jwt.decode(
            id_token,
            key=key.key,
            algorithms=[alg],
            audience=client_id,
            issuer=str(discovery["issuer"]),
            leeway=leeway,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise OIDCError("invalid_token", "ID token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise OIDCError("invalid_token", "ID token audience mismatch") from exc
    except jwt.InvalidIssuerError as exc:
        raise OIDCError("invalid_token", "ID token issuer mismatch") from exc
    except jwt.InvalidSignatureError as exc:
        raise OIDCError("invalid_token", "ID token signature invalid") from exc
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_token", f"ID token rejected: {type(exc).__name__}") from exc

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or iat > time.time() + leeway:
        raise OIDCError("invalid_token", "ID token iat is in the future")
    aud = claims.get("aud")
    azp = claims.get("azp")
    if isinstance(aud, list) and len(aud) > 1 and azp is None:
        raise OIDCError("invalid_token", "multi-audience ID token without azp")
    if azp is not None and not hmac.compare_digest(str(azp).encode(), client_id.encode()):
        raise OIDCError("invalid_token", "ID token azp is not our client")
    got_nonce = claims.get("nonce")
    if not isinstance(got_nonce, str) or not hmac.compare_digest(
        got_nonce.encode("utf-8"), nonce.encode("utf-8")
    ):
        raise OIDCError("invalid_token", "ID token nonce mismatch")
    return claims
