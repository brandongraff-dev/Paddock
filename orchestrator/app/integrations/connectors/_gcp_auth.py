"""Google service-account auth without the Google SDK.

``service_account_json`` (the downloaded key file, stored as ONE secret) is
turned into an OAuth2 access token with the JWT-bearer grant (RFC 7523):

1. build ``{iss: client_email, scope, aud: token_uri, iat, exp}``;
2. sign it RS256 with the key's ``private_key`` (``cryptography``);
3. ``POST token_uri`` ``grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer``.

Used by the GCP SOURCE connector and the Google SecOps SIEM connector. Tokens
are cached per (client_email, scope, key fingerprint) until 5 minutes before
expiry and dropped on a 401, so a rotated key recovers by itself.

Safety: the key file names its own ``token_uri``, which is IGNORED (a hostile
key must not redirect the signed assertion). The token endpoint is always
``https://oauth2.googleapis.com/token`` unless the integration config sets
``token_uri`` explicitly (then it is URL-validated like any other). Error text
is ours (status code + what we were doing), never the key or the assertion.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Mapping, Optional

from ._common import SourceError, checked_url, request_json

DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_REFRESH_MARGIN_S = 300

# (client_email, scope, sha256(private_key)) -> (token, expires_at_monotonic)
_TOKEN_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}


def clear_token_cache() -> None:
    _TOKEN_CACHE.clear()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_key(raw: Optional[str]) -> dict[str, Any]:
    """Parse + sanity-check a service-account key. Messages never echo the key."""
    if not raw:
        raise SourceError("secret 'service_account_json' is required", retryable=False)
    try:
        key = json.loads(raw)
    except ValueError:
        raise SourceError("service_account_json is not valid JSON", retryable=False) from None
    if not isinstance(key, dict) or key.get("type") != "service_account":
        raise SourceError("service_account_json is not a service-account key", retryable=False)
    for f in ("client_email", "private_key"):
        if not key.get(f):
            raise SourceError(f"service_account_json is missing '{f}'", retryable=False)
    return key


def sign_jwt(key: Mapping[str, Any], scope: str, token_uri: str, *,
             now: Optional[float] = None) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    iat = int(now if now is not None else time.time())
    header: dict[str, Any] = {"alg": "RS256", "typ": "JWT"}
    if key.get("private_key_id"):
        header["kid"] = key["private_key_id"]
    claims = {"iss": key["client_email"], "scope": scope, "aud": token_uri,
              "iat": iat, "exp": iat + 3600}
    signing_input = (_b64(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     _b64(json.dumps(claims, separators=(",", ":")).encode()))
    try:
        priv = serialization.load_pem_private_key(str(key["private_key"]).encode(), password=None)
        sig = priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[call-arg,union-attr]
    except Exception:  # noqa: BLE001 - never echo key material
        raise SourceError("service-account private_key could not be used to sign",
                          retryable=False) from None
    return signing_input + "." + _b64(sig)


async def access_token(http: Any, key: Mapping[str, Any], config: Mapping[str, Any], scope: str,
                       *, allow_private: bool = False, force: bool = False) -> str:
    fp = hashlib.sha256(str(key["private_key"]).encode()).hexdigest()
    ck = (str(key["client_email"]), scope, fp)
    now = time.monotonic()
    hit = _TOKEN_CACHE.get(ck)
    if hit and not force and hit[1] - _REFRESH_MARGIN_S > now:
        return hit[0]
    uri = await checked_url(str(config.get("token_uri") or DEFAULT_TOKEN_URI),
                            allow_private=allow_private)
    assertion = sign_jwt(key, scope, uri)
    body = await request_json(http, "POST", uri, what="Google token request",
                              data={"grant_type": JWT_GRANT, "assertion": assertion})
    tok = body.get("access_token") if isinstance(body, dict) else None
    if not tok:
        raise SourceError("Google token response had no access_token", retryable=False)
    try:
        ttl = float(body.get("expires_in") or 3600)
    except (TypeError, ValueError):
        ttl = 3600.0
    _TOKEN_CACHE[ck] = (str(tok), now + ttl)
    return str(tok)
