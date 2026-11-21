"""Test doubles for enterprise identity: a fake OIDC provider served through
``httpx.MockTransport`` (discovery + JWKS + token endpoint with PKCE
verification) that mints real RS256 ID tokens, plus flow helpers."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.test/oauth2/default"
CLIENT_ID = "paddock-client"
CLIENT_SECRET = "s3cret-client-secret"


def s256(v: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdP:
    def __init__(self, issuer: str = ISSUER, client_id: str = CLIENT_ID) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.key = new_key()
        self.kid = "key-1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.jwks_hits = 0
        self.discovery_hits = 0
        self.token_requests: list[dict[str, Any]] = []
        self.algs = ["RS256"]

    # ------------------------------------------------------------------ #
    def rotate(self) -> None:
        self.key = new_key()
        self.kid = f"key-{secrets.token_hex(2)}"

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def claims(self, nonce: str, **over: Any) -> dict[str, Any]:
        now = int(time.time())
        c = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "00u-alice",
            "email": "alice@example.com",
            "email_verified": True,
            "name": "Alice Example",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "groups": ["paddock-analysts"],
        }
        c.update(over)
        return {k: v for k, v in c.items() if v is not None}

    def mint(self, claims: dict[str, Any], *, key=None, kid: str | None = None, alg: str = "RS256") -> str:
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": kid or self.kid})

    def issue_code(self, *, nonce: str, code_challenge: str, id_token: str | None = None, **claim_over) -> str:
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "challenge": code_challenge,
            "id_token": id_token or self.mint(self.claims(nonce, **claim_over)),
        }
        return code

    # ------------------------------------------------------------------ #
    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        base = self.issuer.rstrip("/")
        if url == base + "/.well-known/openid-configuration":
            self.discovery_hits += 1
            return httpx.Response(200, json={
                "issuer": self.issuer,
                "authorization_endpoint": base + "/v1/authorize",
                "token_endpoint": base + "/v1/token",
                "jwks_uri": base + "/v1/keys",
                "userinfo_endpoint": base + "/v1/userinfo",
                "id_token_signing_alg_values_supported": self.algs,
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
            })
        if url == base + "/v1/keys":
            self.jwks_hits += 1
            return httpx.Response(200, json=self.jwks())
        if url == base + "/v1/token" and request.method == "POST":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append({"form": form, "auth": request.headers.get("authorization")})
            expected = "Basic " + base64.b64encode(f"{self.client_id}:{CLIENT_SECRET}".encode()).decode()
            if request.headers.get("authorization") != expected:
                return httpx.Response(401, json={"error": "invalid_client"})
            entry = self.codes.pop(form.get("code", ""), None)
            if entry is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            if s256(form.get("code_verifier", "")) != entry["challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "pkce"})
            return httpx.Response(200, json={
                "access_token": "at-" + secrets.token_hex(8), "token_type": "Bearer",
                "id_token": entry["id_token"], "expires_in": 300,
            })
        return httpx.Response(404, json={"error": "not_found"})


def oidc_provider_body(slug: str = "okta", issuer: str = ISSUER, **over: Any) -> dict[str, Any]:
    body = {
        "slug": slug,
        "kind": "oidc",
        "preset": "okta",
        "display_name": "Okta",
        "oidc": {"issuer": issuer, "client_id": CLIENT_ID},
        "client_secret": CLIENT_SECRET,
        "role_mappings": [
            {"group": "paddock-admins", "role": "admin", "clearance": "restricted"},
            {"group": "paddock-analysts", "role": "analyst", "clearance": "confidential"},
        ],
    }
    body.update(over)
    return body


SPA_VERIFIER = "spa-verifier-" + "x" * 40


async def start(client, slug: str = "okta", *, return_to: str = "/findings", spa: bool = True):
    params = {"return_to": return_to}
    if spa:
        params["spa_challenge"] = s256(SPA_VERIFIER)
    r = await client.get(f"/v1/auth/sso/{slug}/start", params=params)
    assert r.status_code == 302, r.text
    q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    return q


async def callback(client, slug: str, *, code: str, state: str):
    r = await client.get(f"/v1/auth/sso/{slug}/callback", params={"code": code, "state": state})
    assert r.status_code == 303, r.text
    loc = urlsplit(r.headers["location"])
    assert loc.path == "/sso/callback"
    return {k: v[0] for k, v in parse_qs(loc.query).items()}


async def full_login(client, idp: FakeIdP, slug: str = "okta", **claim_over):
    q = await start(client, slug)
    code = idp.issue_code(nonce=q["nonce"], code_challenge=q["code_challenge"], **claim_over)
    return await callback(client, slug, code=code, state=q["state"])
