"""Unit tests for governance hardening that need no database."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import audit
from app import auth as auth_svc
from app.routers.scope import _validate_entry_value


# ---- API-key scopes narrow, never widen ----------------------------------- #

def test_admin_key_scoped_read_is_read_only():
    caps = auth_svc.capabilities_for("admin", frozenset({"read"}))
    assert caps == frozenset({"read"})


def test_viewer_key_cannot_self_escalate():
    caps = auth_svc.capabilities_for("viewer", frozenset({"admin", "write"}))
    assert "admin" not in caps and "write" not in caps


def test_jwt_principal_gets_full_role():
    assert auth_svc.capabilities_for("admin") == auth_svc.ROLE_CAPABILITIES["admin"]


# ---- JWT --------------------------------------------------------------------- #

def test_jwt_without_exp_rejected(monkeypatch):
    import jwt

    monkeypatch.setattr(auth_svc, "_jwt_secret", lambda: "s" * 48)
    tok = jwt.encode({"sub": "1", "typ": "access", "iat": 1}, "s" * 48, algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        auth_svc.verify_jwt(tok)


def test_jwt_wrong_typ_rejected(monkeypatch):
    import time

    import jwt

    monkeypatch.setattr(auth_svc, "_jwt_secret", lambda: "s" * 48)
    now = int(time.time())
    tok = jwt.encode({"sub": "1", "typ": "refresh", "iat": now, "exp": now + 60},
                     "s" * 48, algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        auth_svc.verify_jwt(tok)


# ---- X-Forwarded-For only from trusted proxies -------------------------------- #

def _req(peer: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers,
                    "method": "GET", "path": "/"})


def test_xff_ignored_from_untrusted_peer():
    assert auth_svc.client_ip(_req("203.0.113.9", "10.9.8.7")) == "203.0.113.9"


def test_xff_honoured_from_trusted_proxy():
    assert auth_svc.client_ip(_req("127.0.0.1", "198.51.100.4, 10.0.0.1")) == "198.51.100.4"


def test_xff_garbage_from_trusted_proxy_falls_back():
    assert auth_svc.client_ip(_req("127.0.0.1", "<script>")) == "127.0.0.1"


# ---- Audit sanitising ----------------------------------------------------------- #

def test_audit_sanitize_strips_nul_and_stabilises_floats():
    out = audit._sanitize({"note": "a\x00b", "n": 1e16, "nested": [{"k\x00": 0.5}]})
    assert out == {"note": "ab", "n": "1e+16", "nested": [{"k": "0.5"}]}


def test_audit_hash_stable_after_jsonb_roundtrip():
    import json

    row = {"ts": None, "actor": "a", "details": audit._sanitize({"n": 1e16})}
    h1 = audit.compute_entry_hash(audit.GENESIS_HASH, row)
    row2 = {**row, "details": json.loads(json.dumps(row["details"]))}
    assert audit.compute_entry_hash(audit.GENESIS_HASH, row2) == h1


# ---- Scope entry validation ---------------------------------------------------- #

@pytest.mark.parametrize("kind,value", [
    ("subdomain_wildcard", "com"),
    ("subdomain_wildcard", "*"),
    ("subdomain_wildcard", "co.uk"),
    ("subdomain_wildcard", "*.github.io"),
    ("domain", "*.*"),
    ("domain", "exa\tmple.com"),
    ("domain", "10.0.0.1"),
    ("ipv4_cidr", "0.0.0.0/0"),
    ("ipv4_cidr", "10.0.0.0/8"),
    ("ipv4_cidr", "169.254.169.254/32"),
    ("ipv4_cidr", "169.254.0.0/16"),
    ("ipv6_cidr", "::/0"),
    ("ipv6_cidr", "fd00:ec2::254/128"),
    ("asn", "SAAS15169"),
    ("asn", "AS²"),
])
def test_scope_entry_rejects_dangerous_values(kind, value):
    with pytest.raises(HTTPException) as e:
        _validate_entry_value(kind, value)
    assert e.value.status_code == 422


@pytest.mark.parametrize("kind,value,want", [
    ("domain", "API.Example.COM.", "api.example.com"),
    ("subdomain_wildcard", "*.example.co.uk", "example.co.uk"),
    ("subdomain_wildcard", "bücher.example", "xn--bcher-kva.example"),
    ("ipv4_cidr", "10.1.2.3/24", "10.1.2.0/24"),
    ("ipv4_cidr", "127.0.0.1/32", "127.0.0.1/32"),
    ("ipv6_cidr", "2001:DB8::/32", "2001:db8::/32"),
    ("asn", "as15169", "AS15169"),
])
def test_scope_entry_canonicalised(kind, value, want):
    assert _validate_entry_value(kind, value) == want
