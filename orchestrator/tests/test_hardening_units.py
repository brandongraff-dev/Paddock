"""Unit tests for governance hardening (no database, except the audit-ip test of the X-Forwarded-For section)."""
from __future__ import annotations

import json

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
    # P2.1 (docs/ASSURANCE_P2_1.md 6.3, D35): this used to expect the LEFTMOST entry, '198.51.100.4'. A proxy that
    # APPENDS (nginx, an ALB) leaves whatever the client wrote in front of it, so the leftmost entry is
    # attacker-chosen: a forged audit ip, a limiter bypass, a victim lockout. The address is the Nth entry from the
    # RIGHT (TRUSTED_PROXY_HOPS, default 1) and the client-written prefix is ignored.
    assert auth_svc.client_ip(_req("127.0.0.1", "198.51.100.4, 10.0.0.1")) == "10.0.0.1"


def test_xff_garbage_from_trusted_proxy_falls_back():
    assert auth_svc.client_ip(_req("127.0.0.1", "<script>")) == "127.0.0.1"


def _req_lines(peer: str, lines: list[str]) -> Request:
    headers = [(b"x-forwarded-for", ln.encode()) for ln in lines]
    return Request({"type": "http", "client": (peer, 1234), "headers": headers, "method": "GET", "path": "/"})


def _trust(monkeypatch, cidrs: str = "127.0.0.1/32,::1/128", hops: int = 1) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "trusted_proxy_cidrs", cidrs)
    monkeypatch.setattr(settings, "trusted_proxy_hops", hops)


def test_client_ip_is_the_strict_address(monkeypatch):
    """D35: ONE function, no per-site edits: ``client_ip`` and ``client_ip_strict`` give the same address and the
    same ``ClientAddr`` flag for every shape, so no call site can get the forgeable leftmost entry."""
    _trust(monkeypatch)
    cases = [
        ("203.0.113.9", None), ("203.0.113.9", "10.9.8.7"), ("127.0.0.1", None), ("127.0.0.1", "<script>"),
        ("127.0.0.1", "198.51.100.4"), ("127.0.0.1", "6.6.6.6, 198.51.100.4"), ("127.0.0.1", "1.1.1.1,,2.2.2.2"),
        ("127.0.0.1", ""), ("127.0.0.1", "6.6.6.6, 127.0.0.1"), ("::1", "2001:db8::5"),
    ]
    for peer, xff in cases:
        a, b = auth_svc.client_ip(_req(peer, xff)), auth_svc.client_ip_strict(_req(peer, xff))
        assert a == b and type(a) is type(b), (peer, xff)
        assert getattr(a, "proxied", None) == getattr(b, "proxied", None), (peer, xff)


@pytest.mark.parametrize("xff,want", [
    ("198.51.100.4", "198.51.100.4"),                       # a proxy that saw the client
    ("6.6.6.6, 198.51.100.4", "198.51.100.4"),              # the client wrote 6.6.6.6 itself: ignored
    ("6.6.6.6, 7.7.7.7, 8.8.8.8, 198.51.100.4", "198.51.100.4"),
    ("10.0.0.1, 198.51.100.4", "198.51.100.4"),             # a forged PRIVATE entry in front changes nothing
    ("198.51.100.4, 6.6.6.6", "6.6.6.6"),                   # the rightmost IS what the proxy appended
])
def test_forged_prefix_never_changes_the_address_and_never_picks_the_leftmost(monkeypatch, xff, want):
    _trust(monkeypatch)
    assert auth_svc.client_ip(_req("127.0.0.1", xff)) == want


def test_forged_prefix_across_header_lines(monkeypatch):
    """A proxy that adds its own LINE (HAProxy style) leaves the client-written line first: all lines count."""
    _trust(monkeypatch)
    assert auth_svc.client_ip(_req_lines("127.0.0.1", ["6.6.6.6", "198.51.100.4"])) == "198.51.100.4"


def test_forged_xff_from_an_untrusted_peer_is_ignored_and_flagged(monkeypatch):
    _trust(monkeypatch)
    got = auth_svc.client_ip(_req("203.0.113.9", "6.6.6.6"))
    assert got == "203.0.113.9" and got.proxied is True


def test_two_hops_take_the_second_entry_from_the_right(monkeypatch):
    _trust(monkeypatch, "127.0.0.1/32,10.0.0.0/8", hops=2)
    assert auth_svc.client_ip(_req("127.0.0.1", "6.6.6.6, 198.51.100.4, 10.0.0.2")) == "198.51.100.4"
    # the inner proxy entry must itself be trusted, else the chain is not what the operator configured: fail closed
    assert auth_svc.client_ip(_req("127.0.0.1", "6.6.6.6, 198.51.100.4, 9.9.9.9")) == "127.0.0.1"


def test_a_garbage_or_empty_entry_fails_closed_to_the_peer(monkeypatch):
    _trust(monkeypatch)
    for xff in ("6.6.6.6, <script>", "6.6.6.6, ", ",", " , ", "6.6.6.6, 198.51.100.4:99", "6.6.6.6, 1.2.3"):
        assert auth_svc.client_ip(_req("127.0.0.1", xff)) == "127.0.0.1", xff


def test_client_ip_is_computed_once_per_request(monkeypatch):
    """Cached on ``request.state.client_addr``: the middleware audit (intent + outcome) and every handler see one
    answer, and a header change after the first read cannot change it."""
    _trust(monkeypatch)
    req = _req("127.0.0.1", "198.51.100.4")
    first = auth_svc.client_ip(req)
    assert req.state.client_addr is first
    assert auth_svc.client_ip(req) is first
    req.scope["headers"] = [(b"x-forwarded-for", b"203.0.113.77")]
    assert auth_svc.client_ip(req) == "198.51.100.4"
    # a request with no socket peer caches the absence too
    nopeer = Request({"type": "http", "client": None, "headers": [], "method": "GET", "path": "/"})
    assert auth_svc.client_ip(nopeer) is None and auth_svc.client_ip(nopeer) is None


def test_a_chain_shorter_than_the_configured_hops_warns_and_fails_closed(monkeypatch, caplog):
    """A misconfiguration signal (the operator says 2 appending proxies, the request carries 1 entry): a WARNING, the
    socket peer as the address (a shared limiter bucket: availability, never a forged address)."""
    import logging

    _trust(monkeypatch, hops=2)
    monkeypatch.setattr(auth_svc, "_HOPS_WARNED_AT", 0.0, raising=False)
    with caplog.at_level(logging.WARNING, logger=auth_svc.logger.name):
        got = auth_svc.client_ip(_req("127.0.0.1", "198.51.100.4"))
    assert got == "127.0.0.1" and got.proxied is True
    assert any("trusted_proxy_hops" in (r.getMessage() + str(getattr(r, "__dict__", {}))) for r in caplog.records)


def test_the_hops_warning_is_throttled_and_silent_for_a_direct_trusted_probe(monkeypatch, caplog):
    import logging

    _trust(monkeypatch, hops=2)
    monkeypatch.setattr(auth_svc, "_HOPS_WARNED_AT", 0.0, raising=False)
    with caplog.at_level(logging.WARNING, logger=auth_svc.logger.name):
        for _ in range(5):
            auth_svc.client_ip(_req("127.0.0.1", "198.51.100.4"))
        n = len([r for r in caplog.records if "trusted_proxy_hops" in r.getMessage()])
        assert n == 1, "one warning per throttle window, not one per request"
        caplog.clear()
        monkeypatch.setattr(auth_svc, "_HOPS_WARNED_AT", 0.0, raising=False)
        auth_svc.client_ip(_req("127.0.0.1", None))     # a health probe from the trusted address: no chain at all
        assert not [r for r in caplog.records if "trusted_proxy_hops" in r.getMessage()]


def test_no_warning_without_trusted_proxies(monkeypatch, caplog):
    import logging

    _trust(monkeypatch, cidrs="", hops=3)
    monkeypatch.setattr(auth_svc, "_HOPS_WARNED_AT", 0.0, raising=False)
    with caplog.at_level(logging.WARNING, logger=auth_svc.logger.name):
        assert auth_svc.client_ip(_req("203.0.113.9", "6.6.6.6")) == "203.0.113.9"
    assert not [r for r in caplog.records if "trusted_proxy_hops" in r.getMessage()]


async def _audit_rows_for(db_pool, path: str) -> list:
    async with db_pool.acquire() as con:
        return await con.fetch(
            "SELECT ip::text AS ip, details, method FROM audit_log WHERE path = $1 ORDER BY id", path)


async def _post_as(app, peer: str, headers: dict[str, str]):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app, client=(peer, 4321)), base_url="http://test") as c:
        return await c.post("/v1/owners", json={"pattern": "*", "owner": "x"}, headers=headers)


async def test_audit_ip_ignores_a_forged_prefix_and_says_when_it_is_proxied(app, db_pool, monkeypatch):
    """D35 end to end: the per-request audit ip is the strict address; the row gains ``ip_proxied`` exactly when the
    address may be a forwarding hop; the intent and outcome rows of one request agree."""
    _trust(monkeypatch)
    # an appending proxy at 127.0.0.1 saw 198.51.100.4 and kept the client's own forged entry in front
    await _post_as(app, "127.0.0.1", {"X-Forwarded-For": "6.6.6.6, 198.51.100.4"})
    rows = await _audit_rows_for(db_pool, "/v1/owners")
    assert rows and {r["ip"] for r in rows} == {"198.51.100.4"}, [dict(r) for r in rows]
    assert not any(r["ip"] == "6.6.6.6" for r in rows)
    assert all(json.loads(r["details"]).get("ip_proxied") is not True for r in rows)   # a real, untrusted client
    # an untrusted peer that sends forwarding headers: the peer, flagged
    await _post_as(app, "203.0.113.9", {"X-Forwarded-For": "6.6.6.6"})
    rows = [r for r in await _audit_rows_for(db_pool, "/v1/owners") if r["ip"] == "203.0.113.9"]
    assert rows and all(json.loads(r["details"]).get("ip_proxied") is True for r in rows)
    # a trusted proxy that reported nothing usable: the proxy itself, flagged
    await _post_as(app, "127.0.0.1", {})
    rows = [r for r in await _audit_rows_for(db_pool, "/v1/owners") if r["ip"] == "127.0.0.1"]
    assert rows and all(json.loads(r["details"]).get("ip_proxied") is True for r in rows)


# ---- static guard: nobody but auth.py reads the forwarded-for header (attack 25) ------------------------------ #

_FORWARDING_HEADERS = ("x-forwarded-for", "x-real-ip", "x-client-ip", "forwarded")


def _folded_text(node) -> "str | None":
    """Lower-case text of a string/bytes literal, a constant ``+`` concatenation or an f-string's literal parts
    (``None`` for anything else), so ``b'x-forwarded-for'`` and ``'x-forwarded-' + 'for'`` are seen like the plain form."""
    import ast

    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value
        return (v.decode("latin-1") if isinstance(v, bytes) else v).lower()
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _folded_text(node.left), _folded_text(node.right)
        return a + b if a is not None and b is not None else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            t = _folded_text(v) if isinstance(v, ast.Constant) else ""
            parts.append(t or "")
        return "".join(parts)
    return None


def _xff_offenders(source: str) -> list[str]:
    """Findings in one module: a string constant naming ``x-forwarded-for`` (outside docstrings) or a
    ``.split(',')[0]`` of anything in a module that mentions the header at all."""
    import ast

    tree = ast.parse(source)
    doc_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
                doc_ids.add(id(body[0].value))
    out: list[str] = []
    mentions = False
    for node in ast.walk(tree):
        if id(node) in doc_ids:
            continue
        text = _folded_text(node)
        if text is not None and any(h in text for h in _FORWARDING_HEADERS):
            mentions = True
            out.append(f"line {node.lineno}: reads a client-address forwarding header")
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call):
            f = node.value.func
            idx = node.slice
            if (isinstance(f, ast.Attribute) and f.attr == "split" and isinstance(idx, ast.Constant)
                    and idx.value == 0 and node.value.args
                    and isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value == ","):
                if mentions or "forward" in ast.unparse(node).lower():
                    out.append(f"line {node.lineno}: leftmost entry of a comma list ({ast.unparse(node)})")
    return out


def test_the_static_guard_catches_the_leftmost_idiom():
    bad = ('def ip(request):\n    return request.headers.get("x-forwarded-for", "").split(",")[0].strip()\n')
    assert len(_xff_offenders(bad)) == 2
    bad2 = ('def ip(request):\n    fwd = request.headers.get("X-Forwarded-For")\n    return fwd.split(\',\')[0]\n')
    assert _xff_offenders(bad2)
    fine = 'def ip(request):\n    """mentions x-forwarded-for in a docstring only"""\n    return request.client.host\n'
    assert _xff_offenders(fine) == []


@pytest.mark.parametrize("src", [
    "def ip(r):\n    return dict(r.scope['headers']).get(b'x-forwarded-for')\n",
    "def ip(r):\n    return r.headers.get('x-forwarded-' + 'for')\n",
    "def ip(r):\n    return r.headers.get(b'X-Forwarded-' b'For'.decode())\n",
    "def ip(r):\n    return r.headers.get('X-Real-IP')\n",
    "def ip(r):\n    return r.headers.get('forwarded')\n",
    "def ip(r):\n    return r.headers.get(f'x-forwarded-{\"for\"}')\n",
])
def test_the_static_guard_catches_evasive_spellings(src):
    assert _xff_offenders(src), src


def test_no_module_outside_auth_reads_x_forwarded_for():
    """D35: ``auth.client_ip`` is the only reader; a second reader is how the next call site gets the wrong one."""
    from pathlib import Path

    app_dir = Path(auth_svc.__file__).resolve().parent
    seen = 0
    offenders: dict[str, list[str]] = {}
    for path in sorted(app_dir.rglob("*.py")):
        if path.name == "auth.py" and path.parent == app_dir:
            continue
        seen += 1
        found = _xff_offenders(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(app_dir))] = found
    assert seen > 50
    assert offenders == {}


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
