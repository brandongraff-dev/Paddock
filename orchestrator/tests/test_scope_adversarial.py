"""Adversarial tests for the scope invariant.

The scope check is the one rule nobody breaks, so these tests attack it the
way a hostile target string would:

1. A corpus of known URL-parser differentials (each one a historical SSRF /
   allowlist-bypass class). For every payload we either reject it outright or
   produce exactly the host a real client would connect to.
2. A property-based differential fuzzer: random target strings assembled
   from the nastiest URL fragments are parsed by our normaliser AND by a
   WHATWG parser (Ada -- the parser inside Node.js, close to Chromium) and
   an RFC 3986 parser (urllib, what httpx builds on). Whenever we accept a
   target, every oracle that can parse it must agree on the host.
3. Guardrails: an in-scope NAME that resolves to cloud metadata, loopback or
   a private range is denied unless a CIDR entry explicitly covers it.

None of these tests need Postgres; check() runs against an in-memory pool.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest

from app import scope as scope_svc
from app.scope import normalize, strict_normalize

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

try:  # WHATWG oracle (optional; `pip install ada-url`)
    from ada_url import URL as AdaURL
except Exception:  # pragma: no cover - optional dependency
    AdaURL = None


# --------------------------------------------------------------------------- #
# 1. Known-bypass corpus
# --------------------------------------------------------------------------- #

# (payload, expected canonical host or "" for reject)
BYPASS_CORPUS = [
    # Fragment / query before '@' -- the authority ends at the first #?/
    ("http://evil.com#@target.com", "evil.com"),
    ("http://evil.com?@target.com", "evil.com"),
    ("http://evil.com/@target.com", "evil.com"),
    ("evil.com#@target.com", "evil.com"),
    ("http://evil.com#target.com", "evil.com"),
    # Backslash: WHATWG treats it as '/', RFC 3986 parsers do not.
    ("http://evil.com\\@target.com", ""),
    ("http://target.com\\.evil.com", ""),
    ("https://evil.com:443\\@target.com/x", ""),
    ("http:/\\evil.com", ""),
    ("http:\\\\evil.com", ""),
    ("http:evil.com", ""),
    # Whitespace / control characters that WHATWG silently strips.
    ("http://evil.com\t.target.com", ""),
    ("http://ta\nrget.com", ""),
    ("http://target.com\r\n.evil.com", ""),
    ("http://target.com\x00.evil.com", ""),
    ("http://target.com​", ""),
    ("http://target.com﻿", ""),
    # Percent-encoding in the host.
    ("http://target.com%00.evil.com", ""),
    ("http://%74arget.com", ""),
    ("http://target.com%2f@evil.com", ""),
    # Userinfo: last '@' in the authority wins.
    ("http://target.com@evil.com", "evil.com"),
    ("http://target.com:80@evil.com/", "evil.com"),
    ("http://a@b@evil.com", "evil.com"),
    ("http://evil.com;@target.com", "target.com"),  # every parser agrees
    # IDNA happens before the IPv4 decision (WHATWG order).
    ("http://１２７.0.0.1/", "127.0.0.1"),
    ("http://¹/", "0.0.0.1"),
    # Legacy IPv4 spellings resolve to the same socket address as dotted-quad.
    ("http://0x7f000001/", "127.0.0.1"),
    ("http://2130706433/", "127.0.0.1"),
    ("http://0177.0.0.1/", "127.0.0.1"),
    ("http://127.1/", "127.0.0.1"),
    ("http://0x7f.1/", "127.0.0.1"),
    ("http://0xA9.0xFE.0xA9.0xFE/", "169.254.169.254"),
    ("http://999.0.0.1/", ""),
    ("http://1.2.3.4.5/", ""),
    ("http://08.0.0.1/", ""),
    # IPv6: mapped addresses collapse to IPv4; zone ids refused.
    ("http://[::ffff:169.254.169.254]/", "169.254.169.254"),
    ("http://[::ffff:a9fe:a9fe]/", "169.254.169.254"),
    ("http://[fe80::1%25eth0]/", ""),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("http://2001:db8::1/", ""),  # must be bracketed inside a URL
    ("c1::", ""),                 # host "c1" + empty port, or IPv6? refuse
    ("http://[2001:db8::1]x/", ""),
    ("http://[2001:db8::1/", ""),
    # Ports
    ("example.com:", ""),
    ("example.com:99999", ""),
    ("example.com:8a", ""),
    # Labels
    ("example.com..", ""),
    ("a..example.com", ""),
    (".example.com", ""),
    ("-bad.example.com", ""),
    ("x" * 64 + ".example.com", ""),
    # IDN: browsers map fullwidth / ideographic dots to ASCII; so do we.
    ("http://ｅｘａｍｐｌｅ.com/", "example.com"),
    ("http://example。com/", "example.com"),
    ("http://bücher.example/", "xn--bcher-kva.example"),
    # Scheme-relative / empty
    ("//evil.com", ""),
    ("http://", ""),
    ("http://@/", ""),
    ("1http://evil.com", ""),
]


@pytest.mark.parametrize("payload,want", BYPASS_CORPUS)
def test_known_parser_differentials(payload, want):
    assert normalize(payload) == want


def test_strict_normalize_raises_on_reject():
    with pytest.raises(ValueError):
        strict_normalize("http://evil.com\\@target.com")


# --------------------------------------------------------------------------- #
# 2. Differential fuzzing against real-world parsers
# --------------------------------------------------------------------------- #

def _canon(host: str | None) -> str | None:
    """Canonicalise an oracle's host with OUR canonicalisers, so we compare
    which substring each parser picked as the host -- the part that matters
    for a bypass -- rather than incidental formatting."""
    if not host:
        return None
    h = host.strip("[]")
    try:
        if ":" in h:
            return scope_svc._canonical_ipv6(h)
        v4 = scope_svc._canonical_ipv4(h.lower())
        return v4 if v4 is not None else scope_svc._canonical_hostname(h)
    except (ValueError, UnicodeError):
        return None


def _oracle_hosts(target: str) -> dict[str, str | None]:
    """Host each parser would connect to (None = parser rejects/no host)."""
    target = target.strip(" ")  # callers trim plain spaces
    url = target if "://" in target else f"http://{target}"
    if "://" not in target:
        try:  # a tool turns a bare IPv6 target into http://[addr]/
            ipaddress.IPv6Address(target)
            url = f"http://[{target}]/"
        except ValueError:
            pass
    out: dict[str, str | None] = {}
    try:
        out["rfc3986"] = _canon(urlsplit(url).hostname)
    except ValueError:
        out["rfc3986"] = None
    if AdaURL is not None:
        try:
            out["whatwg"] = _canon(AdaURL(url).hostname)
        except ValueError:
            out["whatwg"] = None
    return out


FRAGMENTS = [
    "http://", "https://", "HTTP://", "http:/", "http:", "//", "ftp://",
    "target.com", "evil.com", "sub.target.com", "127.0.0.1", "0x7f.1",
    "169.254.169.254", "[::1]", "[::ffff:7f00:1]", "ｅｖｉｌ.com", "xn--e1a",
    "@", "#", "?", "/", "\\", ":", ";", ".", "..", "%40", "%2f", "%2e",
    "\t", "\n", " ", "\x00", "​", ":80", ":443", ":", "user:pw@",
    "[", "]", "。", "*",
]

targets = st.one_of(
    st.lists(st.sampled_from(FRAGMENTS), min_size=1, max_size=8).map("".join),
    st.text(alphabet="abc.:/@#?\\[]%01x\t ", min_size=1, max_size=24),
)


@settings(
    max_examples=4000,
    derandomize=True,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(targets)
def test_differential_fuzz_never_disagrees_with_real_parsers(target):
    ours = normalize(target)
    if not ours:
        return  # rejected -> fail-closed, always safe
    for parser, theirs in _oracle_hosts(target).items():
        if theirs is None:
            continue  # that parser refuses the target; it can't be steered
        assert theirs == ours, (
            f"parser differential: {target!r} -> ours={ours!r} {parser}={theirs!r}"
        )


@settings(max_examples=1500, derandomize=True, deadline=None)
@given(st.text(min_size=0, max_size=64))
def test_normalize_total_and_idempotent(target):
    """Never raises; output is empty or a fixed point."""
    out = normalize(target)
    assert isinstance(out, str)
    if out:
        assert normalize(out) == out


# --------------------------------------------------------------------------- #
# 3. check(): guardrails, rebinding, expiry -- against an in-memory pool
# --------------------------------------------------------------------------- #

class _Con:
    def __init__(self, pool: _FakePool):
        self.pool = pool

    async def fetch(self, *_a):
        return self.pool.entries

    async def execute(self, _sql, *args):
        self.pool.decisions.append(args)


class _Acq:
    def __init__(self, pool):
        self.pool = pool

    async def __aenter__(self):
        return _Con(self.pool)

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, entries):
        self.entries = [
            {"id": i + 1, "kind": k, "value": v, "expires_at": exp}
            for i, (k, v, *rest) in enumerate(entries)
            for exp in [rest[0] if rest else None]
        ]
        self.decisions: list[tuple] = []

    def acquire(self):
        return _Acq(self)


@pytest.fixture(autouse=True)
def _reset_caches(monkeypatch):
    scope_svc.scope_cache.invalidate()
    scope_svc.dns_cache._by_host.clear()
    yield
    scope_svc.scope_cache.invalidate()
    scope_svc.dns_cache._by_host.clear()


def _dns(monkeypatch, table: dict[str, list[str]]):
    async def fake_resolve(host):
        return table.get(host, [])

    monkeypatch.setattr(scope_svc.dns_cache, "resolve", fake_resolve)


async def test_in_scope_name_resolving_to_metadata_is_denied(monkeypatch):
    _dns(monkeypatch, {"rebind.target.com": ["169.254.169.254"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    d = await scope_svc.check(pool, "https://rebind.target.com/", worker="t")
    assert d.allow is False
    assert "protected address" in d.reason
    assert pool.decisions[-1][2] == "deny"  # audited


async def test_metadata_denied_even_with_explicit_cidr(monkeypatch):
    _dns(monkeypatch, {})
    pool = _FakePool([("ipv4_cidr", "169.254.0.0/16")])
    for t in ("169.254.169.254", "http://0xA9FEA9FE/", "http://[::ffff:a9fe:a9fe]/"):
        d = await scope_svc.check(pool, t, worker="t")
        assert d.allow is False, t


async def test_in_scope_name_resolving_to_private_needs_cidr(monkeypatch):
    _dns(monkeypatch, {"intranet.target.com": ["10.0.0.7"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    d = await scope_svc.check(pool, "intranet.target.com", worker="t")
    assert d.allow is False and "internal address" in d.reason

    scope_svc.scope_cache.invalidate()
    pool2 = _FakePool([("subdomain_wildcard", "target.com"), ("ipv4_cidr", "10.0.0.0/24")])
    d2 = await scope_svc.check(pool2, "intranet.target.com", worker="t")
    assert d2.allow is True


async def test_public_resolution_and_unresolvable_names_still_allowed(monkeypatch):
    _dns(monkeypatch, {"www.target.com": ["93.184.215.14"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    assert (await scope_svc.check(pool, "www.target.com", worker="t")).allow
    assert (await scope_svc.check(pool, "nxdomain.target.com", worker="t")).allow


async def test_cidr_fallback_requires_every_resolved_address(monkeypatch):
    _dns(monkeypatch, {"rr.other.net": ["203.0.113.5", "198.51.100.9"]})
    pool = _FakePool([("ipv4_cidr", "203.0.113.0/24")])
    d = await scope_svc.check(pool, "rr.other.net", worker="t")
    assert d.allow is False and "some resolved" in d.reason


async def test_expired_entry_denied_inside_cache_ttl(monkeypatch):
    _dns(monkeypatch, {})
    soon = datetime.now(UTC) + timedelta(seconds=30)
    pool = _FakePool([("domain", "target.com", soon)])
    assert (await scope_svc.check(pool, "target.com", worker="t")).allow
    # Time moves past expiry while the cache is still warm.
    later = soon + timedelta(seconds=1)

    class _DT(datetime):
        @classmethod
        def now(cls, tz=None):
            return later

    monkeypatch.setattr(scope_svc, "datetime", _DT)
    assert not (await scope_svc.check(pool, "target.com", worker="t")).allow


async def test_bypass_payload_denied_end_to_end(monkeypatch):
    _dns(monkeypatch, {})
    pool = _FakePool([("domain", "target.com")])
    for t in ("http://evil.com#@target.com", "http://evil.com?@target.com",
              "http://evil.com\\@target.com", "http://evil.com\t@target.com"):
        d = await scope_svc.check(pool, t, worker="t")
        assert d.allow is False, t


def test_hard_deny_list_is_well_formed():
    for net in scope_svc.HARD_DENY_NETS:
        assert isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network)
