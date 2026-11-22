"""DNS-rebinding defence: the worker dials ONLY the addresses the orchestrator vetted.

Every name below ends in ``.vetted.test`` and does not resolve anywhere. The
system resolver is booby-trapped (``getaddrinfo`` answers 169.254.169.254 and
records the call), so a connection that reaches the local server proves it was
made to the vetted IP from the scope-check response, not to a re-resolved one.
"""
from __future__ import annotations

import asyncio
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from app.modules import safe_checks
from app.modules.safe_checks import CheckEnv, FindingCtx, SafeFetcher, ScopeDenied
from app.modules.safe_checks import network_checks, tls as tls_mod
from app.scope_guard import ScopeGuard

from .conftest import FakeOrchestratorClient

pytestmark = pytest.mark.asyncio

HOST = "app.vetted.test"
METADATA = "169.254.169.254"


def allow(ips, host=HOST):
    return {"allow": True, "normalized": host, "matched_entry": 1, "reason": "ok", "resolved_ips": ips}


@pytest.fixture
def resolver_trap(monkeypatch):
    """Any name resolution done by this process is recorded and answers metadata."""
    calls: list[str] = []

    def fake(host, *a, **kw):
        calls.append(str(host))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (METADATA, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)

    async def fake_loop(self, host, *a, **kw):
        calls.append(str(host))
        return fake(host)

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_loop)
    return calls


class Web:
    def __init__(self, bind="127.0.0.1"):
        self.requests: list[tuple[str, str, str]] = []   # method, path, Host header
        self.routes: dict[str, tuple[int, dict]] = {}
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append((self.command, self.path, self.headers.get("Host", "")))
                status, headers = outer.routes.get(self.path, (200, {}))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_HEAD = do_GET

        class S(ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

        self.server = S((bind, 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def web():
    w = Web()
    yield w
    w.close()


def guard(decisions: dict[str, dict] | None = None, default=None):
    orch = FakeOrchestratorClient(scope_decision=default)
    for k, v in (decisions or {}).items():
        orch.set_decision(k, v)
    return orch, ScopeGuard(orch, ttl_sec=60)


# --------------------------------------------------------------------------- #
# HTTP: build_client is pinned
# --------------------------------------------------------------------------- #

async def test_connection_goes_to_the_vetted_ip_not_the_resolver_answer(web, resolver_trap):
    _orch, scope = guard(default=allow(["127.0.0.1"]))
    async with scope.build_client() as c:
        r = await c.get(f"http://{HOST}:{web.port}/x")
    assert r.status_code == 200
    assert web.requests == [("GET", "/x", f"{HOST}:{web.port}")]   # Host header preserved
    assert resolver_trap == []                                   # never resolved by the worker


@pytest.mark.parametrize("bad", [METADATA, "fd00:ec2::254", "fe80::1", "0.0.0.0", "::ffff:169.254.169.254"])
async def test_rebind_to_metadata_or_linklocal_is_refused_even_if_listed(web, bad, resolver_trap):
    # Defence in depth: even if a (buggy/compromised) check response lists it.
    _orch, scope = guard(default=allow([bad]))
    async with scope.build_client() as c:
        with pytest.raises(ScopeDenied):
            await c.get(f"http://{HOST}:{web.port}/")
    assert web.requests == [] and resolver_trap == []


async def test_name_with_no_vetted_ips_is_refused(web, resolver_trap):
    for resp in (allow([]), {"allow": True, "normalized": HOST, "matched_entry": 1, "reason": "ok"}):
        _orch, scope = guard(default=resp)   # an older orchestrator: field absent
        async with scope.build_client() as c:
            with pytest.raises(ScopeDenied, match="no vetted addresses"):
                await c.get(f"http://{HOST}:{web.port}/")
    assert web.requests == [] and resolver_trap == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.7"])
async def test_rebind_to_loopback_or_private_is_refused_when_the_check_denies(web, ip, resolver_trap):
    # The orchestrator denies a name that resolves internal (no CIDR entry).
    _orch, scope = guard(default={"allow": False, "normalized": HOST, "matched_entry": None,
                                   "reason": f"guardrail: {HOST} resolves to internal address {ip}"})
    async with scope.build_client() as c:
        with pytest.raises(ScopeDenied):
            await c.get(f"http://{HOST}:{web.port}/")
    assert web.requests == []


async def test_ip_literal_url_dials_that_ip(web):
    _orch, scope = guard(default={"allow": True, "normalized": "127.0.0.1", "matched_entry": 1, "reason": "ok"})
    async with scope.build_client() as c:
        assert (await c.get(f"http://127.0.0.1:{web.port}/")).status_code == 200


async def test_ipv6_vetted_address(resolver_trap):
    try:
        w = Web("::1")
    except OSError:
        pytest.skip("no IPv6 loopback")
    try:
        _orch, scope = guard(default=allow(["::1"]))
        async with scope.build_client() as c:
            r = await c.get(f"http://{HOST}:{w.port}/v6")
        assert r.status_code == 200 and w.requests == [("GET", "/v6", f"{HOST}:{w.port}")]
    finally:
        w.close()


async def test_second_vetted_ip_is_tried_when_the_first_refuses(web):
    _orch, scope = guard(default=allow(["127.0.0.2", "127.0.0.1"]))
    async with scope.build_client() as c:
        assert (await c.get(f"http://{HOST}:{web.port}/")).status_code == 200


async def test_every_redirect_hop_is_rechecked_and_repinned(web, resolver_trap):
    web.routes["/a"] = (302, {"Location": f"http://other.vetted.test:{web.port}/b"})
    orch, scope = guard(default=allow(["127.0.0.1"]), decisions={
        f"other.vetted.test:{web.port}": allow(["127.0.0.1"], "other.vetted.test")})
    async with scope.build_client(follow_redirects=True) as c:
        r = await c.get(f"http://{HOST}:{web.port}/a")
    assert r.status_code == 200
    assert [h for _m, _p, h in web.requests] == [f"{HOST}:{web.port}", f"other.vetted.test:{web.port}"]
    assert any("other.vetted.test" in t for t in orch.scope_calls)
    assert resolver_trap == []


async def test_redirect_hop_to_a_name_without_vetted_ips_is_refused(web):
    web.routes["/a"] = (302, {"Location": f"http://rebound.vetted.test:{web.port}/b"})
    _orch, scope = guard(default=allow(["127.0.0.1"]), decisions={
        f"rebound.vetted.test:{web.port}": allow([], "rebound.vetted.test")})
    async with scope.build_client(follow_redirects=True) as c:
        with pytest.raises(ScopeDenied):
            await c.get(f"http://{HOST}:{web.port}/a")
    assert [p for _m, p, _h in web.requests] == ["/a"]


# --------------------------------------------------------------------------- #
# HTTPS: SNI + certificate verification keep the hostname
# --------------------------------------------------------------------------- #

OPENSSL = shutil.which("openssl")


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("openssl missing")
    d = tmp_path_factory.mktemp("pincerts")
    for name, san in (("good", "DNS:secure.vetted.test"), ("wrong", "DNS:elsewhere.vetted.test")):
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
                        "-out", f"{name}.pem", "-subj", f"/CN={name}", "-days", "2",
                        "-addext", f"subjectAltName={san}"], cwd=d, check=True, capture_output=True)
    return d


async def tls_web(certs, name):
    seen = {"sni": [], "head": []}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certs / f"{name}.pem"), str(certs / f"{name}.key"))
    ctx.sni_callback = lambda _s, n, _c: seen["sni"].append(n)

    async def h(r, w):
        try:
            seen["head"].append((await r.readuntil(b"\r\n\r\n")).decode())
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await w.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            w.close()

    srv = await asyncio.start_server(h, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1], seen


def trusting(certs, name):
    ctx = ssl.create_default_context(cafile=str(certs / f"{name}.pem"))
    return ctx


async def test_sni_host_header_and_cert_verified_against_the_hostname(certs, resolver_trap):
    srv, port, seen = await tls_web(certs, "good")
    try:
        _orch, scope = guard(default=allow(["127.0.0.1"], "secure.vetted.test"))
        async with scope.build_client(verify=trusting(certs, "good")) as c:
            r = await c.get(f"https://secure.vetted.test:{port}/p")
        assert r.status_code == 200
        assert seen["sni"] == ["secure.vetted.test"]
        assert "Host: secure.vetted.test:" in seen["head"][0]
        assert resolver_trap == []
    finally:
        srv.close()


async def test_certificate_for_another_name_fails_verification(certs):
    srv, port, _seen = await tls_web(certs, "wrong")
    try:
        _orch, scope = guard(default=allow(["127.0.0.1"], "secure.vetted.test"))
        async with scope.build_client(verify=trusting(certs, "wrong")) as c:
            with pytest.raises(httpx.ConnectError):   # verified against the name, not the IP
                await c.get(f"https://secure.vetted.test:{port}/")
    finally:
        srv.close()


async def test_tls_handshake_check_dials_vetted_ip_with_sni(certs, resolver_trap):
    srv, port, seen = await tls_web(certs, "good")
    try:
        hs = await tls_mod.do_handshake("secure.vetted.test", port, addrs=["127.0.0.1"])
        assert hs.ok and seen["sni"] == ["secure.vetted.test"]
        with pytest.raises(ValueError):   # a name without vetted addrs is never resolved
            await tls_mod.do_handshake("secure.vetted.test", port)
        assert resolver_trap == []
    finally:
        srv.close()


async def test_tls_check_end_to_end_uses_the_vetted_ip(certs, resolver_trap, politeness):
    srv, port, seen = await tls_web(certs, "good")
    try:
        orch, scope = guard(default=allow(["127.0.0.1"], "secure.vetted.test"))
        env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
        f = FindingCtx(id="1", rule_id="expiring-certificate", rule_source="tls_check",
                       evidence={"port": port}, asset_value=f"secure.vetted.test:{port}")
        r = await safe_checks.run(f, env)
        assert r is not None and seen["sni"] == ["secure.vetted.test"]
        assert resolver_trap == []
    finally:
        srv.close()


async def test_tls_check_refuses_when_nothing_is_vetted(certs, politeness):
    srv, port, seen = await tls_web(certs, "good")
    try:
        orch, scope = guard(default=allow([METADATA], "secure.vetted.test"))
        env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
        f = FindingCtx(id="1", rule_id="expiring-certificate", rule_source="tls_check",
                       evidence={"port": port}, asset_value=f"secure.vetted.test:{port}")
        with pytest.raises(ScopeDenied):
            await safe_checks.run(f, env)
        assert seen["sni"] == []
    finally:
        srv.close()


# --------------------------------------------------------------------------- #
# TCP port check
# --------------------------------------------------------------------------- #

async def banner_server():
    got = []

    async def h(r, w):
        got.append(1)
        w.write(b"220 hello\r\n")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(h, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1], got


def port_finding(port):
    return FindingCtx(id="1", rule_id="exposed-port", rule_source="policy",
                      evidence={"port": port}, asset_value="db.vetted.test")


async def test_port_check_connects_to_the_vetted_ip_only(resolver_trap, politeness):
    srv, port, got = await banner_server()
    try:
        orch, scope = guard(default=allow(["127.0.0.1"], "db.vetted.test"))
        env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
        r = await safe_checks.run(port_finding(port), env)
        assert r is not None and r.verdict == "confirmed" and got == [1]
        assert resolver_trap == []
    finally:
        srv.close()


@pytest.mark.parametrize("ips", [[METADATA], []])
async def test_port_check_to_internal_or_unvetted_is_refused(ips, resolver_trap, politeness):
    srv, port, got = await banner_server()   # stands in for an internal service
    try:
        orch, scope = guard(default=allow(ips, "db.vetted.test"))
        env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
        with pytest.raises(ScopeDenied):
            await safe_checks.run(port_finding(port), env)
        assert got == [] and resolver_trap == []
    finally:
        srv.close()


async def test_tcp_banner_never_resolves_a_name():
    with pytest.raises(ValueError):
        await network_checks.tcp_banner("db.vetted.test", 22)


# --------------------------------------------------------------------------- #
# Verify redirects: same host only
# --------------------------------------------------------------------------- #

async def test_redirect_to_a_different_host_is_refused_and_recorded(web, politeness):
    web.routes["/a"] = (302, {"Location": f"http://unproven.vetted.test:{web.port}/secret"})
    orch, scope = guard(default=allow(["127.0.0.1"]), decisions={
        f"unproven.vetted.test:{web.port}": allow(["127.0.0.1"], "unproven.vetted.test")})   # in scope!
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
    r = await SafeFetcher(env, "t").get(f"http://{HOST}:{web.port}/a")
    assert r.status == 302 and r.error is None
    assert r.redirect_blocked == f"http://unproven.vetted.test:{web.port}/secret"
    assert r.url == r.redirect_blocked
    assert [p for _m, p, _h in web.requests] == ["/a"]          # the second host was never contacted
    assert orch.outbound_calls[-1]["target"] == r.redirect_blocked   # recorded on the audit trail


async def test_same_host_redirects_are_followed_up_to_the_limit(web, politeness):
    web.routes["/a"] = (301, {"Location": "/b"})
    web.routes["/b"] = (302, {"Location": f"http://{HOST}:{web.port}/c"})
    orch, scope = guard(default=allow(["127.0.0.1"]))
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
    r = await SafeFetcher(env, "t").get(f"http://{HOST}:{web.port}/a")
    assert r.status == 200 and r.redirected and r.redirect_blocked is None
    assert [p for _m, p, _h in web.requests] == ["/a", "/b", "/c"]

    web.routes["/loop"] = (302, {"Location": "/loop"})
    r = await SafeFetcher(env, "t").get(f"http://{HOST}:{web.port}/loop")
    assert r.error == "too many redirects"


async def test_ipv6_vetted_address_is_pinned_with_host_and_sni_preserved():
    """No IPv6 loopback needed: capture what the inner transport is asked to dial."""
    _orch, scope = guard(default=allow(["2001:db8::1"], "secure.vetted.test"))
    t = scope.pinned_transport()
    seen = []

    async def inner(req):
        seen.append(req)
        return httpx.Response(200, request=req)

    t._inner.handle_async_request = inner
    async with httpx.AsyncClient(transport=t) as c:
        await c.get("https://secure.vetted.test:8443/x")
    (req,) = seen
    assert req.url.host == "2001:db8::1" and req.url.port == 8443
    assert req.headers["host"] == "secure.vetted.test:8443"
    assert req.extensions["sni_hostname"] == "secure.vetted.test"


async def test_redirect_to_an_out_of_scope_host_still_raises(web, politeness):
    web.routes["/a"] = (302, {"Location": f"http://evil.vetted.test:{web.port}/"})
    orch, scope = guard(default=allow(["127.0.0.1"]), decisions={
        f"evil.vetted.test:{web.port}": {"allow": False, "normalized": "evil.vetted.test",
                                         "matched_entry": None, "reason": "no matching scope"}})
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
    with pytest.raises(ScopeDenied):
        await SafeFetcher(env, "t").get(f"http://{HOST}:{web.port}/a")
