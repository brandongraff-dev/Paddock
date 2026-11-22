"""Safe verification checks against local test servers.

Real sockets on 127.0.0.1 (a threaded HTTP server, asyncio TLS servers built
from throw-away openssl certificates, a banner TCP server); nothing leaves the
machine. The recurring assertions are the safety ones: only GET/HEAD reach the
server, the byte cap holds, nothing is sent on TCP, and an out-of-scope or
unproven target is never touched.
"""
from __future__ import annotations

import asyncio
import shutil
import ssl
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from app.modules import safe_checks
from app.modules.safe_checks import (
    CheckEnv,
    FindingCtx,
    MethodRefused,
    SafeFetcher,
    ScopeDenied,
    cap_evidence,
    redact_text,
)
from app.modules.safe_checks import network_checks, tls as tls_mod
from app.modules import verify_finding
from app.scope_guard import ScopeDecision

from .conftest import FakeOrchestratorClient

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# local servers
# --------------------------------------------------------------------------- #

class HttpFixture:
    def __init__(self):
        self.routes: dict[str, tuple[int, dict, bytes]] = {}
        self.requests: list[tuple[str, str]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # silence
                pass

            def send_response(self, code, message=None):  # no automatic Server/Date headers
                self.send_response_only(code, message)

            def _serve(self):
                outer.requests.append((self.command, self.path))
                status, headers, body = outer.routes.get(self.path.split("?")[0], (404, {}, b"nope"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        for i in range(0, len(body), 8192):
                            self.wfile.write(body[i:i + 8192])
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            do_GET = do_HEAD = _serve

            def _refuse(self):
                outer.requests.append((self.command, self.path))
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def methods(self) -> set[str]:
        return {m for m, _ in self.requests}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def web():
    s = HttpFixture()
    yield s
    s.close()


class OrchWithVerify(FakeOrchestratorClient):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.results: list[tuple[str, dict, str | None]] = []

    async def verification_result(self, vid, payload, tenant_id=None):
        self.results.append((vid, payload, tenant_id))
        return {"ok": True}


@pytest.fixture
def orch():
    return OrchWithVerify()


@pytest.fixture
def scope(orch):
    from app.scope_guard import ScopeGuard

    return ScopeGuard(orch, ttl_sec=60)


@pytest.fixture
def env(scope, politeness, orch):
    return CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)


def finding(rule_id, source, evidence=None, asset="127.0.0.1", **kw):
    return FindingCtx(id="f-1", rule_id=rule_id, rule_source=source, evidence=evidence or {},
                      asset_value=asset, **kw)


# --------------------------------------------------------------------------- #
# exposed file
# --------------------------------------------------------------------------- #

ENV_BODY = (b"APP_ENV=production\nDATABASE_URL=postgres://admin:hunter2secret@db.internal/app\n"
            b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nTOKEN=abcdef0123456789\n")


async def test_exposed_env_confirmed_with_redacted_evidence(web, env):
    web.routes["/.env"] = (200, {"content-type": "text/plain"}, ENV_BODY)
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "exposed_file"
    blob = str(r.as_dict())
    for secret in ("hunter2secret", "wJalrXUtnFEMI", "abcdef0123456789"):
        assert secret not in blob
    assert r.evidence["status"] == 200 and r.evidence["sha256_16"]
    assert web.methods() == {"GET"}


async def test_exposed_file_gone_is_not_reproducible(web, env):
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    r = await safe_checks.run(f, env)
    assert r.verdict == "not_reproducible" and "404" in r.reason


async def test_spa_catchall_html_is_not_a_hit(web, env):
    web.routes["/.git/HEAD"] = (200, {"content-type": "text/html"}, b"<!doctype html><html></html>")
    r = await safe_checks.run(finding("exposed-git-head", "exposed_file",
                                      {"url": f"{web.base}/.git/HEAD"}), env)
    assert r.verdict == "not_reproducible"


async def test_git_head_confirmed(web, env):
    web.routes["/.git/HEAD"] = (200, {"content-type": "text/plain"}, b"ref: refs/heads/main\n")
    r = await safe_checks.run(finding("exposed-git-head", "exposed_file",
                                      {"url": f"{web.base}/.git/HEAD"}), env)
    assert r.verdict == "confirmed"


async def test_backup_archive_needs_magic_bytes(web, env):
    f = finding("exposed-backup-archive", "exposed_file", {"url": f"{web.base}/backup.zip"})
    web.routes["/backup.zip"] = (200, {"content-type": "text/html"}, b"<html>app</html>")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"
    web.routes["/backup.zip"] = (200, {"content-type": "application/zip"}, b"PK\x03\x04" + b"\0" * 64)
    assert (await safe_checks.run(f, env)).verdict == "confirmed"


async def test_server_error_and_rate_limit_are_inconclusive(web, env):
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    for status in (500, 503, 429):
        web.routes["/.env"] = (status, {}, b"x")
        r = await safe_checks.run(f, env)
        assert r.verdict == "inconclusive", status


async def test_403_with_blocked_site_root_is_inconclusive(web, env):
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    web.routes["/.env"] = (403, {}, b"blocked")
    web.routes["/"] = (403, {}, b"blocked")
    r = await safe_checks.run(f, env)
    assert r.verdict == "inconclusive" and "blocking" in r.reason


async def test_403_with_healthy_site_root_is_a_fix(web, env):
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    web.routes["/.env"] = (403, {}, b"forbidden")
    web.routes["/"] = (200, {}, b"home")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"


async def test_connection_refused_is_inconclusive_not_fixed(env):
    f = finding("exposed-env", "exposed_file", {"url": "http://127.0.0.1:9/.env"})
    r = await safe_checks.run(f, env)
    assert r.verdict == "inconclusive"


# --------------------------------------------------------------------------- #
# safety envelope
# --------------------------------------------------------------------------- #

async def test_response_body_is_byte_capped(web, env):
    web.routes["/big"] = (200, {"content-type": "text/plain"}, b"A" * 2_000_000)
    r = await SafeFetcher(env, "t").get(f"{web.base}/big", max_bytes=4096)
    assert r.status == 200 and r.truncated and len(r.body) == 4096


async def test_only_get_and_head_are_possible(web, env):
    fetcher = SafeFetcher(env, "t")
    for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
        with pytest.raises(MethodRefused):
            await fetcher._send(m, f"{web.base}/x", 0)
    assert web.requests == []
    await fetcher.head(f"{web.base}/x")
    await fetcher.get(f"{web.base}/x")
    assert web.methods() == {"GET", "HEAD"}


async def test_timeout_is_enforced(env, monkeypatch):
    from app.modules.safe_checks import base

    async def hang(reader, writer):
        await asyncio.sleep(5)

    srv = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    monkeypatch.setattr(base, "HTTP_TIMEOUT_SEC", 0.4)
    try:
        r = await SafeFetcher(env, "t").get(f"http://127.0.0.1:{port}/")
    finally:
        srv.close()
    assert r.error == "timeout"


async def test_redirect_hops_are_scope_checked(web, orch, scope, politeness):
    web.routes["/a"] = (302, {"location": "http://localhost:%d/b" % web.port}, b"")
    web.routes["/b"] = (200, {}, b"ok")
    orch.set_decision(f"localhost:{web.port}", {"allow": False, "reason": "not in scope"})
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
    with pytest.raises(ScopeDenied):
        await SafeFetcher(env, "t").get(f"{web.base}/a")
    assert ("GET", "/b") not in web.requests


async def test_out_of_scope_target_is_never_contacted(web, orch, scope, politeness):
    orch.set_decision(f"127.0.0.1:{web.port}", {"allow": False, "reason": "no matching active scope_entry"})
    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch)
    f = finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"})
    with pytest.raises(ScopeDenied):
        await safe_checks.run(f, env)
    assert web.requests == []


async def test_every_request_is_audited(web, env, orch):
    await safe_checks.run(finding("exposed-env", "exposed_file", {"url": f"{web.base}/.env"}), env)
    assert orch.outbound_calls and orch.outbound_calls[0]["tool"] == "safe_check:exposed_file"
    assert orch.outbound_calls[0]["method"] == "GET"


async def test_redaction_and_evidence_cap():
    txt = "DB_PASSWORD=hunter2\nuser=bob\nAuthorization: Bearer abcdefghijklmnop1234\n" \
          "key AKIAABCDEFGHIJKLMNOP and -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    out = redact_text(txt)
    for leak in ("hunter2", "abcdefghijklmnop1234", "AKIAABCDEFGHIJKLMNOP", "MIIabc"):
        assert leak not in out
    big = cap_evidence({"a": "x" * 5000, "b": list(range(500)), "c": {"d": "y" * 5000}})
    import json
    assert len(json.dumps(big)) <= 4096


# --------------------------------------------------------------------------- #
# admin panel / directory listing / default page / version / headers
# --------------------------------------------------------------------------- #

LOGIN = b"<html><title>Grafana Login</title><form><input name=user><input type=password name=p></form></html>"


async def test_admin_panel(web, env):
    f = finding("exposed-admin-panel-grafana", "nuclei", {"matched_at": f"{web.base}/login"})
    web.routes["/login"] = (200, {"content-type": "text/html"}, LOGIN)
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "admin_panel"
    assert "password-input" in r.evidence["markers"]
    web.routes["/login"] = (200, {"content-type": "text/html"}, b"<html>Welcome home</html>")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"
    web.routes.pop("/login")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"
    web.routes["/login"] = (401, {"www-authenticate": 'Basic realm="x"'}, b"")
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.evidence["auth_scheme"] == "Basic"


async def test_directory_listing(web, env):
    f = finding("directory-listing", "nuclei", {"matched_at": f"{web.base}/files/"})
    web.routes["/files/"] = (200, {}, b"<html><title>Index of /files</title><h1>Index of /files</h1></html>")
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "directory_listing"
    web.routes["/files/"] = (200, {}, b"<html>hello</html>")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"


async def test_default_page(web, env):
    f = finding("nginx-default-page", "nuclei", {"matched_at": f"{web.base}/"})
    web.routes["/"] = (200, {}, b"<html><title>Welcome to nginx!</title></html>")
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "default_page"
    web.routes["/"] = (200, {}, b"<html>my app</html>")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"


async def test_version_disclosure(web, env):
    f = finding("server-version-disclosure", "nuclei", {"matched_at": f"{web.base}/"})
    web.routes["/"] = (200, {"Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.4.3"}, b"x")
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "version_disclosure"
    assert r.evidence["headers"]["server"].startswith("Apache/2.4.49")
    web.routes["/"] = (200, {"Server": "nginx"}, b"x")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"


async def test_security_headers(web, env):
    url = f"{web.base}/"
    f = finding("missing-content-security-policy", "header_check", {"url": url})
    web.routes["/"] = (200, {"content-type": "text/html"}, b"x")
    r = await safe_checks.run(f, env)
    assert r.verdict == "confirmed" and r.check_id == "security_headers"
    web.routes["/"] = (200, {"Content-Security-Policy": "default-src 'self'"}, b"x")
    r = await safe_checks.run(f, env)
    assert r.verdict == "not_reproducible"
    assert "default-src" in r.evidence["headers_present"]["content-security-policy"]


async def test_cookie_header_rule_is_per_cookie(web, env):
    f = finding("cookie-missing-httponly", "header_check", {"url": f"{web.base}/", "cookie": "sid"})
    web.routes["/"] = (200, {"Set-Cookie": "sid=1; Path=/; Secure"}, b"x")
    assert (await safe_checks.run(f, env)).verdict == "confirmed"
    web.routes["/"] = (200, {"Set-Cookie": "sid=1; Path=/; HttpOnly"}, b"x")
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"


# --------------------------------------------------------------------------- #
# subdomain takeover (DNS faked, HTTP via a mock transport)
# --------------------------------------------------------------------------- #

def _takeover_env(scope, politeness, orch, chain, err=None, body="", status=404):
    async def lookup(host):
        return chain, err

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    return CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, cname_lookup=lookup,
                    http_client_kwargs={"transport": httpx.MockTransport(handler)})


S3_BODY = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"


async def test_takeover_confirmed_and_fixed_paths(scope, politeness, orch):
    f = finding("subdomain-takeover", "takeover", asset="assets.example.com", )
    f.asset_kind = "subdomain"
    r = await safe_checks.run(f, _takeover_env(scope, politeness, orch,
                                               ["assets.s3.amazonaws.com"], body=S3_BODY))
    assert r.verdict == "confirmed" and r.check_id == "subdomain_takeover"
    assert r.evidence["service"]
    # resource reclaimed: provider now serves something else
    r = await safe_checks.run(f, _takeover_env(scope, politeness, orch,
                                               ["assets.s3.amazonaws.com"], body="<html>ok</html>", status=200))
    assert r.verdict == "not_reproducible"
    # CNAME removed
    r = await safe_checks.run(f, _takeover_env(scope, politeness, orch, []))
    assert r.verdict == "not_reproducible"
    # repointed at our own infrastructure
    r = await safe_checks.run(f, _takeover_env(scope, politeness, orch, ["lb.example.com"]))
    assert r.verdict == "not_reproducible"


async def test_takeover_dns_failure_never_counts_as_fixed(scope, politeness, orch):
    f = finding("subdomain-takeover", "takeover", asset="assets.example.com")
    r = await safe_checks.run(f, _takeover_env(scope, politeness, orch, [], err="dns resolution failed: Timeout"))
    assert r.verdict == "inconclusive"


async def test_takeover_fetch_error_is_inconclusive(scope, politeness, orch):
    def boom(request):
        raise httpx.ConnectError("refused")

    async def lookup(host):
        return ["assets.s3.amazonaws.com"], None

    env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, cname_lookup=lookup,
                   http_client_kwargs={"transport": httpx.MockTransport(boom)})
    r = await safe_checks.run(finding("subdomain-takeover", "takeover", asset="assets.example.com"), env)
    assert r.verdict == "inconclusive"


# --------------------------------------------------------------------------- #
# open port: connect + read only
# --------------------------------------------------------------------------- #

async def test_open_port_banner_and_nothing_sent(env):
    received: list[bytes] = []

    async def serve(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_8.9\r\n")
        await writer.drain()
        try:
            received.append(await asyncio.wait_for(reader.read(100), 0.5))
        except asyncio.TimeoutError:
            received.append(b"")
        writer.close()

    srv = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        f = finding("exposed-ssh", "policy", {"port": port})
        r = await safe_checks.run(f, env)
        assert r.verdict == "confirmed" and r.check_id == "open_port"
        assert "SSH-2.0" in r.evidence["banner"]
        await asyncio.sleep(0.2)
        assert received == [b""]  # not a single byte was sent to the service
    finally:
        srv.close()


async def test_closed_port_is_not_reproducible_and_filtered_is_inconclusive(env, scope, politeness, orch):
    srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()
    f = finding("exposed-redis", "policy", {"port": port})
    assert (await safe_checks.run(f, env)).verdict == "not_reproducible"

    async def filtered(host, port):
        return {"state": "filtered", "error": "timeout"}

    env2 = CheckEnv(scope=scope, politeness=politeness, orchestrator=orch, tcp_banner=filtered)
    assert (await safe_checks.run(f, env2)).verdict == "inconclusive"


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

OPENSSL = shutil.which("openssl")
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("openssl missing")
    d = tmp_path_factory.mktemp("certs")

    def run(*args):
        subprocess.run([OPENSSL, *args], cwd=d, check=True, capture_output=True)

    # self-signed, valid 5 days (expiring) -- RSA so RSA-kex weak suites work
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ss5.key", "-out", "ss5.pem",
        "-subj", "/CN=localhost", "-days", "5")
    # CA + leaf valid 90 days
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-subj", "/CN=Test CA", "-days", "365")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
        "-subj", "/CN=localhost")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "leaf.pem", "-days", "90")
    return d


async def tls_server(certs, cert, key, *, min_v=None, max_v=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certs / cert), str(certs / key))
    if min_v:
        ctx.minimum_version = min_v
    if max_v:
        ctx.maximum_version = max_v
    if ciphers:
        ctx.set_ciphers(ciphers)

    async def h(r, w):
        try:
            await asyncio.sleep(0.2)
        finally:
            w.close()

    srv = await asyncio.start_server(h, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


def tfinding(rule_id, port, **ev):
    return finding(rule_id, "tls_check", {"port": port, **ev}, asset=f"127.0.0.1:{port}")


@needs_openssl
async def test_cert_expiry_and_self_signed(certs, env):
    srv, port = await tls_server(certs, "ss5.pem", "ss5.key")
    try:
        r = await safe_checks.run(tfinding("expiring-certificate", port), env)
        assert r.verdict == "confirmed" and r.evidence["days_remaining"] <= 5
        r = await safe_checks.run(tfinding("self-signed-certificate", port), env)
        assert r.verdict == "confirmed" and r.evidence["self_signed"] is True
        r = await safe_checks.run(tfinding("expired-certificate", port), env)
        assert r.verdict == "not_reproducible"
        env.now = lambda: datetime.now(timezone.utc) + timedelta(days=400)
        r = await safe_checks.run(tfinding("expired-certificate", port), env)
        assert r.verdict == "confirmed" and r.check_id == "tls_certificate"
    finally:
        srv.close()


@needs_openssl
async def test_renewed_ca_signed_certificate_is_not_reproducible(certs, env):
    srv, port = await tls_server(certs, "leaf.pem", "leaf.key")
    try:
        assert (await safe_checks.run(tfinding("expiring-certificate", port), env)).verdict == "not_reproducible"
        assert (await safe_checks.run(tfinding("self-signed-certificate", port), env)).verdict == "not_reproducible"
    finally:
        srv.close()


@needs_openssl
async def test_missing_tls13(certs, env):
    old, p_old = await tls_server(certs, "leaf.pem", "leaf.key", max_v=ssl.TLSVersion.TLSv1_2)
    new, p_new = await tls_server(certs, "leaf.pem", "leaf.key")
    try:
        r = await safe_checks.run(tfinding("missing-tls-1-3", p_old), env)
        assert r.verdict == "confirmed" and r.evidence["negotiated_by_default"] == "TLSv1.2"
        assert (await safe_checks.run(tfinding("missing-tls-1-3", p_new), env)).verdict == "not_reproducible"
    finally:
        old.close()
        new.close()


@needs_openssl
async def test_legacy_protocol_accepted_vs_refused(certs, env):
    if not (await tls_mod.client_can_negotiate("TLSv1") and await tls_mod.client_can_negotiate("TLSv1.1")):
        pytest.skip("this OpenSSL cannot speak TLS 1.0/1.1")
    legacy, p_legacy = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1,
                                        max_v=ssl.TLSVersion.TLSv1_2, ciphers="ALL:@SECLEVEL=0")
    modern, p_modern = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1_2)
    try:
        r = await safe_checks.run(tfinding("legacy-tls-version", p_legacy), env)
        assert r.verdict == "confirmed" and "TLSv1" in r.evidence["accepted"]
        r = await safe_checks.run(tfinding("legacy-tls-version", p_modern), env)
        assert r.verdict == "not_reproducible"
    finally:
        legacy.close()
        modern.close()


@needs_openssl
async def test_legacy_protocol_is_inconclusive_when_client_cannot_offer_it(certs, env, monkeypatch):
    modern, port = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1_2)

    async def never(version):
        return False

    monkeypatch.setattr(tls_mod, "client_can_negotiate", never)
    try:
        r = await safe_checks.run(tfinding("legacy-tls-version", port), env)
        assert r.verdict == "inconclusive" and "cannot offer" in r.reason
    finally:
        modern.close()


@needs_openssl
async def test_weak_cipher(certs, env):
    modern, p_modern = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1_2)
    try:
        r = await safe_checks.run(tfinding("weak-cipher", p_modern, cipher="DES-CBC3-SHA"), env)
        offerable = tls_mod._offerable(tls_mod._families_of("DES-CBC3-SHA"))
        if not offerable:
            assert r.verdict == "inconclusive"
        else:
            assert r.verdict == "not_reproducible"
    finally:
        modern.close()
    if not tls_mod._offerable(["3DES"]):
        pytest.skip("this OpenSSL cannot offer 3DES")
    weak, p_weak = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1,
                                    max_v=ssl.TLSVersion.TLSv1_2, ciphers="DES-CBC3-SHA:@SECLEVEL=0")
    try:
        r = await safe_checks.run(tfinding("weak-cipher", p_weak, cipher="DES-CBC3-SHA"), env)
        assert r.verdict == "confirmed" and "DES-CBC3" in r.evidence["negotiated"]
    finally:
        weak.close()


async def test_weak_cipher_family_the_client_cannot_offer_is_inconclusive(certs, env):
    # RC4 does not exist in OpenSSL 3: a refusal says nothing about an RC4-only server.
    modern, port = await tls_server(certs, "leaf.pem", "leaf.key", min_v=ssl.TLSVersion.TLSv1_2) \
        if OPENSSL else (None, 0)
    if modern is None:
        pytest.skip("openssl missing")
    try:
        if tls_mod._offerable(["RC4"]):
            pytest.skip("this OpenSSL can offer RC4")
        r = await safe_checks.run(tfinding("weak-cipher", port, cipher="TLS_RSA_WITH_RC4_128_SHA"), env)
        assert r.verdict == "inconclusive"
    finally:
        modern.close()


async def test_tls_unreachable_is_inconclusive(env):
    r = await safe_checks.run(tfinding("missing-tls-1-3", 9), env)
    assert r.verdict == "inconclusive"


async def test_der_validity_parser_matches_openssl(certs):
    if OPENSSL is None:
        pytest.skip("openssl missing")
    der = ssl.PEM_cert_to_DER_cert((certs / "ss5.pem").read_text())
    c = tls_mod.parse_cert(der)
    assert c["self_signed"] is True
    assert 4 <= (c["not_after"] - datetime.now(timezone.utc)).days <= 5
    leaf = tls_mod.parse_cert(ssl.PEM_cert_to_DER_cert((certs / "leaf.pem").read_text()))
    assert leaf["self_signed"] is False


# --------------------------------------------------------------------------- #
# registry + job handler
# --------------------------------------------------------------------------- #

async def test_registry_maps_every_advertised_rule():
    cases = [
        ("exposed-env", "exposed_file", "exposed_file"),
        ("exposed-git-head", "exposed_file", "exposed_file"),
        ("missing-strict-transport-security", "header_check", "security_headers"),
        ("cookie-missing-secure", "header_check", "security_headers"),
        ("subdomain-takeover", "takeover", "subdomain_takeover"),
        ("expired-certificate", "tls_check", "tls_certificate"),
        ("self-signed-certificate", "tls_check", "tls_certificate"),
        ("legacy-tls-version", "tls_check", "tls_protocol"),
        ("missing-tls-1-3", "tls_check", "tls_protocol"),
        ("weak-cipher", "tls_check", "tls_weak_cipher"),
    ]
    for rule, src, want in cases:
        ev = {"url": "https://x.example.com/"} if src != "tls_check" else {}
        f = FindingCtx(id="1", rule_id=rule, rule_source=src, evidence=ev, asset_value="x.example.com")
        chk = safe_checks.resolve(f)
        assert chk is not None and chk.id == want, (rule, chk)
    f = FindingCtx(id="1", rule_id="CVE-2021-44228", rule_source="nuclei", asset_value="x.example.com")
    assert safe_checks.resolve(f) is None
    ids = {c["id"] for c in safe_checks.catalogue()}
    assert {"exposed_file", "admin_panel", "directory_listing", "default_page", "version_disclosure",
            "security_headers", "subdomain_takeover", "tls_certificate", "tls_protocol",
            "tls_weak_cipher", "open_port"} <= ids
    # nothing in the catalogue sends anything but GET / HEAD / handshake / connect
    for c in safe_checks.catalogue():
        assert set(c["sends"]) <= {"GET", "HEAD", "DNS", "TLS handshake", "TCP connect"}


def _job(web, **over):
    cfg = {
        "verification_id": "v-1", "purpose": "exploitability", "scope_proof": "verified",
        "tenant_id": "00000000-0000-0000-0000-0000000000aa",
        "finding": {"id": "f-1", "rule_id": "exposed-env", "rule_source": "exposed_file",
                    "evidence": {"url": f"{web.base}/.env"}, "asset": {"kind": "endpoint", "value": "127.0.0.1"}},
    }
    cfg.update(over)
    return cfg


async def test_job_reports_verdict_with_tenant(web, scope, politeness, orch):
    web.routes["/.env"] = (200, {}, ENV_BODY)
    out = await verify_finding.verify("127.0.0.1", scope=scope, politeness=politeness,
                                      orchestrator=orch, scan_id="s", config=_job(web))
    vid, payload, tenant = orch.results[0]
    assert vid == "v-1" and tenant.endswith("aa")
    assert payload["status"] == "done" and payload["verdict"] == "confirmed"
    assert payload["check_id"] == "exposed_file" and "hunter2secret" not in str(payload)
    assert out["summary"]["verdict"] == "confirmed"


async def test_job_without_proof_is_refused_and_target_untouched(web, scope, politeness, orch):
    for proof in ("pending", "expired", "", None):
        await verify_finding.verify("127.0.0.1", scope=scope, politeness=politeness,
                                    orchestrator=orch, scan_id="s", config=_job(web, scope_proof=proof))
    assert [p["status"] for _, p, _ in orch.results] == ["refused"] * 4
    assert web.requests == []


async def test_job_scope_denied_is_reported_as_refused(web, scope, politeness, orch):
    orch.set_decision(f"127.0.0.1:{web.port}", {"allow": False, "reason": "no matching active scope_entry"})
    await verify_finding.verify("127.0.0.1", scope=scope, politeness=politeness,
                                orchestrator=orch, scan_id="s", config=_job(web))
    assert orch.results[0][1]["status"] == "refused" and "scope" in orch.results[0][1]["reason"]
    assert web.requests == []


async def test_job_unsupported_rule(web, scope, politeness, orch):
    cfg = _job(web)
    cfg["finding"] = {"id": "f", "rule_id": "CVE-2021-44228", "rule_source": "nuclei",
                      "evidence": {}, "asset": {"kind": "endpoint", "value": "127.0.0.1"}}
    await verify_finding.verify("127.0.0.1", scope=scope, politeness=politeness,
                                orchestrator=orch, scan_id="s", config=cfg)
    assert orch.results[0][1]["status"] == "unsupported"


async def test_job_check_crash_is_reported_as_error(web, scope, politeness, orch, monkeypatch):
    async def boom(f, e):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(safe_checks, "run", boom)
    await verify_finding.verify("127.0.0.1", scope=scope, politeness=politeness,
                                orchestrator=orch, scan_id="s", config=_job(web))
    assert orch.results[0][1]["status"] == "error"


async def test_dispatcher_knows_the_job_kind():
    from app.main import _DISPATCH

    assert "verify_finding" in _DISPATCH
