# SPDX-License-Identifier: Apache-2.0
"""Fetching a bundle: local sources, the HTTPS safety rules (mocked transport and one real TLS round trip)."""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import threading

import pytest

from paddock_verify import fetch, model

PUBLIC = "93.184.216.34"


class Net(object):
    """A scripted transport + resolver that records what the fetcher asked for."""

    def __init__(self, routes=None, resolve=None):
        self.routes = routes or {}
        self.calls = []
        self.resolved = resolve or {}

    def resolve(self, host, port):
        return list(self.resolved.get(host, [PUBLIC]))

    def transport(self, url, ips, headers, timeout, max_bytes):
        self.calls.append(dict(url=url, ips=list(ips), headers=dict(headers), timeout=timeout, max_bytes=max_bytes))
        r = self.routes.get(url)
        if callable(r):
            r = r()
        if r is None:
            return fetch.Response(404, {}, b"")
        return r

    def source(self, base="https://example.com/.well-known/paddock/", **kw):
        return fetch.HttpSource(base, transport=self.transport, resolve=self.resolve, **kw)


def ok(body=b"{}", **headers):
    return fetch.Response(200, dict((k.lower().replace("_", "-"), v) for k, v in headers.items()), body)


def redirect(to, code=302):
    return fetch.Response(code, {"location": to}, b"")


# --------------------------------------------------------------------------------------------- local sources
def test_dir_source_reads_and_reports_absence(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.json").write_bytes(b"{}")
    s = fetch.DirSource(str(tmp_path))
    assert s.read("a/b.json", 100) == b"{}"
    assert s.read("a/missing.json", 100) is None
    assert s.read("a", 100) is None                                       # a directory is not a file


def test_dir_source_enforces_size_and_path_rules(tmp_path):
    (tmp_path / "big.json").write_bytes(b"x" * 101)
    s = fetch.DirSource(str(tmp_path))
    with pytest.raises(fetch.FetchError) as ei:
        s.read("big.json", 100)
    assert ei.value.code == "input.too_large"
    assert s.read("big.json", 101) == b"x" * 101                           # the limit is inclusive
    for bad in ("../x.json", "/etc/passwd", "a/../../x", "a//b", "", "a/./b", "a\\b", "a b", "é"):
        with pytest.raises(fetch.FetchError) as ei:
            s.read(bad, 10)
        assert ei.value.code == "input.unreadable", bad


def test_dir_source_refuses_symlinks_leaving_the_root(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(str(outside), str(root / "link.json"))
    (root / "real.json").write_bytes(b"ok")
    s = fetch.DirSource(str(root))
    assert s.read("real.json", 10) == b"ok"
    with pytest.raises(fetch.FetchError) as ei:
        s.read("link.json", 10)
    assert ei.value.code == "input.unreadable"


def test_memory_source():
    s = fetch.MemorySource({"keys.json": b"k"})
    assert s.read("keys.json", 10) == b"k" and s.read("revoked.json", 10) is None
    with pytest.raises(fetch.FetchError):
        s.read("keys.json", 0)


def make_bundle(root, with_latest=True):
    (root / "attestation").mkdir(parents=True)
    if with_latest:
        (root / "attestation" / "latest.json").write_bytes(b'{"x":1}')
    (root / "keys.json").write_bytes(b"{}")
    return root


def test_locate_directory_forms(tmp_path):
    root = make_bundle(tmp_path / "plain")
    b = fetch.locate(str(root))
    assert isinstance(b, model.Bundle) and b.envelope() == b'{"x":1}' and b.read("keys.json", 10) == b"{}"
    wk = make_bundle(tmp_path / "site" / ".well-known" / "paddock")
    b = fetch.locate(str(tmp_path / "site"))
    assert b.envelope() == b'{"x":1}'
    assert fetch.locate(str(wk)).envelope() == b'{"x":1}'


def test_locate_file_target_finds_siblings_and_root(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / "attestation" / "4.json").write_bytes(b'{"seq":4}')
    b = fetch.locate(str(root / "attestation" / "4.json"))
    assert b.envelope() == b'{"seq":4}'
    assert b.read("keys.json", 10) == b"{}"                                # the bundle root is the grandparent
    assert b.read("attestation/latest.json", 100) == b'{"x":1}'
    loose = tmp_path / "loose"
    loose.mkdir()
    (loose / "env.json").write_bytes(b'{"e":1}')
    (loose / "keys.json").write_bytes(b'{"k":1}')
    b = fetch.locate(str(loose / "env.json"))
    assert b.envelope() == b'{"e":1}' and b.read("keys.json", 10) == b'{"k":1}'
    assert b.read("revoked.json", 10) is None


def test_locate_overrides_for_keys_and_revoked(tmp_path):
    root = make_bundle(tmp_path / "b")
    k, r = tmp_path / "my-keys.json", tmp_path / "my-revoked.json"
    k.write_bytes(b'{"mine":1}')
    r.write_bytes(b'{"rev":1}')
    b = fetch.locate(str(root), keys=str(k), revoked=str(r))
    assert b.read("keys.json", 100) == b'{"mine":1}' and b.read("revoked.json", 100) == b'{"rev":1}'
    with pytest.raises(fetch.FetchError) as ei:
        fetch.locate(str(root), keys=str(tmp_path / "nope.json"))
    assert ei.value.code == "input.not_found"


def test_locate_errors(tmp_path):
    with pytest.raises(fetch.FetchError) as ei:
        fetch.locate(str(tmp_path / "does-not-exist"))
    assert ei.value.code == "input.not_found"
    (tmp_path / "empty").mkdir()
    with pytest.raises(fetch.FetchError) as ei:
        fetch.locate(str(tmp_path / "empty"))
    assert ei.value.code == "input.not_found"
    make_bundle(tmp_path / "nolatest", with_latest=False)
    with pytest.raises(fetch.FetchError) as ei:
        fetch.locate(str(tmp_path / "nolatest"))
    assert ei.value.code == "input.not_found"
    with pytest.raises(fetch.FetchError) as ei:
        fetch.locate("http://example.com/")
    assert ei.value.code == "input.insecure_transport"


def test_oversize_envelope_target_is_input_too_large(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / "attestation" / "latest.json").write_bytes(b" " * (512 * 1024 + 1))
    b = fetch.locate(str(root))
    with pytest.raises(fetch.FetchError) as ei:
        b.envelope()
    assert ei.value.code == "input.too_large"


def test_bundle_budget_is_per_run_and_cached(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / "a.json").write_bytes(b"x" * 1000)
    b = fetch.locate(str(root), budget=2500)
    assert b.read("a.json", 2000) == b"x" * 1000 and b.read("a.json", 2000) == b"x" * 1000      # cached: counted once
    (root / "c.json").write_bytes(b"y" * 1000)
    (root / "d.json").write_bytes(b"z" * 1000)
    b.read("c.json", 2000)                                                                            # 7 (envelope not yet read) + 2000
    with pytest.raises(fetch.FetchError) as ei:
        b.read("d.json", 2000)
    assert ei.value.code == "input.too_large"


# ----------------------------------------------------------------------------------------------- HTTPS rules
def test_https_get_success_headers_and_not_found():
    net = Net({"https://example.com/.well-known/paddock/keys.json": ok(b'{"k":1}')})
    s = net.source()
    assert s.read("keys.json", 1000) == b'{"k":1}'
    assert s.read("revoked.json", 1000) is None                                  # 404 is absence, not an error
    c = net.calls[0]
    assert c["headers"]["Accept-Encoding"] == "identity" and c["max_bytes"] == 1000 and c["timeout"] == 10.0
    assert not any(k.lower() in ("authorization", "cookie", "proxy-authorization") for k in c["headers"])
    assert c["ips"] == [PUBLIC]


def test_base_url_is_normalised_and_checked():
    net = Net({"https://example.com/b/keys.json": ok()})
    assert net.source("https://example.com/b").read("keys.json", 10) == b"{}"      # a trailing slash is added
    for bad in ("http://example.com/", "ftp://example.com/", "https://user:pw@example.com/", "https://user@example.com/", "https:///x", "example.com"):
        with pytest.raises(fetch.FetchError) as ei:
            net.source(bad).read("keys.json", 10)
        assert ei.value.code == "input.insecure_transport", bad


@pytest.mark.parametrize("host", ["93.184.216.34", "[2606:2800:220:1:248:1893:25c8:1946]", "127.0.0.1", "[::1]", "0x7f.1", "2130706433"])
def test_ip_literal_hosts_are_refused(host):
    net = Net()
    with pytest.raises(fetch.FetchError) as ei:
        net.source("https://%s/.well-known/paddock/" % host).read("keys.json", 10)
    assert ei.value.code == "input.insecure_transport"
    assert net.calls == []


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
                                  "224.0.0.1", "::1", "fc00::1", "fe80::1", "::", "::ffff:127.0.0.1", "192.0.2.1"])
def test_resolved_private_addresses_are_refused(addr):
    net = Net(resolve={"example.com": [addr]})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 10)
    assert ei.value.code == "input.insecure_transport"
    assert net.calls == []


def test_one_private_address_among_public_ones_is_refused_and_allow_private_permits():
    net = Net(resolve={"example.com": [PUBLIC, "10.0.0.1"]})
    with pytest.raises(fetch.FetchError):
        net.source().read("keys.json", 10)
    net = Net({"https://example.com/.well-known/paddock/keys.json": ok()}, resolve={"example.com": ["127.0.0.1"]})
    assert net.source(allow_private=True).read("keys.json", 10) == b"{}"
    assert net.calls[0]["ips"] == ["127.0.0.1"]


def test_resolution_failure_and_empty_answer_are_fetch_failures():
    class Bad(Net):
        def resolve(self, host, port):
            raise OSError("no such host")

    with pytest.raises(fetch.FetchError) as ei:
        Bad().source().read("keys.json", 10)
    assert ei.value.code == "input.fetch_failed"
    with pytest.raises(fetch.FetchError) as ei:
        Net(resolve={"example.com": []}).source().read("keys.json", 10)
    assert ei.value.code == "input.fetch_failed"


def test_redirects_https_to_https_up_to_three():
    base = "https://example.com/.well-known/paddock/"
    net = Net({base + "keys.json": redirect("https://cdn.example.net/a"), "https://cdn.example.net/a": redirect("/b", 301),
               "https://cdn.example.net/b": redirect("c", 307), "https://cdn.example.net/c": ok(b"final")})
    assert net.source().read("keys.json", 100) == b"final"
    assert len(net.calls) == 4
    net = Net({base + "keys.json": redirect("https://e.net/1"), "https://e.net/1": redirect("/2"), "https://e.net/2": redirect("/3"),
               "https://e.net/3": redirect("/4"), "https://e.net/4": ok(b"x")})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 100)
    assert ei.value.code == "input.fetch_failed"                                 # four redirects is one too many


def test_redirect_downgrade_credentials_and_private_targets_are_refused():
    base = "https://example.com/.well-known/paddock/"
    for loc in ("http://example.com/x", "https://user:pw@example.com/x", "https://[::1]/x", "ftp://example.com/x", "//attacker.test/x"):
        net = Net({base + "keys.json": redirect(loc)}, resolve={"attacker.test": ["10.0.0.5"]})
        with pytest.raises(fetch.FetchError) as ei:
            net.source().read("keys.json", 100)
        assert ei.value.code in ("input.insecure_transport",), loc
    net = Net({base + "keys.json": redirect("https://intranet.example/x")}, resolve={"intranet.example": ["192.168.0.10"]})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 100)
    assert ei.value.code == "input.insecure_transport"
    assert len(net.calls) == 1                                                       # the private target was never contacted
    net = Net({base + "keys.json": fetch.Response(302, {}, b"")})
    with pytest.raises(fetch.FetchError):
        net.source().read("keys.json", 100)                                          # a redirect without Location


def test_redirect_loop_terminates():
    base = "https://example.com/.well-known/paddock/"
    net = Net({base + "keys.json": redirect(base + "keys.json")})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 100)
    assert ei.value.code == "input.fetch_failed" and len(net.calls) <= 4


def test_http_errors_encoding_and_oversize():
    base = "https://example.com/.well-known/paddock/"
    for status in (500, 502, 403, 401, 429, 204):
        net = Net({base + "keys.json": fetch.Response(status, {}, b"")})
        with pytest.raises(fetch.FetchError) as ei:
            net.source().read("keys.json", 100)
        assert ei.value.code == "input.fetch_failed", status
    for status in (404, 410):
        assert Net({base + "keys.json": fetch.Response(status, {}, b"")}).source().read("keys.json", 100) is None
    net = Net({base + "keys.json": ok(b"x", content_encoding="gzip")})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 100)
    assert ei.value.code == "input.fetch_failed"
    assert Net({base + "keys.json": ok(b"{}", content_encoding="identity")}).source().read("keys.json", 100) == b"{}"
    net = Net({base + "keys.json": ok(b"x" * 101)})
    with pytest.raises(fetch.FetchError) as ei:
        net.source().read("keys.json", 100)
    assert ei.value.code == "input.too_large"


def test_transport_failures_map_to_fetch_failed():
    for exc in (socket.timeout("t"), ConnectionResetError("r"), ssl.SSLError("tls"), OSError("x")):
        class Boom(Net):
            def transport(self, *a, **k):
                raise exc

        with pytest.raises(fetch.FetchError) as ei:
            Boom().source().read("keys.json", 10)
        assert ei.value.code == "input.fetch_failed"


def test_https_paths_are_checked_before_any_request():
    net = Net()
    s = net.source()
    for bad in ("../keys.json", "/keys.json", "a/../b", "a?x=1", "a#f", "a b", "a\r\nb"):
        with pytest.raises(fetch.FetchError):
            s.read(bad, 10)
    assert net.calls == []


def test_domain_helpers():
    assert fetch.default_base("example.com") == "https://example.com/.well-known/paddock/"
    assert fetch.base_from_keys_hint("https://hosted.test/v1/public/attest/example.com/keys.json") == "https://hosted.test/v1/public/attest/example.com/"
    assert fetch.base_from_keys_hint("https://example.com/.well-known/paddock/keys.json") == "https://example.com/.well-known/paddock/"
    assert fetch.base_from_keys_hint("https://example.com/keys.json") == "https://example.com/"
    for bad in ("http://x/keys.json", "https://x", "https://x/", "https://x/a?b=c", "https://x/a#f", "", "https://u@x/keys.json"):
        assert fetch.base_from_keys_hint(bad) is None, bad
    for ok_text in ("example.com", "a.b.example.org", "xn--bcher-kva.example", "paddock.example.co.uk"):
        assert fetch.looks_like_domain(ok_text)
    for bad in ("example", "/tmp/x", "a b.com", "1.2.3.4", "http://x.com", "x.com/", "-a.com", "a..com", "A.com", ""):
        assert not fetch.looks_like_domain(bad), bad


# ------------------------------------------------------------------------ a real TLS round trip, no mocks
def _self_signed(host):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class TlsServer(object):
    def __init__(self, tmp_path, host, handler):
        cert, key = _self_signed(host)
        (tmp_path / "c.pem").write_bytes(cert)
        (tmp_path / "k.pem").write_bytes(key)
        self.cafile = str(tmp_path / "c.pem")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cafile, str(tmp_path / "k.pem"))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.ctx, self.handler, self.requests = ctx, handler, []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    self.requests.append(data)
                    tls.sendall(self.handler(data))
            except Exception:
                pass

    def close(self):
        self.sock.close()


def test_real_tls_transport_pins_the_validated_address_and_streams_with_a_cap(tmp_path):
    body = b'{"hello":"world"}'
    srv = TlsServer(tmp_path, "paddock.test", lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    try:
        ctx = ssl.create_default_context(cafile=srv.cafile)
        s = fetch.HttpSource("https://paddock.test:%d/.well-known/paddock/" % srv.port, allow_private=True,
                             resolve=lambda host, port: ["127.0.0.1"], ssl_context=ctx)
        assert s.read("keys.json", 1000) == body
        req = srv.requests[0].decode("ascii").lower()
        assert req.startswith("get /.well-known/paddock/keys.json http/1.1")
        assert "host: paddock.test:%d" % srv.port in req and "accept-encoding: identity" in req
        assert "authorization" not in req and "cookie" not in req
        with pytest.raises(fetch.FetchError) as ei:
            s.read("keys.json", 5)                                                  # streamed and capped
        assert ei.value.code == "input.too_large"
    finally:
        srv.close()


def test_real_tls_transport_rejects_a_certificate_for_another_host(tmp_path):
    srv = TlsServer(tmp_path, "other.test", lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    try:
        ctx = ssl.create_default_context(cafile=srv.cafile)
        s = fetch.HttpSource("https://paddock.test:%d/" % srv.port, allow_private=True, resolve=lambda h, p: ["127.0.0.1"], ssl_context=ctx)
        with pytest.raises(fetch.FetchError) as ei:
            s.read("keys.json", 100)
        assert ei.value.code == "input.fetch_failed"
    finally:
        srv.close()
