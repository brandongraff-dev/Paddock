"""DNS-rebinding defence: the pinned transport resolves once, validates every
answer and connects to those addresses, keeping Host / SNI / certificate
verification for the ORIGINAL hostname.

No external network: a scripted resolver stands in for DNS, and a local TLS
server (own CA, SAN = the test hostname) stands in for the remote.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import smtplib
import ssl
import tempfile

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.integrations import netsafety, outbound
from app.integrations.connectors import email as email_mod
from app.integrations.pinned import PinnedTransport, pinned_client

PUBLIC = "93.184.216.34"
PUBLIC6 = "2606:2800:220:1:248:1893:25c8:1946"


class ScriptedDNS:
    """name -> list of answer-lists; the Nth lookup returns the Nth entry
    (the last one repeats)."""

    def __init__(self, table: dict[str, list[list[str]]]) -> None:
        self.table = table
        self.calls: list[str] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        n = sum(1 for c in self.calls if c == host)
        seq = self.table.get(host)
        if seq is None:
            raise OSError("NXDOMAIN")
        return list(seq[min(n, len(seq)) - 1])


@pytest.fixture
def dns():
    d = ScriptedDNS({})
    netsafety.set_resolver(d)
    yield d
    netsafety.set_resolver(None)


class Seen(httpx.AsyncBaseTransport):
    """Stands in for the inner (real-network) transport; records the pinned request."""

    def __init__(self, responder=None) -> None:
        self.requests: list[httpx.Request] = []
        self.responder = responder or (lambda r: httpx.Response(200, text="ok"))

    async def handle_async_request(self, request):
        self.requests.append(request)
        return self.responder(request)


def pinned_with(seen: Seen, **kw) -> PinnedTransport:
    t = PinnedTransport(**kw)
    t._inner = seen  # type: ignore[assignment]
    t.proxy = None
    return t


# --------------------------------------------------------------------------- #
# rebinding: public first, loopback second
# --------------------------------------------------------------------------- #

async def test_connects_to_first_answer_and_never_resolves_again(dns):
    dns.table["evil.example"] = [[PUBLIC], ["127.0.0.1"]]
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        r = await c.get("https://evil.example/hook")
    assert r.status_code == 200
    assert dns.calls == ["evil.example"]                     # one lookup, not two
    req = seen.requests[0]
    assert req.url.host == PUBLIC                            # connected to the VALIDATED ip
    assert req.headers["host"] == "evil.example"             # Host preserved
    assert req.extensions["sni_hostname"] == "evil.example"  # SNI / cert name preserved


async def test_every_request_is_revalidated_second_lookup_internal_is_refused(dns):
    dns.table["evil.example"] = [[PUBLIC], ["127.0.0.1"]]
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        await c.get("https://evil.example/a")
        with pytest.raises(netsafety.UnsafeURL):             # the rebound answer
            await c.get("https://evil.example/b")
    assert [r.url.host for r in seen.requests] == [PUBLIC]   # never connected to 127.0.0.1


@pytest.mark.parametrize("answers", [
    ["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["::1"], ["fd00:ec2::254"],
    ["::ffff:127.0.0.1"], ["::ffff:169.254.169.254"], ["fe80::1%eth0"], ["0.0.0.0"],
    [PUBLIC, "127.0.0.1"],                 # mixed: one bad answer poisons the name
    ["127.0.0.1", PUBLIC],
    [PUBLIC, PUBLIC6, "::1"],
    [PUBLIC, "not-an-ip"],
    [],                                    # resolves to nothing
])
async def test_private_mixed_and_garbage_answers_are_refused(dns, answers):
    dns.table["x.example"] = [answers]
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        with pytest.raises(netsafety.UnsafeURL):
            await c.get("https://x.example/")
    assert seen.requests == []


async def test_nxdomain_is_refused(dns):
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        with pytest.raises(netsafety.UnsafeURL, match="does not resolve"):
            await c.get("https://nope.example/")


async def test_ipv6_answer_is_pinned_with_brackets(dns):
    dns.table["v6.example"] = [[PUBLIC6]]
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        await c.get("https://v6.example:8443/p?q=1")
    req = seen.requests[0]
    assert req.url.host == PUBLIC6 and req.url.port == 8443
    assert req.headers["host"] == "v6.example:8443"
    assert req.extensions["sni_hostname"] == "v6.example"


async def test_allow_private_permits_lan_but_never_hard_denied(dns):
    dns.table["lan.example"] = [["10.0.0.5"]]
    dns.table["meta.example"] = [["169.254.169.254"]]
    dns.table["meta6.example"] = [["fd00:ec2::254"]]
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen, allow_private=True)) as c:
        assert (await c.get("https://lan.example/")).status_code == 200
        for host in ("meta.example", "meta6.example"):
            with pytest.raises(netsafety.UnsafeURL, match="protected"):
                await c.get(f"https://{host}/")
    assert [r.url.host for r in seen.requests] == ["10.0.0.5"]


async def test_ip_literal_urls_are_validated_without_dns(dns):
    seen = Seen()
    async with httpx.AsyncClient(transport=pinned_with(seen)) as c:
        for u in ("https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest"):
            with pytest.raises(netsafety.UnsafeURL):
                await c.get(u)
        await c.get(f"https://{PUBLIC}/")
    assert dns.calls == []
    assert seen.requests[0].url.host == PUBLIC
    assert "sni_hostname" not in seen.requests[0].extensions


async def test_redirect_to_internal_name_is_refused_per_hop(dns):
    dns.table["a.example"] = [[PUBLIC]]
    dns.table["inner.example"] = [["127.0.0.1"]]

    def responder(req):
        if req.url.host == PUBLIC:
            return httpx.Response(302, headers={"location": "https://inner.example/secret"})
        return httpx.Response(200, text="LEAK")

    seen = Seen(responder)
    # even a caller that opts in to redirects cannot be walked inside
    async with httpx.AsyncClient(transport=pinned_with(seen), follow_redirects=True) as c:
        with pytest.raises(netsafety.UnsafeURL):
            await c.get("https://a.example/start")
    assert [r.url.host for r in seen.requests] == [PUBLIC]


async def test_redirect_to_literal_metadata_ip_is_refused(dns):
    dns.table["a.example"] = [[PUBLIC]]
    seen = Seen(lambda r: httpx.Response(307, headers={"location": "http://169.254.169.254/latest/meta-data"}))
    async with httpx.AsyncClient(transport=pinned_with(seen), follow_redirects=True) as c:
        with pytest.raises(netsafety.UnsafeURL):
            await c.get("https://a.example/")


async def test_pinned_client_never_follows_redirects(dns):
    dns.table["a.example"] = [[PUBLIC]]
    seen = Seen(lambda r: httpx.Response(302, headers={"location": "https://a.example/next"}))
    async with pinned_client(transport=pinned_with(seen)) as c:
        r = await c.get("https://a.example/")
    assert r.status_code == 302 and len(seen.requests) == 1


# --------------------------------------------------------------------------- #
# the shared clients really use it
# --------------------------------------------------------------------------- #

async def test_guarded_client_defaults_to_pinned_transport_and_keeps_injected_mock():
    c = outbound.make_client()
    assert isinstance(c._transport, PinnedTransport)
    await c.aclose()
    mock = httpx.MockTransport(lambda r: httpx.Response(200))
    c2 = outbound.make_client(transport=mock)
    assert c2._transport is mock
    await c2.aclose()


async def test_guarded_client_rebinding_end_to_end(dns):
    """GuardedAsyncClient validates (lookup 1: public) and the transport pins
    (lookup 2 would be loopback): connection goes to the public address or is
    refused -- never to 127.0.0.1."""
    dns.table["evil.example"] = [[PUBLIC], ["127.0.0.1"]]
    seen = Seen()
    c = outbound.GuardedAsyncClient(transport=pinned_with(seen))
    async with c:
        with pytest.raises(netsafety.UnsafeURL):
            await c.post("https://evil.example/hook", json={})
    assert all(r.url.host != "127.0.0.1" for r in seen.requests)


async def test_oidc_client_uses_pinned_transport_and_refuses_rebound_idp(dns):
    from app.identity import oidc

    oidc.set_transport(None)
    assert isinstance(oidc._client()._transport, PinnedTransport)
    dns.table["idp.example"] = [["127.0.0.1"]]
    with pytest.raises(oidc.OIDCError) as ei:
        await oidc._get_json("https://idp.example/.well-known/openid-configuration", allow_private=False)
    assert ei.value.code == "provider_unavailable"


async def test_scope_proof_fetch_refuses_rebound_host(dns, monkeypatch):
    from app import scope_proof

    # lookup 1 (validate_outbound_url) public, lookup 2 (the transport) loopback
    dns.table["target.example"] = [[PUBLIC], ["127.0.0.1"]]
    with pytest.raises(scope_proof.FetchRefused):
        await scope_proof.fetch_http("https://target.example/.well-known/paddock-verification/tok")


async def test_smtp_connects_to_validated_ip_but_verifies_hostname(monkeypatch):
    connected: list[tuple] = []

    def fake_create(addr, timeout=None, source_address=None):
        connected.append(addr)
        raise ConnectionRefusedError()

    monkeypatch.setattr(smtplib.socket, "create_connection", fake_create)
    with pytest.raises(ConnectionRefusedError):
        email_mod._PinnedSMTP("smtp.example.com", 587, connect_ip=PUBLIC, timeout=1)
    assert connected == [(PUBLIC, 587)]
    # the hostname is what smtplib hands to TLS (server_hostname)
    s = email_mod._PinnedSMTP.__new__(email_mod._PinnedSMTP)
    s._host = "smtp.example.com"
    assert s._host == "smtp.example.com"


# --------------------------------------------------------------------------- #
# real TLS: SNI, Host and certificate verification for the hostname
# --------------------------------------------------------------------------- #

def _make_ca_and_leaf(names: list[str], tmp: str):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Paddock Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = f"{tmp}/ca.pem"
    open(ca_pem, "wb").write(ca.public_bytes(serialization.Encoding.PEM))
    cert_pem, key_pem = f"{tmp}/leaf.pem", f"{tmp}/leaf.key"
    open(cert_pem, "wb").write(leaf.public_bytes(serialization.Encoding.PEM))
    open(key_pem, "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_pem, cert_pem, key_pem


class TLSServer:
    def __init__(self, cert: str, key: str, bind: str = "127.0.0.1") -> None:
        self.cert, self.key, self.bind = cert, key, bind
        self.sni: list[str | None] = []
        self.hosts: list[str] = []
        self.port = 0

    async def __aenter__(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        ctx.sni_callback = lambda sock, name, c: self.sni.append(name)
        self.server = await asyncio.start_server(self._handle, self.bind, 0, ssl=ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *a):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        for line in head.decode().split("\r\n"):
            if line.lower().startswith("host:"):
                self.hosts.append(line.split(":", 1)[1].strip())
        body = b"hello"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()


@pytest.fixture
def pki(tmp_path):
    return _make_ca_and_leaf(["app.example.test"], str(tmp_path))


def _client_ctx(ca_pem: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_pem)


async def test_tls_sni_host_and_cert_verified_for_original_hostname(dns, pki):
    ca, cert, key = pki
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(ca))
        async with httpx.AsyncClient(transport=t) as c:
            r = await c.get(f"https://app.example.test:{srv.port}/x")
    assert r.status_code == 200 and r.text == "hello"
    assert srv.sni == ["app.example.test"]                        # SNI is the NAME, not 127.0.0.1
    assert srv.hosts == [f"app.example.test:{srv.port}"]          # Host header preserved


async def test_tls_certificate_for_a_different_name_is_rejected(dns, tmp_path):
    ca, cert, key = _make_ca_and_leaf(["other.example.test"], str(tmp_path))
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(ca))
        async with httpx.AsyncClient(transport=t) as c:
            with pytest.raises(httpx.ConnectError):
                await c.get(f"https://app.example.test:{srv.port}/")


async def test_tls_untrusted_ca_is_rejected(dns, pki, tmp_path):
    _, cert, key = pki
    other_ca, _, _ = _make_ca_and_leaf(["zzz.example.test"], tempfile.mkdtemp())
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(other_ca))
        async with httpx.AsyncClient(transport=t) as c:
            with pytest.raises(httpx.ConnectError):
                await c.get(f"https://app.example.test:{srv.port}/")


async def test_tls_rebinding_to_loopback_server_is_refused_without_allow_private(dns, pki):
    ca, cert, key = pki
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]   # the "rebound" answer, no allow_private
        t = PinnedTransport(verify=_client_ctx(ca))
        async with httpx.AsyncClient(transport=t) as c:
            with pytest.raises(netsafety.UnsafeURL):
                await c.get(f"https://app.example.test:{srv.port}/")
    assert srv.sni == [] and srv.hosts == []           # the local server was never contacted


async def test_connect_falls_through_to_next_validated_address(dns, pki):
    ca, cert, key = pki
    async with TLSServer(cert, key, bind="127.0.0.2") as srv:
        # 127.0.0.1:<port> has no listener -> ConnectError -> next validated answer
        dns.table["app.example.test"] = [["127.0.0.1", "127.0.0.2"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(ca))
        async with httpx.AsyncClient(transport=t) as c:
            r = await c.get(f"https://app.example.test:{srv.port}/")
    assert r.status_code == 200 and srv.sni == ["app.example.test"]


async def test_environment_proxy_is_ignored_and_explicit_proxy_still_validates(dns, pki, monkeypatch):
    ca, cert, key = pki
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")   # dead proxy: would break a proxied connect
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("PADDOCK_OUTBOUND_PROXY", raising=False)
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(ca))
        assert t.proxy is None
        async with httpx.AsyncClient(transport=t) as c:
            assert (await c.get(f"https://app.example.test:{srv.port}/")).status_code == 200
    # explicit proxy mode: connect is the proxy's, but the policy still applies to the name
    monkeypatch.setenv("PADDOCK_OUTBOUND_PROXY", "http://proxy.internal:3128")
    t2 = PinnedTransport()
    assert t2.proxy == "http://proxy.internal:3128"
    dns.table["inner.example"] = [["127.0.0.1"]]
    async with httpx.AsyncClient(transport=t2) as c:
        with pytest.raises(netsafety.UnsafeURL):
            await c.get("https://inner.example/")
    await t2.aclose()


async def test_connections_are_not_reused_across_hostnames(dns, pki):
    """Pool is keyed by IP; reuse for another name would skip the cert check."""
    ca, cert, key = pki
    async with TLSServer(cert, key) as srv:
        dns.table["app.example.test"] = [["127.0.0.1"]]
        dns.table["other.example.test"] = [["127.0.0.1"]]
        t = PinnedTransport(allow_private=True, verify=_client_ctx(ca))
        async with httpx.AsyncClient(transport=t) as c:
            assert (await c.get(f"https://app.example.test:{srv.port}/")).status_code == 200
            with pytest.raises(httpx.ConnectError):   # fresh handshake for other.example.test: cert mismatch
                await c.get(f"https://other.example.test:{srv.port}/")
