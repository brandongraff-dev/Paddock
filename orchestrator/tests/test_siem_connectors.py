"""SIEM connectors: Splunk HEC, Microsoft Sentinel, Elastic _bulk, syslog.

HTTP connectors run against ``httpx.MockTransport`` (auth headers, batching,
payload shape, error/retry classification, secret hygiene). Syslog runs
against real local TCP / TLS / UDP listeners. DNS for the example host names
is faked so the REAL ``netsafety`` policy is exercised without network.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app.integrations import REGISTRY, Event
from app.integrations.connectors import load_all
from app.integrations.connectors import sentinel as sentinel_mod
from app.integrations.connectors.elastic import ElasticConnector
from app.integrations.connectors.sentinel import SentinelConnector
from app.integrations.connectors.splunk_hec import SplunkHecConnector
from app.integrations.connectors.syslog import (
    SyslogConnector,
    cef_ext_escape,
    cef_header_escape,
    to_cef,
)
from app.integrations import ocsf

PUBLIC_IP = "93.184.216.34"
FAKE_DNS = {
    "splunk.example.com": PUBLIC_IP,
    "es.example.com": PUBLIC_IP,
    "dce.example.com": PUBLIC_IP,
    "login.microsoftonline.com": PUBLIC_IP,
    "syslog.example.com": PUBLIC_IP,
    "metadata.example.com": "169.254.169.254",
    "lan-splunk.example.com": "10.0.0.7",
}

SECRET = "s3cr3t-T0KEN-value-xyz"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        ip = FAKE_DNS.get(host)
        if ip is None:
            return real(host, port, *args, **kwargs)
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, "", (ip, port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    yield


@pytest.fixture(autouse=True)
def _clear_tokens():
    sentinel_mod.clear_token_cache()
    yield
    sentinel_mod.clear_token_cache()


def _events(n: int, **kw) -> list[Event]:
    return [Event(type="finding.opened", title=f"Finding {i}", severity="high",
                  data={"finding": {"id": f"f-{i}", "rule_id": "exposed-git", "rule_source": "exposed_file",
                                    "severity": "high", "title": f"Finding {i}", "description": "d",
                                    "status": "open", "asset_value": "a.example.com",
                                    "asset_kind": "subdomain"}}, **kw) for i in range(n)]


class Recorder:
    def __init__(self, handler):
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self))


def _no_secret(res):
    assert SECRET not in (res.detail or "")


def test_registry_and_describe():
    load_all()
    for kind in ("splunk_hec", "sentinel", "elastic", "syslog"):
        d = REGISTRY[kind].describe()
        assert d["category"] == "siem" and d["capabilities"] == ["notify"]
        assert d["config_schema"]["type"] == "object"
    assert REGISTRY["splunk_hec"].describe()["secret_fields"] == ["token"]
    assert REGISTRY["sentinel"].describe()["secret_fields"] == ["client_secret"]
    assert REGISTRY["elastic"].describe()["secret_fields"] == ["api_key"]


# --------------------------------------------------------------------------- #
# Splunk HEC
# --------------------------------------------------------------------------- #

def _hec(handler, **cfg):
    rec = Recorder(handler)
    config = {"url": "https://splunk.example.com:8088", "index": "security", **cfg}
    return SplunkHecConnector(config, {"token": SECRET}, rec.client()), rec


def _split_hec(body: bytes) -> list[dict]:
    dec = json.JSONDecoder()
    s, i, out = body.decode(), 0, []
    while i < len(s):
        obj, i = dec.raw_decode(s, i)
        out.append(obj)
    return out


async def test_splunk_batches_events_into_one_request():
    c, rec = _hec(lambda r: httpx.Response(200, json={"text": "Success", "code": 0}))
    evs = _events(3)
    res = await c.deliver_batch(evs)
    assert res.ok and res.status_code == 200
    [req] = rec.requests
    assert str(req.url) == "https://splunk.example.com:8088/services/collector/event"
    assert req.headers["authorization"] == f"Splunk {SECRET}"
    assert req.headers["x-splunk-request-channel"]
    envs = _split_hec(req.content)
    assert len(envs) == 3
    for env, ev in zip(envs, evs):
        assert env["index"] == "security" and env["sourcetype"] == "paddock:ocsf"
        assert env["fields"]["paddock_event_id"] == ev.id
        assert env["event"]["class_uid"] == 2004 and env["event"]["metadata"]["uid"] == ev.id
        assert isinstance(env["time"], float)


async def test_splunk_splits_large_batches():
    c, rec = _hec(lambda r: httpx.Response(200, json={"text": "Success", "code": 0}))
    res = await c.deliver_batch(_events(450))
    assert res.ok and len(rec.requests) == 3  # max_batch 200


@pytest.mark.parametrize("status,body,retryable", [
    (403, {"text": "Invalid token", "code": 4}, False),
    (401, {"text": "Token is required", "code": 2}, False),
    (400, {"text": "Invalid data format", "code": 6}, False),
    (400, {"text": "Incorrect index", "code": 7}, False),
    (503, {"text": "Server is busy", "code": 9}, True),
    (429, {"text": "too many", "code": 9}, True),
    (500, {"text": "Internal server error", "code": 8}, True),
])
async def test_splunk_error_classification(status, body, retryable):
    c, _ = _hec(lambda r: httpx.Response(status, json=body))
    res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable is retryable and res.status_code == status
    assert body["text"] in res.detail
    _no_secret(res)


async def test_splunk_scrubs_echoed_secret_and_handles_timeouts():
    c, _ = _hec(lambda r: httpx.Response(400, text=f"bad token {SECRET}"))
    res = await c.deliver(_events(1)[0])
    assert not res.ok and SECRET not in res.detail and "********" in res.detail

    def boom(r):
        raise httpx.ConnectTimeout("timed out", request=r)

    c, _ = _hec(boom)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable


async def test_splunk_refuses_unsafe_destinations():
    for url in ("https://metadata.example.com:8088", "http://splunk.example.com:8088",
                "https://lan-splunk.example.com:8088"):
        c, rec = _hec(lambda r: httpx.Response(200, json={"code": 0}), url=url)
        res = await c.deliver(_events(1)[0])
        assert not res.ok and res.retryable is False and "unsafe" in res.detail
        assert rec.requests == []


async def test_splunk_tls_verify_toggle_only_for_private():
    c, rec = _hec(lambda r: httpx.Response(200, json={"code": 0}), tls_verify=False)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable and "allow_private" in res.detail
    assert rec.requests == []

    insecure = Recorder(lambda r: httpx.Response(200, json={"text": "Success", "code": 0}))
    c, rec = _hec(lambda r: httpx.Response(500), tls_verify=False,
                  url="https://lan-splunk.example.com:8088", allow_private=True)
    c._insecure_client_factory = insecure.client
    res = await c.deliver(_events(1)[0])
    assert res.ok and len(insecure.requests) == 1 and rec.requests == []
    await c.aclose()


async def test_splunk_test_sends_integration_test_event():
    c, rec = _hec(lambda r: httpx.Response(200, json={"text": "Success", "code": 0}))
    h = await c.test()
    assert h.ok
    [env] = _split_hec(rec.requests[0].content)
    assert env["fields"]["paddock_event_type"] == "integration.test"
    c, _ = _hec(lambda r: httpx.Response(403, json={"text": "Invalid token", "code": 4}))
    h = await c.test()
    assert not h.ok and "Invalid token" in h.detail and SECRET not in h.detail


# --------------------------------------------------------------------------- #
# Microsoft Sentinel (Logs Ingestion API)
# --------------------------------------------------------------------------- #

DCR = "dcr-" + "a" * 32
SENT_CFG = {"dce_endpoint": "https://dce.example.com", "dcr_immutable_id": DCR,
            "stream_name": "Custom-PaddockOCSF_CL", "tenant_id": "tenant-1", "client_id": "app-1"}


def _sentinel(ingest, token=None):
    calls = {"token": 0}

    def handler(r: httpx.Request):
        if r.url.host == "login.microsoftonline.com":
            calls["token"] += 1
            if token:
                return token(r)
            return httpx.Response(200, json={"access_token": f"tok-{calls['token']}",
                                             "expires_in": 3599, "token_type": "Bearer"})
        return ingest(r)

    rec = Recorder(handler)
    return SentinelConnector(SENT_CFG, {"client_secret": SECRET}, rec.client()), rec, calls


async def test_sentinel_token_then_ingest_and_cache():
    c, rec, calls = _sentinel(lambda r: httpx.Response(204))
    evs = _events(3)
    res = await c.deliver_batch(evs)
    assert res.ok, res.detail
    tok_req, ing = rec.requests
    assert tok_req.url.path == "/tenant-1/oauth2/v2.0/token"
    form = parse_qs(tok_req.content.decode())
    assert form["grant_type"] == ["client_credentials"] and form["client_id"] == ["app-1"]
    assert form["scope"] == ["https://monitor.azure.com//.default"]
    assert ing.url.path == f"/dataCollectionRules/{DCR}/streams/Custom-PaddockOCSF_CL"
    assert parse_qs(urlsplit(str(ing.url)).query)["api-version"] == ["2023-01-01"]
    assert ing.headers["authorization"] == "Bearer tok-1"
    rows = json.loads(ing.content)
    assert isinstance(rows, list) and len(rows) == 3
    assert rows[0]["TimeGenerated"].endswith("Z") and rows[0]["EventId"] == evs[0].id
    assert rows[0]["class_uid"] == 2004
    # cached token: a second delivery does not hit Entra again
    assert (await c.deliver(_events(1)[0])).ok
    assert calls["token"] == 1


async def test_sentinel_refreshes_token_once_on_401():
    seen = []

    def ingest(r):
        seen.append(r.headers["authorization"])
        return httpx.Response(401) if len(seen) == 1 else httpx.Response(204)

    c, _, calls = _sentinel(ingest)
    res = await c.deliver(_events(1)[0])
    assert res.ok and calls["token"] == 2 and seen == ["Bearer tok-1", "Bearer tok-2"]


async def test_sentinel_bad_client_secret_is_not_retryable_and_not_leaked():
    c, _, _ = _sentinel(lambda r: httpx.Response(204),
                        token=lambda r: httpx.Response(401, json={"error": "invalid_client",
                                                                  "error_description": f"bad {SECRET}"}))
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable and "invalid_client" in res.detail
    _no_secret(res)


@pytest.mark.parametrize("status,retryable,needle", [
    (429, True, "rate limited"), (503, True, "503"), (403, False, "Monitoring Metrics Publisher"),
    (404, False, "not found"), (413, False, "too large"), (400, False, "400"),
])
async def test_sentinel_ingest_errors(status, retryable, needle):
    c, _, _ = _sentinel(lambda r: httpx.Response(status, json={"error": {"code": "x"}}))
    res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable is retryable and needle in res.detail


async def test_sentinel_splits_bodies_at_1mb():
    bodies = []

    def ingest(r):
        bodies.append(len(r.content))
        return httpx.Response(204)

    c, _, _ = _sentinel(ingest)
    big = [Event(type="change.detected", title="x" * 10, summary="y" * 300_000) for _ in range(7)]
    res = await c.deliver_batch(big)
    assert res.ok and len(bodies) >= 3 and max(bodies) <= sentinel_mod.MAX_BODY_BYTES
    assert "7 record" in res.detail


async def test_sentinel_missing_config_and_unsafe_dce():
    c = SentinelConnector({**SENT_CFG, "dce_endpoint": ""}, {"client_secret": SECRET}, None)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable
    c, rec, _ = _sentinel(lambda r: httpx.Response(204))
    c.config["dce_endpoint"] = "https://metadata.example.com"
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable and rec.requests == []


# --------------------------------------------------------------------------- #
# Elastic _bulk
# --------------------------------------------------------------------------- #

def _elastic(handler, **cfg):
    rec = Recorder(handler)
    return ElasticConnector({"url": "https://es.example.com:9243", **cfg}, {"api_key": SECRET},
                            rec.client()), rec


async def test_elastic_bulk_ndjson_create_with_ids():
    c, rec = _elastic(lambda r: httpx.Response(200, json={"errors": False, "items": []}))
    evs = _events(2)
    res = await c.deliver_batch(evs)
    assert res.ok
    [req] = rec.requests
    assert req.url.path == "/_bulk" and req.headers["authorization"] == f"ApiKey {SECRET}"
    assert req.headers["content-type"] == "application/x-ndjson"
    lines = req.content.decode().splitlines()
    assert len(lines) == 4 and req.content.endswith(b"\n")
    action, doc = json.loads(lines[0]), json.loads(lines[1])
    assert action == {"create": {"_index": "logs-paddock.ocsf-default", "_id": evs[0].id}}
    assert doc["@timestamp"].endswith("Z") and doc["class_uid"] == 2004
    assert doc["event"]["id"] == evs[0].id


async def test_elastic_pipeline_and_custom_stream():
    c, rec = _elastic(lambda r: httpx.Response(200, json={"errors": False}),
                      data_stream="logs-sec-prod", pipeline="ocsf pipe")
    assert (await c.deliver(_events(1)[0])).ok
    assert rec.requests[0].url.params["pipeline"] == "ocsf pipe"
    assert '"_index":"logs-sec-prod"' in rec.requests[0].content.decode()


def _bulk_items(*statuses):
    items = []
    for st in statuses:
        r = {"status": st}
        if st >= 300:
            r["error"] = {"type": {409: "version_conflict_engine_exception", 429: "es_rejected_execution_exception",
                                   400: "mapper_parsing_exception"}.get(st, "x")}
        items.append({"create": r})
    return {"errors": True, "items": items}


@pytest.mark.parametrize("statuses,ok,retryable", [
    ((201, 409), True, None),          # duplicate = already delivered = success
    ((201, 429), False, True),
    ((201, 503), False, True),
    ((201, 400), False, False),
    ((429, 400), False, False),        # any permanent failure -> don't loop forever
])
async def test_elastic_item_level_classification(statuses, ok, retryable):
    c, _ = _elastic(lambda r: httpx.Response(200, json=_bulk_items(*statuses)))
    res = await c.deliver_batch(_events(len(statuses)))
    assert res.ok is ok
    if not ok:
        assert res.retryable is retryable


@pytest.mark.parametrize("status,retryable", [(401, False), (403, False), (502, True), (429, True)])
async def test_elastic_http_errors(status, retryable):
    c, _ = _elastic(lambda r: httpx.Response(status, text=f"nope {SECRET}"))
    res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable is retryable
    _no_secret(res)


async def test_elastic_test_button():
    c, rec = _elastic(lambda r: httpx.Response(200, json={"errors": False}))
    assert (await c.test()).ok
    assert '"action":"integration.test"' in rec.requests[0].content.decode()


# --------------------------------------------------------------------------- #
# Syslog
# --------------------------------------------------------------------------- #

RFC5424 = re.compile(
    rb"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) "
    rb"(?P<sd>\[.*?[^\\]\]) (?P<msg>.*)$", re.S)


def _parse_octet_frames(data: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(data):
        sp = data.index(b" ", i)
        n = int(data[i:sp])
        out.append(data[sp + 1: sp + 1 + n])
        i = sp + 1 + n
    return out


class _Listener:
    def __init__(self):
        self.data = bytearray()
        self.done = asyncio.Event()

    async def handle(self, reader, writer):
        try:
            while chunk := await reader.read(65536):
                self.data.extend(chunk)
        finally:
            writer.close()
            self.done.set()


async def _serve(ssl_ctx=None):
    lst = _Listener()
    server = await asyncio.start_server(lst.handle, "127.0.0.1", 0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port, lst


def _make_pki(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Paddock Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_p = tmp_path / "leaf.pem"
    key_p = tmp_path / "leaf.key"
    cert_p.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert_p, key_p)
    return server_ctx, ca.public_bytes(serialization.Encoding.PEM).decode()


async def _wait(lst):
    await asyncio.wait_for(lst.done.wait(), timeout=5)


async def test_syslog_tcp_private_ocsf_json_octet_counted():
    server, port, lst = await _serve()
    async with server:
        c = SyslogConnector({"host": "127.0.0.1", "port": port, "transport": "tcp",
                             "allow_private": True, "hostname": "paddock-test"}, {}, None)
        evs = _events(3)
        res = await c.deliver_batch(evs)
        assert res.ok, res.detail
        await _wait(lst)
    frames = _parse_octet_frames(bytes(lst.data))
    assert len(frames) == 3
    m = RFC5424.match(frames[0])
    assert m, frames[0][:200]
    assert int(m["pri"]) == 13 * 8 + 3            # facility 13, severity err (high)
    assert m["host"] == b"paddock-test" and m["app"] == b"paddock" and m["msgid"] == b"finding.opened"
    assert dt.datetime.fromisoformat(m["ts"].decode().replace("Z", "+00:00"))
    assert f'eventId="{evs[0].id}"'.encode() in m["sd"] and m["sd"].startswith(b"[paddock@32473 ")
    body = json.loads(m["msg"])
    assert body["class_uid"] == 2004 and body["metadata"]["uid"] == evs[0].id


async def test_syslog_tls_cef_with_verified_cert(tmp_path):
    server_ctx, ca_pem = _make_pki(tmp_path)
    server, port, lst = await _serve(server_ctx)
    async with server:
        c = SyslogConnector({"host": "127.0.0.1", "port": port, "format": "cef", "ca_cert": ca_pem,
                             "allow_private": True}, {}, None)
        ev = Event(type="finding.opened", title="SQL injection | in = login", severity="critical",
                   data={"finding": {"id": "f-9", "rule_id": "sast:python.sqli", "rule_source": "sast",
                                     "severity": "critical", "title": "SQL injection | in = login",
                                     "description": "line1\nline2 a=b", "status": "open",
                                     "cvss": 9.1, "asset_value": "10.0.0.5", "asset_kind": "ipv4",
                                     "evidence": {"cwe": "CWE-89", "file": "app.py", "start_line": 3}}})
        res = await c.deliver(ev)
        assert res.ok, res.detail
        await _wait(lst)
    [frame] = _parse_octet_frames(bytes(lst.data))
    m = RFC5424.match(frame)
    assert int(m["pri"]) == 13 * 8 + 2
    cef = m["msg"].decode()
    assert cef.startswith("CEF:0|Paddock|Paddock|0.1.0|sast:python.sqli|SQL injection \\| in = login|10|")
    ext = cef.split("|", 7)[7]
    assert "externalId=f-9" in ext and "cs4Label=cwe cs4=CWE-89" in ext and "dst=10.0.0.5" in ext
    assert "msg=line1\\nline2 a\\=b" in ext and "cn1=9.1" in ext and "cs5=sast" in ext


async def test_syslog_tls_untrusted_cert_is_permanent_failure(tmp_path):
    server_ctx, _ = _make_pki(tmp_path)
    server, port, _lst = await _serve(server_ctx)
    async with server:
        c = SyslogConnector({"host": "127.0.0.1", "port": port, "allow_private": True}, {}, None)
        res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable is False and "certificate" in res.detail


async def test_syslog_plaintext_never_to_public_hosts():
    for transport in ("tcp", "udp"):
        for allow in (False, True):
            c = SyslogConnector({"host": "syslog.example.com", "port": 514, "transport": transport,
                                 "allow_private": allow}, {}, None)
            res = await c.deliver(_events(1)[0])
            assert not res.ok and res.retryable is False
            assert "plaintext" in res.detail


async def test_syslog_private_target_requires_opt_in_and_metadata_always_refused():
    c = SyslogConnector({"host": "127.0.0.1", "port": 6514}, {}, None)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable and "private" in res.detail
    c = SyslogConnector({"host": "metadata.example.com", "allow_private": True}, {}, None)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and not res.retryable and "protected" in res.detail


async def test_syslog_tls_verify_off_only_with_allow_private():
    from app.integrations.connectors.syslog import _Refused

    with pytest.raises(_Refused):
        SyslogConnector({"host": "x", "tls_verify": False}, {}, None).ssl_context()
    ctx = SyslogConnector({"host": "x", "tls_verify": False, "allow_private": True}, {}, None).ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    strict = SyslogConnector({"host": "x"}, {}, None).ssl_context()
    assert strict.verify_mode == ssl.CERT_REQUIRED and strict.check_hostname
    assert strict.minimum_version >= ssl.TLSVersion.TLSv1_2


async def test_syslog_udp_datagram():
    loop = asyncio.get_running_loop()
    got: asyncio.Queue = asyncio.Queue()

    class P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            got.put_nowait(data)

    transport, _ = await loop.create_datagram_endpoint(P, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        c = SyslogConnector({"host": "127.0.0.1", "port": port, "transport": "udp",
                             "allow_private": True, "format": "cef"}, {}, None)
        res = await c.deliver_batch(_events(2))
        assert res.ok and "UDP" in res.detail
        d1 = await asyncio.wait_for(got.get(), 5)
        await asyncio.wait_for(got.get(), 5)
    finally:
        transport.close()
    m = RFC5424.match(d1)
    assert m and m["msg"].startswith(b"CEF:0|Paddock|")


async def test_syslog_connection_refused_is_retryable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = SyslogConnector({"host": "127.0.0.1", "port": port, "transport": "tcp",
                         "allow_private": True}, {}, None)
    res = await c.deliver(_events(1)[0])
    assert not res.ok and res.retryable is True


async def test_syslog_test_button_over_tcp():
    server, port, lst = await _serve()
    async with server:
        c = SyslogConnector({"host": "127.0.0.1", "port": port, "transport": "tcp",
                             "allow_private": True}, {}, None)
        h = await c.test()
        assert h.ok
        await _wait(lst)
    assert b"integration.test" in bytes(lst.data)


def test_cef_escaping_rules():
    assert cef_header_escape("a|b\\c\nd") == "a\\|b\\\\c d"
    assert cef_ext_escape("k=v\\x\r\ny") == "k\\=v\\\\x\\ny"
    rec = ocsf.event_to_ocsf(Event(type="scan.completed", title="done", severity="info"))
    line = to_cef(rec, Event(type="scan.completed", title="done"))
    assert line.count("|") >= 7 and line.split("|")[6] == "1"
