"""HTTP client: stdlib transport, every transport error wrapped, https-only off loopback, no redirects."""
from __future__ import annotations

import gzip
import http.client
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.utils import formatdate

import pytest

from paddock_agent import envelope
from paddock_agent.client import FleetClient, FleetClientError, backoff_delay, normalize_server

AG = "11111111-1111-4111-8111-111111111111"
TN = "22222222-2222-4222-8222-222222222222"


class Server:
    """A scripted loopback HTTP server that records what it receives."""

    def __init__(self):
        self.requests = []
        self.script = []           # list of callables or (status, headers, body) tuples, consumed in order
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.requests.append({"method": self.command, "path": self.path,
                                       "headers": dict((k.lower(), v) for k, v in self.headers.items()),
                                       "body": body})
                step = outer.script.pop(0) if outer.script else (200, {}, {})
                if callable(step):
                    return step(self)
                status, headers, payload = step
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.close()


def _env(seq=3, payload=b"{}"):
    seed = bytes(range(32))
    return envelope.build_envelope(seed, agent_id=AG, tenant_id=TN, kind="posture", seq=seq,
                                   issued_at=1_790_000_000, payload=payload,
                                   payload_type=envelope.PAYLOAD_TYPE_POSTURE, collectors={"agent": "0.2.0"})


def test_enroll_sends_the_contract_body_with_no_agent_header(server):
    server.script.append((201, {}, {"agent_id": AG, "agent_token": "fat_x", "key_id": "k", "tenant_id": TN}))
    c = FleetClient(server.url)
    out = c.enroll(token="fet_0123456789ab_" + "s" * 30, hostname="web-01", public_key_b64="PUB",
                   proof_b64="PROOF", agent_version="0.2.0", capabilities=["posture"])
    assert out["agent_id"] == AG
    req = server.requests[0]
    assert (req["method"], req["path"]) == ("POST", "/v1/fleet/enroll")
    body = json.loads(req["body"])
    assert set(body) == {"token", "hostname", "public_key_b64", "proof_b64", "agent_version", "capabilities"}
    assert "x-agent-token" not in req["headers"] and "authorization" not in req["headers"]
    assert req["headers"]["user-agent"].startswith("paddock-agent/")


def test_heartbeat_posture_rotate_routes_headers_and_idempotency_key(server):
    c = FleetClient(server.url, agent_id=AG, agent_token="fat_secret")
    env = _env(seq=41)
    for method, route in (("heartbeat", "heartbeat"), ("post_posture", "posture"), ("rotate_key", "keys/rotate")):
        getattr(c, method)(env)
    paths = [r["path"] for r in server.requests]
    assert paths == ["/v1/fleet/%s/heartbeat" % AG, "/v1/fleet/%s/posture" % AG, "/v1/fleet/%s/keys/rotate" % AG]
    for r in server.requests:
        assert r["headers"]["x-agent-token"] == "fat_secret"
        assert r["headers"]["idempotency-key"] == "41"            # Idempotency-Key = seq
        assert "authorization" not in r["headers"]
        assert json.loads(r["body"]) == env


def test_large_envelopes_are_gzipped(server):
    c = FleetClient(server.url, agent_id=AG, agent_token="t")
    env = _env(payload=json.dumps({"x": "A" * 30000}).encode())
    c.post_posture(env)
    r = server.requests[0]
    assert r["headers"]["content-encoding"] == "gzip"
    assert json.loads(gzip.decompress(r["body"])) == env


def test_result_and_inventory_calls(server):
    c = FleetClient(server.url, agent_id=AG, agent_token="t")
    c.post_result("33333333-3333-4333-8333-333333333333", status="applied", output={"a": 1}, revert={"r": 1})
    c.post_inventory({"os_info": {}})
    assert server.requests[0]["path"] == "/v1/fleet/actions/33333333-3333-4333-8333-333333333333/result"
    assert json.loads(server.requests[0]["body"]) == {"status": "applied", "output": {"a": 1}, "revert": {"r": 1}}
    assert server.requests[1]["path"] == "/v1/fleet/%s/inventory" % AG


def test_ids_are_validated_before_they_reach_a_path():
    with pytest.raises(FleetClientError):
        FleetClient("https://x.example", agent_id="../../etc/passwd")
    c = FleetClient("https://x.example", agent_id=AG, agent_token="t")
    with pytest.raises(FleetClientError):
        c.post_result("../x", status="applied", output={})


def test_http_error_statuses_carry_status_and_body(server):
    server.script.extend([(409, {}, {"detail": "seq", "expected_min": 9}), (403, {}, {"error": "re_enroll_required"}),
                          (503, {"Retry-After": "7"}, {"detail": "busy"}), (429, {"Retry-After": "99999"}, {})])
    c = FleetClient(server.url, agent_id=AG, agent_token="t")
    with pytest.raises(FleetClientError) as e1:
        c.heartbeat(_env())
    assert e1.value.status == 409 and e1.value.body["expected_min"] == 9 and not e1.value.transient
    with pytest.raises(FleetClientError) as e2:
        c.heartbeat(_env())
    assert e2.value.auth_failure and e2.value.body_mentions("RE_ENROLL_required") and not e2.value.transient
    with pytest.raises(FleetClientError) as e3:
        c.heartbeat(_env())
    assert e3.value.transient and e3.value.retry_after == 7.0
    with pytest.raises(FleetClientError) as e4:
        c.heartbeat(_env())
    assert e4.value.transient and e4.value.retry_after == 300.0           # capped


def test_refused_connection_is_a_fleet_client_error_not_a_raw_oserror():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                                # nothing listens here now
    c = FleetClient("http://127.0.0.1:%d" % port, agent_id=AG, agent_token="t", timeout_s=2)
    with pytest.raises(FleetClientError) as e:
        c.heartbeat(_env())
    assert e.value.status is None and e.value.transient


def test_timeout_is_wrapped(server):
    server.script.append(lambda h: time.sleep(1.5))
    c = FleetClient(server.url, agent_id=AG, agent_token="t", timeout_s=0.3)
    with pytest.raises(FleetClientError) as e:
        c.heartbeat(_env())
    assert e.value.status is None


def test_connection_reset_mid_response_is_wrapped(server):
    def reset(h):
        h.connection.shutdown(socket.SHUT_RDWR)
        h.close_connection = True
    server.script.append(reset)
    c = FleetClient(server.url, agent_id=AG, agent_token="t", timeout_s=2)
    with pytest.raises(FleetClientError):
        c.heartbeat(_env())


def test_garbage_and_non_json_replies_are_wrapped(server):
    server.script.extend([lambda h: (h.wfile.write(b"HTTP/1.1 banana\r\n\r\n"), setattr(h, "close_connection", True)),
                          (200, {}, b"<html>not json</html>")])
    c = FleetClient(server.url, agent_id=AG, agent_token="t", timeout_s=2)
    with pytest.raises(FleetClientError):
        c.heartbeat(_env())
    with pytest.raises(FleetClientError, match="not JSON"):
        c.heartbeat(_env())


@pytest.mark.parametrize("exc", [OSError("boom"), socket.timeout("t"), ssl.SSLError("tls"), ValueError("v"),
                                 UnicodeError("u"), http.client.IncompleteRead(b"x"),
                                 http.client.RemoteDisconnected("r"), ConnectionResetError("c"),
                                 RuntimeError("anything"), KeyError("k"), MemoryError()])
def test_every_exception_type_from_the_transport_is_wrapped(exc):
    def transport(*a, **k):
        raise exc
    c = FleetClient("https://paddock.example", agent_id=AG, agent_token="t", transport=transport)
    with pytest.raises(FleetClientError) as e:
        c.heartbeat(_env())
    assert type(e.value) is FleetClientError and e.value.status is None


def test_redirects_are_never_followed(server):
    target = Server()
    try:
        server.script.append((302, {"Location": target.url + "/steal"}, {}))
        c = FleetClient(server.url, agent_id=AG, agent_token="fat_secret")
        with pytest.raises(FleetClientError) as e:
            c.heartbeat(_env())
        assert e.value.status == 302
        assert target.requests == []                    # the credential never left
    finally:
        target.close()


@pytest.mark.parametrize("url", ["http://paddock.example", "http://10.0.0.5:8080", "http://[2001:db8::1]",
                                 "ftp://paddock.example", "https://", "https://u:p@paddock.example",
                                 "https://paddock.example/?x=1", "https://paddock.example:99999"])
def test_unsafe_or_malformed_server_urls_are_refused(url):
    with pytest.raises(FleetClientError):
        FleetClient(url)


@pytest.mark.parametrize("url,expect", [("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
                                        ("http://localhost:8080", "http://localhost:8080"),
                                        ("http://[::1]:80", "http://[::1]:80"),
                                        ("paddock.example:8443", "https://paddock.example:8443"),
                                        ("https://paddock.example/", "https://paddock.example")])
def test_acceptable_server_urls(url, expect):
    assert normalize_server(url) == expect


def test_loopback_requests_ignore_proxy_environment(server, monkeypatch):
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(k, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    c = FleetClient(server.url, agent_id=AG, agent_token="t")
    c.heartbeat(_env())
    assert len(server.requests) == 1


def test_clock_skew_is_estimated_from_the_date_header(server):
    server.script.append((200, {"Date": formatdate(time.time() + 45, usegmt=True)}, {}))
    c = FleetClient(server.url, agent_id=AG, agent_token="t")
    assert c.clock_skew_ms is None
    c.heartbeat(_env())
    assert 43_000 <= c.clock_skew_ms <= 47_000          # one-second Date resolution, RTT-corrected


def test_missing_credentials_fail_closed_without_a_request(server):
    c = FleetClient(server.url)
    with pytest.raises(FleetClientError):
        c.heartbeat(_env())
    assert server.requests == []


# --------------------------------------------------------------------------- #
# backoff
# --------------------------------------------------------------------------- #

def test_backoff_is_jittered_exponential_and_capped_at_300():
    assert backoff_delay(1, base=5, rand=lambda: 1.0) == 5.0
    assert backoff_delay(1, base=5, rand=lambda: 0.0) == 2.5
    assert backoff_delay(3, base=5, rand=lambda: 1.0) == 20.0
    assert backoff_delay(7, base=5, rand=lambda: 1.0) == 300.0 and backoff_delay(500, base=5, rand=lambda: 1.0) == 300.0
    highs = [backoff_delay(n, base=5, rand=lambda: 1.0) for n in range(1, 40)]
    assert highs == sorted(highs) and max(highs) == 300.0
    import random
    rng = random.Random(1)
    samples = [backoff_delay(10, base=5, rand=rng.random) for _ in range(500)]
    assert max(samples) <= 300.0 and min(samples) >= 150.0 and len(set(samples)) > 100     # jitter, not constant
