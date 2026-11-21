"""Enrollment CLI, credential file, upload buffer, idempotent replay, backoff,
heartbeat and mirror-port detection, all against a fake Paddock server."""
from __future__ import annotations

import gzip
import json
import os
import stat
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import paddock_sentry
from paddock_sentry import EgressForbidden, install_egress_guard, netif, store, uninstall_egress_guard
from paddock_sentry.buffer import Outbox
from paddock_sentry.cli import main
from paddock_sentry.enroll import EnrollError, enroll, normalize_server
from paddock_sentry.health import Heartbeat, RunStats
from paddock_sentry.ship import Shipper

GOOD_TOKEN = "pet_0a1b2c3d_" + "T" * 32
CRED = "pst_11223344_" + "C" * 32


class FakePaddock:
    """Just enough of otdiscovery's sensor surface + the orchestrator's rules."""

    def __init__(self) -> None:
        self.tokens = {GOOD_TOKEN: "unused"}
        self.revoked = False
        self.applied: dict[str, dict] = {}      # batch_id -> payload (what got "ingested")
        self.ingest_calls = 0
        self.heartbeats: list[dict] = []
        self.fail_ingest = 0                    # answer 503 N times
        self.lose_reply_once = False            # process, then drop the connection
        self.encodings: list[str | None] = []
        self.requests: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def _json(self, code, obj=None):
                data = json.dumps(obj or {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.encodings.append(self.headers.get("Content-Encoding"))
                if self.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return json.loads(raw or b"{}")

            def _authed(self):
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {CRED}":
                    self._json(401, {"detail": "invalid sensor credential"})
                    return False
                if outer.revoked:
                    self._json(403, {"detail": "sensor revoked"})
                    return False
                return True

            def do_GET(self):  # noqa: N802
                self._json(200, {"status": "ok"})

            def do_POST(self):  # noqa: N802
                body = self._body()
                outer.requests.append(self.path)
                if self.path == "/enroll":
                    if outer.tokens.get(body.get("token")) != "unused":
                        return self._json(401, {"detail": "invalid, expired or already-used enrollment token"})
                    outer.tokens[body["token"]] = "used"
                    outer.enroll_body = body
                    return self._json(201, {"sensor_id": str(uuid.uuid4()), "name": body.get("name") or body["hostname"],
                                            "site": "store-42", "credential": CRED})
                if not self._authed():
                    return None
                if self.path == "/heartbeat":
                    outer.heartbeats.append(body)
                    return self._json(200, {"ok": True, "server_time": __import__("time").time()})
                if self.path == "/ingest":
                    outer.ingest_calls += 1
                    if outer.fail_ingest > 0:
                        outer.fail_ingest -= 1
                        return self._json(503, {"detail": "down"})
                    bid = body["batch_id"]
                    if bid not in outer.applied:        # the server applies a batch id once
                        outer.applied[bid] = body
                    if outer.lose_reply_once:
                        outer.lose_reply_once = False
                        self.connection.close()
                        return None
                    return self._json(200, {"duplicate": False})
                return self._json(404)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def paddock():
    s = FakePaddock()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _no_guard():
    yield
    uninstall_egress_guard()
    paddock_sentry.violations.clear()


def _batch(i: int, pad: int = 0) -> dict:
    return {"observations": [{"kind": "flow", "n": i, "pad": "x" * pad}], "window": {"packets": 1}}


# --------------------------------------------------------------------------- #
# enroll
# --------------------------------------------------------------------------- #

def test_enroll_cli_exchanges_token_and_stores_a_0600_credential(paddock, tmp_path, capsys):
    cred = tmp_path / "sub" / "credentials.json"
    rc = main(["enroll", paddock.url, GOOD_TOKEN, "--cred", str(cred), "--name", "lobby-pi"])
    out = capsys.readouterr()
    assert rc == 0 and "lobby-pi" in out.out and CRED not in out.out + out.err
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
    saved = json.loads(cred.read_text())
    assert saved["credential"] == CRED and saved["site"] == "store-42" and saved["server"] == paddock.url
    assert paddock.enroll_body["interfaces"] is not None and paddock.enroll_body["version"]
    assert paddock.requests == ["/enroll"]


def test_enroll_token_can_come_from_the_environment(paddock, tmp_path, monkeypatch):
    monkeypatch.setenv("PADDOCK_SERVER", paddock.url)
    monkeypatch.setenv("PADDOCK_ENROLL_TOKEN", GOOD_TOKEN)
    assert main(["enroll", "--cred", str(tmp_path / "c.json")]) == 0


def test_enroll_with_a_used_or_wrong_token_explains_and_writes_nothing(paddock, tmp_path, capsys):
    cred = tmp_path / "c.json"
    assert main(["enroll", paddock.url, "pet_deadbeef_" + "x" * 30, "--cred", str(cred)]) == 1
    err = capsys.readouterr().err
    assert "single-use" in err and "Sensors > Add sensor" in err
    assert not cred.exists()
    assert main(["enroll", paddock.url, GOOD_TOKEN, "--cred", str(cred)]) == 0
    cred.unlink()
    assert main(["enroll", paddock.url, GOOD_TOKEN, "--cred", str(cred)]) == 1  # already used
    assert not cred.exists()


def test_enroll_refuses_to_overwrite_without_force(paddock, tmp_path, capsys):
    cred = tmp_path / "c.json"
    assert main(["enroll", paddock.url, GOOD_TOKEN, "--cred", str(cred)]) == 0
    paddock.tokens["pet_aaaaaaaa_" + "y" * 30] = "unused"
    assert main(["enroll", paddock.url, "pet_aaaaaaaa_" + "y" * 30, "--cred", str(cred)]) == 1
    assert "already enrolled" in capsys.readouterr().err
    assert main(["enroll", paddock.url, "pet_aaaaaaaa_" + "y" * 30, "--cred", str(cred), "--force"]) == 0


def test_enroll_unreachable_server_is_a_readable_error(tmp_path, capsys):
    assert main(["enroll", "http://127.0.0.1:9", GOOD_TOKEN, "--cred", str(tmp_path / "c.json")]) == 1
    assert "could not reach" in capsys.readouterr().err


def test_plain_http_to_a_remote_server_is_refused():
    with pytest.raises(EnrollError, match="plain http"):
        normalize_server("http://paddock.example.com:8101")
    assert normalize_server("http://paddock.example.com:8101", allow_http=True).startswith("http://")
    assert normalize_server("paddock.example.com:8101") == "https://paddock.example.com:8101"
    assert normalize_server("http://127.0.0.1:8101")  # loopback is fine
    with pytest.raises(EnrollError):
        normalize_server("ftp://x")


def test_enroll_only_connects_to_the_named_server(paddock, tmp_path):
    install_egress_guard(paddock.url)
    enroll(paddock.url, GOOD_TOKEN, cred_path=str(tmp_path / "c.json"))
    import socket
    with pytest.raises(EgressForbidden):
        socket.create_connection(("203.0.113.9", 443), timeout=0.2)


def test_credential_file_must_not_be_group_or_world_readable(tmp_path):
    p = tmp_path / "c.json"
    store.save(p, store.Credentials("http://s", "id", CRED, "n", "site"))
    assert store.load(p).credential == CRED
    os.chmod(p, 0o644)
    with pytest.raises(store.CredentialError, match="chmod 600"):
        store.load(p)
    os.chmod(p, 0o600)
    p.write_text("{not json")
    with pytest.raises(store.CredentialError):
        store.load(p)
    assert store.load(tmp_path / "missing.json") is None


def test_save_never_exposes_the_secret_with_loose_permissions(tmp_path):
    p = tmp_path / "c.json"
    seen: list[int] = []
    real = os.replace

    def spy(src, dst):
        seen.append(stat.S_IMODE(os.stat(src).st_mode))
        return real(src, dst)

    os.replace = spy
    try:
        store.save(p, store.Credentials("http://s", "id", CRED))
    finally:
        os.replace = real
    assert seen == [0o600]


# --------------------------------------------------------------------------- #
# buffer
# --------------------------------------------------------------------------- #

def test_buffer_cap_drops_oldest_first_and_keeps_the_newest(tmp_path):
    box = Outbox(tmp_path, max_bytes=2500)
    for i in range(40):
        box.put({"i": i, "blob": os.urandom(120).hex()})
    files = box.files()
    assert box.size() <= 2500 and box.dropped > 0 and len(files) + box.dropped == 40
    kept = [box.read(f)["i"] for f in files]
    assert kept == sorted(kept) and kept[-1] == 39  # newest survive, order preserved
    assert box.fill_pct() <= 100


def test_buffer_survives_a_restart_and_ignores_crash_leftovers(tmp_path):
    box = Outbox(tmp_path)
    box.put({"i": 1})
    (tmp_path / "00000000000000000001.tmp").write_bytes(b"half written")
    (tmp_path / "00000000000000000002.json.gz").write_bytes(b"not gzip")
    again = Outbox(tmp_path)
    assert not list(tmp_path.glob("*.tmp"))
    payloads = [again.read(f) for f in again.files()]
    assert {"i": 1} in payloads and None in payloads
    assert len(again) == 1  # the corrupt one was discarded on read


def test_oversized_single_batch_does_not_wedge_the_buffer(tmp_path):
    box = Outbox(tmp_path, max_bytes=300)
    box.put({"blob": os.urandom(2000).hex()})
    assert box.size() <= 300 and len(box) == 0 and box.dropped == 1


# --------------------------------------------------------------------------- #
# shipping: compression, idempotency, backoff
# --------------------------------------------------------------------------- #

def test_payloads_are_compressed_and_carry_a_batch_id(paddock):
    sh = Shipper(paddock.url, CRED, sensor_id="s", sleep=lambda s: None)
    big = {"observations": [{"kind": "flow", "i": i, "proto": "tcp"} for i in range(500)]}
    assert sh.send(big)
    assert paddock.encodings[-1] == "gzip"
    (bid, body), = paddock.applied.items()
    assert len(bid) >= 8 and len(body["observations"]) == 500


def test_replay_after_a_lost_reply_does_not_double_count(paddock, tmp_path):
    now = [0.0]
    sh = Shipper(paddock.url, CRED, sensor_id="s", outbox=tmp_path, retries=1, timeout=1.0,
                 sleep=lambda s: None, clock=lambda: now[0])
    paddock.lose_reply_once = True            # server applies the batch, the sensor never hears back
    assert not sh.send(_batch(1))
    assert len(paddock.applied) == 1 and sh.pending == 1
    now[0] += 3600
    assert sh.drain() == 1                    # retry of the SAME batch id
    assert len(paddock.applied) == 1          # applied exactly once server-side
    assert paddock.ingest_calls == 2 and sh.pending == 0


def test_batch_id_is_stable_across_buffering(paddock, tmp_path):
    now = [0.0]
    sh = Shipper("http://127.0.0.1:9", CRED, sensor_id="s", outbox=tmp_path, retries=1, timeout=0.3,
                 sleep=lambda s: None, clock=lambda: now[0])
    sh.send(_batch(1))
    buffered = sh.box.read(sh.box.files()[0])["batch_id"]
    sh.url = paddock.url + "/ingest"
    now[0] += 3600
    sh.drain()
    assert list(paddock.applied) == [buffered]


def test_backoff_stops_hammering_then_resumes_and_drains_oldest_first(paddock, tmp_path):
    now = [0.0]
    sleeps: list[float] = []
    sh = Shipper(paddock.url, CRED, sensor_id="s", outbox=tmp_path, retries=2, timeout=1.0,
                 sleep=sleeps.append, clock=lambda: now[0])
    paddock.fail_ingest = 10**6
    assert not sh.send(_batch(1))
    calls = paddock.ingest_calls
    assert calls == 2 and sleeps                       # retried with a backoff sleep, then buffered
    for i in (2, 3, 4):                                # while backing off: buffer only, no network, no blocking
        assert not sh.send(_batch(i))
    assert paddock.ingest_calls == calls and sh.pending == 4
    assert sh.drain() == 0 and paddock.ingest_calls == calls   # drain respects the backoff too
    paddock.fail_ingest = 0
    now[0] += 3600                                      # server back, backoff elapsed
    assert sh.send(_batch(5))
    order = [b["observations"][0]["n"] for b in paddock.applied.values()]
    assert order == [5, 1, 2, 3, 4] and sh.pending == 0


def test_backoff_grows_and_is_capped():
    now = [0.0]
    sh = Shipper("http://127.0.0.1:9", None, sensor_id="s", retries=1, timeout=0.2, sleep=lambda s: None,
                 clock=lambda: now[0])
    delays = []
    for _ in range(12):
        now[0] = sh._retry_at + 1
        sh.send(_batch(0))
        delays.append(sh._retry_at - now[0])
    assert delays[2] > delays[0] and max(delays) <= 300 * 1.25 + 0.1


def test_poison_batch_is_dropped_not_retried_forever(paddock, tmp_path):
    sh = Shipper(paddock.url, CRED, sensor_id="s", outbox=tmp_path, sleep=lambda s: None)
    sh.box.put({"batch_id": "poison-0001", "observations": []})
    orig = paddock.httpd.RequestHandlerClass.do_POST

    def reject(self):
        self._body()
        self._json(413, {})

    paddock.httpd.RequestHandlerClass.do_POST = reject
    try:
        sh.drain()
    finally:
        paddock.httpd.RequestHandlerClass.do_POST = orig
    assert sh.pending == 0 and sh.stats["rejected"] == 1


def test_revoked_credential_is_reported_not_buffered(paddock, tmp_path):
    paddock.revoked = True
    sh = Shipper(paddock.url, CRED, sensor_id="s", outbox=tmp_path, sleep=lambda s: None)
    assert not sh.send(_batch(1))
    assert sh.auth_failed == 403 and sh.pending == 0


# --------------------------------------------------------------------------- #
# heartbeat
# --------------------------------------------------------------------------- #

def _fake_sysfs(root: Path, nics: dict[str, dict]) -> str:
    for name, spec in nics.items():
        d = root / name
        d.mkdir(parents=True)
        (d / "address").write_text(spec.get("mac", "aa:bb:cc:00:00:01") + "\n")
        (d / "operstate").write_text(("up" if spec.get("carrier", True) else "down") + "\n")
        (d / "carrier").write_text(("1" if spec.get("carrier", True) else "0") + "\n")
        if spec.get("physical", True):
            (d / "device").mkdir()
        if spec.get("wireless"):
            (d / "wireless").mkdir()
        st = d / "statistics"
        st.mkdir()
        (st / "rx_dropped").write_text(str(spec.get("rx_dropped", 0)) + "\n")
        (st / "rx_missed_errors").write_text("0\n")
        (st / "rx_fifo_errors").write_text("0\n")
    return str(root)


def test_heartbeat_reports_only_health_counters_and_drains_the_buffer(paddock, tmp_path):
    sysfs = _fake_sysfs(tmp_path / "net", {"eth1": {"rx_dropped": 100}})
    sh = Shipper(paddock.url, CRED, sensor_id="s", outbox=tmp_path / "box", retries=1, timeout=0.5,
                 sleep=lambda s: None)
    sh.box.put({"batch_id": "pending-0001", "observations": []})
    stats = RunStats()
    stats.add_window({"packets": 1200, "flows": 30, "dropped_flows": 4})
    hb = Heartbeat(paddock.url, CRED, sh, stats, iface="eth1", sysfs=sysfs)
    hb.snapshot()                                          # baseline NIC drops = 100
    (Path(sysfs) / "eth1" / "statistics" / "rx_dropped").write_text("107\n")
    assert hb.post()
    body = paddock.heartbeats[-1]
    h = body["health"]
    assert h["packets_seen"] == 1200 and h["flows_dropped"] == 4 and h["packets_dropped"] == 7
    assert h["buffer_batches"] in (0, 1) and "sent_at" in h and h["iface"] == "eth1"
    allowed = {"sent_at", "uptime_s", "packets_seen", "flows_dropped", "buffer_fill_pct", "buffer_bytes",
               "buffer_batches", "batches_dropped", "last_upload_ts", "last_upload_ok", "iface",
               "packets_dropped"}
    assert set(h) <= allowed                               # nothing beyond the documented counters
    assert set(body) == {"version", "interfaces", "health"}
    assert "pending-0001" in paddock.applied and sh.pending == 0  # the heartbeat caught the buffer up


def test_heartbeat_marks_a_revoked_credential(paddock):
    paddock.revoked = True
    sh = Shipper(paddock.url, CRED, sensor_id="s", sleep=lambda s: None)
    hb = Heartbeat(paddock.url, CRED, sh, RunStats())
    assert not hb.post() and sh.auth_failed == 403


def test_heartbeat_survives_an_unreachable_server():
    sh = Shipper("http://127.0.0.1:9", CRED, sensor_id="s")
    assert not Heartbeat("http://127.0.0.1:9", CRED, sh, RunStats(), timeout=0.3).post()


# --------------------------------------------------------------------------- #
# mirror-port detection
# --------------------------------------------------------------------------- #

def test_pick_interface_prefers_the_unnumbered_port_with_a_link(tmp_path):
    sysfs = _fake_sysfs(tmp_path, {
        "eth0": {}, "eth1": {}, "wlan0": {"wireless": True}, "lo": {"physical": False},
        "docker0": {"physical": False}})
    ips = {"eth0": "10.0.0.5"}
    iface, why = netif.pick_capture_interface(sysfs, ips.get)
    assert iface == "eth1" and "mirror" in why


def test_pick_interface_says_what_to_do_when_it_cannot_decide(tmp_path):
    single = _fake_sysfs(tmp_path / "a", {"eth0": {}})
    iface, why = netif.pick_capture_interface(single, {"eth0": "10.0.0.5"}.get)
    assert iface is None and "USB" in why
    both = _fake_sysfs(tmp_path / "b", {"eth1": {}, "eth2": {}})
    iface, why = netif.pick_capture_interface(both, lambda n: None)
    assert iface is None and "PADDOCK_SENTRY_IFACE" in why
    nolink = _fake_sysfs(tmp_path / "c", {"eth0": {}, "eth1": {"carrier": False}})
    iface, why = netif.pick_capture_interface(nolink, {"eth0": "10.0.0.5"}.get)
    assert iface == "eth1" and "no link yet" in why
    empty = tmp_path / "d"
    empty.mkdir()
    assert netif.pick_capture_interface(str(empty))[0] is None


def test_run_without_enrollment_explains(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("PADDOCK_SENTRY_CRED", str(tmp_path / "none.json"))
    monkeypatch.delenv("PADDOCK_SERVER", raising=False)
    assert main(["run", "--iface", "eth9"]) == 2
    assert "not enrolled" in capsys.readouterr().err
