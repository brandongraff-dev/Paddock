from __future__ import annotations

import importlib.util
import io
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import paddock_sentry
from paddock_sentry import EgressForbidden, install_egress_guard, uninstall_egress_guard
from paddock_sentry.aggregate import OT_PORTS, Aggregator, orient
from paddock_sentry.cli import main, pump
from paddock_sentry.ship import Shipper
from paddock_sentry.sources import bpf_excluding_server, from_file
from paddock_sentry.wire import iter_stream

from .pcapgen import pcap, tcp, udp

HERE = Path(__file__).parent
FIXTURE = HERE / "fixtures" / "sample_capture.pcap"
ROOT = HERE.parents[1]


# --------------------------------------------------------------------------- #
# wire parity with the central parser
# --------------------------------------------------------------------------- #

def _central_parser():
    spec = importlib.util.spec_from_file_location("central_pcap", ROOT / "otdiscovery" / "app" / "pcap.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_stream_parser_matches_central_parser_exactly():
    central = _central_parser().parse(FIXTURE.read_bytes())
    ours = [{k: v for k, v in o.items() if k != "tcp_flags"} for _, _, o in from_file(FIXTURE)]
    assert ours == central and len(ours) == 9


def test_ot_ports_cover_central_identifiers():
    src = (ROOT / "otdiscovery" / "app" / "fingerprint" / "otproto.py").read_text()
    import re
    central_ports = {int(p) for p in re.findall(r"^\s+(\d+): ProtoSpec", src, re.M)}
    assert central_ports <= OT_PORTS


def test_stream_handles_truncated_tail_and_rejects_garbage():
    data = pcap([(1.0, tcp("10.0.0.1", "10.0.0.2", 40000, 80, flags=0x02))])
    assert len(list(iter_stream(io.BytesIO(data[:-5])))) == 0
    assert len(list(iter_stream(io.BytesIO(data)))) == 1
    with pytest.raises(ValueError):
        list(iter_stream(io.BytesIO(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)))


# --------------------------------------------------------------------------- #
# aggregation
# --------------------------------------------------------------------------- #

def test_orientation_prefers_syn_then_well_known_ports():
    assert orient({"src_port": 51000, "dst_port": 443, "tcp_flags": 0x02}) == (True, 443)
    assert orient({"src_port": 443, "dst_port": 51000, "tcp_flags": 0x12}) == (False, 443)
    assert orient({"src_port": 502, "dst_port": 51000}) == (False, 502)
    assert orient({"src_port": 51000, "dst_port": 8080}) == (True, 8080)


def test_flows_aggregate_both_directions_and_carry_no_payload():
    frames = [
        (1.0, tcp("10.0.0.5", "10.0.0.9", 50000, 443, flags=0x02)),
        (1.1, tcp("10.0.0.9", "10.0.0.5", 443, 50000, flags=0x12)),
        (1.2, tcp("10.0.0.5", "10.0.0.9", 50000, 443, payload=b"secret-http-body")),
    ]
    batches: list = []
    pump(iter_stream(io.BytesIO(pcap(frames))), Aggregator(), batches.append)
    flows = [o for o in batches[0]["observations"] if o["kind"] == "flow"]
    assert len(flows) == 1
    f = flows[0]
    assert (f["src_ip"], f["dst_ip"], f["dst_port"], f["packets"], f["tcp_syn"]) == ("10.0.0.5", "10.0.0.9", 443, 3, True)
    assert "payload_hex" not in json.dumps(batches)  # privacy: no payload for non-OT


def test_ot_flows_keep_a_few_payload_samples_for_identification():
    mbap = bytes.fromhex("000100000006010300000001")
    handshake = [(0.1, tcp("10.0.0.5", "10.0.0.20", 50001, 502, flags=0x02)),
                 (0.2, tcp("10.0.0.20", "10.0.0.5", 502, 50001, flags=0x12)),
                 (0.3, tcp("10.0.0.5", "10.0.0.20", 50001, 502, flags=0x10))]
    frames = handshake + [(1.0 + i / 10, tcp("10.0.0.5", "10.0.0.20", 50001, 502, payload=mbap)) for i in range(10)]
    batches: list = []
    pump(iter_stream(io.BytesIO(pcap(frames))), Aggregator(), batches.append)
    samples = [o for o in batches[0]["observations"] if o["kind"] == "packet"]
    assert len(samples) == 3 and samples[0]["payload_hex"].startswith("0001")


def test_windows_split_batches_and_announcements_dedupe():
    ssdp = b"NOTIFY * HTTP/1.1\r\nSERVER: Linux UPnP/1.0 Axis/9.80\r\nNT: upnp:rootdevice\r\n\r\n"
    frames = [(t, udp("10.0.0.61", "239.255.255.250", 1900, 1900, ssdp)) for t in (1, 2, 3, 40, 41)]
    batches: list = []
    pump(iter_stream(io.BytesIO(pcap(frames))), Aggregator(window_s=30), batches.append)
    assert len(batches) == 2
    assert [b["window"]["announcements"] for b in batches] == [1, 1]


def test_flow_table_is_bounded():
    frames = [(1.0, tcp("10.0.0.5", f"10.0.1.{i}", 50000, 80, flags=0x02)) for i in range(1, 60)]
    batches: list = []
    pump(iter_stream(io.BytesIO(pcap(frames))), Aggregator(max_flows=10), batches.append)
    assert batches[0]["window"]["flows"] == 10 and batches[0]["window"]["dropped_flows"] == 49


# --------------------------------------------------------------------------- #
# shipping + safety
# --------------------------------------------------------------------------- #

class _Server:
    def __init__(self, status: int = 200):
        self.status, self.posts = status, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.posts.append((self.path, self.headers.get("Authorization"), json.loads(body)))
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.close()


def test_shipper_posts_with_token_and_sensor_envelope(server):
    sh = Shipper(server.url, "tok-123", sensor_id="lobby-1", site="store-42", sleep=lambda s: None)
    assert sh.send({"observations": [{"kind": "flow"}], "window": {"packets": 1}})
    path, auth, body = server.posts[0]
    assert path == "/ingest" and auth == "Bearer tok-123"
    assert body["sensor"]["id"] == "lobby-1" and body["sensor"]["site"] == "store-42"


def test_outage_spools_to_disk_then_drains_in_order(tmp_path, server):
    sh = Shipper("http://127.0.0.1:9", "t", sensor_id="s", outbox=tmp_path, retries=1, timeout=0.5,
                 sleep=lambda s: None)
    assert not sh.send({"observations": [{"n": 1}]})
    assert not sh.send({"observations": [{"n": 2}]})
    assert len(list(tmp_path.glob("*.json.gz"))) == 2
    sh.url = server.url + "/ingest"  # network is back
    assert sh.send({"observations": [{"n": 3}]})
    assert [p[2]["observations"][0]["n"] for p in server.posts] == [3, 1, 2]
    assert list(tmp_path.glob("*.json.gz")) == []


def test_auth_rejection_is_not_spooled(tmp_path):
    s = _Server(status=401)
    try:
        sh = Shipper(s.url, "bad", sensor_id="s", outbox=tmp_path, sleep=lambda x: None)
        assert not sh.send({"observations": []})
        assert list(tmp_path.glob("*")) == [] and len(s.posts) == 1
    finally:
        s.close()


def test_outbox_is_bounded(tmp_path):
    sh = Shipper("http://127.0.0.1:9", None, sensor_id="s", outbox=tmp_path, retries=1, timeout=0.2,
                 outbox_max_bytes=600, sleep=lambda s: None)
    for i in range(20):
        sh.send({"observations": [{"pad": "x" * 200, "i": i}]})
    assert sum(p.stat().st_size for p in tmp_path.glob("*.json.gz")) <= 600
    assert sh.stats["dropped"] > 0


def test_egress_guard_allows_only_the_server(server):
    install_egress_guard(server.url)
    try:
        sh = Shipper(server.url, None, sensor_id="s", sleep=lambda s: None)
        batches: list = []
        pump(from_file(FIXTURE), Aggregator(), batches.append)
        for b in batches:
            assert sh.send(b)
        observed = {o.get("dst_ip") for b in batches for o in b["observations"]} - {None}
        for ip in sorted(observed)[:3]:
            with pytest.raises(EgressForbidden):
                socket.create_connection((ip, 502), timeout=0.2)
        assert set(paddock_sentry.violations) <= observed
    finally:
        uninstall_egress_guard()
        paddock_sentry.violations.clear()


def test_bpf_excludes_own_server_traffic():
    assert bpf_excluding_server("https://10.1.2.3:8101") == "not (host 10.1.2.3 and tcp port 8101)"
    assert "not port 22" in bpf_excluding_server("http://10.1.2.3", "not port 22")


def test_cli_dry_run_replays_fixture(capsys):
    assert main(["run", "--pcap", str(FIXTURE), "--dry-run"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    kinds = {o["kind"] for line in lines for o in line["observations"]}
    assert {"flow", "dhcp"} <= kinds
