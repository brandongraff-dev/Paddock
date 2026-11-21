"""Behaviour analytics + the Sentry -> otdiscovery contract, end to end."""
from __future__ import annotations

import dataclasses
import io
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from app import behavior
from app.config import Config
from app.fingerprint import fingerprint_devices
from app.main import OtDiscoveryService
from app.pipeline import DiscoveryEngine

SENTRY = Path(__file__).resolve().parents[2] / "sentry"
sys.path.insert(0, str(SENTRY))
from paddock_sentry.aggregate import Aggregator  # noqa: E402
from paddock_sentry.cli import pump  # noqa: E402
from paddock_sentry.wire import iter_stream  # noqa: E402

def _load_pcapgen():
    import importlib.util

    spec = importlib.util.spec_from_file_location("sentry_pcapgen", SENTRY / "tests" / "pcapgen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gen = _load_pcapgen()
pcap, tcp, udp = _gen.pcap, _gen.tcp, _gen.udp

CAM_MAC, CAM = "00:40:8c:00:00:61", "10.10.1.61"      # Axis camera (IoT)
PLC_MAC, PLC = "00:1b:1b:00:00:10", "10.10.5.10"      # Siemens PLC (OT)
WS_MAC = "00:50:56:00:00:01"                          # workstation
SSDP = (b"NOTIFY * HTTP/1.1\r\nSERVER: Linux/4.9 UPnP/1.0 Axis/9.80\r\n"
        b"NT: urn:schemas-onvif-org:device:NetworkVideoTransmitter:1\r\n\r\n")
MBAP = bytes.fromhex("000100000006010300000001")


def _site_traffic(t0: float = 1_000.0, *, scan: bool = True) -> bytes:
    f: list[tuple[float, bytes]] = []
    f.append((t0, udp(CAM, "239.255.255.250", 1900, 1900, SSDP, smac=CAM_MAC)))
    # workstation polls the PLC over Modbus (identifies the PLC as OT)
    f.append((t0 + 1, tcp("10.10.5.50", PLC, 50100, 502, payload=MBAP, smac=WS_MAC, dmac=PLC_MAC)))
    if scan:  # camera sweeps 20 hosts on telnet
        for i in range(20):
            f.append((t0 + 2 + i / 100, tcp(CAM, f"10.10.1.{100 + i}", 41000 + i, 23, flags=0x02, smac=CAM_MAC)))
    # an admin telnets INTO the camera
    f.append((t0 + 3, tcp("10.10.9.5", CAM, 52000, 23, flags=0x02, dmac=CAM_MAC)))
    # camera reaches the server VLAN over SMB
    f.append((t0 + 4, tcp(CAM, "10.10.2.50", 42000, 445, flags=0x02, smac=CAM_MAC)))
    # PLC phones home to the internet
    f.append((t0 + 5, tcp(PLC, "8.8.4.4", 49000, 443, flags=0x02, smac=PLC_MAC)))
    return pcap(f)


def _sensor_batches(data: bytes) -> list[dict]:
    out: list[dict] = []
    pump(iter_stream(io.BytesIO(data)), Aggregator(window_s=3600), out.append)
    return out


def _rules(findings) -> dict[str, set[str]]:
    r: dict[str, set[str]] = {}
    for f in findings:
        r.setdefault(f["rule_id"], set()).add(f["asset_value"])
    return r


# --------------------------------------------------------------------------- #
# Day-one detectors
# --------------------------------------------------------------------------- #

async def test_day_one_detectors_fire_on_a_realistic_site():
    engine = DiscoveryEngine(Config(), db=None, orch=None)
    for b in _sensor_batches(_site_traffic()):
        res = await engine.ingest(observations=b["observations"])
    rules = _rules(engine_findings(engine))
    assert rules["device_lateral_scan"] == {CAM}
    assert rules["cleartext_management"] == {CAM}
    assert rules["iot_crosses_segment"] == {CAM}
    assert rules["ot_internet_egress"] == {PLC}
    assert res["behavior"]["segment_pairs"] >= 2


def engine_findings(engine: DiscoveryEngine) -> list[dict]:
    devices = fingerprint_devices(engine.observations)
    flows = [o for o in engine.observations if o["kind"] == "flow"]
    return behavior.analyze(devices, flows).findings


async def test_quiet_site_raises_nothing():
    f = [(1.0, udp(CAM, "239.255.255.250", 1900, 1900, SSDP, smac=CAM_MAC)),
         (2.0, tcp(CAM, "10.10.1.1", 40000, 53, flags=0x02, smac=CAM_MAC)),      # DNS: infra
         (3.0, tcp(CAM, "34.1.2.3", 40001, 443, flags=0x02, smac=CAM_MAC))]      # vendor cloud
    batches = _sensor_batches(pcap(f))
    obs = [o for b in batches for o in b["observations"]]
    devices = fingerprint_devices(obs)
    res = behavior.analyze(devices, [o for o in obs if o["kind"] == "flow"])
    assert res.findings == []


def test_scan_threshold_is_respected():
    obs = [o for b in _sensor_batches(_site_traffic(scan=False)) for o in b["observations"]]
    res = behavior.analyze(fingerprint_devices(obs), [o for o in obs if o["kind"] == "flow"])
    assert "device_lateral_scan" not in _rules(res.findings)


def test_segment_matrix_and_edges_from_observed_traffic():
    obs = [o for b in _sensor_batches(_site_traffic()) for o in b["observations"]]
    res = behavior.analyze(fingerprint_devices(obs), [o for o in obs if o["kind"] == "flow"])
    pairs = {(m["from"], m["to"]) for m in res.segment_matrix}
    assert ("10.10.1.0/24", "10.10.2.0/24") in pairs
    assert all(e["kind"] == "can_reach_observed" for e in res.edges)


# --------------------------------------------------------------------------- #
# Learned baselines (per device class)
# --------------------------------------------------------------------------- #

def _cam_flow(ts: float, dst: str, port: int) -> list[dict]:
    data = pcap([(ts, udp(CAM, "239.255.255.250", 1900, 1900, SSDP, smac=CAM_MAC)),
                 (ts + 0.1, tcp(CAM, dst, 40000, port, flags=0x02, smac=CAM_MAC))])
    return [o for b in _sensor_batches(data) for o in b["observations"]]


def test_baseline_learns_then_flags_new_behaviour(tmp_path):
    store = behavior.BaselineStore(str(tmp_path / "baselines.json"))
    p = behavior.BehaviorParams(learn_s=3600)

    def run(obs):
        return behavior.analyze(fingerprint_devices(obs), [o for o in obs if o["kind"] == "flow"],
                                params=p, baselines=store).findings

    assert run(_cam_flow(0, "52.1.1.1", 443)) == []           # learning: cloud on 443
    assert run(_cam_flow(1800, "52.1.1.2", 8883)) == []       # still learning: MQTT
    drift = [f for f in run(_cam_flow(7200, "45.9.9.9", 6667)) if f["rule_id"] == "behavior_drift"]
    assert len(drift) == 1 and drift[0]["evidence"]["port"] == 6667   # IRC after learning
    assert run(_cam_flow(7300, "45.9.9.9", 6667)) == []       # alerted once, not every window
    assert run(_cam_flow(7400, "52.1.1.3", 443)) == []        # learned behaviour stays quiet

    reloaded = behavior.BaselineStore(str(tmp_path / "baselines.json"))
    assert reloaded.profiles == store.profiles and reloaded.alerted == store.alerted


# --------------------------------------------------------------------------- #
# Memory bounds + the HTTP contract with Sentry
# --------------------------------------------------------------------------- #

async def test_flows_age_out_and_store_is_capped():
    cfg = dataclasses.replace(Config(), flow_retention_s=100, max_observations=50)
    engine = DiscoveryEngine(cfg, db=None, orch=None)
    old = [{"kind": "flow", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "tcp",
            "dst_port": 80, "first_seen": 0, "last_seen": 0}]
    new = [{"kind": "flow", "src_ip": "10.0.0.1", "dst_ip": f"10.0.1.{i}", "proto": "tcp",
            "dst_port": 80, "first_seen": 1000, "last_seen": 1000} for i in range(80)]
    await engine.ingest(observations=old)
    await engine.ingest(observations=new)
    assert len(engine.observations) == 50
    assert all(o["last_seen"] == 1000 for o in engine.observations)


@pytest.fixture
async def http():
    cfg = dataclasses.replace(Config(), sentry_tokens=("s3cret",), enable_db=False)
    svc = OtDiscoveryService(cfg)
    svc.engine = DiscoveryEngine(cfg, db=None, orch=None)
    client = TestClient(TestServer(svc.make_app()))
    await client.start_server()
    yield client
    await client.close()


async def test_ingest_requires_sensor_token(http):
    r = await http.post("/ingest", json={"observations": [{"kind": "flow"}]})
    assert r.status == 401
    r = await http.post("/ingest", json={"observations": [{"kind": "flow"}]},
                        headers={"Authorization": "Bearer wrong"})
    assert r.status == 401


async def test_sentry_batches_ingest_end_to_end_with_sensor_health(http):
    for b in _sensor_batches(_site_traffic()):
        envelope = {"observations": b["observations"],
                    "sensor": {"id": "lobby-1", "site": "store-42", "version": "0.1.0", "window": b["window"]}}
        r = await http.post("/ingest", json=envelope, headers={"Authorization": "Bearer s3cret"})
        assert r.status == 200
        body = await r.json()
    assert body["behavior_findings"] >= 4
    stats = await (await http.get("/stats")).json()
    assert stats["sensors"]["lobby-1"]["site"] == "store-42"
    assert stats["sensors"]["lobby-1"]["batches"] == 1
    assert stats["segment_matrix"]
