"""Exposure / segmentation logic: IT/OT violations and public OT exposure."""
from __future__ import annotations

from app.config import Config
from app.exposure import analyze
from app.fingerprint import fingerprint_devices

CFG = Config()


def _rule_ids(result):
    return {f["rule_id"] for f in result.findings}


def test_flat_network_ot_shares_segment_with_it():
    # A PLC and a Windows workstation on the same /24 -> no segmentation.
    obs = [
        {"kind": "packet", "proto": "tcp", "src_port": 40000, "dst_port": 502,
         "src_ip": "10.0.0.5", "src_mac": "00:50:56:00:00:05",
         "dst_ip": "10.0.0.10", "dst_mac": "00:1b:1b:00:00:10"},
        {"kind": "dhcp", "ip": "10.0.0.5", "mac": "00:50:56:00:00:05",
         "vendor_class": "MSFT 5.0"},
    ]
    devices = fingerprint_devices(obs)
    result = analyze(devices, CFG.ipv4_segment_prefix, CFG.ipv6_segment_prefix)

    assert result.ot_it_violations == 1
    assert "ot_it_exposure" in _rule_ids(result)
    seg = {s.cidr: s for s in result.segments}["10.0.0.0/24"]
    assert seg.classification == "mixed"
    finding = next(f for f in result.findings if f["rule_id"] == "ot_it_exposure")
    assert finding["severity"] == "high"
    assert finding["rule_source"] == "policy"
    assert finding["asset_kind"] == "ot_device"


def test_cross_segment_it_to_ot_flow():
    # PLC isolated on its own OT subnet, but an IT host in another subnet is
    # observed talking to it -> cross-segment IT/OT exposure.
    obs = [
        {"kind": "packet", "proto": "tcp", "src_port": 40001, "dst_port": 502,
         "src_ip": "10.0.1.50", "src_mac": "00:50:56:00:00:50",
         "dst_ip": "10.0.5.10", "dst_mac": "00:1b:1b:00:00:10"},
        {"kind": "dhcp", "ip": "10.0.1.50", "mac": "00:50:56:00:00:50",
         "vendor_class": "MSFT 5.0"},
    ]
    devices = fingerprint_devices(obs)
    result = analyze(devices, CFG.ipv4_segment_prefix, CFG.ipv6_segment_prefix)

    assert result.ot_it_violations == 1
    f = next(f for f in result.findings if f["rule_id"] == "ot_it_exposure")
    peers = f["evidence"]["it_peers"]
    assert any(p["peer_ip"] == "10.0.1.50" for p in peers)


def test_public_ot_exposure_is_high():
    obs = [
        {"kind": "packet", "proto": "tcp", "src_port": 40002, "dst_port": 502,
         "src_ip": "45.33.32.100", "src_mac": "00:50:56:00:00:99",
         "dst_ip": "45.33.32.156", "dst_mac": "00:1b:1b:00:00:aa"},
    ]
    devices = fingerprint_devices(obs)
    result = analyze(devices, CFG.ipv4_segment_prefix, CFG.ipv6_segment_prefix)

    assert result.ot_public == 1
    f = next(f for f in result.findings if f["rule_id"] == "ot_public_exposure")
    assert f["severity"] == "high"
    assert "45.33.32.156" in f["evidence"]["public_ips"]
    seg = {s.cidr: s for s in result.segments}["45.33.32.0/24"]
    assert seg.internet_facing is True


def test_properly_segmented_ot_has_no_exposure_finding():
    # OT-only private subnet, OT<->OT traffic only -> clean.
    obs = [
        {"kind": "packet", "proto": "tcp", "src_port": 40003, "dst_port": 502,
         "src_ip": "10.0.5.11", "src_mac": "00:1b:1b:00:00:bb",
         "dst_ip": "10.0.5.10", "dst_mac": "00:1b:1b:00:00:cc"},
    ]
    devices = fingerprint_devices(obs)
    result = analyze(devices, CFG.ipv4_segment_prefix, CFG.ipv6_segment_prefix)

    assert result.ot_it_violations == 0
    assert result.ot_public == 0
    assert result.findings == []
    seg = {s.cidr: s for s in result.segments}["10.0.5.0/24"]
    assert seg.classification == "ot"
