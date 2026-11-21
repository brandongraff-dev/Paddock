"""OT protocol identification from the bundled sample capture fixture.

The capture is parsed passively (byte parse, no socket) and every industrial
protocol is identified by port + banner pattern, attaching to the correct
device as its server endpoint.
"""
from __future__ import annotations

from app import pcap
from app.fingerprint import fingerprint_devices, otproto

EXPECTED_BY_PORT = {
    502: ("modbus", "plc"),
    20000: ("dnp3", "rtu"),
    47808: ("bacnet", "hvac_controller"),
    44818: ("ethernet_ip", "plc"),
    102: ("s7comm", "plc"),
    4840: ("opcua", "ot_server"),
}


def test_every_ot_protocol_identified_with_banner(sample_capture):
    obs = pcap.parse(sample_capture)
    seen: dict[int, otproto.OtHit] = {}
    for o in obs:
        if o.get("kind") != "packet":
            continue
        hit = otproto.identify(o)
        if hit is not None:
            seen[hit.port] = hit

    for port, (proto, dtype) in EXPECTED_BY_PORT.items():
        assert port in seen, f"missing OT identification on port {port}"
        hit = seen[port]
        assert hit.protocol == proto
        assert hit.type == dtype
        assert hit.role == "ot"
        # payload pattern (not just the port) confirmed the protocol
        assert hit.banner_matched is True
        assert hit.confidence >= 90


def test_non_ot_port_is_not_misidentified():
    assert otproto.identify({
        "kind": "packet", "proto": "tcp",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
        "src_port": 44444, "dst_port": 443, "payload_hex": "16030100",
    }) is None


def test_wrong_transport_rejected():
    # Modbus is TCP; a UDP/502 packet must not be called Modbus.
    assert otproto.identify({
        "kind": "packet", "proto": "udp",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
        "src_port": 5000, "dst_port": 502, "payload_hex": "",
    }) is None


def test_capture_yields_expected_device_inventory(sample_capture):
    obs = pcap.parse(sample_capture)
    devices = fingerprint_devices(obs)
    by_ip = {d.primary_ip: d for d in devices if d.primary_ip}

    # Six OT devices, each with its vendor + protocol.
    plc = by_ip["10.10.5.10"]
    assert plc.role == "ot" and plc.vendor == "Siemens" and "modbus" in plc.protocols

    rtu = by_ip["10.10.5.11"]
    assert rtu.role == "ot" and rtu.type == "rtu" and "dnp3" in rtu.protocols

    hvac = by_ip["10.10.6.20"]
    assert hvac.role == "ot" and hvac.vendor == "Honeywell" and "bacnet" in hvac.protocols

    enip = by_ip["10.10.5.12"]
    assert enip.role == "ot" and "ethernet_ip" in enip.protocols

    # IoT devices from announcements.
    printer = by_ip["10.10.1.60"]
    assert printer.role == "iot" and printer.type == "printer"
    assert printer.vendor == "Hewlett-Packard"

    camera = by_ip["10.10.1.61"]
    assert camera.role == "iot" and camera.type == "camera"

    ot_devices = [d for d in devices if d.role == "ot"]
    assert len(ot_devices) == 6

    # The DHCP host (MSFT) is classified IT, not an IoT/OT device asset.
    it_hosts = [d for d in devices if d.role == "it"]
    assert any(d.os and "Windows" in d.os for d in it_hosts)
    assert all(not d.is_device for d in it_hosts)
