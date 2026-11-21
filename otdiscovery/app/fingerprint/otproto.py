"""Identify OT / industrial protocols in *passively observed* traffic.

Each identifier keys off the well-known server port AND, when payload bytes are
present in the capture, a byte pattern specific to the protocol. We NEVER send
a request to confirm -- identification is read-only over the provided packets.

The "device" side of a flow is whichever endpoint owns the server port (e.g.
the :502 side of a Modbus/TCP flow is the PLC). The caller uses that to attach
the protocol to the right device.

Returned role is always ``ot`` for these industrial protocols; ``type`` is the
equipment class the protocol most often fronts (refined later by OUI/mDNS).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ProtoSpec:
    name: str
    port: int
    transport: str  # tcp | udp | any
    type: str       # device class the protocol usually fronts
    # a payload-prefix / predicate check that raises confidence when it matches
    description: str


# Well-known industrial / OT protocol server ports.
_SPECS: dict[int, ProtoSpec] = {
    502: ProtoSpec("modbus", 502, "tcp", "plc", "Modbus/TCP (MBAP header)"),
    20000: ProtoSpec("dnp3", 20000, "tcp", "rtu", "DNP3 (0x0564 start)"),
    47808: ProtoSpec("bacnet", 47808, "udp", "hvac_controller", "BACnet/IP (BVLC 0x81)"),
    44818: ProtoSpec("ethernet_ip", 44818, "tcp", "plc", "EtherNet/IP (CIP encapsulation)"),
    2222: ProtoSpec("ethernet_ip_io", 2222, "udp", "plc", "EtherNet/IP implicit I/O"),
    102: ProtoSpec("s7comm", 102, "tcp", "plc", "S7comm (TPKT/COTP + 0x32)"),
    4840: ProtoSpec("opcua", 4840, "tcp", "ot_server", "OPC-UA (HEL/OPN/MSG)"),
    789: ProtoSpec("crimson", 789, "tcp", "hmi", "Red Lion Crimson"),
    1911: ProtoSpec("fox", 1911, "tcp", "building_controller", "Niagara Fox"),
    9600: ProtoSpec("omron_fins", 9600, "tcp", "plc", "OMRON FINS"),
}

OT_PORTS = frozenset(_SPECS)


def _payload_bytes(obs: dict[str, Any]) -> bytes:
    for key in ("payload_hex", "payload"):
        v = obs.get(key)
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, str) and v:
            s = v.strip()
            try:
                return bytes.fromhex(s.replace(" ", "").replace(":", ""))
            except ValueError:
                return s.encode("latin-1", errors="ignore")
    return b""


# --- per-protocol passive banner/pattern checks ---------------------------- #

def _check_modbus(p: bytes) -> bool:
    # MBAP: transaction id (2) | protocol id (2, == 0x0000) | length (2) | unit
    if len(p) < 8:
        return False
    protocol_id = int.from_bytes(p[2:4], "big")
    length = int.from_bytes(p[4:6], "big")
    return protocol_id == 0 and 1 <= length <= 260


def _check_dnp3(p: bytes) -> bool:
    return len(p) >= 2 and p[0] == 0x05 and p[1] == 0x64


def _check_bacnet(p: bytes) -> bool:
    # BVLC: type byte 0x81 for BACnet/IP
    return len(p) >= 1 and p[0] == 0x81


def _check_ethernet_ip(p: bytes) -> bool:
    # CIP encapsulation: command (2, LE) in known set, status (4..8) == 0
    if len(p) < 24:
        return False
    cmd = int.from_bytes(p[0:2], "little")
    known = {0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070, 0x0072, 0x0073}
    status = int.from_bytes(p[8:12], "little")
    return cmd in known and status == 0


def _check_s7comm(p: bytes) -> bool:
    # TPKT (0x03 0x00) then COTP; S7 PDU begins 0x32 after the COTP header.
    if len(p) < 8 or p[0] != 0x03 or p[1] != 0x00:
        return False
    return 0x32 in p[4:9]


def _check_opcua(p: bytes) -> bool:
    return len(p) >= 4 and p[0:3] in (b"HEL", b"OPN", b"MSG", b"ACK", b"ERR")


_CHECKS = {
    "modbus": _check_modbus,
    "dnp3": _check_dnp3,
    "bacnet": _check_bacnet,
    "ethernet_ip": _check_ethernet_ip,
    "ethernet_ip_io": _check_ethernet_ip,
    "s7comm": _check_s7comm,
    "opcua": _check_opcua,
}


@dataclass(frozen=True)
class OtHit:
    protocol: str
    device_ip: Optional[str]
    device_mac: Optional[str]
    peer_ip: Optional[str]
    type: str
    role: str
    confidence: int
    port: int
    banner_matched: bool
    evidence: str


def _server_side(obs: dict[str, Any]) -> tuple[int, str, Optional[str], Optional[str], Optional[str]]:
    """Return (server_port, which, device_ip, device_mac, peer_ip).

    Picks whichever endpoint owns a known OT server port as the device.
    """
    sp = obs.get("src_port")
    dp = obs.get("dst_port")
    src_ip = obs.get("src_ip")
    dst_ip = obs.get("dst_ip")
    src_mac = obs.get("src_mac")
    dst_mac = obs.get("dst_mac")

    dp_i = int(dp) if isinstance(dp, int) or (isinstance(dp, str) and dp.isdigit()) else None
    sp_i = int(sp) if isinstance(sp, int) or (isinstance(sp, str) and sp.isdigit()) else None

    if dp_i in OT_PORTS:
        return dp_i, "dst", dst_ip, dst_mac, src_ip
    if sp_i in OT_PORTS:
        return sp_i, "src", src_ip, src_mac, dst_ip
    return -1, "", None, None, None


def identify(obs: dict[str, Any]) -> Optional[OtHit]:
    """Identify an OT protocol in one packet/flow observation, or None."""
    port, _which, dev_ip, dev_mac, peer_ip = _server_side(obs)
    spec = _SPECS.get(port)
    if spec is None:
        return None

    # Transport must be compatible (allow unknown transport through).
    transport = str(obs.get("proto") or obs.get("transport") or "").lower()
    if transport and spec.transport != "any" and transport not in (spec.transport, ""):
        # port collision on the wrong transport -> not this protocol
        return None

    payload = _payload_bytes(obs)
    check = _CHECKS.get(spec.name)
    banner = bool(check(payload)) if (check and payload) else False

    # Port alone: moderate confidence. Port + matching banner: high.
    confidence = 55
    if banner:
        confidence = 92
    elif payload:
        # payload present but did not match -> weak; could be port reuse
        confidence = 40

    return OtHit(
        protocol=spec.name,
        device_ip=dev_ip,
        device_mac=dev_mac,
        peer_ip=peer_ip,
        type=spec.type,
        role="ot",
        confidence=confidence,
        port=port,
        banner_matched=banner,
        evidence=spec.description + (" [banner matched]" if banner else " [port-only]"),
    )
