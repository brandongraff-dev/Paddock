"""A minimal, passive PCAP reader.

Parses the classic libpcap file format (Ethernet -> IPv4 -> TCP/UDP) into the
same normalized observation dicts the rest of the pipeline consumes. It is a
pure byte parser over a buffer we were *handed*: it never opens a socket,
reassembles nothing it would have to request, and tolerates truncated or
malformed records by skipping them.

For a handful of UDP services whose announcements/fingerprints we care about we
also do a shallow, best-effort decode:
  * UDP 67/68 (DHCP/BOOTP) -> option 60 (vendor class) + option 55 (PRL) + MAC
  * UDP 1900 (SSDP)        -> the ASCII header block
  * UDP 5353 (mDNS)        -> printable service-name fragments

Everything else is emitted as a generic ``packet`` observation carrying the
5-tuple and a short payload prefix, which is all the OT-protocol identifier
needs.
"""
from __future__ import annotations

import struct
from typing import Any, Iterator, Optional

# pcap global-header magic numbers (and their byte-swapped forms).
_MAGICS = {
    0xA1B2C3D4: ("<", 1),   # little-endian, microsecond
    0xD4C3B2A1: (">", 1),   # big-endian, microsecond
    0xA1B23C4D: ("<", 1000),  # little-endian, nanosecond
    0x4D3CB2A1: (">", 1000),  # big-endian, nanosecond
}

_PAYLOAD_PREFIX = 96  # bytes of L7 payload we keep for banner matching


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _printable(raw: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else " " for b in raw)


def _parse_dhcp(payload: bytes) -> Optional[dict[str, Any]]:
    # BOOTP: op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    # ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
    # magic cookie(4)=0x63825363 then TLV options.
    if len(payload) < 240:
        return None
    if payload[236:240] != b"\x63\x82\x53\x63":
        return None
    chaddr = payload[28:34]
    out: dict[str, Any] = {"kind": "dhcp", "mac": _mac(chaddr)}
    yiaddr = payload[16:20]
    if any(yiaddr):
        out["ip"] = ".".join(str(b) for b in yiaddr)
    i = 240
    n = len(payload)
    while i < n:
        code = payload[i]
        if code == 255:  # END
            break
        if code == 0:    # PAD
            i += 1
            continue
        if i + 1 >= n:
            break
        length = payload[i + 1]
        val = payload[i + 2 : i + 2 + length]
        if code == 60:
            out["vendor_class"] = _printable(val).strip()
        elif code == 55:
            out["param_req_list"] = ",".join(str(b) for b in val)
        elif code == 12:
            out["hostname"] = _printable(val).strip()
        i += 2 + length
    return out


def _parse_ssdp(payload: bytes, src_ip: str, src_mac: str) -> dict[str, Any]:
    text = payload.decode("latin-1", errors="replace")
    out: dict[str, Any] = {"kind": "ssdp", "src_ip": src_ip, "src_mac": src_mac}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "server":
            out["server"] = val
        elif key in ("st", "nt"):
            out["st"] = val
        elif key == "usn":
            out["usn"] = val
        elif key == "location":
            out["location"] = val
    return out


def _parse_mdns(payload: bytes, src_ip: str, src_mac: str) -> dict[str, Any]:
    # Pull printable label fragments (service names like _ipp._tcp.local).
    frags: list[str] = []
    cur: list[str] = []
    for b in payload[12:]:  # skip the 12-byte DNS header
        if 32 <= b < 127 and b not in (0x00,):
            cur.append(chr(b))
        else:
            if len(cur) >= 3:
                frags.append("".join(cur))
            cur = []
    if len(cur) >= 3:
        frags.append("".join(cur))
    return {
        "kind": "mdns",
        "src_ip": src_ip,
        "src_mac": src_mac,
        "service": " ".join(frags),
        "name": " ".join(frags),
    }


def _parse_ip_packet(eth_payload: bytes, src_mac: str, dst_mac: str) -> Optional[dict[str, Any]]:
    if len(eth_payload) < 20:
        return None
    version = eth_payload[0] >> 4
    if version != 4:
        return None  # IPv6 and others: skipped in this minimal reader
    ihl = (eth_payload[0] & 0x0F) * 4
    if ihl < 20 or len(eth_payload) < ihl:
        return None
    proto = eth_payload[9]
    src_ip = ".".join(str(b) for b in eth_payload[12:16])
    dst_ip = ".".join(str(b) for b in eth_payload[16:20])
    l4 = eth_payload[ihl:]

    if proto == 6 and len(l4) >= 20:  # TCP
        src_port = struct.unpack("!H", l4[0:2])[0]
        dst_port = struct.unpack("!H", l4[2:4])[0]
        data_off = (l4[12] >> 4) * 4
        payload = l4[data_off:] if data_off <= len(l4) else b""
        return {
            "kind": "packet",
            "proto": "tcp",
            "src_mac": src_mac, "dst_mac": dst_mac,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "payload_hex": payload[:_PAYLOAD_PREFIX].hex(),
        }

    if proto == 17 and len(l4) >= 8:  # UDP
        src_port = struct.unpack("!H", l4[0:2])[0]
        dst_port = struct.unpack("!H", l4[2:4])[0]
        payload = l4[8:]
        if dst_port in (67, 68) or src_port in (67, 68):
            dh = _parse_dhcp(payload)
            if dh is not None:
                dh.setdefault("src_ip", src_ip)
                dh.setdefault("src_mac", src_mac)
                if not dh.get("mac"):
                    dh["mac"] = src_mac
                return dh
        if dst_port == 1900 or src_port == 1900:
            return _parse_ssdp(payload, src_ip, src_mac)
        if dst_port == 5353 or src_port == 5353:
            return _parse_mdns(payload, src_ip, src_mac)
        return {
            "kind": "packet",
            "proto": "udp",
            "src_mac": src_mac, "dst_mac": dst_mac,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "payload_hex": payload[:_PAYLOAD_PREFIX].hex(),
        }
    return None


def _parse_ethernet(frame: bytes) -> Optional[dict[str, Any]]:
    if len(frame) < 14:
        return None
    dst_mac = _mac(frame[0:6])
    src_mac = _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    # strip one 802.1Q VLAN tag if present
    if ethertype == 0x8100 and len(frame) >= 18:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ethertype != 0x0800:  # only IPv4 in this minimal reader
        return None
    return _parse_ip_packet(frame[offset:], src_mac, dst_mac)


def iter_observations(data: bytes) -> Iterator[dict[str, Any]]:
    """Yield normalized observations from classic-pcap bytes."""
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[0:4])[0]
    meta = _MAGICS.get(magic)
    if meta is None:
        # not a classic pcap (could be pcapng 0x0A0D0D0A) -- unsupported here
        return
    endian, _ = meta
    i = 24
    n = len(data)
    rec_hdr = endian + "IIII"
    rec_sz = struct.calcsize(rec_hdr)
    while i + rec_sz <= n:
        _ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(
            rec_hdr, data[i : i + rec_sz]
        )
        i += rec_sz
        if incl_len <= 0 or i + incl_len > n:
            break
        frame = data[i : i + incl_len]
        i += incl_len
        try:
            obs = _parse_ethernet(frame)
        except Exception:
            obs = None
        if obs is not None:
            yield obs


def parse(data: bytes) -> list[dict[str, Any]]:
    """Return all observations parsed from classic-pcap bytes."""
    return list(iter_observations(data))


def looks_like_pcap(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return struct.unpack("<I", data[0:4])[0] in _MAGICS
