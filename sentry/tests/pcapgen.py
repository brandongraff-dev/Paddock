"""Build classic-pcap bytes from simple packet specs (tests only)."""
from __future__ import annotations

import socket
import struct


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _ip_hdr(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    total = 20 + payload_len
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))


def tcp(src, dst, sport, dport, flags=0x18, payload=b"", smac="00:11:22:33:44:01", dmac="00:11:22:33:44:02"):
    l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    return _mac(dmac) + _mac(smac) + b"\x08\x00" + _ip_hdr(src, dst, 6, len(l4)) + l4


def udp(src, dst, sport, dport, payload=b"", smac="00:11:22:33:44:01", dmac="00:11:22:33:44:02"):
    l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _mac(dmac) + _mac(smac) + b"\x08\x00" + _ip_hdr(src, dst, 17, len(l4)) + l4


def pcap(frames: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, fr in frames:
        sec = int(ts)
        out += struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr
    return out
