"""Network-interface discovery: which port is the mirror/SPAN port?

Read-only (sysfs + one ``SIOCGIFADDR`` ioctl); nothing here sends a packet.

A mirror/SPAN port is the NIC that has a link but *no IPv4 address*: the
switch copies traffic onto it and the sensor only listens. The other NIC (or
Wi-Fi) is the management side that reaches the Paddock server. On a Raspberry
Pi that is the built-in ``eth0`` (management) plus a USB Ethernet adapter
(capture).
"""
from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from typing import Any, Callable

SYSFS = "/sys/class/net"
_VIRTUAL_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "zt", "tailscale",
                     "bond", "dummy", "ifb", "sit", "gre", "vlan")


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _ipv4_of(name: str) -> str | None:
    """The interface's primary IPv4 address, or None (SIOCGIFADDR; Linux)."""
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            return socket.inet_ntoa(packed[20:24])
        finally:
            s.close()
    except (OSError, ImportError):
        return None


def list_interfaces(sysfs: str = SYSFS, ipv4_of: Callable[[str], str | None] = _ipv4_of) -> list[dict[str, Any]]:
    root = Path(sysfs)
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        name = d.name
        if name.startswith(_VIRTUAL_PREFIXES):
            continue
        carrier = _read(d / "carrier")
        speed = _read(d / "speed")
        out.append({
            "name": name,
            "mac": _read(d / "address"),
            "up": (_read(d / "operstate") == "up") or carrier == "1",
            "carrier": carrier == "1",
            "speed_mbps": int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
            "wireless": (d / "wireless").exists() or (d / "phy80211").exists(),
            "physical": (d / "device").exists(),
            "ipv4": ipv4_of(name),
        })
    return out


def pick_capture_interface(
    sysfs: str = SYSFS, ipv4_of: Callable[[str], str | None] = _ipv4_of
) -> tuple[str | None, str]:
    """Choose the mirror-port NIC. Returns ``(name | None, explanation)``."""
    nics = [n for n in list_interfaces(sysfs, ipv4_of) if n["physical"] and not n["wireless"]]
    if not nics:
        return None, "no wired network interface found"
    unnumbered_up = [n for n in nics if n["carrier"] and not n["ipv4"]]
    if len(unnumbered_up) == 1:
        n = unnumbered_up[0]
        return n["name"], f"{n['name']} has a link and no IP address: that is your mirror port"
    if len(unnumbered_up) > 1:
        names = ", ".join(n["name"] for n in unnumbered_up)
        return None, (f"several ports have a link but no IP ({names}); set PADDOCK_SENTRY_IFACE "
                      "to the one plugged into the switch's mirror port")
    unnumbered = [n for n in nics if not n["ipv4"]]
    if len(unnumbered) == 1:
        n = unnumbered[0]
        return n["name"], (f"{n['name']} has no IP address but no link yet: plug it into the "
                           "switch's mirror port")
    if len(nics) == 1:
        return None, ("only one wired port and it carries your management IP: add a second "
                      "(USB) Ethernet adapter for the mirror port")
    return None, "every wired port has an IP address; set PADDOCK_SENTRY_IFACE to the mirror port"


def nic_drops(iface: str, sysfs: str = SYSFS) -> int:
    """Packets the NIC/kernel dropped on receive (cumulative since boot)."""
    stats = Path(sysfs) / iface / "statistics"
    total = 0
    for f in ("rx_dropped", "rx_missed_errors", "rx_fifo_errors"):
        v = _read(stats / f)
        if v and v.isdigit():
            total += int(v)
    return total


def interface_report() -> list[dict[str, Any]]:
    """What the heartbeat/enrollment tell the server about NICs (no addresses)."""
    keep = ("name", "up", "speed_mbps", "mac")
    return [{k: n[k] for k in keep if n.get(k) is not None}
            for n in list_interfaces() if n["physical"]][:32]


def hostname() -> str:
    return socket.gethostname()[:253]


def exists(iface: str) -> bool:
    return os.path.exists(f"{SYSFS}/{iface}")
