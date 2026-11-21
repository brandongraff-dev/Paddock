"""Packet sources: a capture file, a spool directory, or a live interface.

Live capture shells out to ``tcpdump`` (read-only; it cannot inject) with a
small snap length -- headers plus the short payload prefix OT identification
needs -- and a BPF filter that excludes the sensor's own traffic to its
server so it never reports on itself.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from .wire import iter_stream

log = logging.getLogger("paddock_sentry.sources")

Record = tuple[float, int, dict[str, Any]]
SNAPLEN = 192  # ethernet+ip+tcp headers + 96-byte payload prefix, with room for options


def from_file(path: str | Path) -> Iterator[Record]:
    with open(path, "rb") as fh:
        yield from iter_stream(fh)


def from_spool(directory: str | Path, *, poll_s: float = 2.0, once: bool = False) -> Iterator[Record]:
    """Consume ``*.pcap`` files dropped into a directory (e.g. by a router's
    rotating capture), deleting each after it has been fully read."""
    d = Path(directory)
    while True:
        files = sorted(
            (p for p in d.glob("*.pcap") if time.time() - p.stat().st_mtime > poll_s),
            key=lambda p: p.stat().st_mtime,
        )
        for p in files:
            yield from from_file(p)
            p.unlink(missing_ok=True)
        if once:
            return
        time.sleep(poll_s)


def bpf_excluding_server(server_url: str | None, extra: str | None = None) -> str:
    parts: list[str] = []
    if server_url:
        u = urlsplit(server_url)
        port = u.port or (443 if u.scheme == "https" else 80)
        host = u.hostname or ""
        try:
            ipaddress.ip_address(host)
            parts.append(f"not (host {host} and tcp port {port})")
        except ValueError:
            parts.append(f"not (tcp port {port} and host {host})" if host else "")
    if extra:
        parts.append(f"({extra})")
    return " and ".join(p for p in parts if p) or "ip"


def live(iface: str, *, server_url: str | None = None, bpf: str | None = None) -> Iterator[Record]:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise RuntimeError("tcpdump not found: install it (apt install tcpdump) or use --pcap/--spool")
    cmd = [tcpdump, "-i", iface, "-U", "-n", "-s", str(SNAPLEN), "-w", "-",
           bpf_excluding_server(server_url, bpf)]
    log.info("capturing: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)  # noqa: S603
    try:
        assert proc.stdout is not None
        yield from iter_stream(proc.stdout)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
