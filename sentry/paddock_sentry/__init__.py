"""Paddock Sentry -- a passive network sensor for IoT / OT / Wi-Fi visibility.

HARD INVARIANT -- LISTEN ONLY
=============================
Sentry reads packets from a mirror/SPAN port (or a capture file) and ships
compact observations to the Paddock server. It never transmits a packet to,
connects to, or probes any device it observes.

Enforced three ways:
  1. Architectural: the capture source is ``tcpdump -w -`` (read-only) or a
     file; there is no packet-crafting code in this package.
  2. Runtime: ``install_egress_guard(server)`` patches ``socket.connect`` so
     the ONLY permitted outbound connection is to the configured server.
     Anything else raises ``EgressForbidden`` and is counted.
  3. Tested: tests/test_safety.py drives a full replay and asserts zero
     connection attempts other than to the server.
"""
from __future__ import annotations

import socket as _socket
import threading
from urllib.parse import urlsplit

__version__ = "0.1.0"
PASSIVE_ONLY = True


class EgressForbidden(RuntimeError):
    """The sensor tried to connect somewhere other than its server."""


_lock = threading.Lock()
_allowed: set[str] = set()
_installed = False
violations: list[str] = []
_orig_connect = _socket.socket.connect


def _resolve(host: str, port: int) -> set[str]:
    try:
        return {info[4][0] for info in _socket.getaddrinfo(host, port)}
    except OSError:
        return set()


def install_egress_guard(server_url: str | None) -> None:
    """Allow outbound connections only to ``server_url``'s host (all its IPs)."""
    global _installed
    allowed: set[str] = set()
    if server_url:
        parts = urlsplit(server_url)
        if parts.hostname:
            port = parts.port or (443 if parts.scheme == "https" else 80)
            allowed = {parts.hostname} | _resolve(parts.hostname, port)
    with _lock:
        _allowed.clear()
        _allowed.update(allowed)
        if _installed:
            return

        def guarded_connect(sock, address):  # type: ignore[no-untyped-def]
            host = address[0] if isinstance(address, tuple) else str(address)
            if sock.family in (_socket.AF_INET, _socket.AF_INET6) and host not in _allowed:
                violations.append(str(host))
                raise EgressForbidden(f"sentry may only connect to its server, not {host!r}")
            return _orig_connect(sock, address)

        _socket.socket.connect = guarded_connect  # type: ignore[method-assign]
        _installed = True


def uninstall_egress_guard() -> None:
    global _installed
    with _lock:
        _socket.socket.connect = _orig_connect  # type: ignore[method-assign]
        _installed = False
        _allowed.clear()
