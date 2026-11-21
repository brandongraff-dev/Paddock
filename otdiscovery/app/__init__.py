"""palantir-asm passive IoT/OT device-discovery service.

======================================================================
HARD SAFETY INVARIANT  --  PASSIVE ONLY, NEVER PROBE A DEVICE
======================================================================

This service identifies connected IoT and industrial/OT devices (PLCs,
RTUs, HVAC/water controllers, cameras, printers, appliances) and flags
their exposure. It does so *exclusively* from passively-provided network
observations:

    * a PCAP file, or a list of observed packets / flows,
    * mDNS / SSDP / UPnP announcements the devices broadcast anyway,
    * DHCP fingerprints seen on the wire,
    * MAC addresses (-> OUI vendor lookup against a bundled table),
    * OT protocol traffic *observed passively* in the provided capture.

It MUST NEVER initiate a connection to a discovered device. Active
scanning of OT equipment is dangerous: PLCs and water/HVAC controllers
can hang, fault, or drop their control loop under an unsolicited probe
(the canonical reason OT security is "passive-first"). There is no code
path in this service that opens a socket to a discovered target, sends a
Modbus/DNP3/S7/BACnet/EtherNet-IP/OPC-UA request, or otherwise touches a
device. We only *parse data that was handed to us*.

Enforcement (defence in depth):
    1. Architectural -- no module here calls socket.connect()/sendto()
       against a device address; the only outbound socket this process
       opens is to the orchestrator (to upsert assets/findings) and,
       optionally, to Postgres (to read the CVE feed).
    2. Runtime  -- ``active_probe_guard(device_ips)`` wraps the analysis
       pipeline. It patches the stdlib socket so that ANY attempt to
       connect to a discovered device address raises
       ``ActiveProbeForbidden`` immediately, and records the attempt.
    3. Tested   -- tests/test_safety.py drives the full ingest+analyze
       pipeline over the sample capture and asserts the guard recorded
       zero connection attempts to any discovered device address.
"""
from __future__ import annotations

import socket as _socket
from contextlib import contextmanager
from typing import Iterable, Iterator

__version__ = "0.1.0"

# The single source of truth for the invariant, surfaced on /healthz etc.
PASSIVE_ONLY = True
SAFETY_INVARIANT = (
    "otdiscovery is passive-only: it never initiates a connection to, or "
    "sends a packet at, a discovered device. All device intelligence is "
    "derived from passively-provided observations (pcap / announcements / "
    "flows). No active scan of OT is ever performed."
)


class ActiveProbeForbidden(RuntimeError):
    """Raised when something tries to open a socket to a discovered device.

    Hitting this is a hard bug: the service must never probe a target. The
    guard turns a would-be active probe into a loud, test-visible failure
    rather than letting a packet reach a (possibly fragile) OT device.
    """


def _norm_ip(value: object) -> str:
    return str(value).strip().strip("[]").lower()


class _GuardState:
    """Records connection attempts and the set of forbidden device targets."""

    def __init__(self, forbidden: Iterable[str]) -> None:
        self.forbidden: set[str] = {_norm_ip(v) for v in forbidden if v}
        # Every (host) we were asked to connect to, forbidden or not.
        self.attempts: list[str] = []
        # The subset that targeted a discovered device (should always be []).
        self.violations: list[str] = []

    def check(self, host: object) -> None:
        h = _norm_ip(host)
        self.attempts.append(h)
        if h in self.forbidden:
            self.violations.append(h)
            raise ActiveProbeForbidden(
                f"refused active connection to discovered device {h!r}: "
                "otdiscovery is passive-only (see app.SAFETY_INVARIANT)"
            )


@contextmanager
def active_probe_guard(device_ips: Iterable[str]) -> Iterator["_GuardState"]:
    """Forbid, for the duration of the block, any socket connect to a device.

    ``socket.socket.connect`` / ``connect_ex`` are wrapped so that a
    connection to any address in ``device_ips`` raises
    ``ActiveProbeForbidden`` before a packet can leave. Connections to
    everything else (the orchestrator, Postgres) pass through untouched.

    The yielded state object records every attempted destination and the
    forbidden ones it blocked, so tests can assert the pipeline opened no
    socket to a discovered target.
    """
    state = _GuardState(device_ips)

    real_connect = _socket.socket.connect
    real_connect_ex = _socket.socket.connect_ex

    def _host_of(address: object) -> object:
        # AF_INET/AF_INET6 use (host, port[, ...]); other families pass through.
        if isinstance(address, tuple) and address:
            return address[0]
        return None

    def guarded_connect(self: _socket.socket, address: object):  # type: ignore[override]
        host = _host_of(address)
        if host is not None:
            state.check(host)
        return real_connect(self, address)

    def guarded_connect_ex(self: _socket.socket, address: object):  # type: ignore[override]
        host = _host_of(address)
        if host is not None:
            state.check(host)
        return real_connect_ex(self, address)

    _socket.socket.connect = guarded_connect  # type: ignore[assignment]
    _socket.socket.connect_ex = guarded_connect_ex  # type: ignore[assignment]
    try:
        yield state
    finally:
        _socket.socket.connect = real_connect  # type: ignore[assignment]
        _socket.socket.connect_ex = real_connect_ex  # type: ignore[assignment]
