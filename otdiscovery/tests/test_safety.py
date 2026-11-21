"""The hard safety invariant: otdiscovery NEVER connects to a discovered device.

Two layers are asserted:
  1. ``active_probe_guard`` turns any socket connect to a discovered device
     address into an immediate ``ActiveProbeForbidden`` (defence in depth).
  2. Driving the full ingest+analyze pipeline over the sample capture opens
     ZERO sockets to any discovered device address.
"""
from __future__ import annotations

import socket

import pytest

from app import ActiveProbeForbidden, active_probe_guard
from app.config import Config
from app.pipeline import DiscoveryEngine


def test_guard_blocks_connect_to_a_discovered_device():
    with active_probe_guard({"10.10.5.10"}) as guard:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(ActiveProbeForbidden):
                s.connect(("10.10.5.10", 502))   # would be an active OT probe
            with pytest.raises(ActiveProbeForbidden):
                s.connect_ex(("10.10.5.10", 502))
        finally:
            s.close()
    assert "10.10.5.10" in guard.violations


def test_guard_restores_socket_after_exit():
    before = socket.socket.connect
    with active_probe_guard({"1.2.3.4"}):
        assert socket.socket.connect is not before
    assert socket.socket.connect is before


@pytest.mark.asyncio
async def test_pipeline_opens_no_socket_to_any_discovered_device(sample_capture):
    # No orchestrator / DB wired: the pipeline does pure passive analysis, so
    # the only sockets it could open would be to devices -- and it opens none.
    engine = DiscoveryEngine(Config(), db=None, orch=None)
    result = await engine.ingest(pcap_bytes=sample_capture)

    assert result["ot_devices"] == 6
    assert result["active_probe_attempts_to_devices"] == 0
    assert engine.last_guard_violations == []

    discovered_ips = {ip for d in engine.last_inventory for ip in d.ips}
    assert discovered_ips, "expected to discover device IPs from the capture"
    # Not one discovered device address was contacted.
    assert not (set(engine.last_guard_attempts) & discovered_ips)


@pytest.mark.asyncio
async def test_analyze_reuses_stored_observations(sample_capture):
    engine = DiscoveryEngine(Config(), db=None, orch=None)
    await engine.ingest(pcap_bytes=sample_capture)
    # /analyze re-runs over the stored observations without new input.
    again = await engine.analyze()
    assert again["ot_devices"] == 6
    assert again["active_probe_attempts_to_devices"] == 0
