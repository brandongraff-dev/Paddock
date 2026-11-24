"""port_scan coverage markers and fail-closed tool handling (Provable Containment builders-1/2).

The assurance builder grants full-port coverage only from ``ports_scanned == "1-65535"`` AND
``tool_exit_ok`` AND ``results_posted`` in the scan's result_summary. These tests pin what the worker
records, so a regression here can never turn into a false HOLDS downstream.
"""
from __future__ import annotations

import json

import pytest

from app.config import settings
from app.modules import port_scan
from tests.conftest import FakeProcess

pytestmark = pytest.mark.asyncio


def _naabu(port_lines: list[dict], returncode: int = 0, raw: bytes | None = None):
    out = raw if raw is not None else b"\n".join(json.dumps(x).encode() for x in port_lines) + b"\n"
    return lambda args: FakeProcess(stdout_bytes=out, returncode=returncode)


async def _scan(fake_orch, scope, politeness, target="1.2.3.4", ports="top-100"):
    return await port_scan.scan(target, scope=scope, politeness=politeness,
                                orchestrator=fake_orch, ports=ports)


@pytest.mark.parametrize("spec", ["1-65535", "full", "1-1000,1001-65535", " FULL "])
async def test_full_scan_records_the_literal_full_range(fake_orch, scope, politeness, fake_subprocess, spec):
    fake_subprocess.register("naabu", _naabu([{"host": "1.2.3.4", "port": 22}]))
    r = await _scan(fake_orch, scope, politeness, ports=spec)
    assert r["summary"]["ports_scanned"] == "1-65535"
    assert r["summary"]["tool_exit_ok"] is True
    assert "results_posted" not in r["summary"]    # only the worker may set it, after the posts


@pytest.mark.parametrize("spec,marker", [("top-100", "top-100"), ("22,443", "22,443"),
                                         ("1-65534", "1-65534"), ("2-65535", "2-65535")])
async def test_partial_scan_never_claims_the_full_range(fake_orch, scope, politeness, fake_subprocess,
                                                        spec, marker):
    fake_subprocess.register("naabu", _naabu([]))
    r = await _scan(fake_orch, scope, politeness, ports=spec)
    assert r["summary"]["ports_scanned"] == marker
    assert r["summary"]["ports_scanned"] != "1-65535"


async def test_nonzero_exit_is_a_visible_failure_not_zero_ports(fake_orch, scope, politeness, fake_subprocess):
    # Old behaviour: ToolFailed -> result None -> summary {"ports": 0}, scan completed, no finding.
    fake_subprocess.register(
        "naabu", lambda args: FakeProcess(stdout_bytes=b'{"host":"1.2.3.4","port":22}\n',
                                          stderr_bytes=b"boom", returncode=2))
    r = await _scan(fake_orch, scope, politeness, ports="1-65535")
    assert r["summary"]["tool_exit_ok"] is False
    assert "exited 2" in r["summary"]["tool_error"]
    assert {f["rule_id"] for f in r["findings"]} == {"tool-error-naabu"}


async def test_timeout_is_a_visible_failure(fake_orch, scope, politeness, fake_subprocess, monkeypatch):
    monkeypatch.setattr(settings, "subprocess_timeout_sec", 0)     # budget floor off
    monkeypatch.setattr(port_scan, "naabu_timeout_sec", lambda ports: 0.2)
    fake_subprocess.register("naabu", lambda args: FakeProcess(raise_timeout=True))
    r = await _scan(fake_orch, scope, politeness, ports="1-65535")
    assert r["summary"]["tool_exit_ok"] is False
    assert "timeout" in r["summary"]["tool_error"]
    assert {f["rule_id"] for f in r["findings"]} == {"tool-error-naabu"}


async def test_missing_binary_is_a_visible_failure(fake_orch, scope, politeness, fake_subprocess):
    r = await _scan(fake_orch, scope, politeness, ports="1-65535")
    assert r["summary"]["tool_exit_ok"] is False
    assert {f["rule_id"] for f in r["findings"]} == {"tool-unavailable-naabu"}


async def test_unreadable_output_cannot_back_a_complete_scan(fake_orch, scope, politeness, fake_subprocess):
    raw = b'{"host":"1.2.3.4","port":22}\nnot json at all\n{"host":"1.2.3.4","port":"x"}\n'
    fake_subprocess.register("naabu", _naabu([], raw=raw))
    r = await _scan(fake_orch, scope, politeness, ports="1-65535")
    assert r["summary"]["tool_exit_ok"] is False
    assert "2 unreadable" in r["summary"]["tool_error"]
    assert r["summary"]["open_ports"] == [22]          # what was readable is still reported


async def test_full_scan_budget_covers_the_polite_rate(monkeypatch):
    """65535 ports at -rate 100 is ~655 s: over the 600 s default, so the budget must grow."""
    monkeypatch.setattr(settings, "subprocess_timeout_sec", 600)
    assert port_scan.naabu_timeout_sec("1-65535") > 655
    assert port_scan.naabu_timeout_sec("top-100") == 600     # small scans keep the configured budget


async def test_ipv6_tool_failure_finding_carries_the_exact_target(fake_orch, scope, politeness,
                                                                  fake_subprocess):
    """builders-2: _host_of('2606:4700:4700::1111') is '2606'; the finding must name the real target."""
    r = await _scan(fake_orch, scope, politeness, target="2606:4700:4700::1111", ports="1-65535")
    (f,) = r["findings"]
    assert f["target_canonical"] == "2606:4700:4700::1111"
    assert f["target_kind"] == "ipv6"
    assert f["target_host"] == "2606:4700:4700::1111"


async def test_ipv6_host_asset_kind_is_ipv6(fake_orch, scope, politeness, fake_subprocess):
    fake_subprocess.register("naabu", _naabu([{"host": "2606:4700:4700::1111", "port": 443}]))
    r = await _scan(fake_orch, scope, politeness, target="2606:4700:4700::1111")
    host = [a for a in r["assets"] if a["kind"] in ("ipv4", "ipv6")]
    assert [a["kind"] for a in host] == ["ipv6"]
    assert r["summary"]["tool_exit_ok"] is True
