from __future__ import annotations

import json

import pytest

from app.modules import port_scan
from tests.conftest import FakeProcess


pytestmark = pytest.mark.asyncio


async def test_port_scan_emits_port_and_service_assets(fake_orch, scope, politeness, fake_subprocess):
    out = b"\n".join([
        json.dumps({"host": "1.2.3.4", "port": 22}).encode(),
        json.dumps({"host": "1.2.3.4", "port": 443}).encode(),
    ]) + b"\n"
    fake_subprocess.register("naabu", lambda args: FakeProcess(stdout_bytes=out))
    result = await port_scan.scan(
        "1.2.3.4", scope=scope, politeness=politeness, orchestrator=fake_orch, ports="22,443",
    )
    kinds = {a["kind"] for a in result["assets"]}
    assert "port" in kinds
    assert "service" in kinds
    assert result["summary"]["ports"] == 2


async def test_port_scan_drops_out_of_scope_rows(fake_orch, scope, politeness, fake_subprocess):
    out = b"\n".join([
        json.dumps({"host": "1.2.3.4", "port": 22}).encode(),
        json.dumps({"host": "9.9.9.9", "port": 80}).encode(),  # not in scope
    ]) + b"\n"
    fake_orch.set_decision("9.9.9.9", {"allow": False, "normalized": "9.9.9.9",
                                        "matched_entry": None, "reason": "not in scope"})
    fake_subprocess.register("naabu", lambda args: FakeProcess(stdout_bytes=out))
    result = await port_scan.scan(
        "1.2.3.4", scope=scope, politeness=politeness, orchestrator=fake_orch, ports="22,80",
    )
    ports_emitted = [a["canonical"] for a in result["assets"] if a["kind"] == "port"]
    assert "1.2.3.4:22" in ports_emitted
    assert all("9.9.9.9" not in p for p in ports_emitted)


async def test_port_scan_tool_missing_yields_info_finding(fake_orch, scope, politeness, fake_subprocess):
    # Do not register naabu factory -> resolve_binary returns None.
    result = await port_scan.scan(
        "1.2.3.4", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in result["findings"]}
    assert "tool-unavailable-naabu" in rules
    # Service keeps running: the summary is well-formed.
    assert result["summary"]["ports"] == 0
