"""A scan whose results never landed, or whose tool failed, must FAIL, never complete.

Provable Containment builders-1: the worker posted {"assets"...}/{"findings"...} bodies the
orchestrator 422s, swallowed the error and still completed the scan; the assurance builder then
read "completed + full-port config" as "every port probed" (false HOLDS with zero edges).
"""
from __future__ import annotations

import json

import pytest

from app import main as worker_main
from app.main import Worker
from tests.conftest import FakeProcess

pytestmark = pytest.mark.asyncio


class _Redis:
    def __init__(self):
        self.acked: list[str] = []
        self.events: list[dict] = []

    async def xack(self, *a):
        self.acked.append(a[-1])

    async def xadd(self, _stream, fields):
        self.events.append(fields)


def _worker(fake_orch, scope, politeness) -> Worker:
    w = Worker()
    w.redis, w.orch, w.scope, w.politeness = _Redis(), fake_orch, scope, politeness
    return w


def _naabu(*ports: int, returncode: int = 0):
    out = b"".join(json.dumps({"host": "1.2.3.4", "port": p}).encode() + b"\n" for p in ports)
    return lambda args: FakeProcess(stdout_bytes=out, returncode=returncode)


async def _run(w, ports="1-65535", target="1.2.3.4"):
    await w._handle_bound_job("1-0", {"scan_id": "s1", "kind": "port_scan", "target": target,
                                      "config": {"ports": ports}})


async def test_clean_full_scan_records_all_three_markers(fake_orch, scope, politeness, fake_subprocess):
    fake_subprocess.register("naabu", _naabu(22, 443))
    await _run(_worker(fake_orch, scope, politeness))
    assert fake_orch.scan_fails == []
    ((sid, summary),) = fake_orch.scan_completes
    assert sid == "s1"
    assert summary["ports_scanned"] == "1-65535"
    assert summary["tool_exit_ok"] is True
    assert summary["results_posted"] is True
    # the three posts used the orchestrator's real shapes (the fake asserts them), in this order
    assert [p for p, _ in fake_orch.bodies] == ["/v1/assets/bulk", "/v1/edges/bulk"]


@pytest.mark.parametrize("failing", ["assets", "edges", "findings"])
async def test_a_failed_bulk_post_fails_the_scan(fake_orch, scope, politeness, fake_subprocess, failing):
    # naabu missing => a finding exists too, so all three kinds can fail; use a scan with ports for
    # assets/edges and add a finding via a monkeypatched module result for "findings".
    fake_subprocess.register("naabu", _naabu(22))
    w = _worker(fake_orch, scope, politeness)
    if failing == "findings":
        orig = worker_main._DISPATCH["port_scan"]

        async def with_finding(wk, scan_id, target, config):
            res = await orig(wk, scan_id, target, config)
            res["findings"] = [{
                "target_canonical": "1.2.3.4", "target_kind": "ipv4", "rule_id": "x",
                "rule_source": "policy", "severity": "info", "title": "t", "description": "d"}]
            return res
        worker_main._DISPATCH["port_scan"] = with_finding
        try:
            fake_orch.fail_posts = {failing}
            await _run(w)
        finally:
            worker_main._DISPATCH["port_scan"] = orig
    else:
        fake_orch.fail_posts = {failing}
        await _run(w)
    assert fake_orch.scan_completes == []
    ((sid, err),) = fake_orch.scan_fails
    assert sid == "s1" and "results not posted" in err and failing in err


async def test_tool_failure_fails_the_scan_and_lands_the_finding(fake_orch, scope, politeness,
                                                                 fake_subprocess):
    fake_subprocess.register("naabu", _naabu(22, returncode=2))
    await _run(_worker(fake_orch, scope, politeness))
    assert fake_orch.scan_completes == []
    ((_, err),) = fake_orch.scan_fails
    assert "naabu exited 2" in err
    (posted,) = fake_orch.findings_calls          # the tool-error finding still reaches the orchestrator
    assert posted[0]["rule_id"] == "tool-error-naabu"


async def test_missing_tool_fails_the_scan(fake_orch, scope, politeness, fake_subprocess):
    await _run(_worker(fake_orch, scope, politeness))
    assert fake_orch.scan_completes == []
    assert "not installed" in fake_orch.scan_fails[0][1]


async def test_results_posted_is_never_set_by_the_module(fake_orch, scope, politeness, fake_subprocess):
    """Only the worker, after the posts, may claim results_posted (the builder trusts it)."""
    from app.modules import port_scan
    fake_subprocess.register("naabu", _naabu(22))
    res = await port_scan.scan("1.2.3.4", scope=scope, politeness=politeness, orchestrator=fake_orch,
                               ports="1-65535")
    assert "results_posted" not in res["summary"]


async def test_full_scan_job_budget_exceeds_the_default_job_timeout():
    assert worker_main._job_timeout_sec("port_scan", {"ports": "1-65535"}) > 655
    assert worker_main._job_timeout_sec("port_scan", {"ports": "top-100"}) == worker_main.settings.job_timeout_sec
    assert worker_main._job_timeout_sec("http_probe", {}) == worker_main.settings.job_timeout_sec
