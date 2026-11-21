"""Server wiring: capability gating, schemas, guards, and a real stdio round trip."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time

import httpx
import pytest
import uvicorn

from paddock_mcp import server as srv
from paddock_mcp.client import PaddockClient

from .fake_paddock import FID, make_app


def _client(caps):
    log: list = []
    return PaddockClient("http://paddock.test", "pak_test",
                         transport=httpx.ASGITransport(app=make_app(list(caps), log))), log


def names(caps, allow_write):
    return [t.name for t in srv.enabled_tools(frozenset(caps), allow_write)]


def test_read_only_by_default():
    base = names({"read"}, False)
    assert "list_findings" in base and "get_posture_summary" in base
    assert "trigger_scan" not in base and "propose_remediation" not in base
    # a powerful key still gets no write tools unless the operator opts in
    assert names({"read", "scan", "admin", "write"}, False) == base


def test_write_tools_need_both_opt_in_and_capability():
    assert "trigger_scan" not in names({"read"}, True)                       # read-only key
    assert "trigger_scan" in names({"read", "scan"}, True)
    assert "propose_remediation" not in names({"read", "scan"}, True)        # needs admin
    assert {"trigger_scan", "propose_remediation"} <= set(names({"read", "scan", "admin"}, True))
    assert names(set(), True) == []


async def test_registered_tools_have_clean_schemas_and_call_through():
    c, log = _client(["read", "scan"])
    s = srv.build_server(c, frozenset({"read", "scan"}), allow_write=True)
    listed = await s.list_tools()
    by = {t.name: t for t in listed}
    assert "trigger_scan" in by and "propose_remediation" not in by
    props = _schema(by["list_findings"])["properties"]
    assert "c" not in props and {"severity", "status", "limit"} <= set(props)
    assert _schema(by["get_finding"])["required"] == ["finding_id"]
    ann = getattr(by["get_finding"], "annotations", None)
    if ann is not None:
        assert _ro(ann) is True and _ro(by["trigger_scan"].annotations) is False
    res = await s.call_tool("check_scope", {"target": "app.example.com"})
    assert "in_scope" in json.dumps(_payload(res))
    with pytest.raises(Exception) as e:                                       # bad input is an error, not a crash
        await s.call_tool("get_finding", {"finding_id": "nope"})
    assert "UUID" in str(e.value)


def _schema(t):
    return getattr(t, "inputSchema", None) or t.input_schema


def _ro(a):
    return getattr(a, "readOnlyHint", None) if hasattr(a, "readOnlyHint") else a.read_only_hint


def _payload(res):
    if isinstance(res, tuple):
        res = res[-1]
    if isinstance(res, dict):
        return res
    sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
    if sc:
        return sc
    return [getattr(x, "text", x) for x in (getattr(res, "content", None) or res)]


def test_http_guard_refuses_open_bind_without_token():
    class S:
        def streamable_http_app(self):
            return lambda *a: None
    with pytest.raises(SystemExit):
        srv.http_app(S(), None, "0.0.0.0")
    srv.http_app(S(), None, "127.0.0.1")
    assert isinstance(srv.http_app(S(), "tok", "0.0.0.0"), srv.BearerGuard)


async def test_bearer_guard():
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=srv.BearerGuard(inner, "s3cret")),
                                 base_url="http://t") as h:
        assert (await h.get("/mcp")).status_code == 401
        assert (await h.get("/mcp", headers={"Authorization": "Bearer nope"})).status_code == 401
        assert (await h.get("/mcp", headers={"Authorization": "Basic s3cret"})).status_code == 401
        assert (await h.get("/mcp", headers={"Authorization": "Bearer s3cret"})).status_code == 200


# --------------------------------------------------------------------------- #
# real stdio round trip against a live fake API
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_paddock():
    port = _free_port()
    log: list = []
    cfg = uvicorn.Config(make_app(["read", "scan"], log), host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", log
    server.should_exit = True
    th.join(timeout=5)


def _rpc(proc, msg):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    if "id" not in msg:
        return None
    return json.loads(proc.stdout.readline())


def test_stdio_end_to_end(live_paddock):
    url, log = live_paddock
    env = {**os.environ, "PADDOCK_URL": url, "PADDOCK_API_KEY": "pak_test"}
    env.pop("PADDOCK_MCP_ALLOW_WRITE", None)
    proc = subprocess.Popen([sys.executable, "-m", "paddock_mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, cwd=os.path.dirname(os.path.dirname(__file__)))
    try:
        init = _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        assert init["result"]["serverInfo"]["name"] == "paddock"
        assert "untrusted" in init["result"]["instructions"]
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tl = _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        got = {t["name"] for t in tl["result"]["tools"]}
        assert "list_findings" in got and "trigger_scan" not in got       # key has scan, operator did not opt in
        call = _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "get_finding", "arguments": {"finding_id": FID}}})
        assert not call["result"].get("isError")
        assert "ci-trivy" in json.dumps(call["result"])
        bad = _rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                          "params": {"name": "get_finding", "arguments": {"finding_id": "x"}}})
        assert bad["result"].get("isError") or "error" in bad
        nope = _rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "trigger_scan", "arguments": {"target": "a.example.com"}}})
        assert nope["result"].get("isError") or "error" in nope
        assert not [x for x in log if x[1] == "/v1/scans"]
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_startup_failures_are_clear(live_paddock):
    url, _ = live_paddock
    base = {**os.environ}
    cwd = os.path.dirname(os.path.dirname(__file__))
    r = subprocess.run([sys.executable, "-m", "paddock_mcp"], env={**base, "PADDOCK_URL": "", "PADDOCK_API_KEY": ""},
                       capture_output=True, text=True, cwd=cwd, timeout=30)
    assert r.returncode != 0 and "PADDOCK_URL" in r.stderr
    r = subprocess.run([sys.executable, "-m", "paddock_mcp"], env={**base, "PADDOCK_URL": url, "PADDOCK_API_KEY": "bad"},
                       capture_output=True, text=True, cwd=cwd, timeout=30)
    assert r.returncode != 0 and "invalid API key" in r.stderr
    r = subprocess.run([sys.executable, "-m", "paddock_mcp", "--list-tools", "--allow-write"],
                       env={**base, "PADDOCK_URL": url, "PADDOCK_API_KEY": "pak_test"},
                       capture_output=True, text=True, cwd=cwd, timeout=30)
    assert r.returncode == 0 and "trigger_scan\twrite" in r.stdout and "propose_remediation" not in r.stdout
