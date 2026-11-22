"""GuardedRunner tests: HTTP/TCP probes go through the guard and target only the
replica. Uses FakeBackend (no containers) with scripted exec output."""
from __future__ import annotations

import pytest

from app.engine.runner import GuardedRunner, _parse_http
from app.sandbox.backend import FakeBackend
from app.sandbox.guard import IsolationGuard
from app.sandbox.types import ExecResult, IsolationError, Replica, SandboxSpec


def _dump(status=200, headers=None, body="hello"):
    lines = [f"HTTP/1.1 {status} X"]
    for k, v in (headers or {"Server": "nginx"}).items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


async def _verified(backend) -> Replica:
    guard = IsolationGuard(backend)
    return await guard.build(SandboxSpec(component="web", image="nginx:1.20", port=80))


def test_parse_http_basic():
    p = _parse_http(_dump(200, {"Server": "nginx", "X-Powered-By": "php"}, "body!"))
    assert p.status == 200 and p.ok
    assert p.headers["Server"] == "nginx" and p.headers["X-Powered-By"] == "php"
    assert "body!" in p.body_excerpt


def test_parse_http_redirect_chain_takes_last():
    raw = _dump(301, {"Location": "/login"}, "") + _dump(200, {"Server": "x"}, "ok")
    p = _parse_http(raw)
    assert p.status == 200


def test_parse_http_no_status():
    assert _parse_http("garbage").error is not None


@pytest.mark.asyncio
async def test_http_probe_parses_scripted_curl():
    backend = FakeBackend()
    backend.register(ExecResult(0, _dump(200, {"Server": "nginx"}, "<h1>hi</h1>")),
                     argv_prefix=("curl",))
    replica = await _verified(backend)
    guard = IsolationGuard(backend)
    runner = GuardedRunner(guard)
    r = await runner.http(replica, "/admin")
    assert r.status == 200 and "<h1>hi</h1>" in r.body_excerpt


@pytest.mark.asyncio
async def test_http_probe_curl_failure_is_error():
    backend = FakeBackend()
    backend.register(ExecResult(7, "", "could not connect"), argv_prefix=("curl",))
    guard = IsolationGuard(backend)
    replica = await guard.build(SandboxSpec(component="web", image="nginx:1.20", port=80))
    r = await GuardedRunner(guard).http(replica, "/")
    assert not r.ok and r.error is not None


@pytest.mark.asyncio
async def test_tcp_open_true_false():
    backend = FakeBackend()
    guard = IsolationGuard(backend)
    runner = GuardedRunner(guard)
    replica = await guard.build(SandboxSpec(component="db", image="redis:6", port=6379))
    backend.register(ExecResult(0, ""), argv_prefix=("python3", "-c"))
    assert await runner.tcp_open(replica) is True
    backend2 = FakeBackend()
    guard2 = IsolationGuard(backend2)
    r2 = await guard2.build(SandboxSpec(component="db", image="redis:6", port=6379))
    backend2.register(ExecResult(1, ""), argv_prefix=("python3", "-c"))
    assert await GuardedRunner(guard2).tcp_open(r2) is False


@pytest.mark.asyncio
async def test_tcp_open_false_without_port():
    backend = FakeBackend()
    guard = IsolationGuard(backend)
    replica = await guard.build(SandboxSpec(component="x", image="x:1"))  # no port
    assert await GuardedRunner(guard).tcp_open(replica) is False


@pytest.mark.asyncio
async def test_runner_refuses_unverified_replica():
    backend = FakeBackend()
    guard = IsolationGuard(backend)
    # A replica straight from the backend is NOT verified; the guard must refuse.
    raw = await backend.build(SandboxSpec(component="web", image="nginx:1.20", port=80))
    with pytest.raises(IsolationError):
        await GuardedRunner(guard).http(raw, "/")
