"""Shared test fixtures.

A ``FakeProcess`` + ``FakeRunner`` stand in for subprocess calls so no real
binaries are needed in CI.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest

from app.orchestrator import OrchestratorClient
from app.scope_guard import ScopeDecision, ScopeGuard, normalize_target
from app.util.politeness import PolitenessLimiter


# --- FakeProcess -----------------------------------------------------------


@dataclass
class FakeProcess:
    """Stands in for asyncio.subprocess.Process."""

    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""
    returncode: int = 0
    raise_timeout: bool = False
    terminated: bool = False
    killed: bool = False

    async def communicate(self, input: bytes | None = None):
        if self.raise_timeout:
            await asyncio.sleep(5)  # longer than any test timeout
        return self.stdout_bytes, self.stderr_bytes

    async def wait(self) -> int:
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakeSubprocessRegistry:
    """Pluggable replacement for ``asyncio.create_subprocess_exec`` used by
    the SubprocessRunner. Register a factory per tool name.
    """

    def __init__(self):
        self.factories: dict[str, Callable[[list[str]], FakeProcess]] = {}
        self.calls: list[tuple[str, list[str]]] = []

    def register(self, tool: str, factory: Callable[[list[str]], FakeProcess]):
        self.factories[tool] = factory

    async def create(self, *args, **kwargs) -> FakeProcess:
        full = list(args)
        if not full:
            return FakeProcess(returncode=127)
        # First positional is the binary path; derive the tool name from it.
        import os

        tool = os.path.basename(full[0])
        self.calls.append((tool, full[1:]))
        factory = self.factories.get(tool)
        if factory is None:
            return FakeProcess(stdout_bytes=b"", returncode=0)
        return factory(full[1:])


@pytest.fixture
def fake_subprocess(monkeypatch):
    reg = FakeSubprocessRegistry()
    # Stub both the binary lookup and the process creator.
    import app.util.runner as runner_mod

    monkeypatch.setattr(runner_mod, "resolve_binary",
                        lambda tool: f"/fake/bin/{tool}" if tool in reg.factories else None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", reg.create)
    return reg


# --- Fake orchestrator -----------------------------------------------------


class FakeOrchestratorClient:
    """Captures everything the worker would send to the orchestrator."""

    def __init__(self, *, scope_decision: dict | None = None):
        # Default: every target is in scope.
        self._default_decision = scope_decision or {"allow": True, "normalized": "", "matched_entry": 1, "reason": "ok"}
        self._overrides: dict[str, dict] = {}
        self.scope_calls: list[str] = []
        self.assets_calls: list[dict] = []
        self.findings_calls: list[list[dict]] = []
        self.tls_grades_calls: list[list[dict]] = []
        self.outbound_calls: list[dict] = []
        self.scan_starts: list[str] = []
        self.scan_completes: list[tuple[str, dict]] = []
        self.scan_fails: list[tuple[str, str]] = []

    def set_decision(self, target: str, decision: dict):
        self._overrides[normalize_target(target)] = decision

    async def scope_check(self, target: str):
        self.scope_calls.append(target)
        key = normalize_target(target)
        resp = self._overrides.get(key, self._default_decision).copy()
        resp.setdefault("normalized", key)
        return resp

    async def scan_start(self, scan_id: str):
        self.scan_starts.append(scan_id)

    async def scan_complete(self, scan_id: str, result_summary):
        self.scan_completes.append((scan_id, result_summary))

    async def scan_fail(self, scan_id: str, error: str):
        self.scan_fails.append((scan_id, error))

    async def scan_create_child(self, *_a, **_kw):
        import uuid

        return str(uuid.uuid4())

    async def assets_bulk(self, assets, edges=None):
        self.assets_calls.append({"assets": assets, "edges": edges or []})
        return {"ok": True}

    async def findings_bulk(self, findings):
        self.findings_calls.append(findings)
        return {"ok": True}

    async def tls_grades_bulk(self, items):
        self.tls_grades_calls.append(items)
        return {"ok": True, "upserted": len(items)}

    async def outbound_log(self, row):
        self.outbound_calls.append(row)

    async def close(self):
        pass


@pytest.fixture
def fake_orch():
    return FakeOrchestratorClient()


@pytest.fixture
def scope(fake_orch):
    return ScopeGuard(fake_orch, ttl_sec=60)


@pytest.fixture
def politeness():
    # Short delay, floor of 10 is not valid (floor enforced to 100); use the
    # minimum legal value for tests so they don't wait a quarter-second each.
    return PolitenessLimiter(default_concurrency=2, default_delay_ms=100, floor_ms=100)
