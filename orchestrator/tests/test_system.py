"""GET /v1/system: the install inventory behind Settings -> System.

Service probes are patched: nothing here touches the network.
"""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from app import system


@pytest.fixture(autouse=True)
def _fresh_cache():
    system.reset_cache()
    yield
    system.reset_cache()


def test_dns_failure_is_found_through_the_exception_chain():
    inner = socket.gaierror(-2, "Name or service not known")
    outer = RuntimeError("connect failed")
    outer.__cause__ = inner
    assert system._is_dns_failure(outer) is True
    assert system._is_dns_failure(RuntimeError("refused")) is False


def test_version_prefers_the_release_env(monkeypatch):
    monkeypatch.setenv("PADDOCK_VERSION", "1.2.3")
    assert system.version() == "1.2.3"
    monkeypatch.delenv("PADDOCK_VERSION")
    assert system.version()  # package metadata or the 0.1.0 fallback


async def test_collect_classifies_services_and_hides_urls(monkeypatch):
    async def fake_status(_app):
        return {"components": [
            {"name": "api", "status": "up"},
            {"name": "database", "status": "up"},
            {"name": "queue", "status": "degraded"},
        ]}

    async def fake_probe(url: str) -> str:
        if "brain" in url:
            return "down"
        if "graphsync" in url:
            return "up"
        return "not_installed"

    monkeypatch.setattr(system.billing_status, "collect", fake_status)
    monkeypatch.setattr(system, "_probe_service", fake_probe)
    out = await system.collect(SimpleNamespace())

    by_key = {r["key"]: r["status"] for r in out["core"] + out["services"]}
    assert by_key["database"] == "up"
    assert by_key["queue"] == "down"
    assert by_key["brain"] == "down"
    assert by_key["graphsync"] == "up"
    assert by_key["remediation"] == "not_installed"
    assert out["counts"] == {"up": 3, "down": 2, "not_installed": 7}
    assert "http" not in repr(out)  # no URLs or hostnames leave the process


async def test_system_requires_admin(client, db_pool, monkeypatch):
    from .test_governance import _hdr, _seed_user_with_key

    async def fake_status(_app):
        return {"components": [{"name": "api", "status": "up"}]}

    async def fake_probe(_url: str) -> str:
        return "not_installed"

    monkeypatch.setattr(system.billing_status, "collect", fake_status)
    monkeypatch.setattr(system, "_probe_service", fake_probe)
    _, viewer = await _seed_user_with_key(db_pool, "vera", "viewer", "public")
    _, admin = await _seed_user_with_key(db_pool, "ada", "admin", "public")
    from app.config import settings

    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        assert (await client.get("/v1/system")).status_code == 401
        assert (await client.get("/v1/system", headers=_hdr(viewer))).status_code == 403
        r = await client.get("/v1/system", headers=_hdr(admin))
    finally:
        settings.auth_mode = prev
    assert r.status_code == 200
    body = r.json()
    assert body["edition"] == "community"
    assert {s["key"] for s in body["services"]} >= {"brain", "remediation"}
