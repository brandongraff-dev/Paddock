"""Shared helpers for the integrations-core tests (no real network, ever)."""
from __future__ import annotations

import base64
import json
import os
import socket
from typing import Any, Callable

import httpx
import pytest

PUBLIC_IP = "93.184.216.34"

FAKE_HOSTS: dict[str, str] = {
    "hooks.example.com": PUBLIC_IP,
    "hooks.slack.com": PUBLIC_IP,
    "prod-00.westus.logic.azure.com": PUBLIC_IP,
    "events.pagerduty.com": PUBLIC_IP,
    "events.eu.pagerduty.com": PUBLIC_IP,
    "smtp.example.com": PUBLIC_IP,
    "lan.example.com": "10.0.0.5",
    "meta.example.com": "169.254.169.254",
}


@pytest.fixture
def fake_dns(monkeypatch):
    """Resolve the test hostnames without DNS; everything else falls through."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host in FAKE_HOSTS:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (FAKE_HOSTS[host], port or 443))]
        if isinstance(host, str) and host.endswith(".invalid"):
            raise socket.gaierror("no such host")
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return FAKE_HOSTS


@pytest.fixture
def secret_key(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    monkeypatch.delenv("PADDOCK_SECRET_KEY_OLD", raising=False)


class Recorder:
    """An httpx MockTransport that records requests and answers from a handler."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.handler = handler or (lambda req: httpx.Response(200, text="ok"))
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    def json(self, i: int = -1) -> Any:
        return json.loads(self.requests[i].content)
