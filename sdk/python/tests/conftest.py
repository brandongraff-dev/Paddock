"""A tiny in-memory fake of the Paddock API, served through httpx.MockTransport."""
from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from paddock_sdk import PaddockClient, RetryPolicy

Handler = Callable[[httpx.Request], httpx.Response]


class FakeAPI:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Handler | list[httpx.Response] | Any] = {}
        self.calls: list[httpx.Request] = []

    def on(self, method: str, path: str, resp: Any) -> None:
        self.routes[(method.upper(), path)] = resp

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = (request.method, request.url.path)
        if key not in self.routes:
            return httpx.Response(404, json={"detail": "Not Found"})
        r = self.routes[key]
        if callable(r):
            return r(request)
        if isinstance(r, list) and r and all(isinstance(x, httpx.Response) for x in r):
            return r.pop(0) if len(r) > 1 else r[0]
        if isinstance(r, httpx.Response):
            return r
        return httpx.Response(200, json=r)

    def body(self, i: int = -1) -> Any:
        return json.loads(self.calls[i].content or b"null")


@pytest.fixture
def api() -> FakeAPI:
    return FakeAPI()


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def client(api, sleeps, monkeypatch) -> PaddockClient:
    for var in ("PADDOCK_URL", "PADDOCK_API_KEY", "PADDOCK_TOKEN", "PADDOCK_PROFILE", "PADDOCK_CONFIG"):
        monkeypatch.delenv(var, raising=False)
    c = PaddockClient(
        "http://paddock.test",
        api_key="pak_abcd1234_secret",
        transport=httpx.MockTransport(api),
        retry=RetryPolicy(max_retries=2, sleep=sleeps.append),
    )
    yield c
    c.close()
