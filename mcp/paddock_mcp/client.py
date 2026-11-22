"""Minimal async HTTP client for the Paddock /v1 API.

The MCP server never holds more authority than the API key it is given: every
call goes through Paddock's normal auth, RBAC, ABAC, scope and audit paths.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx


class PaddockError(Exception):
    """A Paddock API call failed. ``detail`` is safe to show to the model."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason_phrase
    d = body.get("detail", body) if isinstance(body, dict) else body
    if isinstance(d, dict):
        d = d.get("message") or d.get("error") or str(d)
    return str(d)[:500]


class PaddockClient:
    def __init__(self, base_url: str, api_key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None,
                 timeout: float = 30.0):
        if not base_url:
            raise ValueError("PADDOCK_URL is required")
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, transport=transport,
            headers={"X-API-Key": api_key, "User-Agent": "paddock-mcp", "Accept": "application/json"},
        )
        self._caps: Optional[frozenset[str]] = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def request(self, method: str, path: str, *, params: Optional[dict[str, Any]] = None,
                      json: Any = None) -> Any:
        params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = await self._http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise PaddockError(0, f"cannot reach Paddock at {self.base_url}: {type(exc).__name__}") from None
        if resp.status_code >= 400:
            raise PaddockError(resp.status_code, _detail(resp))
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            raise PaddockError(resp.status_code, "response was not JSON") from None

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, body: Any = None, **params: Any) -> Any:
        return await self.request("POST", path, params=params, json=body)

    async def whoami(self) -> dict[str, Any]:
        return await self.get("/v1/auth/me")

    async def capabilities(self) -> frozenset[str]:
        if self._caps is None:
            me = await self.whoami()
            self._caps = frozenset(me.get("capabilities") or [])
        return self._caps
