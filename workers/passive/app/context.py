"""Module context plumbing.

A `ModuleContext` is handed to every module and bundles:
- the orchestrator client (for scope_check + bulk posts)
- the rate limiter
- an aiohttp session (shared, pooled)
- the worker settings

Modules should never construct their own aiohttp session or orchestrator
client; they ask the context so we get one connection pool, one rate limiter,
and consistent User-Agent + timeouts across the service.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import aiohttp

from .config import Settings
from .orchestrator import OrchestratorClient
from .util.rate_limit import RateLimiter


@dataclass
class ModuleContext:
    settings: Settings
    orchestrator: OrchestratorClient
    rate_limiter: RateLimiter
    http: aiohttp.ClientSession
    scan_id: Optional[str] = None

    async def get_json(
        self,
        url: str,
        source: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> tuple[int, Any]:
        """GET as JSON, rate-limited against the named source bucket."""
        await self.rate_limiter.acquire(source)
        async with self.http.get(url, headers=headers, params=params) as resp:
            status = resp.status
            if status >= 400:
                return status, None
            try:
                return status, await resp.json(content_type=None)
            except Exception:
                return status, None

    async def get_text(
        self,
        url: str,
        source: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> tuple[int, Optional[str]]:
        await self.rate_limiter.acquire(source)
        async with self.http.get(url, headers=headers, params=params) as resp:
            status = resp.status
            if status >= 400:
                return status, None
            return status, await resp.text()
