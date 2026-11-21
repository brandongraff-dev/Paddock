"""Thin async client for the orchestrator HTTP API.

We only POST matched-asset ``threat_intel`` findings to it. Everything we
read for matching (assets, findings) comes straight from the shared database
in db.py; the orchestrator owns finding upsert + event emission.
"""
from __future__ import annotations

import os

import logging
from typing import Any

import aiohttp

log = logging.getLogger(__name__)


class OrchestratorClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: int = 30,
        user_agent: str = "paddock-threatintel/0.1",
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._ua = user_agent
        self._session = session
        self._owns_session = session is None

    async def __aenter__(self) -> "OrchestratorClient":
        await self.ensure()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def ensure(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                headers={
                    "User-Agent": self._ua,
                    "Accept": "application/json",
                    # Service credential for AUTH_MODE=enforce (hardened profile).
                    **({"X-API-Key": k} if (k := os.environ.get("SERVICE_API_KEY")) else {}),
                },
            )

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """POST /v1/findings/bulk -- upsert a batch of threat_intel findings."""
        await self.ensure()
        assert self._session is not None
        if not findings:
            return {"inserted": 0, "updated": 0, "items": []}
        url = f"{self.base_url}/v1/findings/bulk"
        try:
            async with self._session.post(url, json={"items": findings}) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: bulk_findings failed: %s", exc)
            return {"inserted": 0, "updated": 0, "items": [], "error": str(exc)}
