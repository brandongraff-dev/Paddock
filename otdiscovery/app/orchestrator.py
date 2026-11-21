"""Thin async client for the orchestrator HTTP API.

otdiscovery projects discovered devices + segments as assets and emits exposure
/ cve_match findings. It never writes assets or findings directly in Postgres;
the orchestrator owns those tables. (It *reads* the shared ``cves`` feed via its
own pool -- see app/db.py.)

Contract (matches the orchestrator routers):
  * POST /v1/assets/bulk   {items:[AssetIn...]}  -> upsert by (kind, canonical)
  * POST /v1/edges/bulk    {edges:[EdgeIn...]}   -> upsert, resolve by (kind,canonical)
  * POST /v1/findings/bulk {items:[FindingIn...]} -> upsert by (asset,rule)
"""
from __future__ import annotations

import os

import logging
from typing import Any

import aiohttp

log = logging.getLogger("otdiscovery.orchestrator")


class OrchestratorClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: int = 30,
        user_agent: str = "paddock-otdiscovery/0.1",
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

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        await self.ensure()
        assert self._session is not None
        url = f"{self.base_url}{path}"
        try:
            async with self._session.post(url, json=body) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator POST %s failed: %s", path, exc)
            return {"error": str(exc)}

    async def bulk_assets(self, assets: list[dict[str, Any]]) -> dict[str, Any]:
        if not assets:
            return {"inserted": 0, "updated": 0}
        return await self._post("/v1/assets/bulk", {"items": assets})

    async def bulk_edges(self, edges: list[dict[str, Any]]) -> dict[str, Any]:
        if not edges:
            return {"edges_inserted": 0, "edges_updated": 0}
        return await self._post("/v1/edges/bulk", {"edges": edges})

    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        if not findings:
            return {"inserted": 0, "updated": 0}
        return await self._post("/v1/findings/bulk", {"items": findings})
