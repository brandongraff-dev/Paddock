"""Thin async client for the orchestrator HTTP API.

We use it for everything we are not meant to write directly: listing
`technology` assets and bulk-upserting `cve_match` findings.
"""
from __future__ import annotations

import logging
from typing import Any, AsyncIterator

import aiohttp

log = logging.getLogger(__name__)


class OrchestratorClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: int = 30,
        user_agent: str = "palantir-asm-intel/0.1",
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
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def ensure(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                headers={"User-Agent": self._ua, "Accept": "application/json"},
            )

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------
    async def list_technology_assets(
        self, *, limit: int = 500, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Return `technology` assets that carry CPE or vendor/product metadata."""
        await self.ensure()
        assert self._session is not None
        params = {"kind": "technology", "limit": str(limit), "offset": str(offset)}
        url = f"{self.base_url}/v1/assets"
        try:
            async with self._session.get(url, params=params) as resp:
                resp.raise_for_status()
                body = await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: list_technology_assets failed: %s", exc)
            return []
        # The orchestrator returns {"items":[...]} by contract. Be lenient.
        if isinstance(body, dict):
            items = body.get("items") or body.get("assets") or []
        elif isinstance(body, list):
            items = body
        else:
            items = []
        return [a for a in items if isinstance(a, dict)]

    async def iter_technology_assets(
        self, *, page_size: int = 500
    ) -> AsyncIterator[dict[str, Any]]:
        offset = 0
        while True:
            page = await self.list_technology_assets(limit=page_size, offset=offset)
            if not page:
                return
            for asset in page:
                yield asset
            if len(page) < page_size:
                return
            offset += page_size

    async def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        await self.ensure()
        assert self._session is not None
        url = f"{self.base_url}/v1/assets/{asset_id}"
        try:
            async with self._session.get(url) as resp:
                if resp.status == 404:
                    return None
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: get_asset %s failed: %s", asset_id, exc)
            return None

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """POST /v1/findings/bulk — upsert a batch of findings."""
        await self.ensure()
        assert self._session is not None
        if not findings:
            return {"accepted": 0}
        url = f"{self.base_url}/v1/findings/bulk"
        try:
            async with self._session.post(url, json={"items": findings}) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: bulk_findings failed: %s", exc)
            return {"accepted": 0, "error": str(exc)}
