"""HTTP client for the orchestrator. We never write findings/chains with
raw INSERTs — everything goes through the orchestrator so its audit log
is the source of truth."""
from __future__ import annotations

import os

import logging
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)


class OrchestratorClient:
    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self._base = base_url.rstrip("/")
        # Service credential for AUTH_MODE=enforce (hardened profile).
        key = os.environ.get("SERVICE_API_KEY")
        self._client = httpx.AsyncClient(
            base_url=self._base, timeout=timeout,
            headers={"X-API-Key": key} if key else None,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # -- findings -----------------------------------------------------------

    async def upsert_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """POST /v1/findings/bulk — upsert (asset_id, rule_id, rule_source)."""
        if not findings:
            return []
        r = await self._client.post(
            "/v1/findings/bulk", json={"findings": findings}
        )
        r.raise_for_status()
        data = r.json()
        return data.get("findings", data) if isinstance(data, dict) else data

    async def patch_finding(
        self, finding_id: str, patch: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        r = await self._client.patch(f"/v1/findings/{finding_id}", json=patch)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    # -- chains -------------------------------------------------------------

    async def upsert_chain(self, chain: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/chains — upsert a finding_chain row via the audit path.

        Semantic key: (chain_rule_id, anchor_asset_id, sorted(finding_ids)).
        """
        r = await self._client.post("/v1/chains", json=chain)
        r.raise_for_status()
        return r.json()

    # -- health -------------------------------------------------------------

    async def ping(self) -> bool:
        try:
            r = await self._client.get("/healthz", timeout=2.0)
            return r.status_code == 200
        except Exception:
            return False
