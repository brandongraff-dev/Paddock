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

from . import tenancy

log = logging.getLogger("otdiscovery.orchestrator")


class OrchestratorClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: int = 30,
        user_agent: str = "paddock-otdiscovery/0.1",
        session: aiohttp.ClientSession | None = None,
        tenant: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        # Tenant the writes land in (X-Paddock-Tenant; honoured for the service key).
        self.tenant = tenant
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
                # Stamps X-Paddock-Tenant from the tenant context on EVERY request, so a
                # shared session stays correct across tenants (app/tenancy.py).
                trace_configs=[tenancy.aiohttp_trace_config()],
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

    def for_tenant(self, tenant: str | None) -> "OrchestratorClient":
        """A view of this client whose writes land in ``tenant`` (shares the
        connection pool; closing the view never closes the parent's session)."""
        child = OrchestratorClient(self.base_url, timeout_s=int(self._timeout.total or 30),
                                   user_agent=self._ua, session=self._session, tenant=tenant)
        child._parent = self  # type: ignore[attr-defined]
        child._owns_session = False
        return child

    async def request(self, method: str, path: str, *, json_body: Any = None,
                      headers: dict[str, str] | None = None) -> tuple[int, Any]:
        """Raw call returning ``(status, json)``; transport errors -> ``(503, {...})``.
        Used for the sensor enrollment / heartbeat / idempotency endpoints, where
        the HTTP status itself is the answer."""
        parent = getattr(self, "_parent", None)
        if parent is not None:
            await parent.ensure()
            self._session = parent._session
        await self.ensure()
        assert self._session is not None
        try:
            async with self._session.request(method, f"{self.base_url}{path}", json=json_body,
                                             headers=headers) as resp:
                try:
                    data = await resp.json(content_type=None)
                except Exception:  # noqa: BLE001
                    data = {}
                return resp.status, data
        except (aiohttp.ClientError, TimeoutError) as exc:
            log.warning("orchestrator %s %s failed: %s", method, path, exc)
            return 503, {"detail": "orchestrator unavailable"}

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        parent = getattr(self, "_parent", None)
        if parent is not None:
            await parent.ensure()
            self._session = parent._session
        await self.ensure()
        assert self._session is not None
        url = f"{self.base_url}{path}"
        headers = {"X-Paddock-Tenant": self.tenant} if self.tenant else None
        try:
            async with self._session.post(url, json=body, headers=headers) as resp:
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
