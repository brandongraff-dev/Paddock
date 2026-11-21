"""HTTP client for the orchestrator.

Every bulk upsert, scope check, scan status change and outbound audit row
goes through here. No raw database access from workers — the orchestrator
owns the canonicalization rules.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx
import structlog
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app import USER_AGENT
from app.config import settings

log = structlog.get_logger(__name__)


class OrchestratorError(RuntimeError):
    pass


class OrchestratorClient:
    """Thin async client with retries and the worker's identity baked in."""

    def __init__(self, base_url: str | None = None, worker_id: str | None = None):
        self._base = (base_url or settings.orchestrator_url).rstrip("/")
        self._worker_id = worker_id or settings.worker_id
        self._client = httpx.AsyncClient(
            base_url=self._base,
            timeout=httpx.Timeout(settings.http_timeout_sec),
            headers={
                "User-Agent": USER_AGENT,
                "X-Worker-Id": self._worker_id,
                # Orchestrator in AUTH_MODE=enforce (hardened / lite) only
                # accepts the fleet's shared service key.
                **({"X-API-Key": _svc_key} if (_svc_key := os.environ.get("SERVICE_API_KEY")) else {}),
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # -------- low-level ----------------------------------------------------

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=0.3, max=2.0),
            retry=retry_if_exception_type((httpx.TransportError,)),
            reraise=True,
        ):
            with attempt:
                r = await self._client.request(method, path, **kwargs)
                if r.status_code >= 500:
                    raise httpx.TransportError(f"orchestrator {r.status_code}")
                return r
        raise OrchestratorError("unreachable")  # pragma: no cover

    # -------- scope --------------------------------------------------------

    async def scope_check(self, target: str) -> dict[str, Any]:
        """POST /v1/scope/check — the rule nobody breaks."""
        r = await self._request("POST", "/v1/scope/check", json={"target": target})
        r.raise_for_status()
        return r.json()

    # -------- scans --------------------------------------------------------

    async def scan_start(self, scan_id: str) -> None:
        await self._request(
            "POST", f"/v1/scans/{scan_id}/start", json={"worker_id": self._worker_id}
        )

    async def scan_complete(self, scan_id: str, result_summary: dict[str, Any]) -> None:
        await self._request(
            "POST",
            f"/v1/scans/{scan_id}/complete",
            json={"result_summary": result_summary},
        )

    async def scan_fail(self, scan_id: str, error: str) -> None:
        await self._request("POST", f"/v1/scans/{scan_id}/fail", json={"error": error})

    async def scan_create_child(
        self,
        parent_scan_id: str,
        kind: str,
        target: str,
        config: dict[str, Any] | None = None,
    ) -> str:
        r = await self._request(
            "POST",
            "/v1/scans",
            json={
                "kind": kind,
                "target": target,
                "config": config or {},
                "parent_scan_id": parent_scan_id,
            },
        )
        r.raise_for_status()
        return r.json()["scan_id"]

    # -------- bulk upserts -------------------------------------------------

    async def assets_bulk(self, assets: list[dict[str, Any]], edges: list[dict[str, Any]] | None = None) -> dict:
        r = await self._request(
            "POST",
            "/v1/assets/bulk",
            json={"assets": assets, "edges": edges or []},
        )
        r.raise_for_status()
        return r.json()

    async def findings_bulk(self, findings: list[dict[str, Any]]) -> dict:
        r = await self._request("POST", "/v1/findings/bulk", json={"findings": findings})
        r.raise_for_status()
        return r.json()

    async def tls_grades_bulk(self, items: list[dict[str, Any]]) -> dict:
        """Upsert TLS posture grades (one per asset/host) via the orchestrator.

        POST /v1/tls-grades/bulk  body: ``{"items": [{asset_id, host, grade,
        score, protocols, weak_ciphers, issues, cert_expires}, ...]}``
        """
        r = await self._request("POST", "/v1/tls-grades/bulk", json={"items": items})
        r.raise_for_status()
        return r.json()

    # -------- verification (safe checks) ------------------------------------

    async def verification_result(
        self, verification_id: str, payload: dict[str, Any], tenant_id: str | None = None
    ) -> dict:
        """POST /v1/verifications/{id}/result: report a safe-check verdict.

        The orchestrator owns every consequence (finding state, priority,
        reopen on a failed fix, events); the worker only reports what it saw.
        """
        headers = {"X-Paddock-Tenant": tenant_id} if tenant_id else {}
        r = await self._request(
            "POST", f"/v1/verifications/{verification_id}/result", json=payload, headers=headers
        )
        r.raise_for_status()
        return r.json()

    # -------- audit --------------------------------------------------------

    async def outbound_log(self, row: dict[str, Any]) -> None:
        """Audit every outbound request. This endpoint is not in the first
        CONTRACTS.md draft; see docs/ACTIVE_NOTES.md.
        """
        row = {"worker": self._worker_id, **row}
        try:
            await self._request("POST", "/v1/outbound/bulk", json={"entries": [row]})
        except Exception as e:  # pragma: no cover - best-effort audit
            log.warning("outbound_log.failed", error=str(e), row=row)


def new_outbound_row(
    *,
    target: str,
    tool: str,
    method: str | None = None,
    request_summary: str | None = None,
    response_code: int | None = None,
    scope_matched: bool = True,
    scope_entry_id: int | None = None,
    started_at: float | None = None,
    duration_ms: int | None = None,
    bytes_in: int | None = None,
    bytes_out: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "target": target,
        "tool": tool,
        "method": method,
        "request_summary": request_summary,
        "response_code": response_code,
        "scope_matched": scope_matched,
        "scope_entry_id": scope_entry_id,
        "started_at": started_at or time.time(),
        "duration_ms": duration_ms,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "error": error,
    }
