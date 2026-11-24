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
from app import tenancy
from app.config import settings

log = structlog.get_logger(__name__)


class OrchestratorError(RuntimeError):
    pass


#: orchestrator bulk endpoints accept at most 1000 rows per request (AssetBulkIn/EdgeBulkIn/FindingBulkIn).
BULK_MAX = 1000


def _chunks(rows: list[dict[str, Any]], n: int = BULK_MAX):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


def assets_bulk_body(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Exact ``AssetBulkIn`` body: ``{"items": [{kind, value, canonical, source, metadata}]}``."""
    return {"items": list(assets)}


def edges_bulk_body(edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Exact ``EdgeBulkIn`` body: ``{"edges": [{src_kind, src_canonical, dst_kind, dst_canonical, kind}]}``."""
    return {"edges": list(edges)}


_TARGET_KEYS = ("target_host", "target_canonical", "target_kind")


def findings_bulk_body(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Exact ``FindingBulkIn`` body. Maps the modules' ``target_*`` keys to ``asset_value/asset_kind``.

    A finding with no target cannot be attached to an asset, so it raises rather than being dropped:
    a finding that silently vanishes is how a tool-failure marker used to go missing.
    """
    items: list[dict[str, Any]] = []
    for f in findings:
        item = {k: v for k, v in f.items() if k not in _TARGET_KEYS}
        if not item.get("asset_id") and not item.get("asset_value"):
            value = f.get("target_canonical") or f.get("target_host")
            if not value:
                raise OrchestratorError(f"finding {f.get('rule_id')!r} has no target to attach to")
            item["asset_value"] = value
            if f.get("target_kind") and not item.get("asset_kind"):
                item["asset_kind"] = f["target_kind"]
        items.append(item)
    return {"items": items}


class OrchestratorClient:
    """Thin async client with retries and the worker's identity baked in."""

    def __init__(self, base_url: str | None = None, worker_id: str | None = None):
        self._base = (base_url or settings.orchestrator_url).rstrip("/")
        self._worker_id = worker_id or settings.worker_id
        self._client = httpx.AsyncClient(
            base_url=self._base,
            timeout=httpx.Timeout(settings.http_timeout_sec),
            # Echo the job's tenant + scan on EVERY callback (app/tenancy.py): the
            # orchestrator verifies they match the job it issued.
            event_hooks={"request": [tenancy.httpx_request_hook]},
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
        r = await self._request(
            "POST",
            f"/v1/scans/{scan_id}/complete",
            json={"result_summary": result_summary},
        )
        r.raise_for_status()

    async def scan_fail(self, scan_id: str, error: str) -> None:
        r = await self._request("POST", f"/v1/scans/{scan_id}/fail", json={"error": error})
        r.raise_for_status()

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
        """POST /v1/assets/bulk ``{"items": [...]}`` then POST /v1/edges/bulk ``{"edges": [...]}``.

        The orchestrator's ``AssetBulkIn`` accepts ``items`` only and edges go to their own endpoint;
        this client used to post ``{"assets", "edges"}`` to /assets/bulk, which was a 422 that the
        worker swallowed while still completing the scan (Provable Containment builders-1). Any
        non-2xx, or a response that does not account for every row sent, RAISES: the caller must
        treat "results not posted" as a failed scan, never as a clean one.
        """
        out: dict[str, Any] = {"assets_sent": 0, "edges_sent": 0}
        for chunk in _chunks(assets):
            body = assets_bulk_body(chunk)
            r = await self._request("POST", "/v1/assets/bulk", json=body)
            r.raise_for_status()
            data = r.json()
            landed = int(data.get("inserted", -1)) + int(data.get("updated", -1))
            if landed != len(chunk):
                raise OrchestratorError(
                    f"assets bulk accepted {landed} of {len(chunk)} rows")
            out["assets_sent"] += len(chunk)
        if edges:
            out["edges_sent"] = (await self.edges_bulk(edges))["edges_sent"]
        return out

    async def edges_bulk(self, edges: list[dict[str, Any]]) -> dict:
        """POST /v1/edges/bulk ``{"edges": [...]}`` (EdgeBulkIn); raises on any non-2xx."""
        out = {"edges_sent": 0, "edges_skipped_missing_endpoint": 0}
        for chunk in _chunks(edges):
            r = await self._request("POST", "/v1/edges/bulk", json=edges_bulk_body(chunk))
            r.raise_for_status()
            data = r.json()
            out["edges_sent"] += len(chunk)
            out["edges_skipped_missing_endpoint"] += int(data.get("edges_skipped_missing_endpoint", 0))
        if out["edges_skipped_missing_endpoint"]:
            # Edges are graph decoration (the assurance builder reads port assets), so a skipped
            # edge is a warning; a rejected request still raises above.
            log.warning("edges_bulk.skipped_missing_endpoint", n=out["edges_skipped_missing_endpoint"])
        return out

    async def findings_bulk(self, findings: list[dict[str, Any]]) -> dict:
        """POST /v1/findings/bulk ``{"items": [...]}`` (FindingBulkIn); raises on any non-2xx.

        Modules describe the target as ``target_canonical``/``target_host``/``target_kind``; the
        orchestrator wants ``asset_value``/``asset_kind`` (or an ``asset_id``). The translation is
        done here, once, by :func:`findings_bulk_body`.
        """
        out: dict[str, Any] = {"findings_sent": 0}
        for chunk in _chunks(findings):
            r = await self._request("POST", "/v1/findings/bulk", json=findings_bulk_body(chunk))
            r.raise_for_status()
            r.json()
            out["findings_sent"] += len(chunk)
        return out

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
