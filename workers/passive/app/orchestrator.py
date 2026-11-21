"""Thin async HTTP client to the orchestrator.

This is the ONLY way this worker talks to the shared store. We never touch
Postgres or Redis streams directly for state writes — that's the orchestrator's
job. We *do* read from `queue:passive` on Redis (CONTRACTS.md puts queues on
the worker side).

The scope_check endpoint is the hard gate:
  POST /v1/scope/check  {target: str}
    -> {allow: bool, matched_entry?: int, normalized: str, reason: str}

We cache allow decisions for `scope_cache_ttl_s` seconds (default 60) and
re-check otherwise. Dropped (deny) items increment a counter and are not
logged with their value to avoid leaking out-of-scope strings.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import aiohttp
from loguru import logger

from .config import Settings
from .util.cache import TTLCache


@dataclass
class ScopeDecision:
    allow: bool
    normalized: str
    reason: str
    matched_entry: Optional[int] = None


class OrchestratorClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._session: Optional[aiohttp.ClientSession] = None
        self._scope_cache: TTLCache[ScopeDecision] = TTLCache(
            ttl_seconds=settings.scope_cache_ttl_s
        )
        # counters we expose for log summaries
        self.dropped_out_of_scope = 0

    async def __aenter__(self) -> "OrchestratorClient":
        await self.start()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.settings.http_timeout_s)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": self.settings.http_user_agent},
            )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("OrchestratorClient used outside of start()/aenter")
        return self._session

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    async def scope_check(self, value: str) -> ScopeDecision:
        cached = await self._scope_cache.get(value)
        if cached is not None:
            return cached
        url = f"{self.settings.orchestrator_url}/v1/scope/check"
        try:
            async with self.session.post(url, json={"target": value}) as resp:
                resp.raise_for_status()
                data = await resp.json()
        except Exception as e:
            # Fail-closed: a scope service outage must not open the gate.
            logger.warning("scope_check failed; failing closed value_hash={}", hash(value))
            return ScopeDecision(
                allow=False, normalized=value, reason=f"scope_check_error: {e!s}"
            )
        decision = ScopeDecision(
            allow=bool(data.get("allow", False)),
            normalized=str(data.get("normalized", value)),
            reason=str(data.get("reason", "")),
            matched_entry=data.get("matched_entry"),
        )
        await self._scope_cache.set(value, decision)
        return decision

    async def filter_in_scope(self, values: Iterable[str]) -> list[str]:
        """Async-parallel scope check of a batch; returns only allowed values."""
        values = list(set(v for v in values if v))
        if not values:
            return []
        decisions = await asyncio.gather(*(self.scope_check(v) for v in values))
        kept: list[str] = []
        for v, d in zip(values, decisions):
            if d.allow:
                kept.append(d.normalized or v)
            else:
                self.dropped_out_of_scope += 1
        return kept

    # ------------------------------------------------------------------
    # Assets / Findings
    # ------------------------------------------------------------------
    async def post_assets(self, assets: list[dict[str, Any]]) -> dict[str, Any]:
        if not assets:
            return {"accepted": 0, "ids": []}
        url = f"{self.settings.orchestrator_url}/v1/assets/bulk"
        async with self.session.post(url, json={"assets": assets}) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def post_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        if not findings:
            return {"accepted": 0, "ids": []}
        url = f"{self.settings.orchestrator_url}/v1/findings/bulk"
        async with self.session.post(url, json={"findings": findings}) as resp:
            resp.raise_for_status()
            return await resp.json()

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        result_summary: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Best-effort scan status update.

        CONTRACTS.md does not spell out a scan-status mutation endpoint; we
        document the one we use in docs/PASSIVE_NOTES.md. We try PATCH first
        (clean REST) and fall back to POST .../status.
        """
        body: dict[str, Any] = {"status": status}
        if result_summary is not None:
            body["result_summary"] = result_summary
        if error is not None:
            body["error"] = error

        patch_url = f"{self.settings.orchestrator_url}/v1/scans/{scan_id}"
        post_url = f"{self.settings.orchestrator_url}/v1/scans/{scan_id}/status"
        try:
            async with self.session.patch(patch_url, json=body) as resp:
                if resp.status < 400:
                    return
                if resp.status not in (404, 405):
                    resp.raise_for_status()
        except aiohttp.ClientResponseError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("scan PATCH failed scan_id={} err={}", scan_id, e)

        try:
            async with self.session.post(post_url, json=body) as resp:
                if resp.status >= 400:
                    logger.warning(
                        "scan status fallback POST failed scan_id={} status={}",
                        scan_id, resp.status,
                    )
        except Exception as e:  # noqa: BLE001
            logger.warning("scan POST failed scan_id={} err={}", scan_id, e)
