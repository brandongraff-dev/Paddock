"""Chromium screenshotter.

One screenshot per endpoint. Playwright is a heavy dependency; this module
is written so an environment without playwright installed still surfaces
a clean "tool unavailable" finding rather than killing the worker.
"""
from __future__ import annotations

import hashlib
import os
import time
from typing import Any
from urllib.parse import urlsplit

import structlog

from app import USER_AGENT
from app.config import settings
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeGuard, normalize_target
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


async def capture(
    url: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    asset_id: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    await scope.allow(url)
    host = _host_of(url)

    try:
        from playwright.async_api import async_playwright
    except Exception:
        return {
            "assets": [], "edges": [], "findings": [{
                "target_host": host,
                "target_canonical": normalize_target(url),
                "target_kind": "endpoint",
                "rule_id": "tool-unavailable-playwright",
                "rule_source": "policy",
                "severity": "info",
                "title": "playwright not installed on this worker",
                "description": "Screenshot module skipped; playwright import failed.",
                "evidence": {"tool": "playwright"},
            }],
            "summary": {},
        }

    allowed_host = urlsplit(url).hostname
    os.makedirs(os.path.join(settings.data_dir, "screenshots"), exist_ok=True)
    stem = asset_id or hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    out_path = os.path.join(settings.data_dir, "screenshots", f"{stem}.png")

    async with politeness.acquire(host):
        t0 = time.monotonic()
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    ctx = await browser.new_context(
                        viewport={"width": settings.screenshot_viewport_width,
                                  "height": settings.screenshot_viewport_height},
                        device_scale_factor=settings.screenshot_device_scale,
                        user_agent=USER_AGENT,
                        ignore_https_errors=False,
                    )
                    # Block third-party domains: no outbound trackers, no data leaks.
                    async def _route(route, request):
                        rhost = urlsplit(request.url).hostname or ""
                        if rhost and allowed_host and rhost != allowed_host and not rhost.endswith("." + allowed_host):
                            await route.abort()
                        else:
                            await route.continue_()
                    await ctx.route("**/*", _route)
                    page = await ctx.new_page()
                    await page.goto(url, timeout=settings.screenshot_timeout_ms,
                                    wait_until="domcontentloaded")
                    await page.screenshot(path=out_path, full_page=False)
                    await ctx.close()
                finally:
                    await browser.close()
        except Exception as e:
            await orchestrator.outbound_log(new_outbound_row(
                target=url, tool="playwright", method="screenshot",
                error=str(e), scope_matched=True,
            ))
            log.warning("screenshot.error", url=url, error=str(e))
            return {"assets": [], "edges": [], "findings": [], "summary": {"error": str(e)}}
    duration_ms = int((time.monotonic() - t0) * 1000)
    await orchestrator.outbound_log(new_outbound_row(
        target=url, tool="playwright", method="screenshot",
        duration_ms=duration_ms, scope_matched=True,
    ))

    size = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    assets = [{
        "kind": "endpoint",
        "value": url,
        "canonical": normalize_target(url),
        "source": "screenshot",
        "metadata": {
            "screenshot_path": out_path,
            "screenshot_bytes": size,
            "viewport": [settings.screenshot_viewport_width, settings.screenshot_viewport_height],
            "device_scale_factor": settings.screenshot_device_scale,
        },
    }]
    return {"assets": assets, "edges": [], "findings": [], "summary": {"path": out_path, "bytes": size}}
