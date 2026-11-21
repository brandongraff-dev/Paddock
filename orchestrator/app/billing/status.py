"""Public status endpoint: ``GET /status``.

Unauthenticated, so it is deliberately boring: a fixed set of component names,
each ``up`` or ``degraded``, an overall verdict and a timestamp. No versions,
hostnames, error text, tenant data or counts. The result is cached in-process
(``STATUS_CACHE_SEC``, default 15 s) so a public page, an uptime monitor or an
attacker cannot turn it into load on the database.

Components: ``api`` (this process answered), ``database``, ``queue`` (Redis),
``scheduler`` (the background loop, only when enabled).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import weakref
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["status"])

CACHE_SEC = float(os.environ.get("STATUS_CACHE_SEC", "15"))
_PROBE_TIMEOUT = 2.0
_cache: tuple[float, dict[str, Any]] | None = None
_locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _locks.get(loop)
    if lock is None:
        lock = _locks[loop] = asyncio.Lock()
    return lock


def reset_cache() -> None:
    global _cache
    _cache = None


async def _probe(coro) -> str:
    try:
        await asyncio.wait_for(coro, timeout=_PROBE_TIMEOUT)
        return "up"
    except Exception:  # noqa: BLE001 -- the reason is intentionally not exposed
        return "degraded"


async def _db(app) -> None:
    async with app.state.pool.acquire() as con:
        await con.execute("SELECT 1")


async def _redis(app) -> None:
    await app.state.redis.ping()


async def collect(app) -> dict[str, Any]:
    components = [{"name": "api", "status": "up"}]
    components.append({"name": "database", "status": await _probe(_db(app)) if getattr(app.state, "pool", None) else "degraded"})
    components.append({"name": "queue", "status": await _probe(_redis(app)) if getattr(app.state, "redis", None) else "degraded"})
    if settings.scheduler_enabled:
        task = getattr(app.state, "scheduler_task", None)
        # A test/embedded app without the lifespan has no task: report nothing
        # rather than a false alarm.
        if task is not None:
            components.append({"name": "scheduler", "status": "degraded" if task.done() else "up"})
    degraded = any(c["status"] != "up" for c in components)
    return {
        "status": "degraded" if degraded else "operational",
        "components": components,
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


@router.get("/status")
async def public_status(request: Request) -> JSONResponse:
    global _cache
    now = time.monotonic()
    cached = _cache
    if cached is None or now - cached[0] >= CACHE_SEC:
        async with _lock():  # one probe at a time; late arrivals reuse its result
            cached = _cache
            if cached is None or time.monotonic() - cached[0] >= CACHE_SEC:
                cached = (time.monotonic(), await collect(request.app))
                _cache = cached
    return JSONResponse(
        cached[1],
        headers={"Cache-Control": f"public, max-age={int(CACHE_SEC)}", "X-Content-Type-Options": "nosniff"},
    )
