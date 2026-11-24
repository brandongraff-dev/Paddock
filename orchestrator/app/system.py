"""System inventory: ``GET /v1/system`` (admin).

Answers "what is actually running in this install?" for the dashboard's
Settings -> System page: the Paddock version, the edition, the profile
(auth mode, scheduler) and one row per component with a health state.

Components are the stateful core (database, queue, scheduler) plus the compute
services the orchestrator proxies to. A service's state is one of

* ``up``             -- answered ``/healthz``;
* ``down``           -- configured and resolvable but not answering (a crash,
                        a slow start, a failing health check);
* ``not_installed``  -- its hostname does not resolve, which is what the lite
                        stack looks like for every service it leaves out.

No URLs, hostnames, error text or secrets are returned, only fixed keys and
labels. The result is cached in-process for a few seconds so refreshing the
page cannot turn into probe load.
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
import weakref
from importlib import metadata
from typing import Any

from fastapi import APIRouter, Depends, Request

from . import licensing
from .auth import require
from .billing import status as billing_status
from .config import settings

router = APIRouter(prefix="/v1/system", tags=["system"])

CACHE_SEC = float(os.environ.get("SYSTEM_CACHE_SEC", "10"))
_PROBE_TIMEOUT = 1.5

# key, label, what it does, settings attribute holding its base URL
SERVICES: tuple[tuple[str, str, str, str], ...] = (
    ("correlation", "Correlation", "Attack paths and chains across findings", "correlation_url"),
    ("brain", "Brain", "Triage and natural-language Ask", "brain_url"),
    ("graphsync", "Graph sync", "Neo4j-backed graph paths and blast radius", "graphsync_url"),
    ("codeanalysis", "Code analysis", "Reachability and static analysis (SAST)", "codeanalysis_url"),
    ("mlrisk", "Risk model", "Adaptive risk ranking and anomaly detection", "mlrisk_url"),
    ("ontology", "Ontology", "Asset and finding vocabulary and mappings", "ontology_url"),
    ("threatintel", "Threat intel", "CVE, EPSS and KEV enrichment", "threatintel_url"),
    ("otdiscovery", "Device discovery", "IoT and OT devices from Sentry sensors", "otdiscovery_url"),
    ("remediation", "Remediation", "Fix generation behind the approval gate", "remediation_url"),
)

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


def version() -> str:
    """``PADDOCK_VERSION`` (set by the release build) > package metadata > 0.1.0."""
    v = os.environ.get("PADDOCK_VERSION")
    if v:
        return v
    try:
        return metadata.version("paddock-orchestrator")
    except metadata.PackageNotFoundError:
        return "0.1.0"


def _is_dns_failure(exc: BaseException) -> bool:
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, socket.gaierror):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


async def _probe_service(base_url: str) -> str:
    try:
        import httpx  # lazy: keeps the import optional like the other proxies
    except Exception:  # noqa: BLE001
        return "down"
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as http:
            r = await http.get(base_url.rstrip("/") + "/healthz")
        return "up" if r.status_code < 400 else "down"
    except Exception as exc:  # noqa: BLE001 -- the reason is intentionally not exposed
        return "not_installed" if _is_dns_failure(exc) else "down"


async def collect(app) -> dict[str, Any]:
    st = await billing_status.collect(app)
    core_labels = {
        "api": ("API", "Orchestrator: auth, scope, assets, findings, audit"),
        "database": ("Database", "PostgreSQL with row-level tenant isolation"),
        "queue": ("Queue", "Redis: jobs and the live event stream"),
        "scheduler": ("Scheduler", "Continuous-monitoring schedules"),
    }
    core = [
        {
            "key": c["name"],
            "label": core_labels.get(c["name"], (c["name"], ""))[0],
            "description": core_labels.get(c["name"], ("", ""))[1],
            "status": "up" if c["status"] == "up" else "down",
        }
        for c in st["components"]
    ]
    results = await asyncio.gather(*(_probe_service(getattr(settings, attr)) for _, _, _, attr in SERVICES))
    services = [
        {"key": key, "label": label, "description": desc, "status": status}
        for (key, label, desc, _), status in zip(SERVICES, results)
    ]
    counts = {"up": 0, "down": 0, "not_installed": 0}
    for row in core + services:
        counts[row["status"]] += 1
    return {
        "version": version(),
        "auth_mode": settings.auth_mode,
        "scheduler_enabled": settings.scheduler_enabled,
        "core": core,
        "services": services,
        "counts": counts,
    }


@router.get("", dependencies=[Depends(require("admin"))])
async def system_inventory(request: Request) -> dict[str, Any]:
    """What this install is made of, and what is healthy right now."""
    global _cache
    now = time.monotonic()
    cached = _cache
    if cached is None or now - cached[0] >= CACHE_SEC:
        async with _lock():
            cached = _cache
            if cached is None or time.monotonic() - cached[0] >= CACHE_SEC:
                cached = (time.monotonic(), await collect(request.app))
                _cache = cached
    lic = await licensing.current_license(request)  # per tenant, so never cached above
    return {**cached[1], "edition": lic.edition, "license_status": lic.status}
