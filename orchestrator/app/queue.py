"""Redis helpers: scan job enqueue + event stream fan-out.

Jobs go onto Redis Streams (not plain lists) so workers can run as a
consumer group and acknowledge individually. The queue a scan lands on
is picked from its `kind` prefix: everything before the first `_`:

    passive_subdomains        -> queue:passive
    active_http_probe         -> queue:active
    correlate_chains          -> queue:correlate
    nuclei_scan               -> queue:active  (explicit alias)
    httpx / tlsx / katana ... -> queue:active  (explicit aliases)

The consumer side is not part of the orchestrator; workers XREADGROUP
from these streams.

`stream:events` is for fan-out of lifecycle events (asset_added,
finding_opened, ...). The dashboard and correlation subscribe to it.
"""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
from fastapi import Request

from . import tenancy
from .config import settings

logger = logging.getLogger(__name__)

# Explicit aliases for scan kinds that do not match the prefix convention.
_KIND_TO_QUEUE: dict[str, str] = {
    "nuclei": "active",
    "nuclei_scan": "active",
    "httpx": "active",
    "naabu": "active",
    "katana": "active",
    "tlsx": "active",
    "playwright": "active",
    "shodan": "passive",
    "ct_logs": "passive",
    "github_search": "passive",
    "wayback": "passive",
    "dns": "passive",
}


def _bucket_for_kind(kind: str) -> str:
    k = kind.lower().strip()
    if k in _KIND_TO_QUEUE:
        return _KIND_TO_QUEUE[k]
    prefix = k.split("_", 1)[0]
    if prefix in {"passive", "active", "correlate"}:
        return prefix
    # Unknown: default to active queue (least privileged, worker still scope-checks).
    return "active"


def queue_name_for(kind: str) -> str:
    return {
        "passive": settings.queue_passive,
        "active": settings.queue_active,
        "correlate": settings.queue_correlate,
    }[_bucket_for_kind(kind)]


async def create_redis(url: str | None = None) -> aioredis.Redis:
    # socket_timeout must exceed the longest XREAD block (SSE tails the event
    # stream with block=15s); redis-py >= 6 defaults it to 5s, which made every
    # idle /v1/events read fail with "Timeout reading from redis".
    r: aioredis.Redis = aioredis.from_url(
        url or settings.redis_url, decode_responses=True, socket_timeout=60
    )
    await r.ping()
    return r


def get_redis(request: Request) -> aioredis.Redis:
    r = getattr(request.app.state, "redis", None)
    if r is None:
        raise RuntimeError("redis client not initialised on app.state.redis")
    return r


async def enqueue_scan(r: aioredis.Redis, job: dict[str, Any]) -> str:
    """Push a scan job onto its kind-specific stream. Returns the stream id."""
    stream = queue_name_for(job["kind"])
    # Workers echo this back (X-Paddock-Tenant) so their callbacks land in the
    # tenant that queued the job.
    # Every queued unit of work names its tenant (workers bind it for the whole
    # job and echo it back on each callback; job_binding.py verifies it).
    if "tenant_id" not in job:
        tid = tenancy.current_tenant_id()
        if tid is None:
            raise RuntimeError("refusing to enqueue a scan job without a tenant (TENANCY_STRICT)")
        job = {**job, "tenant_id": tid}
    # Streams want flat string fields; encode the whole job as JSON under 'job'.
    sid = await r.xadd(stream, {"job": json.dumps(job, default=str)})
    logger.info(
        "scan_enqueued", extra={"stream": stream, "stream_id": sid, "scan_id": job.get("scan_id")}
    )
    return sid


async def publish_event(r: aioredis.Redis, event: dict[str, Any]) -> str:
    # Consumers (correlation, triage, changewatch, intel, integrations ...) bind
    # the event's tenant before touching data, so every event says whose it is.
    if "tenant_id" not in event:
        tid = tenancy.current_tenant_id()
        if tid is not None:
            event = {**event, "tenant_id": tid}
    sid = await r.xadd(settings.events_stream, {"event": json.dumps(event, default=str)})
    return sid


async def read_events(
    r: aioredis.Redis, since: str = "$", block_ms: int = 15000, count: int = 50
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Async iterator over stream:events. Yields (stream_id, event_dict).

    `since` is a stream id. `$` means 'only new messages'. `0` means 'from
    the beginning'. The caller is responsible for tracking the last id.
    """
    last_id = since
    while True:
        resp = await r.xread({settings.events_stream: last_id}, count=count, block=block_ms)
        if not resp:
            # keep-alive tick so SSE clients can detect hangups
            yield (last_id, {"event": "keepalive"})
            continue
        for _stream, entries in resp:
            for sid, fields in entries:
                last_id = sid
                raw = fields.get("event")
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    payload = {"raw": raw}
                yield (sid, payload)
