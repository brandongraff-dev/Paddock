"""Integrations worker: ``python -m app.integrations.worker``.

Two loops in one process:

1. **Dispatcher** -- consumes ``stream:events`` as consumer group
   ``integrations`` (XREADGROUP), maps each entry to an ``Event``
   (``service.event_from_stream``), fans it out with ``service.emit`` and
   XACKs. On start it first re-reads its own pending entries (id ``0``), so a
   crash between read and ack never loses an event; ``emit`` is idempotent so
   re-processing never double-sends.
2. **Delivery loop** -- every ``INTEGRATIONS_POLL_SEC`` claims due deliveries
   (lease + SKIP LOCKED: safe to run several replicas) and hands them to the
   connector, with exponential backoff and dead-lettering.

It never accepts inbound connections. Secrets are decrypted per batch, in
memory only.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import time
from typing import Any, Optional

import httpx

from ..config import settings
from ..db import create_pool
from ..middleware import configure_logging
from ..queue import create_redis
from . import service
from .settings import isettings

log = logging.getLogger("app.integrations.worker")


def consumer_name() -> str:
    return isettings.integrations_consumer_name or socket.gethostname() or f"pid-{os.getpid()}"


async def ensure_group(r: Any, stream: str, group: str) -> None:
    try:
        await r.xgroup_create(stream, group, id="$", mkstream=True)
    except Exception as exc:  # noqa: BLE001
        if "BUSYGROUP" not in str(exc):
            raise


async def handle_entry(pool: Any, sid: str, fields: dict[str, Any]) -> bool:
    """Map + emit one stream entry. Returns True when it may be acked."""
    try:
        event = await service.event_from_stream(pool, fields, sid)
    except Exception:  # noqa: BLE001 -- a malformed entry must not wedge the stream
        log.exception("integration_stream_map_failed", extra={"stream_id": sid})
        return True
    if event is None:
        return True
    # fan_out (not emit) so a DB outage leaves the entry un-acked for retry.
    try:
        await service.fan_out(pool, event)
    except Exception:  # noqa: BLE001
        log.exception("integration_fan_out_failed", extra={"stream_id": sid})
        return False
    return True


async def consume_once(pool: Any, r: Any, *, stream: str, group: str, consumer: str,
                       start_id: str = ">", block_ms: int | None = 5000, count: int = 50) -> int:
    """Read one batch; returns how many entries were processed AND acked."""
    resp = await r.xreadgroup(group, consumer, {stream: start_id}, count=count, block=block_ms)
    acked = 0
    for _stream, entries in resp or []:
        for sid, fields in entries:
            if not fields or await handle_entry(pool, sid, fields):   # empty == trimmed while pending
                await r.xack(stream, group, sid)
                acked += 1
    return acked


async def reclaim_stale(r: Any, *, stream: str, group: str, consumer: str, min_idle_ms: int = 60_000) -> None:
    try:
        await r.xautoclaim(stream, group, consumer, min_idle_time=min_idle_ms, start_id="0-0", count=500)
    except Exception:  # noqa: BLE001 -- older servers / fakes: own-PEL drain still runs
        log.debug("xautoclaim unavailable", exc_info=True)


async def dispatcher_loop(pool: Any, r: Any, stop: asyncio.Event) -> None:
    stream, group, consumer = settings.events_stream, isettings.integrations_consumer_group, consumer_name()
    await ensure_group(r, stream, group)
    # Take over entries a dead replica read but never acked, then drain our
    # own un-acked backlog before reading new entries.
    await reclaim_stale(r, stream=stream, group=group, consumer=consumer)
    while not stop.is_set():
        if await consume_once(pool, r, stream=stream, group=group, consumer=consumer,
                              start_id="0", block_ms=1) == 0:
            break
    while not stop.is_set():
        try:
            await consume_once(pool, r, stream=stream, group=group, consumer=consumer)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("integration_dispatcher_error")
            await _sleep(stop, 2.0)


async def delivery_loop(pool: Any, stop: asyncio.Event,
                        transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
    while not stop.is_set():
        try:
            n = await service.process_due(pool, transport=transport)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("integration_delivery_loop_error")
            n = 0
        _heartbeat()
        if n < isettings.integrations_batch:
            await _sleep(stop, isettings.integrations_poll_sec)


def _heartbeat() -> None:
    try:
        with open(isettings.integrations_heartbeat_path, "w") as fh:
            fh.write(str(int(time.time())))
    except OSError:
        pass


async def _sleep(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def run() -> None:
    configure_logging()
    service.load_connectors()
    pool = await create_pool()
    r = await create_redis()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass
    log.info("integrations_worker_started", extra={"consumer": consumer_name()})
    tasks = [asyncio.create_task(dispatcher_loop(pool, r, stop)),
             asyncio.create_task(delivery_loop(pool, stop))]
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await r.aclose()
    await pool.close()
    log.info("integrations_worker_stopped")


def main() -> None:  # pragma: no cover
    asyncio.run(run())


if __name__ == "__main__":  # pragma: no cover
    main()
