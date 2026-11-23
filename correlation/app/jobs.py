"""Consumer for the orchestrator's Redis fallback jobs (``queue:correlate``).

When correlation is unreachable the orchestrator ``XADD``s one entry per job to
the ``queue:correlate`` stream::

    {"job": json.dumps({"kind": ..., "op": <op>, "tenant_id": <uuid>,
                        "payload": {...}})}      # payload only for twin_* ops

Semantics (this module owns them; ``main._job_handlers`` supplies the ops):

* Every job runs inside ITS tenant (``tenancy.tenant_context``). A job with no
  / malformed ``tenant_id`` is rejected (logged, acked, never run), even in
  non-strict mode: queued work must never silently fall into another tenant.
* Ack only after the handler succeeded.
* Poison messages (unparseable, missing tenant, invalid payload, a 4xx from the
  shared endpoint code, unknown ``op``) are logged and acked: retrying cannot
  fix them.
* Transient errors leave the entry pending; it is re-claimed after
  ``RETRY_IDLE_MS`` and, after ``MAX_ATTEMPTS`` deliveries, copied to the
  ``<stream>:dead`` dead-letter stream and acked.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Mapping

from . import tenancy

log = logging.getLogger("correlation.jobs")

MAX_ATTEMPTS = 5
RETRY_IDLE_MS = 30_000
DEAD_SUFFIX = ":dead"

Handler = Callable[[Any], Awaitable[Any]]


class PoisonJob(Exception):
    """The job can never succeed (bad shape / payload); ack and drop it."""


async def process(handlers: Mapping[str, Handler], fields: Mapping[str, Any]) -> bool:
    """Run one queue entry. Returns ``True`` when it is finished (done, or
    poison / unknown and so to be acked); raises on a transient failure (the
    caller must NOT ack)."""
    raw = fields.get("job")
    try:
        job = json.loads(raw) if isinstance(raw, (str, bytes)) else None
    except (ValueError, RecursionError):
        job = None
    if not isinstance(job, dict):
        log.warning("dropping malformed queue job (not a JSON object)")
        return True
    op = job.get("op")
    try:
        tid = tenancy.event_tenant(job)
    except tenancy.TenantError as exc:
        log.warning("rejecting job %r: bad tenant_id: %s", op, exc)
        return True
    if tid is None:
        log.warning("rejecting job %r: no tenant_id (never run cross-tenant)", op)
        return True
    handler = handlers.get(op) if isinstance(op, str) else None
    if handler is None:
        log.warning("dropping job with unknown op %r (tenant %s)", op, tid)
        return True
    try:
        with tenancy.tenant_context(tid):
            await handler(job.get("payload"))
    except PoisonJob as exc:
        log.warning("poison job %s (tenant %s): %s", op, tid, exc)
    except Exception as exc:
        status = getattr(exc, "status_code", None)  # HTTPException from shared code
        if isinstance(status, int) and 400 <= status < 500 and status not in (408, 429):
            log.warning("poison job %s (tenant %s): rejected %s: %s", op, tid, status,
                        getattr(exc, "detail", ""))
        else:
            raise
    return True


async def _handle(redis: Any, stream: str, group: str, handlers: Mapping[str, Handler],
                  msg_id: str, fields: Mapping[str, Any]) -> None:
    try:
        await process(handlers, fields)
    except asyncio.CancelledError:
        raise
    except Exception:
        attempts = await _deliveries(redis, stream, group, msg_id)
        if attempts < MAX_ATTEMPTS:
            log.exception("job %s failed (attempt %d/%d); will retry", msg_id, attempts, MAX_ATTEMPTS)
            return
        log.error("job %s failed %d times; moving to dead-letter", msg_id, attempts, exc_info=True)
        try:
            await redis.xadd(stream + DEAD_SUFFIX, dict(fields))
        except Exception:
            log.exception("dead-letter write failed for %s; leaving pending", msg_id)
            return
    await redis.xack(stream, group, msg_id)


async def _deliveries(redis: Any, stream: str, group: str, msg_id: str) -> int:
    try:
        rows = await redis.xpending_range(stream, group, min=msg_id, max=msg_id, count=1)
        if rows:
            r = rows[0]
            return int(r["times_delivered"] if isinstance(r, dict) else r[3])
    except Exception:
        log.warning("xpending_range failed for %s", msg_id)
    return 1


async def consume(redis: Any, *, stream: str, group: str, consumer: str,
                  handlers: Mapping[str, Handler]) -> None:
    """Consumer loop: new entries, plus re-claim of entries pending too long."""
    try:
        # id="0": jobs queued while correlation was down must still be consumed.
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            log.warning("xgroup_create(%s): %s", stream, e)
    log.info("job consumer started: stream=%s group=%s name=%s", stream, group, consumer)
    while True:
        try:
            # entries left pending by a failed attempt (or a dead consumer)
            claimed = await redis.xautoclaim(stream, group, consumer,
                                             min_idle_time=RETRY_IDLE_MS, start_id="0-0", count=16)
            for msg_id, fields in (claimed[1] if claimed else []):
                if fields is not None:
                    await _handle(redis, stream, group, handlers, msg_id, fields)
            resp = await redis.xreadgroup(groupname=group, consumername=consumer,
                                          streams={stream: ">"}, count=16, block=5000)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("job queue read failed; backing off")
            await asyncio.sleep(2.0)
            continue
        for _name, items in resp or []:
            for msg_id, fields in items:
                await _handle(redis, stream, group, handlers, msg_id, fields)
