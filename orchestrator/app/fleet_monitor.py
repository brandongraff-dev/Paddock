"""Fleet agent liveness (docs/ASSURANCE_P2.md section 6): a copy of ``sensors.monitor_loop`` for host agents.

A signed heartbeat or posture is the ONLY proof of life (``fleet_posture`` refreshes ``last_seen`` and flips
``online`` back on). This loop does the other half: an agent that has been silent for more than its
``silent_after_s`` (default 300 s) is flagged ``online = FALSE`` / ``offline_since = now``, an ``agent.offline``
event is raised, and the assurance graph is invalidated so the ``host_fw`` builder drops that host's coverage
and facts within a tick. Silence is never "fine": a silent server may be the compromised one.

Legacy (v1, keyless) and revoked agents are never swept: they cannot send evidence, so flagging them would
flap an alarm forever.

Events: ``agent.offline`` / ``agent.online`` go through the integrations fan-out when those types are
registered in ``integrations.base.EVENT_TYPES``; every transition is ALSO an audit row
(``fleet.agent.offline`` / ``fleet.agent.online``, actor ``system:fleet-monitor``), so it is observable either way.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any

from . import audit, tenancy

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system:fleet-monitor"


def monitor_interval_s() -> int:
    try:
        return max(5, int(os.environ.get("FLEET_AGENT_MONITOR_SEC") or 30))
    except ValueError:
        return 30


async def emit_transition(pool: Any, agent: dict[str, Any], kind: str, **extra: Any) -> None:
    """Record ``offline``/``online`` for ``agent`` (a mapping with ``id``, ``tenant_id``, ``hostname``): an
    audit row and, when the event type exists, an integrations event. Never raises."""
    tid = str(agent["tenant_id"])
    with tenancy.tenant_context(tid):
        try:
            await audit.record(
                pool, action=f"fleet.agent.{kind}", actor=SYSTEM_ACTOR, actor_role="system",
                resource_type="fleet_agent", resource_id=str(agent["id"]),
                details={"hostname": agent["hostname"], **{k: v for k, v in extra.items() if v is not None}},
                tenant_id=tid)
        except Exception:  # noqa: BLE001
            logger.exception("fleet_transition_audit_failed", extra={"agent": str(agent["id"])})
        try:
            from .integrations import service as isvc
            from .integrations.base import EVENT_TYPES, Event

            etype = f"agent.{kind}"
            if etype not in EVENT_TYPES:
                return
            host = agent["hostname"]
            if kind == "offline":
                ev = Event(
                    type=etype, severity="high", title=f"Host agent {host} went silent",
                    summary=f"No signed heartbeat from {host} for {extra.get('silent_for_s', '?')}s: its "
                            "host evidence is no longer usable.",
                    data={"agent_id": str(agent["id"]), "hostname": host, **extra},
                    url=isvc.dashboard_url("/fleet"), tenant_id=tid,
                    id=isvc.stable_event_id(f"agent.offline:{agent['id']}:{extra.get('since', '')}"))
            else:
                ev = Event(
                    type=etype, severity="info", title=f"Host agent {host} is back",
                    summary=f"{host} is sending signed evidence again.",
                    data={"agent_id": str(agent["id"]), "hostname": host, **extra},
                    url=isvc.dashboard_url("/fleet"), tenant_id=tid,
                    id=isvc.stable_event_id(f"agent.online:{agent['id']}:{extra.get('at', '')}"))
            await isvc.emit(pool, ev)
        except Exception:  # noqa: BLE001 -- an event must never break liveness handling
            logger.exception("fleet_transition_event_failed", extra={"agent": str(agent["id"])})


async def sweep_silent(pool: Any) -> dict[str, int]:
    """Flag agents silent for longer than their ``silent_after_s``. One tenant at a time (RLS): call inside
    ``tenancy.tenant_context``."""
    async with pool.acquire() as con:
        async with con.transaction():
            rows = await con.fetch(
                """UPDATE fleet_agents SET online = FALSE, offline_since = NOW(),
                          status = CASE WHEN status IN ('online', 'enrolled', 'stale') THEN 'offline' ELSE status END
                    WHERE status <> 'revoked' AND legacy = FALSE AND online = TRUE
                      AND COALESCE(last_seen, enrolled_at) < NOW() - make_interval(secs => silent_after_s)
                RETURNING id, tenant_id, hostname, last_seen, enrolled_at, silent_after_s""")
            if rows:
                from .fleet_posture import invalidate_assurance

                await invalidate_assurance(con)
    for r in rows:
        seen = r["last_seen"] or r["enrolled_at"]
        silent_for = int((datetime.now(timezone.utc) - seen).total_seconds())
        await emit_transition(pool, dict(r), "offline", since=seen.isoformat(), silent_for_s=silent_for,
                              silent_after_s=r["silent_after_s"])
    return {"offline": len(rows)}


async def sweep_all_tenants(pool: Any) -> int:
    n = 0
    for tid in await tenancy.list_tenant_ids(pool):
        with tenancy.tenant_context(tid):
            n += (await sweep_silent(pool))["offline"]
    return n


async def fleet_agent_monitor_loop(app: Any) -> None:
    """Background task (started from the lifespan): never dies on an error."""
    interval = monitor_interval_s()
    logger.info("fleet_agent_monitor_started", extra={"interval_sec": interval})
    while True:
        try:
            await asyncio.sleep(interval)
            pool = getattr(app.state, "pool", None)
            if pool is not None:
                await sweep_all_tenants(pool)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("fleet_agent_monitor_failed")
