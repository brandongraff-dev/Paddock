"""Continuous-monitoring scheduler.

A single background task (started from the FastAPI lifespan) wakes every
`settings.scheduler_interval_sec` seconds, reads the enabled `schedules` that
are due, and enqueues the scan(s) for each schedule's `target_scope` by
reusing the exact dispatch path `POST /v1/scans` uses
(`scans.dispatch_scoped_scan`). It then records `last_run_at`, `last_scan_id`,
`last_status` and the computed `next_run_at`.

Hard guarantees:
- The scheduler NEVER probes anything itself. It only resolves scope entries
  to target strings and enqueues jobs onto Redis; workers do the probing and
  the per-request scope check still applies at dispatch.
- A single bad schedule can never kill the loop: every tick and every
  per-schedule run is wrapped in try/except.
- `croniter` is an optional import. When it is missing (or a schedule has no
  cron) the next run is computed from `config.every_n_minutes`, falling back
  to `settings.scheduler_default_minutes`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import settings
from .models import ScheduleOut, ScheduleRunOut
from .routers import scans as scans_mod

logger = logging.getLogger(__name__)

# Optional dependency. If croniter is installed we honour cron strings;
# otherwise schedules fall back to config.every_n_minutes.
try:  # pragma: no cover - import guard
    from croniter import croniter as _croniter  # type: ignore
except Exception:  # pragma: no cover - exercised via croniter_cls=None in tests
    _croniter = None


def croniter_available() -> bool:
    """True when the optional `croniter` dependency is importable."""
    return _croniter is not None


# --------------------------------------------------------------------------- #
# Next-run computation (pure, unit-tested)
# --------------------------------------------------------------------------- #

def compute_next_run(
    now: datetime,
    cron: str | None = None,
    config: dict[str, Any] | None = None,
    croniter_cls: Any = _croniter,
) -> datetime:
    """Return the next run time strictly after `now`.

    - With a cron string AND croniter available -> croniter's next tick.
    - Otherwise -> `now + config.every_n_minutes` (minutes), falling back to
      `settings.scheduler_default_minutes`.

    `croniter_cls` is injectable so both branches are unit-testable
    regardless of whether croniter is installed in the environment.
    """
    config = config or {}
    if cron and croniter_cls is not None:
        try:
            return croniter_cls(cron, now).get_next(datetime)
        except Exception:
            logger.warning("cron_parse_failed", extra={"cron": cron})
            # fall through to the interval path
    every = config.get("every_n_minutes")
    try:
        minutes = int(every) if every is not None else int(settings.scheduler_default_minutes)
    except (TypeError, ValueError):
        minutes = int(settings.scheduler_default_minutes)
    if minutes <= 0:
        minutes = int(settings.scheduler_default_minutes)
    return now + timedelta(minutes=minutes)


# --------------------------------------------------------------------------- #
# Scope-entry -> target resolution
# --------------------------------------------------------------------------- #

async def resolve_scope_targets(pool, target_scope: str) -> list[str]:
    """Resolve a schedule's `target_scope` to a list of target strings.

    - "all" / "*" / "" -> every active, unexpired scope entry.
    - a value matching an active scope entry -> that entry.
    - otherwise -> treat the string (comma-separated allowed) as literal
      target(s); the per-target scope check at dispatch decides admissibility.

    For `subdomain_wildcard` entries the leading `*.` is stripped so the base
    domain is scanned. ASN entries are skipped (no target to enqueue).
    """
    ts = (target_scope or "").strip()
    wildcard = ts.lower() in {"", "all", "*"}
    async with pool.acquire() as con:
        if wildcard:
            rows = await con.fetch(
                """
                SELECT kind, value FROM scope_entries
                 WHERE active = TRUE
                   AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY id
                """
            )
        else:
            rows = await con.fetch(
                """
                SELECT kind, value FROM scope_entries
                 WHERE active = TRUE
                   AND value = $1
                   AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY id
                """,
                ts,
            )

    targets: list[str] = []
    for row in rows:
        if row["kind"] == "asn":
            continue
        value = row["value"]
        if row["kind"] == "subdomain_wildcard":
            value = value.lstrip("*.")
        if value:
            targets.append(value)

    if not targets and not wildcard:
        targets = [t.strip() for t in ts.split(",") if t.strip()]
    return targets


# --------------------------------------------------------------------------- #
# Row helper
# --------------------------------------------------------------------------- #

def row_to_schedule(row) -> ScheduleOut:
    d = dict(row)
    if isinstance(d.get("config"), str):
        d["config"] = json.loads(d["config"])
    elif d.get("config") is None:
        d["config"] = {}
    return ScheduleOut.model_validate(d)


_SCHEDULE_COLS = (
    "id, name, scan_kind, target_scope, cron, enabled, last_run_at, "
    "next_run_at, last_status, config"
)


# --------------------------------------------------------------------------- #
# Running a single schedule
# --------------------------------------------------------------------------- #

async def run_schedule(pool, r, row, now: datetime | None = None) -> ScheduleRunOut:
    """Enqueue the scan(s) for one schedule and update its bookkeeping.

    Returns a ScheduleRunOut with the refreshed schedule, the number of jobs
    enqueued, their scan ids, and a `last_status` string:
      ok            -> at least one job enqueued
      no_targets    -> target_scope resolved to nothing
      scope_denied  -> targets resolved but all failed the scope check
      refused_kind  -> the scan kind is on the refusal list
      error         -> an unexpected failure (the loop never dies on it)
    """
    now = now or datetime.now(timezone.utc)
    config = dict(row["config"]) if not isinstance(row["config"], str) else json.loads(row["config"])

    scan_ids: list[Any] = []
    status = "ok"
    try:
        targets = await resolve_scope_targets(pool, row["target_scope"])
        if not targets:
            status = "no_targets"
        else:
            denied = 0
            for target in targets:
                try:
                    scan = await scans_mod.dispatch_scoped_scan(
                        pool,
                        r,
                        kind=row["scan_kind"],
                        target=target,
                        config=config,
                        worker="orchestrator.scheduler",
                        reason=f"schedule:{row['id']}",
                    )
                    scan_ids.append(scan.id)
                except scans_mod.ScanKindRefused:
                    status = "refused_kind"
                    break
                except scans_mod.ScopeDenied:
                    denied += 1
                    logger.info(
                        "schedule_target_out_of_scope",
                        extra={"schedule_id": str(row["id"]), "target": target},
                    )
            if not scan_ids and status == "ok":
                status = "scope_denied" if denied else "no_targets"
    except Exception:  # noqa: BLE001 - a bad schedule must not kill the loop
        logger.exception("schedule_dispatch_failed", extra={"schedule_id": str(row["id"])})
        status = "error"

    next_run = compute_next_run(now, cron=row["cron"], config=config)
    last_scan_id = scan_ids[-1] if scan_ids else None
    async with pool.acquire() as con:
        updated = await con.fetchrow(
            f"""
            UPDATE schedules
               SET last_run_at = $2,
                   last_scan_id = $3,
                   last_status = $4,
                   next_run_at = $5
             WHERE id = $1
         RETURNING {_SCHEDULE_COLS}
            """,
            row["id"],
            now,
            last_scan_id,
            status,
            next_run,
        )
    return ScheduleRunOut(
        schedule=row_to_schedule(updated),
        enqueued=len(scan_ids),
        scan_ids=scan_ids,
        status=status,
    )


async def run_due_schedules(pool, r, now: datetime | None = None) -> int:
    """Run every enabled schedule that is due. Returns how many were run.

    A schedule is due when it is enabled and either has never run
    (`next_run_at IS NULL`) or its `next_run_at <= now`.
    """
    now = now or datetime.now(timezone.utc)
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"""
            SELECT {_SCHEDULE_COLS}
              FROM schedules
             WHERE enabled = TRUE
               AND (next_run_at IS NULL OR next_run_at <= $1)
             ORDER BY next_run_at NULLS FIRST
            """,
            now,
        )
    ran = 0
    for row in rows:
        try:
            await run_schedule(pool, r, row, now)
            ran += 1
        except Exception:  # noqa: BLE001 - defensive: one bad row never stops the sweep
            logger.exception(
                "schedule_run_failed", extra={"schedule_id": str(row["id"])}
            )
    return ran


# --------------------------------------------------------------------------- #
# Background loop
# --------------------------------------------------------------------------- #

async def scheduler_loop(app) -> None:
    """Forever: sleep one interval, then run the due schedules.

    Wrapped so neither a DB blip nor a bad schedule can stop the loop; only
    cancellation (shutdown) breaks out.
    """
    interval = int(settings.scheduler_interval_sec)
    logger.info("scheduler_started", extra={"interval_sec": interval})
    while True:
        try:
            await asyncio.sleep(interval)
            pool = getattr(app.state, "pool", None)
            r = getattr(app.state, "redis", None)
            if pool is None or r is None:
                continue
            await run_due_schedules(pool, r)
        except asyncio.CancelledError:
            logger.info("scheduler_stopped")
            raise
        except Exception:  # noqa: BLE001
            logger.exception("scheduler_tick_failed")
