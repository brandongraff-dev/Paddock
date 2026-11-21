"""Data-retention purge job.

Deletes rows older than a per-table horizon, in bounded batches, from the
high-volume operational tables:

=========================  ==============  ==================================
table                      timestamp col   default (env var)
=========================  ==============  ==================================
scope_decisions            decided_at      180 d (RETENTION_SCOPE_DECISIONS_DAYS)
outbound_log               started_at      180 d (RETENTION_OUTBOUND_LOG_DAYS)
integration_deliveries     updated_at      90 d  (RETENTION_INTEGRATION_DELIVERIES_DAYS)
                                           only terminal rows: sent/dead/skipped
observation tables         auto-detected   30 d  (RETENTION_OBSERVATIONS_DAYS)
RETENTION_EXTRA entries    as given        as given ("table:col:days,...")
=========================  ==============  ==================================

A policy with ``days <= 0`` is disabled; a table that does not exist is
skipped. ``audit_log`` (the tamper-evident hash chain) and
``schema_migrations`` are NEVER purged -- a policy naming them is refused,
whatever the configuration says.

The job runs from the scheduler loop (app/scheduler.py) every
``RETENTION_INTERVAL_SEC`` under a Postgres advisory lock, so with N
orchestrator replicas exactly one purges at a time. Each run that deletes
anything appends one ``retention_purge`` row to the audit log with the
per-table counts.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from .opsconfig import ops_settings

logger = logging.getLogger(__name__)

RETENTION_LOCK_KEY = 0x5041_4444_5245  # "PADDRE"
NEVER_PURGE = frozenset({"audit_log", "schema_migrations"})
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

# Tables other streams may add for sensor / device observations. The first
# timestamp-ish column found is used as the horizon column.
OBSERVATION_TABLE_CANDIDATES = (
    "observations",
    "sentry_observations",
    "device_observations",
    "ot_observations",
    "flow_observations",
    "asset_observations",
)
_OBS_TS_COLUMNS = ("observed_at", "last_seen", "ts", "created_at")


class RetentionPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    table: str
    column: str
    days: int
    # Optional constant SQL predicate (never user input) ANDed to the horizon.
    where: str | None = None

    def validate(self) -> None:
        if self.table in NEVER_PURGE:
            raise RetentionPolicyError(f"{self.table} is never purged")
        if not _IDENT.match(self.table) or not _IDENT.match(self.column):
            raise RetentionPolicyError(f"invalid identifier in policy {self!r}")


def parse_extra(spec: str) -> list[Policy]:
    out: list[Policy] = []
    for item in (s.strip() for s in (spec or "").split(",")):
        if not item:
            continue
        parts = item.split(":")
        if len(parts) != 3:
            raise RetentionPolicyError(f"RETENTION_EXTRA entry {item!r} is not table:column:days")
        p = Policy(parts[0].strip().lower(), parts[1].strip().lower(), int(parts[2]))
        p.validate()
        out.append(p)
    return out


def configured_policies() -> list[Policy]:
    s = ops_settings
    pols = [
        Policy("scope_decisions", "decided_at", s.retention_scope_decisions_days),
        Policy("outbound_log", "started_at", s.retention_outbound_log_days),
        Policy(
            "integration_deliveries",
            "updated_at",
            s.retention_integration_deliveries_days,
            where="status IN ('sent', 'dead', 'skipped')",
        ),
    ]
    pols += parse_extra(s.retention_extra)
    return pols


async def _observation_policies(con: Any, days: int) -> list[Policy]:
    if days <= 0:
        return []
    rows = await con.fetch(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = ANY($1::text[]) "
        "AND data_type IN ('timestamp with time zone', 'timestamp without time zone')",
        list(OBSERVATION_TABLE_CANDIDATES),
    )
    cols: dict[str, set[str]] = {}
    for r in rows:
        cols.setdefault(r["table_name"], set()).add(r["column_name"])
    out = []
    for t in OBSERVATION_TABLE_CANDIDATES:
        for c in _OBS_TS_COLUMNS:
            if c in cols.get(t, set()):
                out.append(Policy(t, c, days))
                break
    return out


async def _purge_one(con: Any, p: Policy, batch: int, max_batches: int) -> int:
    p.validate()
    exists = await con.fetchval(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
        "AND table_name = $1 AND column_name = $2",
        p.table,
        p.column,
    )
    if not exists:
        return 0
    extra = f" AND ({p.where})" if p.where else ""
    sql = (
        f'DELETE FROM "{p.table}" WHERE ctid = ANY(ARRAY('
        f'SELECT ctid FROM "{p.table}" WHERE "{p.column}" < NOW() - make_interval(days => $1)'
        f"{extra} LIMIT $2))"
    )
    total = 0
    for _ in range(max_batches):
        status = await con.execute(sql, p.days, batch)
        n = int(status.split()[-1]) if status.startswith("DELETE") else 0
        total += n
        if n < batch:
            break
    return total


async def run_retention(
    pool: Any,
    policies: list[Policy] | None = None,
    *,
    batch_size: int | None = None,
    max_batches: int = 1000,
) -> dict[str, int] | None:
    """Purge expired rows. Returns {table: deleted} or None if another
    replica holds the retention lock."""
    from . import audit
    from .metrics import RETENTION_LAST_RUN, RETENTION_PURGED

    batch = int(batch_size or ops_settings.retention_batch_size)
    counts: dict[str, int] = {}
    async with pool.acquire() as con:
        if not await con.fetchval("SELECT pg_try_advisory_lock($1)", RETENTION_LOCK_KEY):
            logger.info("retention_skipped_locked")
            return None
        try:
            pols = list(policies) if policies is not None else configured_policies()
            if policies is None:
                pols += await _observation_policies(con, ops_settings.retention_observations_days)
            for p in pols:
                p.validate()  # refuses audit_log even if constructed directly
                if p.days <= 0:
                    continue
                try:
                    n = await _purge_one(con, p, batch, max_batches)
                except Exception:  # noqa: BLE001 -- one bad table never stops the rest
                    logger.exception("retention_purge_failed", extra={"table": p.table})
                    continue
                counts[p.table] = counts.get(p.table, 0) + n
                if n:
                    RETENTION_PURGED.labels(p.table).inc(n)
        finally:
            await con.execute("SELECT pg_advisory_unlock($1)", RETENTION_LOCK_KEY)
    RETENTION_LAST_RUN.set(time.time())
    if any(counts.values()):
        logger.info("retention_purged", extra={"counts": counts})
        try:
            await audit.record(
                pool,
                action="retention_purge",
                actor="system:retention",
                actor_role="system",
                resource_type="retention",
                details={"deleted": counts},
            )
        except Exception:  # noqa: BLE001
            logger.exception("retention_audit_failed")
    return counts
