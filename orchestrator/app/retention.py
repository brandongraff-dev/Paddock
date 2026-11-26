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
agent_inventory (v1)       collected_at    30 d  (RETENTION_AGENT_INVENTORY_DAYS)
agent_posture (signed)     received_at     90 d  (RETENTION_AGENT_POSTURE_DAYS)
invariant_runs             evaluated_at    365 d (RETENTION_INVARIANT_RUNS_DAYS)
                                           never the newest row of a (tenant, invariant), never ``pinned``
agent_manifests            last_ref_at     7 d   (RETENTION_AGENT_MANIFESTS_DAYS)
                                           only lists no agent references any more
advisory_fixes (global)    removed_at      30 d  (RETENTION_ADVISORY_FIXES_DAYS)
advisory_snapshots (glob.) fetched_at      keeps the last 14 per (source, scope),
                                           ``rejected`` rows 90 d (RETENTION_ADVISORY_REJECTED_DAYS),
                                           never one a live advisory row points at
RETENTION_EXTRA entries    as given        as given ("table:col:days,...")
=========================  ==============  ==================================

The P2.1 rows (docs/ASSURANCE_P2_1.md 1.11, 6.2): ``invariant_runs`` keeps "since when" alive because the newest row
of each invariant is the ledger anchor; an unreferenced manifest is garbage (a referenced one never expires, however
old); the advisory tables are GLOBAL (written by the intel service as the platform tenant), so their policies run in the
platform tenant's turn only. A ``rejected`` snapshot is kept for 90 days as evidence and does not count toward the 14.
``advisory_fixes`` are purged before ``advisory_snapshots``, whose primary keys they reference.

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
import os
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


# Fleet agent v2 (docs/ASSURANCE_P2.md E8): the v1 inventory history and the signed posture history are bounded
# by default. The posture ROW is only written when the content digest changes or at most hourly, so 90 days is a
# few thousand rows per host at worst. A purged posture only ever turns into silence (UNKNOWN), never a pass.
AGENT_INVENTORY_DAYS_DEFAULT = 30
AGENT_POSTURE_DAYS_DEFAULT = 90


# P2.1 (docs/ASSURANCE_P2_1.md 1.11 and 6.2).
INVARIANT_RUNS_DAYS_DEFAULT = 365
AGENT_MANIFESTS_DAYS_DEFAULT = 7
ADVISORY_FIXES_DAYS_DEFAULT = 30
ADVISORY_REJECTED_DAYS_DEFAULT = 90
#: advisory_snapshots keep the newest N non-rejected rows of each (source, scope); a floor of this many days of age is
#: also required, so nothing fresh can go whatever the fetch rate (set RETENTION_ADVISORY_SNAPSHOTS_DAYS=0 to disable)
ADVISORY_SNAPSHOTS_KEEP = 14
ADVISORY_SNAPSHOTS_MIN_AGE_DAYS_DEFAULT = 1


def _env_days(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


class RetentionPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    table: str
    column: str
    days: int
    # Optional constant SQL predicate (never user input) ANDed to the horizon.
    where: str | None = None
    # A GLOBAL table (no tenant_id; RLS lets only the platform tenant write it): purged in the platform tenant's turn
    # only, once per run, instead of once per tenant.
    platform_only: bool = False

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


#: no advisory row (live or removed-but-not-yet-purged) names the snapshot as its last sighting
_SNAPSHOT_UNREFERENCED = ("NOT EXISTS (SELECT 1 FROM advisory_fixes f "
                          "WHERE f.last_seen_snapshot = advisory_snapshots.id)")


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
        Policy("agent_inventory", "collected_at",
               _env_days("RETENTION_AGENT_INVENTORY_DAYS", AGENT_INVENTORY_DAYS_DEFAULT)),
        Policy("agent_posture", "received_at",
               _env_days("RETENTION_AGENT_POSTURE_DAYS", AGENT_POSTURE_DAYS_DEFAULT)),
        # invariant_runs (6.2, D34): everything older than the horizon EXCEPT the newest row of each (tenant, invariant)
        # (so "since when" always has an anchor) and pinned rows (P3 attestations hold them). The correlated reference is
        # valid inside _purge_one's ``SELECT ctid FROM "invariant_runs"`` subquery. Rows with an identical timestamp are
        # both kept (the comparison is strict): never a deletion on a tie.
        Policy("invariant_runs", "evaluated_at",
               _env_days("RETENTION_INVARIANT_RUNS_DAYS", INVARIANT_RUNS_DAYS_DEFAULT),
               where="NOT pinned AND EXISTS (SELECT 1 FROM invariant_runs n "
                     "WHERE n.invariant_id = invariant_runs.invariant_id "
                     "AND n.tenant_id = invariant_runs.tenant_id "
                     "AND n.evaluated_at > invariant_runs.evaluated_at)"),
        # agent_manifests (1.5, 1.11): only a list no agent references. A ref is per tenant (tenant_id is compared, so a
        # reference in tenant A never protects tenant B's copy of the same sha).
        Policy("agent_manifests", "last_ref_at",
               _env_days("RETENTION_AGENT_MANIFESTS_DAYS", AGENT_MANIFESTS_DAYS_DEFAULT),
               where="NOT EXISTS (SELECT 1 FROM agent_manifest_refs r "
                     "WHERE r.tenant_id = agent_manifests.tenant_id AND r.manifest_sha = agent_manifests.sha256)"),
        # advisory_fixes BEFORE advisory_snapshots (the FK points that way): removed rows after 30 days.
        Policy("advisory_fixes", "removed_at",
               _env_days("RETENTION_ADVISORY_FIXES_DAYS", ADVISORY_FIXES_DAYS_DEFAULT), platform_only=True),
        # advisory_snapshots: every rejected row after 90 days ...
        Policy("advisory_snapshots", "fetched_at",
               _env_days("RETENTION_ADVISORY_REJECTED_DAYS", ADVISORY_REJECTED_DAYS_DEFAULT),
               where="status = 'rejected' AND " + _SNAPSHOT_UNREFERENCED, platform_only=True),
        # ... and a superseded row once 14 newer non-rejected rows of the same (source, scope) exist. The ``current``
        # row is never a candidate (it is the staleness clock), nor is one a live or recently removed advisory row names.
        Policy("advisory_snapshots", "fetched_at",
               _env_days("RETENTION_ADVISORY_SNAPSHOTS_DAYS", ADVISORY_SNAPSHOTS_MIN_AGE_DAYS_DEFAULT),
               where="status = 'superseded' AND " + _SNAPSHOT_UNREFERENCED + " AND (SELECT count(*) FROM "
                     "advisory_snapshots n WHERE n.source = advisory_snapshots.source "
                     "AND n.scope = advisory_snapshots.scope AND n.status <> 'rejected' "
                     f"AND (n.fetched_at, n.id) > (advisory_snapshots.fetched_at, advisory_snapshots.id)) "
                     f">= {ADVISORY_SNAPSHOTS_KEEP}", platform_only=True),
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

    from . import tenancy

    batch = int(batch_size or ops_settings.retention_batch_size)
    counts: dict[str, int] = {}
    per_tenant: dict[str, dict[str, int]] = {}
    async with pool.acquire() as con:
        if not await con.fetchval("SELECT pg_try_advisory_lock($1)", RETENTION_LOCK_KEY):
            logger.info("retention_skipped_locked")
            return None
        try:
            pols = list(policies) if policies is not None else configured_policies()
            if policies is None:
                pols += await _observation_policies(con, ops_settings.retention_observations_days)
            # RLS hides every other tenant's rows, so purge each tenant inside
            # its own context (before this only the default tenant was ever
            # purged and every other tenant's data was retained forever).
            tids = await tenancy.list_tenant_ids(pool)
            active_tids = set(tids)
            if tenancy.DEFAULT_TENANT_ID not in tids:
                # A suspended platform tenant must not stop the purge of the global tables it alone may write
                # (platform_only policies run in its turn); tenant policies are unaffected by the extra turn
                # because a suspended tenant is skipped for them below.
                tids = [*tids, tenancy.DEFAULT_TENANT_ID]
            for tid in tids:
                with tenancy.tenant_context(tid):
                    async with pool.acquire() as tcon:
                        for p in pols:
                            p.validate()  # refuses audit_log even if constructed directly
                            if p.days <= 0:
                                continue
                            if p.platform_only and tid != tenancy.DEFAULT_TENANT_ID:
                                continue  # a global table: the platform tenant's turn only
                            if not p.platform_only and tid not in active_tids:
                                continue  # the platform turn added above is for global tables only
                            try:
                                n = await _purge_one(tcon, p, batch, max_batches)
                            except Exception:  # noqa: BLE001 -- one bad table never stops the rest
                                logger.exception("retention_purge_failed", extra={"table": p.table})
                                continue
                            counts[p.table] = counts.get(p.table, 0) + n
                            if n:
                                per_tenant.setdefault(tid, {})[p.table] = n
                                RETENTION_PURGED.labels(p.table).inc(n)
        finally:
            await con.execute("SELECT pg_advisory_unlock($1)", RETENTION_LOCK_KEY)
    RETENTION_LAST_RUN.set(time.time())
    if any(counts.values()):
        logger.info("retention_purged", extra={"counts": counts})
        for tid, deleted in per_tenant.items():
            try:
                with tenancy.tenant_context(tid):
                    await audit.record(
                        pool,
                        action="retention_purge",
                        actor="system:retention",
                        actor_role="system",
                        resource_type="retention",
                        details={"deleted": deleted},
                    )
            except Exception:  # noqa: BLE001
                logger.exception("retention_audit_failed")
    return counts
