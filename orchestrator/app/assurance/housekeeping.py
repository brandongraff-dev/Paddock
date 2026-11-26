"""Assurance housekeeping: ``invariant_runs`` compaction (docs/ASSURANCE_P2_1.md 6.2, D34).

The run ledger (``invariant_runs``) gets a row on every verdict or digest change and once a day per invariant. Each row
carries the full stored result: witnesses, up to 200 blind spots, up to 5000 + 5000 target refs, up to 5000 passing
targets, up to megabytes per row. Nothing needs those lists after a month; the question a ledger answers later is "what
was the decision, since when, on which definition and coverage". So:

* ``compact_runs`` rewrites rows older than ``assurance_runs_compact_days`` in bounded batches: it KEEPS the decision
  (digest, verdict, reasons, evaluated_at, valid_until, evidence tier, coverage, violation count, graph version, document
  hash, assertion, the blind-spot summary and the first 5 witnesses) and DROPS the target lists, the blind spots, the
  boundaries and the exception detail. It never deletes a row, never touches ``pinned`` rows (P3 attestations hold them
  whole), and never touches the real columns the runner and the API read.
* Deleting is retention's job (``retention.py``: 365 days, except the newest row of each invariant and pinned rows).

``run_compaction`` is the scheduler's entry: one Postgres advisory lock so N replicas compact once, one pass per active
tenant inside that tenant's context (RLS), one audit row per tenant per run only when something was compacted.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from .. import tenancy
from ..config import settings

logger = logging.getLogger(__name__)

#: ``pg_try_advisory_lock`` key of the compaction pass ("PADDCO"); one replica at a time.
COMPACT_LOCK_KEY = 0x5041_4444_434F
#: keys of a stored result that survive compaction (``witnesses`` is kept separately: only its first 5 entries).
RUN_KEEP_KEYS = ("invariant", "digest", "assertion", "verdict", "reasons", "evaluated_at", "valid_until",
                 "evidence_tier", "coverage", "violation_count", "graph_version", "doc_sha", "blind_spot_summary")
KEEP_WITNESSES = 5
#: upper bound on batches per tenant per pass (bounded work per tick, the rest goes next time)
MAX_BATCHES = 200

# A WHITELIST, not a deny list: a heavy key a later release adds to the stored result is dropped by default instead of
# silently kept forever. A result that is not a JSON object is left as it is (and stamped, so it is not retried).
_COMPACT_SQL = """
WITH due AS (
    SELECT id FROM invariant_runs
     WHERE compacted_at IS NULL AND NOT pinned
       AND evaluated_at < COALESCE($3::timestamptz, now()) - make_interval(days => $1::int)
     ORDER BY evaluated_at, id
     LIMIT $2::int
     FOR UPDATE SKIP LOCKED
)
UPDATE invariant_runs r
   SET result = CASE WHEN jsonb_typeof(r.result) = 'object' THEN
         COALESCE((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(r.result) e
                    WHERE e.key = ANY($4::text[])), '{}'::jsonb)
         || jsonb_build_object(
              'witnesses',
              CASE WHEN jsonb_typeof(r.result->'witnesses') = 'array' THEN
                     COALESCE((SELECT jsonb_agg(w.value ORDER BY w.n)
                                 FROM (SELECT x.value, x.n FROM jsonb_array_elements(r.result->'witnesses')
                                         WITH ORDINALITY AS x(value, n) ORDER BY x.n LIMIT $5::int) w), '[]'::jsonb)
                   ELSE '[]'::jsonb END,
              'compacted', true)
       ELSE r.result END,
       compacted_at = COALESCE($3::timestamptz, now())
  FROM due WHERE r.id = due.id
RETURNING r.id
"""


async def compact_runs(con: Any, days: int, batch: int, *, now: Optional[datetime] = None) -> int:
    """Compact at most ``batch`` runs older than ``days`` in the connection's tenant; returns how many. Idempotent."""
    rows = await con.fetch(_COMPACT_SQL, int(days), int(batch), now, list(RUN_KEEP_KEYS), KEEP_WITNESSES)
    return len(rows)


async def run_compaction(pool: Any, *, days: Optional[int] = None, batch: Optional[int] = None,
                         max_batches: int = MAX_BATCHES, now: Optional[datetime] = None
                         ) -> Optional[dict[str, int]]:
    """Compact every active tenant's old runs. ``{tenant_id: compacted}`` for the tenants where something happened, or
    ``None`` when another replica holds the lock. A failing tenant is logged and skipped; it never stops the others."""
    from .. import audit  # noqa: PLC0415
    from ..opsconfig import ops_settings  # noqa: PLC0415

    horizon = int(days if days is not None else settings.assurance_runs_compact_days)
    size = int(batch or ops_settings.retention_batch_size)
    done: dict[str, int] = {}
    async with pool.acquire() as lock_con:
        if not await lock_con.fetchval("SELECT pg_try_advisory_lock($1)", COMPACT_LOCK_KEY):
            logger.info("assurance_compaction_skipped_locked")
            return None
        try:
            for tid in await tenancy.list_tenant_ids(pool):
                total = 0
                try:
                    with tenancy.tenant_context(tid):
                        async with pool.acquire() as con:
                            for _ in range(max(1, int(max_batches))):
                                n = await compact_runs(con, horizon, size, now=now)
                                total += n
                                if n < size:
                                    break
                except Exception:  # noqa: BLE001 -- one tenant never stops the rest
                    logger.exception("assurance_compaction_failed", extra={"tenant": tid})
                if total:
                    done[tid] = total
                    try:
                        with tenancy.tenant_context(tid):
                            await audit.record(
                                pool, action="assurance_runs_compact", actor="system:housekeeping",
                                actor_role="system", resource_type="invariant_runs",
                                details={"compacted": total, "days": horizon})
                    except Exception:  # noqa: BLE001 -- the audit row is best effort, the compaction is done
                        logger.exception("assurance_compaction_audit_failed", extra={"tenant": tid})
        finally:
            await lock_con.execute("SELECT pg_advisory_unlock($1)", COMPACT_LOCK_KEY)
    if done:
        logger.info("assurance_runs_compacted", extra={"counts": done})
    return done
