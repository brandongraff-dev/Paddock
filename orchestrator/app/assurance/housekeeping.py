"""Assurance housekeeping (docs/ASSURANCE_P2_1.md 6.1 and 6.2, D33 and D34).

Two jobs live here because both are about what stays true about OLD data while the invariants move on:

1. **Finding annotation for invariants nobody re-checks (6.1, D33).** A disabled, archived, invalid or unentitled
   invariant is never evaluated, so its open findings are never re-verified: they stay open (closing them would be a
   false verification) and are *annotated* ``metadata.invariant_state`` so nobody mistakes them for live ones. The router
   annotates in the same transaction as the toggle, the runner annotates what it detects (``invalid_definition``,
   ``not_entitled``), and ``reconcile_orphans`` repairs any drift on the loop's tick (per tenant, at most every
   ``runner.RECONCILE_EVERY_S``). Nothing here ever changes a finding's status, and nothing here closes anything.
2. **``invariant_runs`` compaction (6.2).**

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

#: the annotation values (``findings.metadata.invariant_state``); "active" is the absence of the key
STATE_DISABLED, STATE_ARCHIVED = "disabled", "archived"
STATE_INVALID, STATE_NOT_ENTITLED = "invalid_definition", "not_entitled"
STATES = (STATE_DISABLED, STATE_ARCHIVED, STATE_INVALID, STATE_NOT_ENTITLED)

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


# --------------------------------------------------------------------------------------------
# Finding annotation (6.1, D33)
# --------------------------------------------------------------------------------------------

#: which findings belong to the invariant ``$1``: its own rule id, or an estate finding ``<rule id>@<target>``. The
#: ``@`` keeps ``acme:aa`` from matching ``acme:aa-bb``.
_OWN = "(f.rule_id = 'invariant:' || {inv} OR starts_with(f.rule_id, 'invariant:' || {inv} || '@'))"


def state_of(enabled: bool, archived_at: Any, last_graph_version: Any = None, last_reasons: Any = None) -> str:
    """The invariant's lifecycle state from its stored columns: ``archived``, ``disabled``, ``invalid_definition`` (an
    enabled one whose last recorded evaluation was the synthetic ``invalid_definition`` UNKNOWN) or ``active``.
    ``not_entitled`` is decided by the runner against billing, not by columns."""
    if archived_at is not None:
        return STATE_ARCHIVED
    if not enabled:
        return STATE_DISABLED
    if last_graph_version is not None and isinstance(last_reasons, list) and last_reasons == [STATE_INVALID]:
        return STATE_INVALID
    return "active"


async def annotate_findings(con: Any, invariant_id: str, state: str) -> int:
    """Mark the open and triaged findings of ``invariant_id`` with ``state``; returns how many CHANGED (a finding that
    already carries this state keeps its original ``invariant_state_at``). Never touches a status."""
    if state not in STATES:
        raise ValueError(f"unknown invariant state {state!r}")
    rows = await con.fetch(
        "UPDATE findings f SET metadata = f.metadata || jsonb_build_object("
        "'invariant_state', $2::text, 'invariant_state_at', to_jsonb(now())) "
        "WHERE f.rule_source = 'invariant' AND f.status IN ('open', 'triaged') AND " + _OWN.format(inv="$1::text") +
        " AND f.metadata->>'invariant_state' IS DISTINCT FROM $2::text RETURNING f.id", invariant_id, state)
    return len(rows)


async def clear_annotations(con: Any, invariant_id: str, *, only_if_enabled: bool = False) -> int:
    """Remove the annotation from every finding of ``invariant_id`` (whatever its status: a closed finding keeps the
    reason in its history, not a stale "disabled" flag). Used on re-enable (the row is enabled by then) and by the
    runner when a verdict is back. ``only_if_enabled`` makes it a no-op unless the invariant row is enabled and not
    archived right now: the runner's clear must never wipe the annotation of a disable that landed a moment ago."""
    guard = (" AND EXISTS (SELECT 1 FROM invariants i WHERE i.invariant_id = $1::text AND i.enabled "
             "AND i.archived_at IS NULL)") if only_if_enabled else ""
    rows = await con.fetch(
        "UPDATE findings f SET metadata = f.metadata - 'invariant_state' - 'invariant_state_at' "
        "WHERE f.rule_source = 'invariant' AND f.metadata ? 'invariant_state' AND " + _OWN.format(inv="$1::text") +
        guard + " RETURNING f.id", invariant_id)
    return len(rows)


_WANT = """
WITH want AS (
  SELECT invariant_id,
         CASE WHEN archived_at IS NOT NULL THEN 'archived'
              WHEN NOT enabled THEN 'disabled'
              WHEN NOT $1::boolean THEN 'not_entitled'
              WHEN last_graph_version IS NOT NULL AND last_result->'reasons' = '["invalid_definition"]'::jsonb
                   THEN 'invalid_definition'
         END AS state
    FROM invariants
)
"""
_ANNOTATE_ALL = _WANT + (
    "UPDATE findings f SET metadata = f.metadata || jsonb_build_object("
    "'invariant_state', w.state, 'invariant_state_at', to_jsonb(now())) FROM want w "
    "WHERE w.state IS NOT NULL AND f.rule_source = 'invariant' AND f.status IN ('open', 'triaged') AND "
    + _OWN.format(inv="w.invariant_id") + " AND f.metadata->>'invariant_state' IS DISTINCT FROM w.state "
    "RETURNING f.id")
_CLEAR_ALL = _WANT + (
    "UPDATE findings f SET metadata = f.metadata - 'invariant_state' - 'invariant_state_at' FROM want w "
    "WHERE w.state IS NULL AND f.rule_source = 'invariant' AND f.metadata ? 'invariant_state' AND "
    + _OWN.format(inv="w.invariant_id") + " RETURNING f.id")


async def reconcile_orphans(pool: Any, tenant_id: str, *, entitled: bool = True) -> dict[str, int]:
    """Bring every annotation of one tenant in line with what its invariants are now (idempotent, set based).

    Repairs what the toggle routes cannot: an invariant disabled or re-enabled behind the API's back (a restore, a
    script, a std copy toggled elsewhere), a finding created by an evaluation that raced a disable, and the states only
    the runner can see (``invalid_definition`` from the last recorded verdict, ``not_entitled`` from billing).
    ``{"annotated": n, "cleared": m}``. Never changes a finding's status."""
    with tenancy.tenant_context(tenant_id):
        async with pool.acquire() as con:
            async with con.transaction():
                annotated = await con.fetch(_ANNOTATE_ALL, bool(entitled))
                cleared = await con.fetch(_CLEAR_ALL, bool(entitled))
    return {"annotated": len(annotated), "cleared": len(cleared)}
