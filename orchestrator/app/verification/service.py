"""Verification orchestration (schema 026).

Lifecycle of one verification (a row in ``finding_verifications``)::

    scheduled --(due, gate passes)--> queued --(worker result)--> done
        |                                |                        refused | unsupported | error
        |                                '--(no result in 30 min)--> error
        '--(gate refuses)--> refused     '--(finding no longer fixed)--> cancelled (fix purpose)

THE GATE: nothing is queued unless (1) ``scope.check`` allows the target
(guardrails, expiry, audit row) AND (2) the scope entry that authorises it has
a verified or attested proof-of-control that has not lapsed -- whether or not
``REQUIRE_SCOPE_PROOF`` is on globally. Verification sends real packets at a
target, so it always demands proof. A refusal is recorded on the ledger with
its reason; it is never silently dropped.

The orchestrator never touches a target. It queues a ``verify_finding`` job on
the active worker stream (the same path scans use); the worker runs the safe
check and reports back to :func:`apply_result`, which owns every consequence:

* finding ``exploitability`` / ``last_verified_at`` (feeds the explained
  priority; a verdict never auto-closes a finding);
* prove-fixed: a ``fix`` verification of a finding marked fixed that is
  ``not_reproducible`` stamps ``fix_verified_at`` (counted as a *verified fix*
  by the reports); still ``confirmed`` -> reopened with "fix did not hold";
  ``inconclusive`` -> retried by :func:`sweep`, then left fixed-but-unverified;
* integration events (finding.verified / fix_verified / fix_failed, plus the
  existing finding.reopened).
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import asyncpg

from .. import audit, lifecycle, tenancy
from .. import scope as scope_svc
from ..queue import publish_event
from .models import VerificationOut

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system:verification"
PROVEN = scope_svc.PROVEN_STATUSES
EVIDENCE_LIMIT = 8192

# Evidence keys from the finding that a check may need; everything else stays home.
_JOB_EVIDENCE_KEYS = (
    "url", "matched_at", "matched-at", "target_url", "matcher_name", "port", "protocol",
    "cipher", "cookie", "service", "host", "versions", "status",
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    """Timings; read once from the environment (tests overwrite the fields)."""

    fix_delay_sec: int = 60       # settle time before re-checking a fix marked in the UI/ticket
    pr_delay_sec: int = 300       # a merged PR still has to deploy
    retry_sec: int = 600          # between attempts when a re-check was inconclusive
    max_attempts: int = 3         # fix re-checks per fix episode
    stale_queue_sec: int = 1800   # a queued job with no result after this is an error
    sweep_batch: int = 50

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            fix_delay_sec=_env_int("VERIFY_FIX_DELAY_SEC", 60),
            pr_delay_sec=_env_int("VERIFY_PR_DELAY_SEC", 300),
            retry_sec=_env_int("VERIFY_RETRY_SEC", 600),
            max_attempts=_env_int("VERIFY_MAX_ATTEMPTS", 3),
            stale_queue_sec=_env_int("VERIFY_STALE_QUEUE_SEC", 1800),
        )


cfg = Settings.from_env()

_COLS = (
    "id, finding_id, purpose, trigger, requested_by, status, verdict, check_id, target, "
    "scope_entry_id, scope_proof, scan_id, evidence, reason, requested_at, run_after, "
    "dispatched_at, checked_at, completed_at"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(ts: datetime | None) -> datetime | None:
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def _j(v: Any) -> dict[str, Any]:
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {}
    return v if isinstance(v, dict) else {}


def row_out(row: asyncpg.Record | dict[str, Any], *, already: bool = False) -> VerificationOut:
    d = dict(row)
    d["evidence"] = _j(d.get("evidence"))
    return VerificationOut.model_validate({**d, "already_in_flight": already})


def cap_evidence(ev: Any) -> dict[str, Any]:
    """Belt and braces: the worker already redacts and caps; refuse oversize anyway."""
    ev = _j(ev)
    raw = json.dumps(ev, default=str)
    if len(raw) <= EVIDENCE_LIMIT:
        return ev
    return {"truncated": True, "note": f"evidence exceeded {EVIDENCE_LIMIT} bytes and was dropped",
            "keys": sorted(ev)[:20]}


# =========================================================================== #
# The gate
# =========================================================================== #

@dataclass
class Gate:
    ok: bool
    reason: str = ""
    normalized: str = ""
    entry_id: int | None = None
    proof: str | None = None


def _effective(row: dict[str, Any], now: datetime) -> bool:
    status = row.get("status")
    if status not in PROVEN:
        return False
    if status == "attested":
        exp = _aware(row.get("attestation_expires_at"))
        if exp is not None and exp <= now:
            return False
    return True


async def gate(pool, target: str, *, worker: str = "orchestrator.verification") -> Gate:
    """Scope-check ``target`` and demand a proven, effective scope entry."""
    decision = await scope_svc.check(pool, target=target, worker=worker, reason="finding_verification")
    if not decision.allow:
        return Gate(False, f"scope: {decision.reason}", decision.normalized)
    now = _now()
    async with pool.acquire() as con:
        rows = [dict(r) for r in await con.fetch(
            """
            SELECT e.id, e.kind, e.value, p.status, p.attestation_expires_at
              FROM scope_entries e LEFT JOIN scope_proofs p ON p.scope_entry_id = e.id
             WHERE e.active = TRUE AND (e.expires_at IS NULL OR e.expires_at > NOW())
            """
        )]
    by_id = {r["id"]: r for r in rows}
    matched = by_id.get(decision.matched_entry_id)
    if matched is not None and _effective(matched, now):
        return Gate(True, "ok", decision.normalized, matched["id"], matched["status"])
    # With REQUIRE_SCOPE_PROOF off, scope.check may have matched an unproven entry
    # while a proven one also covers the target: look for one before refusing.
    proven = [r for r in rows if _effective(r, now)]
    ip = scope_svc._is_ip(decision.normalized)
    hit, eid = (scope_svc._match_host_rules(decision.normalized, proven) if ip is None
                else scope_svc._match_ip_rules(ip, proven))
    if hit and eid is not None:
        return Gate(True, "ok", decision.normalized, eid, by_id[eid]["status"])
    if matched is not None:
        st = matched.get("status") or "pending"
        return Gate(False, f"scope entry {matched['id']} ({matched['kind']} {matched['value']}) "
                           f"has no verified proof-of-control (status: {st}); verify or attest it first",
                    decision.normalized, matched["id"], st)
    return Gate(False, "no scope entry with a verified or attested proof-of-control covers this target",
                decision.normalized)


# =========================================================================== #
# Targets + job payload
# =========================================================================== #

def _target_of(f: dict[str, Any]) -> str | None:
    ev = _j(f.get("evidence"))
    for k in ("url", "matched_at", "matched-at", "target_url"):
        v = ev.get(k)
        if isinstance(v, str) and v.startswith(("http://", "https://")):
            return v
    v = (f.get("asset_value") or f.get("asset_canonical") or "").strip()
    return v or None


def _job_finding(f: dict[str, Any]) -> dict[str, Any]:
    ev = _j(f.get("evidence"))
    md = _j(f.get("metadata"))
    return {
        "id": str(f["id"]), "rule_id": f["rule_id"], "rule_source": f["rule_source"],
        "severity": f["severity"], "title": f["title"],
        "evidence": {k: ev[k] for k in _JOB_EVIDENCE_KEYS if k in ev},
        "metadata": {"tags": [str(t) for t in (md.get("tags") or [])][:20]},
        "asset": {"kind": f.get("asset_kind"), "value": f.get("asset_value")},
    }


_FINDING_SQL = """
    SELECT f.id, f.status, f.rule_id, f.rule_source, f.severity, f.title, f.evidence, f.metadata,
           f.exploitability, f.fix_verified_at, f.status_changed_at, f.first_seen, f.asset_id,
           a.kind AS asset_kind, a.value AS asset_value, a.canonical AS asset_canonical
      FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
     WHERE f.id = $1
"""


# =========================================================================== #
# Request + dispatch
# =========================================================================== #

class FindingNotFound(Exception):
    pass


async def request(
    pool,
    r,
    *,
    finding_id: UUID,
    purpose: str,
    trigger: str,
    requested_by: str,
    run_after: datetime | None = None,
    reason: str | None = None,
) -> VerificationOut:
    """Create a ledger row and (when due) dispatch it. Returns the row as it ends up
    (``refused`` carries the reason). An in-flight row for the same finding and
    purpose is returned with ``already_in_flight`` instead of a duplicate."""
    when = run_after or _now()
    async with pool.acquire() as con:
        if not await con.fetchval("SELECT 1 FROM findings WHERE id = $1", finding_id):
            raise FindingNotFound(str(finding_id))
        await _expire_stale(con)
        try:
            row = await con.fetchrow(
                f"""
                INSERT INTO finding_verifications
                    (finding_id, purpose, trigger, requested_by, status, run_after, reason)
                VALUES ($1, $2, $3, $4, 'scheduled', $5, $6)
                RETURNING {_COLS}
                """,
                finding_id, purpose, trigger, requested_by, when, reason,
            )
        except asyncpg.UniqueViolationError:
            existing = await con.fetchrow(
                f"SELECT {_COLS} FROM finding_verifications WHERE finding_id = $1 AND purpose = $2 "
                "AND status IN ('scheduled', 'queued') ORDER BY requested_at DESC LIMIT 1",
                finding_id, purpose,
            )
            return row_out(existing, already=True)
    if _aware(when) <= _now():
        out = await dispatch(pool, r, row["id"])
        if out is not None:
            return out
    return row_out(row)


async def schedule_fix_check(pool, r, finding_id: Any, *, trigger: str, actor: str,
                             delay_sec: int | None = None) -> VerificationOut | None:
    """Schedule the "prove it's fixed" re-check for a finding just marked fixed.
    Best effort: it must never fail the status change that triggered it."""
    try:
        delay = delay_sec if delay_sec is not None else (
            cfg.pr_delay_sec if trigger == "fix_pr" else cfg.fix_delay_sec)
        return await request(
            pool, r, finding_id=UUID(str(finding_id)), purpose="fix", trigger=trigger,
            requested_by=actor, run_after=_now() + timedelta(seconds=max(0, delay)),
            reason="re-checking after the finding was marked fixed",
        )
    except FindingNotFound:
        return None
    except Exception:  # noqa: BLE001
        logger.exception("schedule_fix_check_failed", extra={"finding_id": str(finding_id)})
        return None


async def _expire_stale(con) -> int:
    n = await con.fetchval(
        """
        WITH s AS (
            UPDATE finding_verifications
               SET status = 'error', completed_at = NOW(),
                   reason = 'the worker did not report a result in time'
             WHERE status = 'queued' AND dispatched_at < NOW() - make_interval(secs => $1)
         RETURNING 1)
        SELECT COUNT(*) FROM s
        """,
        float(cfg.stale_queue_sec),
    )
    return int(n or 0)


async def _finish(pool, vid: UUID, status: str, reason: str, **extra: Any) -> VerificationOut:
    sets = ["status = $2", "reason = $3", "completed_at = NOW()"]
    args: list[Any] = [vid, status, reason]
    for k, v in extra.items():
        args.append(v)
        sets.append(f"{k} = ${len(args)}")
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"UPDATE finding_verifications SET {', '.join(sets)} WHERE id = $1 RETURNING {_COLS}",
            *args,
        )
    return row_out(row)


async def dispatch(pool, r, vid: UUID) -> VerificationOut | None:
    """Claim a scheduled row, gate it, and put the job on the worker stream."""
    from ..routers import scans as scans_mod

    async with pool.acquire() as con:
        claimed = await con.fetchrow(
            f"""
            UPDATE finding_verifications SET status = 'queued', dispatched_at = NOW()
             WHERE id = $1 AND status = 'scheduled'
         RETURNING {_COLS}
            """,
            vid,
        )
        if claimed is None:
            return None
        f = await con.fetchrow(_FINDING_SQL, claimed["finding_id"])
    if f is None:
        return await _finish(pool, vid, "cancelled", "the finding no longer exists")
    f = dict(f)
    purpose = claimed["purpose"]
    if purpose == "fix" and f["status"] != "fixed":
        return await _finish(pool, vid, "cancelled",
                             f"the finding is no longer fixed (status: {f['status']})")
    target = _target_of(f)
    if target is None:
        return await _finish(pool, vid, "refused", "the finding has no target to verify")

    g = await gate(pool, target)
    if not g.ok:
        logger.info("verification_refused", extra={"verification_id": str(vid), "reason": g.reason})
        return await _finish(pool, vid, "refused", g.reason, target=g.normalized or None,
                             scope_entry_id=g.entry_id, scope_proof=g.proof)

    config = {
        "verification_id": str(vid), "purpose": purpose, "scope_proof": g.proof,
        "scope_entry_id": g.entry_id, "tenant_id": tenancy.current_tenant_id(),
        "finding": _job_finding(f),
    }
    try:
        scan = await scans_mod._insert_and_enqueue(
            pool, r, kind="verify_finding", normalized_target=g.normalized, config=config,
            priority=3, parent_scan_id=None, matched_entry_id=g.entry_id,
        )
    except Exception:  # noqa: BLE001
        logger.exception("verification_enqueue_failed", extra={"verification_id": str(vid)})
        return await _finish(pool, vid, "error", "could not queue the job on the worker stream",
                             target=g.normalized)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            UPDATE finding_verifications
               SET target = $2, scope_entry_id = $3, scope_proof = $4, scan_id = $5
             WHERE id = $1 RETURNING {_COLS}
            """,
            vid, g.normalized, g.entry_id, g.proof, scan.id,
        )
    return row_out(row)


# =========================================================================== #
# Applying a worker result
# =========================================================================== #

class AlreadyDecided(Exception):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class ResultRejected(Exception):
    """The caller is not the worker job this verification was dispatched to."""




async def apply_result(pool, r, vid: UUID, body, *, actor: str,
                       job_scan_id: str | None = None) -> VerificationOut:
    """Record the worker's result and apply its consequences. Idempotent: a result for
    a row that already finished is rejected (:class:`AlreadyDecided`).

    Only the dispatched job may answer: the row must be ``queued`` (a gated,
    dispatched check; never ``scheduled``, which the proof gate has not run for)
    and ``job_scan_id`` (the worker's ``X-Paddock-Scan``) must equal the scan the
    row was dispatched as, else :class:`ResultRejected`."""
    checked_at = _aware(body.checked_at) or _now()
    fix_event: str | None = None
    reopened = False
    detail: dict[str, Any] = {}
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                f"SELECT {_COLS} FROM finding_verifications WHERE id = $1 FOR UPDATE", vid)
            if row is None:
                raise FindingNotFound(str(vid))
            if row["status"] not in ("queued", "scheduled"):
                raise AlreadyDecided(row["status"])
            if row["status"] != "queued":
                raise ResultRejected("verification has not been dispatched")
            if (row["scan_id"] is None or not job_scan_id
                    or str(row["scan_id"]).lower() != str(job_scan_id).lower()):
                raise ResultRejected("result does not come from the job this verification was dispatched as")
            done = body.status == "done"
            updated = await con.fetchrow(
                f"""
                UPDATE finding_verifications
                   SET status = $2, verdict = $3, check_id = COALESCE($4, check_id),
                       evidence = $5::jsonb, reason = $6, checked_at = $7, completed_at = NOW()
                 WHERE id = $1 RETURNING {_COLS}
                """,
                vid, body.status, body.verdict if done else None, body.check_id,
                json.dumps(cap_evidence(body.evidence)),
                (body.reason or None), checked_at if done else None,
            )
            fid = row["finding_id"]
            if done:
                f = await con.fetchrow(
                    "SELECT id, status, title, severity, asset_id FROM findings WHERE id = $1 FOR UPDATE", fid)
                if f is not None:
                    await con.execute(
                        "UPDATE findings SET exploitability = $2, last_verified_at = $3 WHERE id = $1",
                        fid, body.verdict, checked_at,
                    )
                    if row["purpose"] == "fix" and f["status"] == "fixed":
                        if body.verdict == "not_reproducible":
                            await con.execute(
                                "UPDATE findings SET fix_verified_at = $2 WHERE id = $1", fid, checked_at)
                            await lifecycle.record_history(
                                con, fid, "fixed", "fixed",
                                f"verified fixed: {body.check_id or 'safe check'} could not reproduce it",
                                None, SYSTEM_ACTOR)
                            fix_event = "finding_fix_verified"
                        elif body.verdict == "confirmed":
                            await con.execute(
                                """
                                UPDATE findings
                                   SET status = 'open', status_reason = 'fix did not hold',
                                       status_by = $2, status_changed_at = NOW(),
                                       accepted_until = NULL, fix_verified_at = NULL
                                 WHERE id = $1
                                """,
                                fid, SYSTEM_ACTOR,
                            )
                            await lifecycle.record_history(
                                con, fid, "fixed", "open", "fix did not hold", None, SYSTEM_ACTOR)
                            dups = await con.fetch(
                                """
                                UPDATE findings
                                   SET status = 'open', status_reason = 'fix did not hold',
                                       status_by = $2, status_changed_at = NOW(),
                                       accepted_until = NULL, fix_verified_at = NULL
                                 WHERE duplicate_of = $1 AND status = 'fixed' RETURNING id
                                """,
                                fid, SYSTEM_ACTOR,
                            )
                            for d in dups:
                                await lifecycle.record_history(
                                    con, d["id"], "fixed", "open",
                                    f"fix did not hold (follows primary {fid})", None, SYSTEM_ACTOR)
                            fix_event, reopened = "finding_fix_failed", True
                    detail = {"title": f["title"], "severity": f["severity"], "finding_status": f["status"]}
    out = row_out(updated)

    # ---- after commit: audit + events (best effort) -----------------------------
    try:
        await audit.record(
            pool, action="update", actor=actor, resource_type="findings", resource_id=str(out.finding_id),
            method="POST", path=f"/v1/verifications/{vid}/result", status=200,
            details={"transition": "verification", "verification_id": str(vid), "purpose": out.purpose,
                     "status": out.status, "verdict": out.verdict, "check_id": out.check_id,
                     "fix_event": fix_event, "reopened": reopened},
        )
    except Exception:  # noqa: BLE001
        logger.exception("verification_audit_failed")
    if out.status == "done" and r is not None:
        base = {"finding_id": str(out.finding_id), "verification_id": str(vid), "verdict": out.verdict,
                "check_id": out.check_id, "purpose": out.purpose,
                "checked_at": (out.checked_at or checked_at).isoformat()}
        events: list[dict[str, Any]] = []
        if out.purpose == "exploitability" or (out.purpose == "fix" and not fix_event
                                               and detail.get("finding_status") != "fixed"):
            events.append({"event": "finding_verified", **base})
        if fix_event:
            events.append({"event": fix_event, **base})
        if reopened:
            events.append({"event": "finding_reopened", "finding_id": str(out.finding_id),
                           "status": "open", "reason": "fix did not hold"})
        for ev in events:
            try:
                await publish_event(r, ev)
            except Exception:  # noqa: BLE001
                logger.exception("publish_event_failed")
    return out


# =========================================================================== #
# Remediation PR merged
# =========================================================================== #

async def remediation_merged(pool, r, remediation_id: UUID, *, actor: str) -> dict[str, Any]:
    """A remediation PR was merged: record it and schedule the re-check."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE remediations SET status = 'merged' WHERE id = $1 "
            "AND status IN ('proposed', 'verified', 'pr_open', 'merged') RETURNING id, finding_id, status",
            remediation_id,
        )
    if row is None:
        raise FindingNotFound(str(remediation_id))
    scheduled = None
    if row["finding_id"] is not None:
        async with pool.acquire() as con:
            cur = await con.fetchval("SELECT status FROM findings WHERE id = $1", row["finding_id"])
        # A merged PR does not close the finding by itself (a human or the ticket does).
        # Already fixed -> prove the fix; still open -> re-check whether it is exploitable
        # (evidence for the reviewer; it never closes the finding on its own).
        if cur == "fixed":
            scheduled = await schedule_fix_check(pool, r, row["finding_id"], trigger="fix_pr", actor=actor)
        elif cur is not None:
            try:
                scheduled = await request(
                    pool, r, finding_id=row["finding_id"], purpose="exploitability", trigger="fix_pr",
                    requested_by=actor, run_after=_now() + timedelta(seconds=cfg.pr_delay_sec),
                    reason="re-checking after the remediation PR was merged")
            except Exception:  # noqa: BLE001
                logger.exception("merged_recheck_failed")
    return {"remediation_id": str(remediation_id), "finding_id": str(row["finding_id"]) if row["finding_id"] else None,
            "verification": scheduled.model_dump(mode="json") if scheduled else None}


# =========================================================================== #
# Sweep (called from the scheduler loop, once per tenant)
# =========================================================================== #

async def sweep(pool, r) -> dict[str, int]:
    """Dispatch due rows, time out stale ones, retry inconclusive fix re-checks."""
    out = {"expired": 0, "dispatched": 0, "retried": 0}
    async with pool.acquire() as con:
        out["expired"] = await _expire_stale(con)
        due = await con.fetch(
            "SELECT id FROM finding_verifications WHERE status = 'scheduled' AND run_after <= NOW() "
            "ORDER BY run_after LIMIT $1", cfg.sweep_batch)
        # fix re-checks that ended without an answer, still fixed-but-unproven, under the attempt cap
        again = await con.fetch(
            """
            SELECT DISTINCT ON (v.finding_id) v.finding_id
              FROM finding_verifications v JOIN findings f ON f.id = v.finding_id
             WHERE v.purpose = 'fix' AND f.status = 'fixed' AND f.fix_verified_at IS NULL
               AND v.status IN ('done', 'error')
               AND (v.status = 'error' OR v.verdict = 'inconclusive')
               AND v.completed_at < NOW() - make_interval(secs => $1)
               AND NOT EXISTS (SELECT 1 FROM finding_verifications x
                                WHERE x.finding_id = v.finding_id AND x.purpose = 'fix'
                                  AND (x.status IN ('scheduled', 'queued')
                                       OR x.requested_at > v.requested_at))
               AND (SELECT COUNT(*) FROM finding_verifications y
                     WHERE y.finding_id = v.finding_id AND y.purpose = 'fix'
                       AND y.requested_at >= COALESCE(f.status_changed_at, f.first_seen)) < $2
             ORDER BY v.finding_id, v.requested_at DESC LIMIT $3
            """,
            float(cfg.retry_sec), cfg.max_attempts, cfg.sweep_batch)
    for row in due:
        try:
            if await dispatch(pool, r, row["id"]) is not None:
                out["dispatched"] += 1
        except Exception:  # noqa: BLE001 -- one bad row never stops the sweep
            logger.exception("verification_dispatch_failed", extra={"verification_id": str(row["id"])})
    for row in again:
        try:
            await request(pool, r, finding_id=row["finding_id"], purpose="fix", trigger="retry",
                          requested_by=SYSTEM_ACTOR, reason="retrying an inconclusive re-check")
            out["retried"] += 1
        except Exception:  # noqa: BLE001
            logger.exception("verification_retry_failed", extra={"finding_id": str(row["finding_id"])})
    return out
