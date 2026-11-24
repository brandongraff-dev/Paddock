"""Verdicts -> findings (docs/ASSURANCE_P1.md section 6).

Rules, and why they are what they are:

* ``VIOLATED`` opens (or refreshes) **one finding per root-cause target**, through the existing
  in-process upsert (``routers.findings.bulk_upsert``) so dedupe, suppression, SLA, ticketing and
  SIEM events all behave as for any other source. A finding that was ``fixed`` and whose
  violation is back is **reopened** (history row + ``finding_reopened`` event); the upsert alone
  never changes a status. ``accepted`` / ``false_positive`` / ``wontfix`` / suppressed findings are
  never disturbed: a person decided that, a machine must not undo it.
* ``HOLDS`` closes the invariant's open findings. The re-evaluation is the verification, but only
  when the evidence under the HOLDS is at least ``observed``: a HOLDS that rests on a
  configuration read ("the rules say closed") does not stamp ``fix_verified_at``.
* ``UNKNOWN`` never opens or closes anything. "We cannot tell" is neither a new problem nor a
  fix. This is also why a ``VIOLATED`` verdict never closes findings for targets that dropped out
  of the witness list: the list is capped and root-cause filtered, and the dropped target may only
  have become unprovable, not safe.
* The evidence has a **constant key set** (the upsert merges evidence with ``||``, so a varying
  key set would leave stale keys behind) and never carries ``url`` / ``matched_at`` / a CVE-like
  string: those keys steer verification jobs and CVE de-duplication, which are meaningless here.

Everything here works on the plain ``Result.to_dict()`` so this module never imports the
(optional) assurance library.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional, Sequence

from .. import audit, lifecycle
from ..queue import publish_event

logger = logging.getLogger(__name__)

ACTOR = "system:assurance"
RULE_PREFIX = "invariant:"
ESTATE_KIND = "org"
ESTATE_VALUE = "paddock-assurance"
REOPEN_REASON = "invariant violated again"
VERIFYING_TIERS = frozenset({"observed", "tested"})
_MAX_RULE_ID = 256
_MAX_TITLE = 512
#: Evidence keys. Constant on purpose (see module docstring).
EVIDENCE_KEYS = ("invariant", "digest", "verdict", "target_ref", "witness", "coverage", "graph_version")

_REASON_TEXT = {
    "no_sensor": "nothing reports on it",
    "tier_below_min": "the evidence is weaker than the invariant requires",
    "future_timestamp": "its evidence is dated in the future",
    "stale": "its evidence is out of date",
}


@dataclass
class SyncReport:
    """What one ``sync_findings`` call did (also folded into the evaluation summary)."""

    verdict: str = ""
    targets: int = 0
    opened: int = 0
    updated: int = 0
    reopened: int = 0
    closed: int = 0
    verified: int = 0            # closed AND stamped fix_verified_at
    left_alone: int = 0          # fixed-but-suppressed, accepted, false positive, ...
    suppressed: int = 0
    skipped: str = ""            # why nothing was done ('unknown', 'findings_disabled', ...)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _NullRedis:
    """Stands in for redis when the caller has none: events are best effort, never required."""

    async def xadd(self, *_a: Any, **_k: Any) -> str:
        return "0-0"


# --------------------------------------------------------------------------------------------
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------------------------

def target_of(assertion: str, witness: dict[str, Any]) -> Optional[str]:
    """The root-cause node a witness is about: the last hop's destination, or for ``covered`` the
    blind node itself. ``None`` for a witness we cannot place (never invent a target)."""
    if assertion == "covered":
        node = (witness.get("detail") or {}).get("node")
        return node if isinstance(node, str) and node else None
    hops = witness.get("hops") or []
    if not hops:
        return None
    dst = hops[-1].get("dst")
    return dst if isinstance(dst, str) and dst else None


def asset_uuid(ref: str) -> Optional[uuid.UUID]:
    """``asset:<uuid>`` -> UUID; any other node reference -> None (estate fallback)."""
    if not ref.startswith("asset:"):
        return None
    try:
        return uuid.UUID(ref[len("asset:"):])
    except ValueError:
        return None


def rule_id_for(invariant_id: str, target_ref: str, *, estate: bool) -> str:
    """``invariant:<id>`` for an asset-backed target.

    An estate-asset finding carries ``@<target>`` as well: the upsert key is ``(asset, rule_id,
    source)`` and every non-asset target shares the one estate asset, so without a discriminator
    two different blind or exposed addresses would overwrite each other (and the lifecycle's
    duplicate collapse would hide all but one of them).
    """
    base = f"{RULE_PREFIX}{invariant_id}"
    if not estate:
        return base
    rid = f"{base}@{target_ref}"
    if len(rid) > _MAX_RULE_ID:
        rid = f"{base}@{hashlib.sha256(target_ref.encode()).hexdigest()[:32]}"
    return rid


def _label(ref: str, labels: dict[str, str]) -> str:
    return labels.get(ref) or ref


def _hop_text(hop: dict[str, Any], labels: dict[str, str]) -> str:
    proto, ports = hop.get("proto", ""), hop.get("ports", "")
    what = " ".join(x for x in (proto, ports) if x)
    how = hop.get("basis", "")
    src = hop.get("source", "")
    meta = ", ".join(x for x in (how, src) if x)
    return f"{_label(hop.get('src', ''), labels)} -> {_label(hop.get('dst', ''), labels)}" \
           f" ({what}{'; ' if what and meta else ''}{meta})"


def describe_witness(assertion: str, witness: dict[str, Any], labels: dict[str, str]) -> str:
    """The witness in words (what a person reads in the finding)."""
    detail = witness.get("detail") or {}
    if assertion == "covered":
        node = _label(detail.get("node", ""), labels)
        direction = detail.get("direction", "both")
        parts = []
        for d in ("in", "out"):
            r = detail.get(f"reason_{d}")
            if r:
                parts.append(f"{'inbound' if d == 'in' else 'outbound'}: {_REASON_TEXT.get(r, r)}")
        if not parts:
            r = detail.get("reason", "")
            parts.append(f"{direction}: {_REASON_TEXT.get(r, r)}")
        return f"{node} is not fully covered ({'; '.join(parts)})."
    hops = witness.get("hops") or []
    if assertion == "exposes-only":
        if not hops:
            return "An exposed connection exceeds the allowed ports."
        h = hops[0]
        bad = detail.get("disallowed_ports", "?")
        ok = detail.get("allowed_ports") or "none"
        return (f"{_label(h.get('src', ''), labels)} can open {h.get('proto', '')} connections to "
                f"{_label(h.get('dst', ''), labels)} on ports {h.get('ports', '?')} "
                f"({h.get('basis', '?')} evidence); only {ok} are allowed, so {bad} are not.")
    if not hops:
        return "A connection path exists."
    path = "; then ".join(_hop_text(h, labels) for h in hops)
    n = len(hops)
    return (f"A path of {n} connection{'s' if n != 1 else ''} exists: {path}. "
            f"Weakest evidence on the path: {witness.get('weakest_basis', '?')}.")


_REMEDIATION = {
    "covered": ("Close the gap: sync the missing configuration source or deploy a sensor that sees "
                "this node in the missing direction, then wait for the next evaluation. Until "
                "then other invariants cannot rule out connections at this node."),
    "exposes-only": ("Restrict the exposed ports to the allowed list (or remove the rule), or "
                     "declare a reasoned, expiring exception in the invariant. This finding "
                     "closes by itself when the next evaluation holds."),
    "unreachable": ("Remove or narrow the connection that forms the path (for example restrict the "
                    "source range or port on the rule shown), or segment the networks. This "
                    "finding closes by itself when the next evaluation holds."),
}


def build_items(
    *, invariant_id: str, title: str, assertion: str, digest: str, severity: str, result: dict[str, Any],
    graph_version: int, proposed: Sequence[str], labels: dict[str, str], live_assets: set[uuid.UUID],
) -> tuple[list[dict[str, Any]], list[str]]:
    """``(FindingIn payloads, target refs)``: one per distinct root-cause target, in witness order."""
    items: list[dict[str, Any]] = []
    targets: list[str] = []
    seen: set[str] = set()
    for w in result.get("witnesses") or []:
        target = target_of(assertion, w)
        if target is None or target in seen:
            continue
        seen.add(target)
        aid = asset_uuid(target)
        estate = aid is None or aid not in live_assets
        evidence = {
            "invariant": invariant_id, "digest": digest, "verdict": "VIOLATED",
            "target_ref": target, "witness": w, "coverage": result.get("coverage") or {},
            "graph_version": graph_version,
        }
        item: dict[str, Any] = {
            "rule_id": rule_id_for(invariant_id, target, estate=estate),
            "rule_source": "invariant",
            "severity": severity,
            "title": f"{title}: {_label(target, labels)}"[:_MAX_TITLE],
            "description": describe_witness(assertion, w, labels),
            "remediation": _REMEDIATION.get(assertion, _REMEDIATION["unreachable"]),
            "evidence": evidence,
            "metadata": {"invariant_id": invariant_id, "target_ref": target,
                         "proposed_fixes": sorted(proposed)},
        }
        if estate:
            item.update(asset_value=ESTATE_VALUE, asset_kind=ESTATE_KIND)
        else:
            item["asset_id"] = str(aid)
        items.append(item)
        targets.append(target)
    return items, targets


# --------------------------------------------------------------------------------------------
# DB
# --------------------------------------------------------------------------------------------

async def _asset_labels(pool, result: dict[str, Any], assertion: str) -> tuple[dict[str, str], set[uuid.UUID]]:
    """Display values for the asset nodes the witnesses mention, and which of them still exist
    (a graph node may outlive its asset row; the finding FK must not break the whole batch)."""
    refs: set[str] = set()
    for w in result.get("witnesses") or []:
        for h in w.get("hops") or []:
            refs.update(x for x in (h.get("src"), h.get("dst")) if isinstance(x, str))
        t = target_of(assertion, w)
        if t:
            refs.add(t)
    ids = sorted({a for r in refs if (a := asset_uuid(r)) is not None})
    if not ids:
        return {}, set()
    async with pool.acquire() as con:
        rows = await con.fetch("SELECT id, value FROM assets WHERE id = ANY($1::uuid[])", ids)
    live = {r["id"] for r in rows}
    return {f"asset:{r['id']}": r["value"] for r in rows}, live


async def _publish(redis: Any, event: dict[str, Any]) -> None:
    if redis is None:
        return
    try:
        await publish_event(redis, event)
    except Exception:  # noqa: BLE001 -- events are best effort
        logger.exception("assurance_publish_failed", extra={"event_name": event.get("event")})


async def _audit(pool, finding_id: Any, details: dict[str, Any]) -> None:
    try:
        await audit.record(
            pool, action="update", actor=ACTOR, actor_role="service", resource_type="findings",
            resource_id=str(finding_id), details=details)
    except Exception:  # noqa: BLE001 -- never fail a sync on audit
        logger.exception("assurance_audit_failed", extra={"finding_id": str(finding_id)})


async def _reopen(pool, redis: Any, finding_id: Any, now: datetime, rep: SyncReport) -> None:
    """``fixed`` -> ``open`` for a recurrence. Guarded on the status so a concurrent human
    transition wins; history is written in the same transaction as the status."""
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                "UPDATE findings SET status = 'open', status_reason = $2, status_by = $3, "
                "status_changed_at = $4, accepted_until = NULL, fix_verified_at = NULL "
                "WHERE id = $1 AND status = 'fixed' AND suppressed_by IS NULL RETURNING id",
                finding_id, REOPEN_REASON, ACTOR, now)
            if row is None:
                return
            await lifecycle.record_history(con, finding_id, "fixed", "open", REOPEN_REASON, None, ACTOR)
    rep.reopened += 1
    await _audit(pool, finding_id, {"transition": "invariant_reopen", "from": "fixed", "to": "open",
                                    "reason": REOPEN_REASON})
    await _publish(redis, {"event": "finding_reopened", "finding_id": str(finding_id),
                           "status": "open", "reason": REOPEN_REASON})


_CLOSE_SQL = """
WITH due AS (
    SELECT id, status FROM findings
     WHERE rule_source = 'invariant'
       AND (rule_id = $1::text OR starts_with(rule_id, $2::text))
       AND status IN ('open', 'triaged') AND suppressed_by IS NULL
     FOR UPDATE
)
UPDATE findings f
   SET status = 'fixed', status_reason = $3::text, status_by = $4::text, status_changed_at = $5::timestamptz,
       accepted_until = NULL,
       fix_verified_at = CASE WHEN $6::boolean THEN $5::timestamptz ELSE NULL END
  FROM due WHERE f.id = due.id
RETURNING f.id, due.status AS from_status
"""


async def _close_all(pool, redis: Any, invariant_id: str, tier: Optional[str], graph_version: int,
                     now: datetime, rep: SyncReport) -> None:
    verified = tier in VERIFYING_TIERS
    reason = (f"invariant holds at graph version {graph_version}"
              f" (evidence: {tier or 'none'}{'' if verified else ', not enough to verify'})")
    base = f"{RULE_PREFIX}{invariant_id}"
    async with pool.acquire() as con:
        async with con.transaction():
            rows = await con.fetch(_CLOSE_SQL, base, base + "@", reason, ACTOR, now, verified)
            for r in rows:
                await lifecycle.record_history(con, r["id"], r["from_status"], "fixed", reason, None, ACTOR)
    rep.closed += len(rows)
    rep.verified += len(rows) if verified else 0
    for r in rows:
        await _audit(pool, r["id"], {"transition": "invariant_holds", "from": r["from_status"],
                                     "to": "fixed", "verified": verified, "evidence_tier": tier})
        await _publish(redis, {"event": "finding_closed", "finding_id": str(r["id"]), "status": "fixed"})


async def sync_findings(
    pool, redis: Any, *, invariant_id: str, title: str, finding_enabled: bool = True,
    proposed_fixes: Sequence[str] = (), result: dict[str, Any], graph_version: int, now: datetime,
) -> SyncReport:
    """Apply one verdict (``Result.to_dict()``) to the tenant's findings. Must run inside the
    tenant's context (``tenancy.tenant_context``); every statement is tenant-scoped by the pool.
    Idempotent: running it twice with the same result changes nothing the second time.
    """
    verdict = str(result.get("verdict", ""))
    assertion = str(result.get("assertion", "unreachable"))
    rep = SyncReport(verdict=verdict)
    if verdict == "UNKNOWN":
        rep.skipped = "unknown"
        return rep
    if verdict == "HOLDS":
        await _close_all(pool, redis, invariant_id, result.get("evidence_tier"), graph_version, now, rep)
        return rep
    if verdict != "VIOLATED":
        rep.skipped = "unrecognised_verdict"
        return rep
    if not finding_enabled:
        rep.skipped = "findings_disabled"
        return rep

    from ..models import FindingBulkIn
    from ..routers import findings as findings_router

    labels, live = await _asset_labels(pool, result, assertion)
    items, targets = build_items(
        invariant_id=invariant_id, title=title, assertion=assertion, digest=str(result.get("digest", "")),
        severity=str(result.get("severity", "high")), result=result, graph_version=graph_version,
        proposed=proposed_fixes, labels=labels, live_assets=live)
    rep.targets = len(items)
    if not items:
        rep.skipped = "no_targets"
        return rep
    out = await findings_router.bulk_upsert(
        FindingBulkIn.model_validate({"items": items}), pool=pool, r=redis if redis is not None else _NullRedis())
    rep.opened, rep.updated, rep.suppressed = out.inserted, out.updated, out.suppressed
    for f in out.items:
        if f.status == "fixed":
            if f.suppressed_by is not None:
                rep.left_alone += 1
            else:
                await _reopen(pool, redis, f.id, now, rep)
        elif f.status not in ("open", "triaged"):
            rep.left_alone += 1
    return rep


__all__ = ["ACTOR", "ESTATE_KIND", "ESTATE_VALUE", "EVIDENCE_KEYS", "SyncReport", "asset_uuid", "build_items",
           "describe_witness", "rule_id_for", "sync_findings", "target_of"]
