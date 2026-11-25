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
  fix.
* A ``VIOLATED`` verdict closes the findings of targets that PROVABLY stopped violating, and
  nothing else. The witness list is capped (5) and root-cause filtered, so it can never be the
  evidence that a target is fine; the library's ``violating_targets`` (EVERY violator found,
  sorted, capped at 5000 with ``violating_truncated``) can. An open finding is closed only if its
  target is absent from that list AND the list is complete (not truncated, present, non-empty)
  AND the target is not a blind spot inbound and not in the library's ``unproven_targets`` (a
  target nobody can see into, or that an unknown edge could still reach, may merely have become
  unprovable, not safe: the evaluator would answer UNKNOWN for it alone). ``fix_verified_at``
  follows the same evidence-tier rule as HOLDS.
* Fencing: when the caller passes ``lease_owner`` (the runner does), every close is done inside a
  transaction that first proves that owner still holds a live tenant lease (database clock) and
  that the evaluated graph version is not older than the tenant's current one. A stale evaluator
  (its lease lapsed while it ran) therefore can never close or verify a finding that a newer
  evaluator just opened. Opening and refreshing findings is not fenced beyond a pre-check: a
  stale VIOLATED is noise, never a false all-clear.
* ``host-config`` (P2) verdicts have hop-less witnesses (``detail.node`` is the host). One finding
  per (invariant, host): several failing clauses of one host are folded into ONE finding (the
  first clause is the evidence, all of them are in the description). A host that is merely
  ``UNKNOWN`` (no agent, silent, stale, unsigned, approximate, in conflict) keeps its open
  finding, both under a VIOLATED verdict (``unproven_targets``) and under a HOLDS that a lower
  coverage floor let stand with unknown hosts (those hosts are not closed by the HOLDS).
* The evidence has a **constant key set** (the upsert merges evidence with ``||``, so a varying
  key set would leave stale keys behind) and never carries ``url`` / ``matched_at`` / a CVE-like
  string: those keys steer verification jobs and CVE de-duplication, which are meaningless here.

Everything here works on the plain ``Result.to_dict()`` so this module never imports the
(optional) assurance library.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional, Sequence

from .. import audit, lifecycle
from ..queue import publish_event
from . import store

logger = logging.getLogger(__name__)

ACTOR = "system:assurance"
RULE_PREFIX = "invariant:"
ESTATE_KIND = "org"
ESTATE_VALUE = "paddock-assurance"
#: assertions whose witnesses have no hops: the node is ``detail.node``.
HOPLESS_ASSERTIONS = frozenset({"covered", "host-config"})
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
    skipped: str = ""            # why nothing was done ('unknown', 'findings_disabled', 'lease_lost', ...)
    close_skipped: str = ""      # why a VIOLATED verdict closed nothing ('truncated', 'no_target_list', ...)
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
    """The root-cause node a witness is about: the last hop's destination, or for ``covered`` and
    ``host-config`` (hop-less witnesses) the node in ``detail.node``. ``None`` for a witness we
    cannot place (never invent a target)."""
    if assertion in HOPLESS_ASSERTIONS:
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


def agent_uuid(ref: str) -> Optional[uuid.UUID]:
    """``agent:<uuid>`` -> UUID; any other node reference -> None."""
    if not ref.startswith("agent:"):
        return None
    try:
        return uuid.UUID(ref[len("agent:"):])
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


_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def _text(value: Any, limit: int = 160) -> str:
    """A witness value as one short, single-line, printable string (agent-supplied text is data:
    never let it break the layout or smuggle a newline into a finding)."""
    s = _CTRL.sub(" ", str(value if value is not None else "")).strip()
    return s if len(s) <= limit else s[:limit - 1] + "..."


def _host_clause(detail: dict[str, Any]) -> str:
    predicate = _text(detail.get("predicate") or detail.get("field") or "a host-config clause")
    observed = _text(detail.get("observed"), 80)
    op, expected = _text(detail.get("op"), 20), _text(detail.get("expected"), 80)
    need = f"{op} {expected}".strip()
    return f"{predicate} (found {observed or 'nothing'}{'; required ' + need if need else ''})"


def _host_evidence(detail: dict[str, Any]) -> str:
    bits = [f"{_text(detail.get('tier'), 20) or 'unknown'} evidence"]
    if detail.get("signed") == "true":
        bits.append("signed by the host's agent")
    if detail.get("key_id"):
        bits.append(f"key {_text(detail['key_id'], 64)}")
    if detail.get("seq"):
        bits.append(f"seq {_text(detail['seq'], 20)}")
    if detail.get("observed_at"):
        bits.append(f"as of {_text(detail['observed_at'], 32)}")
    return ", ".join(bits)


def describe_host_witnesses(witnesses: Sequence[dict[str, Any]], labels: dict[str, str]) -> str:
    """One host, one or more failing clauses, in words. ``witnesses`` all have the same node."""
    details = [w.get("detail") or {} for w in witnesses] or [{}]
    node = _label(_text(details[0].get("node"), 128), labels)
    clauses = "; ".join(f"{i}) {_host_clause(d)}" if len(details) > 1 else _host_clause(d)
                        for i, d in enumerate(details, 1))
    return (f"{node} does not meet the required configuration: {clauses}. "
            f"Evidence: {_host_evidence(details[0])}.")


def describe_witness(assertion: str, witness: dict[str, Any], labels: dict[str, str]) -> str:
    """The witness in words (what a person reads in the finding)."""
    detail = witness.get("detail") or {}
    if assertion == "host-config":
        return describe_host_witnesses([witness], labels)
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
    "host-config": ("Change the host's configuration so the clause above holds (for the SSH and firewall "
                    "invariants: edit sshd_config / the firewall policy, then reload the service). The "
                    "agent reports the new configuration on its next posture and this finding closes by "
                    "itself when the invariant holds; a host that goes silent stays open."),
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
    by_host: dict[str, list[dict[str, Any]]] = {}
    if assertion == "host-config":         # every failing clause of a host goes in its one finding
        for w in result.get("witnesses") or []:
            t = target_of(assertion, w)
            if t is not None:
                by_host.setdefault(t, []).append(w)
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
            "description": (describe_host_witnesses(by_host[target], labels) if assertion == "host-config"
                            else describe_witness(assertion, w, labels)),
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
    agents = sorted({a for r in refs if (a := agent_uuid(r)) is not None})
    if not ids and not agents:
        return {}, set()
    labels: dict[str, str] = {}
    live: set[uuid.UUID] = set()
    async with pool.acquire() as con:
        if ids:
            rows = await con.fetch("SELECT id, value FROM assets WHERE id = ANY($1::uuid[])", ids)
            live = {r["id"] for r in rows}
            labels = {f"asset:{r['id']}": r["value"] for r in rows}
        if agents:
            try:       # a managed host is shown by its hostname (display only, never a target)
                for r in await con.fetch("SELECT id, hostname FROM fleet_agents WHERE id = ANY($1::uuid[])",
                                         agents):
                    if r["hostname"]:
                        labels[f"agent:{r['id']}"] = _text(r["hostname"], 100)
            except Exception:  # noqa: BLE001 -- a label is cosmetic
                logger.exception("assurance_agent_labels_failed")
    return labels, live


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
       AND NOT COALESCE((evidence->>'target_ref') = ANY($7::text[]), false)
     FOR UPDATE
)
UPDATE findings f
   SET status = 'fixed', status_reason = $3::text, status_by = $4::text, status_changed_at = $5::timestamptz,
       accepted_until = NULL,
       fix_verified_at = CASE WHEN $6::boolean THEN $5::timestamptz ELSE NULL END
  FROM due WHERE f.id = due.id
RETURNING f.id, due.status AS from_status
"""

#: ``$7`` (``_CLOSE_SQL``) = targets the HOLDS must leave open: for ``host-config``, the hosts a
#: lower coverage floor let the verdict stand over without being proven (no agent, silent, stale,
#: unsigned, approximate, in conflict). Empty for every other assertion: HOLDS closes all, as in P1.

#: Like ``_CLOSE_SQL`` but only for findings whose target is provably no longer violating:
#: ``$7`` = every target the evaluator still finds violating, ``$8`` = targets it cannot see into.
#: A finding without a recorded target (``evidence.target_ref``) is never closed this way.
_CLOSE_RESOLVED_SQL = """
WITH due AS (
    SELECT id, status FROM findings
     WHERE rule_source = 'invariant'
       AND (rule_id = $1::text OR starts_with(rule_id, $2::text))
       AND status IN ('open', 'triaged') AND suppressed_by IS NULL
       AND evidence->>'target_ref' IS NOT NULL
       AND NOT ((evidence->>'target_ref') = ANY($7::text[]))
       AND NOT ((evidence->>'target_ref') = ANY($8::text[]))
     FOR UPDATE
)
UPDATE findings f
   SET status = 'fixed', status_reason = $3::text, status_by = $4::text, status_changed_at = $5::timestamptz,
       accepted_until = NULL,
       fix_verified_at = CASE WHEN $6::boolean THEN $5::timestamptz ELSE NULL END
  FROM due WHERE f.id = due.id
RETURNING f.id, due.status AS from_status
"""


async def _fenced(con, lease_owner: Optional[str], graph_version: int, rep: SyncReport) -> bool:
    """True if it is safe to close findings from this evaluation. Must run in the transaction
    that does the closing (the state row stays share-locked until it ends). No ``lease_owner`` =
    an unfenced caller (the API, tests): allowed, as before."""
    if lease_owner is None:
        return True
    current = await store.fence_lease(con, lease_owner)
    if current is None:
        rep.skipped = "lease_lost"
        return False
    if current > graph_version:
        # The graph moved on while we evaluated: this verdict describes an older world. The
        # invariant stays due (its last_graph_version is behind), the next evaluation decides.
        rep.skipped = "graph_moved"
        return False
    return True


async def _after_close(pool, redis: Any, rows: list[Any], verified: bool, tier: Optional[str], transition: str,
                       rep: SyncReport) -> None:
    rep.closed += len(rows)
    rep.verified += len(rows) if verified else 0
    for r in rows:
        await _audit(pool, r["id"], {"transition": transition, "from": r["from_status"],
                                     "to": "fixed", "verified": verified, "evidence_tier": tier})
        await _publish(redis, {"event": "finding_closed", "finding_id": str(r["id"]), "status": "fixed"})


async def _close_all(pool, redis: Any, invariant_id: str, tier: Optional[str], graph_version: int,
                     now: datetime, rep: SyncReport, lease_owner: Optional[str] = None,
                     keep: Sequence[str] = ()) -> None:
    verified = tier in VERIFYING_TIERS
    reason = (f"invariant holds at graph version {graph_version}"
              f" (evidence: {tier or 'none'}{'' if verified else ', not enough to verify'})")
    if keep:
        reason += f"; {len(keep)} undecided target(s) left open"
    base = f"{RULE_PREFIX}{invariant_id}"
    async with pool.acquire() as con:
        async with con.transaction():
            if not await _fenced(con, lease_owner, graph_version, rep):
                return
            rows = await con.fetch(_CLOSE_SQL, base, base + "@", reason, ACTOR, now, verified, list(keep))
            for r in rows:
                await lifecycle.record_history(con, r["id"], r["from_status"], "fixed", reason, None, ACTOR)
    await _after_close(pool, redis, rows, verified, tier, "invariant_holds", rep)


def _blind_targets(result: dict[str, Any]) -> list[str]:
    """Nodes the evaluator could not see INTO (inbound or both) and that matter to this verdict:
    a finding for such a node must stay open, because "no known path" is not "fixed" there."""
    out: set[str] = set()
    for b in result.get("blind_spots") or []:
        if not isinstance(b, dict) or not isinstance(b.get("node"), str):
            continue
        if b.get("relevant") is False:
            continue
        if b.get("direction", "both") in ("in", "both", "host"):   # 'host': host-config facts
            out.add(b["node"])
    return sorted(out)


def _undecided_hosts(result: dict[str, Any]) -> Optional[list[str]]:
    """Hosts a ``host-config`` HOLDS stood over without proving them (the library lists them in
    ``unproven_targets``; their blind spots are added too). ``None`` when that list cannot be
    trusted (absent, malformed or truncated): then a HOLDS closes nothing."""
    unproven = result.get("unproven_targets")
    if (not isinstance(unproven, list) or not all(isinstance(t, str) for t in unproven)
            or result.get("violating_truncated")):
        return None
    return sorted(set(unproven) | set(_blind_targets(result)))


async def _close_resolved(pool, redis: Any, invariant_id: str, result: dict[str, Any], graph_version: int,
                          now: datetime, rep: SyncReport, lease_owner: Optional[str]) -> None:
    """While the verdict is still ``VIOLATED``: close findings of targets that no longer violate
    (see the module docstring for what "provably" requires)."""
    targets = result.get("violating_targets")
    unproven = result.get("unproven_targets")
    if (not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets)
            or not isinstance(unproven, list) or not all(isinstance(t, str) for t in unproven)):
        rep.close_skipped = "no_target_list"          # older library, or nothing to compare with
        return
    if result.get("violating_truncated"):
        rep.close_skipped = "truncated"               # the list is not the whole set: close nothing
        return
    tier = result.get("evidence_tier")
    verified = tier in VERIFYING_TIERS
    reason = (f"no longer violating at graph version {graph_version}; the invariant still has "
              f"{len(targets)} other violating target(s) (evidence: {tier or 'none'}"
              f"{'' if verified else ', not enough to verify'})")
    base = f"{RULE_PREFIX}{invariant_id}"
    async with pool.acquire() as con:
        async with con.transaction():
            if not await _fenced(con, lease_owner, graph_version, rep):
                return
            rows = await con.fetch(_CLOSE_RESOLVED_SQL, base, base + "@", reason, ACTOR, now, verified,
                                   targets, sorted(set(_blind_targets(result)) | set(unproven)))
            for r in rows:
                await lifecycle.record_history(con, r["id"], r["from_status"], "fixed", reason, None, ACTOR)
    await _after_close(pool, redis, rows, verified, tier, "invariant_target_resolved", rep)


async def sync_findings(
    pool, redis: Any, *, invariant_id: str, title: str, finding_enabled: bool = True,
    proposed_fixes: Sequence[str] = (), result: dict[str, Any], graph_version: int, now: datetime,
    lease_owner: Optional[str] = None,
) -> SyncReport:
    """Apply one verdict (``Result.to_dict()``) to the tenant's findings. Must run inside the
    tenant's context (``tenancy.tenant_context``); every statement is tenant-scoped by the pool.
    Idempotent: running it twice with the same result changes nothing the second time.

    ``lease_owner``: the evaluation lease token of the caller (the runner passes it). When given,
    closing is fenced on it (module docstring); a fenced-out call changes nothing and reports
    ``skipped='lease_lost'`` / ``'graph_moved'``.
    """
    verdict = str(result.get("verdict", ""))
    assertion = str(result.get("assertion", "unreachable"))
    rep = SyncReport(verdict=verdict)
    if verdict == "UNKNOWN":
        rep.skipped = "unknown"
        return rep
    if verdict == "HOLDS":
        keep: list[str] = []
        if assertion == "host-config":
            held = _undecided_hosts(result)
            if held is None:
                rep.close_skipped = "no_target_list" if not result.get("violating_truncated") else "truncated"
                return rep
            keep = held
        await _close_all(pool, redis, invariant_id, result.get("evidence_tier"), graph_version, now, rep,
                         lease_owner, keep)
        return rep
    if verdict != "VIOLATED":
        rep.skipped = "unrecognised_verdict"
        return rep
    if not finding_enabled:
        rep.skipped = "findings_disabled"
        return rep
    if lease_owner is not None:
        async with pool.acquire() as con:
            if await store.fence_lease(con, lease_owner) is None:
                rep.skipped = "lease_lost"            # a stale evaluator writes nothing at all
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
    await _close_resolved(pool, redis, invariant_id, result, graph_version, now, rep, lease_owner)
    return rep


__all__ = ["ACTOR", "ESTATE_KIND", "ESTATE_VALUE", "EVIDENCE_KEYS", "SyncReport", "asset_uuid", "build_items",
           "describe_witness", "rule_id_for", "sync_findings", "target_of"]
