"""Replica verification: do an exploit's PRECONDITIONS hold on a rebuilt copy?

DEFENSIVE INVARIANT. Nothing here executes an exploit, payload, or command,
not even against a replica. Verification only evaluates *facts* that a
sandbox runner collected about the replica (versions, flags, listeners,
reachable symbols, files, config) against safe, allowlisted precondition
specs. Anything off the allowlist is refused by :mod:`.safety` before any
fact is read. The functions below are pure: facts dicts in, verdicts out.

Facts shape (what a real runner reports; synthetic secrets, no production
data)::

    {
      "versions": {"openssl": "3.0.2"},
      "flags": {"debug_endpoint": True},
      "listening": ["tcp/5432", "udp/53"],      # "proto/port" strings
      "reachable_symbols": ["pkg.mod.func"],
      "files": ["/etc/app/legacy.conf"],
      "config": {"tls.min_version": "1.0"},
    }
"""
from __future__ import annotations

import re
from typing import Any, Optional, Protocol

from .model import (
    EvidenceLabel,
    Precondition,
    PreconditionKind,
    ReplicaPlan,
    ReplicaVerdict,
)
from .safety import assert_preconditions_allowed, assert_safe_text


class ReplicaRunner(Protocol):
    """The sandbox contract a real runner must satisfy (not implemented here).

    The runner builds an isolated copy (no network egress, synthetic
    secrets, no production data) after the plan's ``scope_asset_id`` has been
    scope-checked like a target. It is NEVER handed a payload, exploit, or
    command: it only reports facts and executes customer-supplied health
    checks.
    """

    def build(self, plan: ReplicaPlan) -> dict[str, Any]:
        """Stand up the replica and return its facts dict."""
        ...

    def apply_fix(self, plan: ReplicaPlan, fix: str) -> dict[str, Any]:
        """Apply a fix (a config/patch change id) and return the new facts."""
        ...

    def run_health(self, plan: ReplicaPlan) -> dict[str, bool]:
        """Run the plan's health checks; map check name -> passed."""
        ...


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_CLAUSE_RE = re.compile(r"^\s*(<=|>=|==|<|>)?\s*(.+?)\s*$")
_LEADING_INT = re.compile(r"^\d+")


def parse_version(text: Any) -> Optional[tuple[int, ...]]:
    """Parse a dotted version into a tuple of ints, or ``None`` if garbled.

    Each dot-separated part contributes its leading digits; trailing
    non-numeric suffixes ("2k", "7-beta") are ignored. Parsing stops at the
    first part with no leading digits, so "3.0.7-rc1" == (3, 0, 7). A string
    with no numeric first part is unparseable.
    """
    if not isinstance(text, str):
        return None
    parts: list[int] = []
    for piece in text.strip().lstrip("vV").split("."):
        m = _LEADING_INT.match(piece)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts) if parts else None


def compare_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """-1/0/1 comparison of two parsed versions, zero-padding the shorter."""
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


def version_in_range(version: Any, range_spec: Any) -> bool:
    """True iff ``version`` satisfies every clause of ``range_spec``.

    ``range_spec`` is one or more comma-separated clauses such as
    ``"<3.0.7"`` or ``">=1.0.2,<1.1"``. A clause without an operator means
    ``==``. Anything unparseable returns False.
    """
    have = parse_version(version)
    if have is None or not isinstance(range_spec, str) or not range_spec.strip():
        return False
    for clause in range_spec.split(","):
        m = _CLAUSE_RE.match(clause)
        if not m:
            return False
        op = m.group(1) or "=="
        want = parse_version(m.group(2))
        if want is None:
            return False
        c = compare_versions(have, want)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0}[op]
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------
# Precondition evaluation
# ---------------------------------------------------------------------------

def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_collection(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple, set, frozenset)) else []


def check_precondition(pre: Precondition, facts: dict) -> bool:
    """Evaluate one precondition against a facts dict. Pure; never raises on data.

    Missing, malformed, or unknown input yields False. (The safety allowlist
    guard lives in :func:`verify_preconditions` / :func:`verify_fix`.)
    """
    try:
        facts = _as_dict(facts)
        spec = _as_dict(pre.spec)
        kind = pre.kind
        if kind == PreconditionKind.VERSION_IN_RANGE:
            component = spec.get("component")
            versions = _as_dict(facts.get("versions"))
            if not isinstance(component, str) or component not in versions:
                return False
            return version_in_range(versions[component], spec.get("range"))
        if kind == PreconditionKind.FLAG_ENABLED:
            flag = spec.get("flag")
            return _as_dict(facts.get("flags")).get(flag) is True
        if kind == PreconditionKind.ENDPOINT_EXPOSED:
            proto, port = spec.get("proto"), spec.get("port")
            if not isinstance(proto, str) or isinstance(port, bool) or not isinstance(port, int):
                return False
            wanted = f"{proto.lower()}/{port}"
            listening = {str(x).lower() for x in _as_collection(facts.get("listening"))}
            return wanted in listening
        if kind == PreconditionKind.CODE_REACHABLE:
            return spec.get("symbol") in _as_collection(facts.get("reachable_symbols")) \
                and isinstance(spec.get("symbol"), str)
        if kind == PreconditionKind.FILE_PRESENT:
            return isinstance(spec.get("path"), str) \
                and spec["path"] in _as_collection(facts.get("files"))
        if kind == PreconditionKind.CONFIG_VALUE:
            key = spec.get("key")
            config = _as_dict(facts.get("config"))
            return "equals" in spec and key in config and config[key] == spec["equals"]
    except Exception:  # data problems never raise; they are simply "not met"
        return False
    return False


def _details(preconditions: list[Precondition], facts: dict) -> dict[str, bool]:
    """Stable per-precondition results keyed by kind (``kind#n`` for repeats)."""
    out: dict[str, bool] = {}
    for pre in preconditions:
        key = pre.kind.value
        n = 1
        while key in out:
            n += 1
            key = f"{pre.kind.value}#{n}"
        out[key] = check_precondition(pre, facts)
    return out


def _require_scope(plan: ReplicaPlan) -> None:
    if not plan.scope_asset_id or not plan.scope_asset_id.strip():
        raise ValueError("replica plan needs scope_asset_id (replicas are scope-checked)")


def verify_preconditions(
    plan: ReplicaPlan, preconditions: list[Precondition], facts: dict
) -> ReplicaVerdict:
    """Check whether every precondition holds on the replica's facts.

    Raises :class:`~.safety.UnsafeWargameAction` for any off-allowlist
    precondition and ``ValueError`` for a missing ``scope_asset_id``. A
    non-rebuildable component is not verified: the hop stays inferred.
    """
    assert_preconditions_allowed(preconditions)
    if not plan.rebuildable:
        return ReplicaVerdict(
            component_id=plan.component_id,
            preconditions_met=False,
            details={},
            label=EvidenceLabel.PROVED_REPLICA,
            note="component not rebuildable; hop stays inferred",
        )
    _require_scope(plan)
    details = _details(preconditions, facts)
    met = bool(details) and all(details.values())
    present = sum(details.values())
    note = f"{present} of {len(details)} preconditions present on the replica"
    assert_safe_text(note)
    return ReplicaVerdict(
        component_id=plan.component_id,
        preconditions_met=met,
        details=details,
        label=EvidenceLabel.PROVED_REPLICA,
        note=note,
    )


def verify_fix(
    plan: ReplicaPlan,
    preconditions: list[Precondition],
    facts_before: dict,
    facts_after: dict,
    health_results: dict[str, bool],
) -> ReplicaVerdict:
    """Judge a fix by comparing replica facts before and after it.

    ``fix_closes_hop`` is True when all preconditions were met before the fix
    (the hop was viable) and NOT all are met after it: removing any one
    necessary precondition makes the hop non-viable. ``fix_breaks_service`` is
    True if any supplied health check failed. With no health checks it stays
    ``None`` (unknown); absence of checks is never reported as safe.
    ``preconditions_met`` and ``details`` describe the post-fix facts.
    """
    assert_preconditions_allowed(preconditions)
    if not plan.rebuildable:
        return ReplicaVerdict(
            component_id=plan.component_id,
            preconditions_met=False,
            details={},
            note="component not rebuildable; hop stays inferred",
        )
    _require_scope(plan)
    before = _details(preconditions, facts_before)
    after = _details(preconditions, facts_after)
    was_viable = bool(before) and all(before.values())
    still_viable = bool(after) and all(after.values())
    closes = was_viable and not still_viable

    notes = []
    if not was_viable:
        notes.append("hop was not viable before the fix, so there is nothing to close")
    notes.append("fix removed a necessary precondition" if closes
                 else "all preconditions still present after the fix" if still_viable
                 else "no preconditions were present to remove")
    breaks: Optional[bool]
    if not health_results:
        breaks = None
        notes.append("no health checks were supplied; service impact unknown")
    else:
        failed = sorted(k for k, ok in health_results.items() if ok is not True)
        breaks = bool(failed)
        notes.append(f"health checks failed: {', '.join(failed)}" if failed
                     else "all health checks passed")
    note = "; ".join(notes)
    assert_safe_text(note)
    return ReplicaVerdict(
        component_id=plan.component_id,
        preconditions_met=still_viable,
        details=after,
        fix_closes_hop=closes,
        fix_breaks_service=breaks,
        label=EvidenceLabel.PROVED_REPLICA,
        note=note,
    )
