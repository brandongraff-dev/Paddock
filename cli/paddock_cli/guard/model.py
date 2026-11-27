# SPDX-License-Identifier: AGPL-3.0-or-later
"""Finding model, report and constants (contract 3.4, D8, D10).

``GuardFinding`` is deliberately not an extension of ``paddock_cli.model.Finding``: Guard imports
only the standard library and itself (D4).
"""
from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field
from typing import Any

from paddock_cli.guard import GUARD_VERSION

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
TIERS: tuple[str, ...] = ("low", "medium", "high")
_TIER_RANK = {t: i + 1 for i, t in enumerate(TIERS)}
TIER_EVIDENCE: tuple[str, ...] = (
    "measured", "ai-estimated", "unmeasured", "insufficient-n", "not-labellable",
)
STATUSES: tuple[str, ...] = ("open", "suppressed", "baselined")
SCOPES: tuple[str, ...] = ("file", "project")

SCHEMA_REPORT = "paddock-guard/report/v1"
SCHEMA_BASELINE = "paddock-guard/baseline/v1"
TOOL_NAME = "paddock-guard"

# D8: a release build (GUARD_VERSION without a ``.dev`` suffix) treats a check with no
# ``tiers.json`` entry as ``medium``. ``test_g0_model`` asserts that the two agree.
REQUIRE_TIERS = True

# SARIF security-severity per severity (contract 3.4).
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}

# Fields of a finding that carry repo-derived text (8.4 item 2).
DATA_FIELDS: tuple[str, ...] = ("file", "evidence", "data")

# Note codes (4.0.1): notes, not checks.
META_MALFORMED_SUPPRESSION = "PG-META-001"
META_CHECKS_OFF = "PG-META-002"
META_HOOK_EVASION = "PG-META-003"
META_HOOK_EXHAUSTED = "PG-META-004"


def severity_rank(sev: str) -> int:
    try:
        return _SEV_RANK[sev]
    except KeyError:
        raise ValueError("unknown severity: %r" % (sev,)) from None


def tier_rank(tier: str) -> int:
    try:
        return _TIER_RANK[tier]
    except KeyError:
        raise ValueError("unknown tier: %r" % (tier,)) from None


def fingerprint(check_id: str, file: str, anchor: str) -> str:
    """First 16 hex of sha256 of ``check_id|file|anchor`` (D10).

    ``anchor`` is a semantic key chosen by the check: never a line number, raw line text,
    any character of a secret or any hash of a secret.
    """
    return hashlib.sha256(("%s|%s|%s" % (check_id, file, anchor)).encode("utf-8", "replace")).hexdigest()[:16]


def norm_relpath(path: str) -> str | None:
    """Normalise a repo-relative posix path; None for anything unsafe (3.9 item 5)."""
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path or path.startswith("/"):
        return None
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return posixpath.join(*parts)


@dataclass(frozen=True)
class Hit:
    """What a check returns (contract 3.4)."""

    file: str
    line: int | None = None
    end_line: int | None = None
    anchor: str = ""
    evidence: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    related: tuple[str, ...] = ()


_FINDING_KEYS = (
    "fingerprint", "check_id", "title", "severity", "confidence", "blocking", "file", "line",
    "end_line", "evidence", "message", "fix_hint", "agent_prompt", "fixer", "cwe",
    "tier_evidence", "status", "data",
)


@dataclass
class GuardFinding:
    fingerprint: str
    check_id: str
    title: str
    severity: str
    confidence: str
    blocking: bool
    file: str
    line: int | None
    end_line: int | None
    evidence: str
    message: str
    fix_hint: str
    agent_prompt: str
    fixer: str | None
    cwe: str | None
    tier_evidence: str
    status: str = "open"
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in _FINDING_KEYS}

    def sort_key(self) -> tuple:
        return (-severity_rank(self.severity), self.file, self.line or 0, self.check_id, self.fingerprint)


def _empty_config_changes() -> dict[str, Any]:
    return {
        "disabled_checks": [], "excluded": [], "severity_overrides": [], "packages": [],
        "ignored_loosening": [],
    }


@dataclass
class Report:
    mode: dict[str, Any] = field(default_factory=lambda: {
        "tier": "high", "scope": "full", "base": None, "offline": False, "fail_on": "high"})
    findings: list[GuardFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_off_at_tier: list[str] = field(default_factory=list)
    suppressions_added: list[dict[str, Any]] = field(default_factory=list)
    baseline_growth: int = 0
    config_changes: dict[str, Any] = field(default_factory=_empty_config_changes)
    origin: dict[str, str] = field(default_factory=dict)
    complete: bool = True
    timings: dict[str, float] = field(default_factory=dict)  # per-check wall seconds, not serialised
    first_line_notices: list[str] = field(default_factory=list)  # config notices, shown first

    # -- derived -------------------------------------------------------------------------
    @property
    def blocking(self) -> int:
        return sum(1 for f in self.findings if f.blocking)

    def open_findings(self) -> list[GuardFinding]:
        return [f for f in self.findings if f.status == "open"]

    def summary(self) -> dict[str, Any]:
        opened = self.open_findings()
        by_sev: dict[str, int] = {}
        by_check: dict[str, int] = {}
        for f in opened:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_check[f.check_id] = by_check.get(f.check_id, 0) + 1
        return {
            "blocking": self.blocking,
            "open": len(opened),
            "suppressed": sum(1 for f in self.findings if f.status == "suppressed"),
            "baselined": sum(1 for f in self.findings if f.status == "baselined"),
            "complete": bool(self.complete),
            "by_severity": dict(sorted(by_sev.items(), key=lambda kv: -severity_rank(kv[0]))),
            "by_check": dict(sorted(by_check.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_REPORT,
            "tool": {"name": TOOL_NAME, "version": GUARD_VERSION},
            "root": ".",
            "mode": dict(self.mode),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in sorted(self.findings, key=GuardFinding.sort_key)],
            "notes": list(self.notes),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "checks_run": list(self.checks_run),
            "checks_off_at_tier": list(self.checks_off_at_tier),
            "suppressions_added": list(self.suppressions_added),
            "baseline_growth": int(self.baseline_growth),
            "config_changes": {k: list(v) for k, v in self.config_changes.items()},
            "origin": dict(self.origin),
        }
