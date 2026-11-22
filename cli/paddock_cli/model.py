"""Shared data types: findings and scan results."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# finding kinds, in display order
KINDS = ("malicious", "dependency", "secret", "code", "config", "typosquat")
KIND_TITLES = {
    "malicious": "Malicious packages",
    "dependency": "Vulnerable dependencies",
    "secret": "Secrets",
    "code": "Code",
    "config": "Configuration",
    "typosquat": "Look-alike packages",
}


def rank(sev: str) -> int:
    return RANK.get((sev or "").lower(), 2)


def fingerprint(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


@dataclass
class Finding:
    id: str                      # stable across line shifts (see fingerprint())
    kind: str                    # one of KINDS
    severity: str
    title: str
    message: str
    why: str                     # "why it matters", one or two sentences
    file: str                    # repo-relative, posix
    line: int | None = None
    end_line: int | None = None
    rule_id: str = ""
    fix: str = ""                # short human hint, e.g. "upgrade to 4.17.21"
    refs: list[str] = field(default_factory=list)
    cwe: str | None = None
    cvss: float | None = None
    data: dict[str, Any] = field(default_factory=dict)   # kind-specific facts
    fixable: bool = False        # set by `paddock fix` planning, informational in scan

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "severity": self.severity, "title": self.title,
            "message": self.message, "why": self.why, "file": self.file, "line": self.line,
            "end_line": self.end_line, "rule_id": self.rule_id, "fix": self.fix,
            "references": self.refs, "cwe": self.cwe, "cvss": self.cvss, "data": self.data,
            "auto_fixable": self.fixable,
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    # facts about what was looked at, shown in the report header
    stats: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity if f.severity in c else "medium"] += 1
        return c

    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=rank, default=None)

    def at_or_above(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if rank(f.severity) >= rank(sev)]
