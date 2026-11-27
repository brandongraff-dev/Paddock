# SPDX-License-Identifier: Apache-2.0
"""The verification report: JSON form (schema/verifier-report.schema.json) and the human text.

Every sentence comes from ``wording`` (templates filled from integers, enums and registry names) or from the fixed
message of a reason code. Nothing an issuer controls reaches the output as free text; a custom invariant id appears
only in code style next to the disclaimer. A bare "pass" or "secure" is never printed, UNKNOWN is never shown as
holding, and an accepted headline is printed only when every evaluated step passed.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, NamedTuple, Optional

from . import SPEC_VERSION, __version__, codes, limits, wording

REPORT_VERSION = 1
CUSTOM_ROOTS_LINE = "custom trust roots in use"
REVOCATION_NOT_CHECKED = "revocation NOT checked"

#: reason code -> one-line template (otherwise the fixed message of the code is printed)
_ONE_LINERS = {
    "chain.superseded": "W-SUPERSEDED", "chain.seq_rollback": "W-ROLLBACK", "chain.prev_mismatch": "W-CHAIN-BROKEN",
    "chain.seq_gap": "W-CHAIN-BROKEN", "chain.latest_mismatch": "W-CHAIN-BROKEN", "chain.fork": "W-CHAIN-BROKEN",
    "dns.no_binding": "W-DNS-UNBOUND", "dns.mismatch": "W-DNS-UNBOUND", "dns.record_conflict": "W-DNS-UNBOUND",
    "key.revoked": "W-KEY-REVOKED", "engine.advisory": "W-ENGINE-ADVISORY", "policy.shrank": "W-POLICY-SHRANK",
    "digest.changed": "W-DIGEST-CHANGED", "std.digest_mismatch": "W-STD-UNRECOGNISED", "std.id_unknown": "W-STD-UNRECOGNISED",
}


class Reason(NamedTuple):
    code: str
    cls: str                 # R | U | W
    step: Optional[int]
    params: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        c = codes.get(self.code)
        return {"code": self.code, "class": self.cls, "step": self.step, "params": dict(self.params),
                "message": c.message if c else "Unknown reason."}


class Report(object):
    """What ``verify`` returns. ``to_dict`` is the JSON report; ``to_text`` the human text."""

    def __init__(self) -> None:
        self.now = ""
        self.target = ""
        self.profile = "baseline"
        self.policy_name = None  # type: Optional[str]
        self.policy_sha256 = None  # type: Optional[str]
        self.reasons = []  # type: List[Reason]       # R and U, in step order
        self.warnings = []  # type: List[Reason]
        self.checks = []  # type: List[Dict[str, Any]]
        self.subject = None  # type: Optional[str]
        self.key = None  # type: Optional[Dict[str, Any]]
        self.statement = None  # type: Optional[Dict[str, Any]]
        self.results = []  # type: List[Dict[str, Any]]
        self.human_lines = []  # type: List[str]
        self.limits_id = None  # type: Optional[str]
        self.state_update = None  # type: Optional[Dict[str, Any]]
        self.custom_roots = False
        self.exit = codes.EXIT_UNVERIFIABLE
        self.decision = "unverifiable"
        self.primary = None  # type: Optional[str]

    def finish(self) -> "Report":
        self.exit = codes.exit_for(r.cls for r in self.reasons + self.warnings)
        self.decision = {0: "accepted", 1: "rejected", 2: "unverifiable"}[self.exit]
        decisive = "R" if self.exit == 1 else ("U" if self.exit == 2 else None)
        self.primary = next((r.code for r in self.reasons if r.cls == decisive), None) if decisive else None
        return self

    def headline(self) -> str:
        if self.exit == 0:
            return wording.headline("accepted", name=self.policy_name or "policy") if self.profile == "policy" else wording.headline("baseline")
        c = codes.get(self.primary) if self.primary else None
        msg = (c.message if c else "No decision.")
        return wording.headline("rejected" if self.exit == 1 else "unverifiable", message=msg)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_version": REPORT_VERSION,
            "verifier": {"name": "paddock-verify", "version": __version__},
            "spec": SPEC_VERSION,
            "now": self.now,
            "target": self.target,
            "profile": self.profile,
            "policy_sha256": self.policy_sha256,
            "decision": self.decision,
            "exit": self.exit,
            "primary": self.primary,
            "reasons": [r.as_dict() for r in self.reasons],
            "warnings": [r.as_dict() for r in self.warnings],
            "checks": self.checks,
            "subject": self.subject,
            "key": self.key,
            "statement": self.statement,
            "results": self.results,
            "human": self.text_lines(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, ensure_ascii=True) + "\n"

    # ---------------------------------------------------------------------------------------- human text
    def text_lines(self, quiet: bool = False) -> List[str]:
        lines = []  # type: List[str]
        if self.profile == "baseline":
            lines.append(wording.profile_line())
        lines.append(self.headline())
        if quiet:
            return lines
        if self.custom_roots:
            lines.append(CUSTOM_ROOTS_LINE)
        lines.extend(self.human_lines)
        for r in self.reasons + self.warnings:
            lines.append(_reason_line(r))
        if self.limits_id is not None:
            text = limits.limits_text(self.limits_id)
            if text is not None:
                lines.append("")
                lines.append(text.rstrip("\n"))
        lines.append(wording.render("W-FOOTER"))
        return lines

    def to_text(self, quiet: bool = False) -> str:
        return "\n".join(self.text_lines(quiet)) + "\n"


def _reason_line(r: Reason) -> str:
    t = _ONE_LINERS.get(r.code)
    if t is not None:
        return "- " + wording.render(t)
    c = codes.get(r.code)
    return "- %s: %s" % (r.code, c.message if c else "")


# ------------------------------------------------------------------------------------------ line builders
def key_line(custody: str, vendor_certified: Optional[bool], dns_bound: Optional[bool], dnssec: str) -> str:
    return wording.render("W-KEY", custody=custody if custody in ("hosted", "byok-kms", "byok-hsm") else "hosted",
                          cert="vendor_certified" if vendor_certified else "domain_only",
                          dns="dns_not_checked" if dns_bound is None else ("dns_bound" if dns_bound else "dns_unbound"),
                          dnssec=dnssec if dnssec in ("ad_asserted", "not_asserted", "unknown") else "unknown")


def result_lines(inv: str, name: Optional[str], r: Dict[str, Any]) -> List[str]:
    """Lines for one disclosed result. ``name`` is the registry name for a std id, ``None`` for a custom one."""
    out = []  # type: List[str]
    shown = name if name is not None and _name_ok(name) else inv
    if name is None and not inv.startswith("std:"):
        out.append(wording.render("W-CUSTOM-NAME", id=inv))
    status = r["status"]
    if status == "HOLDS":
        cov = r["coverage"]
        out.append(wording.render("W-HOLDS", name=shown, tier_phrase=wording.tier_phrase(r["tier"]), covered=cov["covered"],
                                  universe=cov["universe"], pct=cov["percent_floor"], valid_until=r["valid_until"]))
    elif status == "EXPIRED":
        out.append(wording.render("W-HOLDS-EXPIRED", name=shown, valid_until=r["valid_until"]))
    elif status == "VIOLATED":
        out.append(wording.render("W-VIOLATED", name=shown, violations=r["violations"]))
    else:
        for code in r["reason_codes"]:
            out.append(wording.render("W-UNKNOWN", name=shown, reason_phrase=wording.reason_phrase(code)))
    if r.get("exceptions"):
        out.append(wording.render("W-EXC", n=r["exceptions"]))
    return out


def _name_ok(name: str) -> bool:
    try:
        wording.render("W-VIOLATED", name=name, violations=0)
        return True
    except wording.WordingError:
        return False
