"""Adversarial verifier (THREAT-MODEL LAYER 4).

An INDEPENDENT second pass that, given ONLY the finding + the diff, answers:
does this diff address THIS finding and NOTHING else? It flags any out-of-scope
change. The result is stored in ``remediations.verifier_report``.

Two verifiers run:
  * A deterministic, rule-based verifier that ALWAYS runs and is AUTHORITATIVE.
    It re-derives, from the change class and the diff alone, whether the diff is
    a tight, in-scope fix for the finding — and only that.
  * An optional LLM second opinion (``llm.verify_second_opinion``). It can only
    make the verdict STRICTER: if it DISAGREES (says the diff doesn't address
    the finding, or that it is out of scope), the overall verdict is REJECT.
    Its absence never weakens the result.

Disagreement ⇒ reject. The LLM never sees it can "approve past" the rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import gate

# Map a finding's change class to the diff change class(es) that address it, and
# to the rule_source(s) a legitimate finding of that class carries.
_CLASS_TO_SOURCES: dict[str, set[str]] = {
    "dependency_bump": {"sca", "cve_match"},
    "security_header": {"header_check"},
    "config_fix": {"tls_check", "tls_grade", "policy"},
    "tls_fix": {"tls_check", "tls_grade"},
    "dotfile_block": {"exposed_file", "nuclei"},
}


@dataclass
class VerifyResult:
    ok: bool
    verdict: str                       # 'addresses_finding' | 'rejected'
    reasons: list[str] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "verdict": self.verdict,
            "reasons": self.reasons,
            **self.report,
        }


def _rule_verify(
    finding: dict[str, Any],
    change_class: str,
    diff_text: str,
    expected: dict[str, Any],
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []
    parsed = gate.parse_unified(diff_text)

    # 1. The finding's rule_source must plausibly match the change class, so a
    #    fix isn't silently applied to an unrelated finding.
    rule_source = str(finding.get("rule_source") or "")
    allowed_sources = _CLASS_TO_SOURCES.get(change_class, set())
    if allowed_sources and rule_source and rule_source not in allowed_sources:
        reasons.append(
            f"finding rule_source {rule_source!r} does not match change class "
            f"{change_class!r} (expected one of {sorted(allowed_sources)})"
        )

    # 2. In-scope: exactly one logical target, no stray files.
    if len(parsed.files) != 1:
        reasons.append(f"diff touches {len(parsed.files)} files; expected exactly 1")

    # 3. The diff must actually encode the fix the finding asks for.
    if change_class == "dependency_bump":
        pkg = str(expected.get("package") or "")
        fixed = str(expected.get("fixed_version") or "")
        region = " ".join(l for _, l in parsed.added)
        if pkg and pkg.lower() not in region.lower():
            reasons.append("diff does not mention the vulnerable package")
        if fixed and fixed not in region:
            reasons.append("diff does not set the OSV fixed_version")
        # Nothing added may introduce code/scripts (defence in depth w/ gate).
        for _, line in parsed.added:
            if any(tok in line for tok in ("eval(", "exec(", "require(", "import ", "<script")):
                reasons.append(f"out-of-scope code added: {line.strip()[:60]!r}")
    else:
        directive = str(expected.get("directive") or "")
        added_text = "\n".join(l for _, l in parsed.added)
        if directive and directive.strip() not in added_text:
            reasons.append("diff does not add the expected directive")

    report = {
        "rule_verifier": {
            "files": parsed.files,
            "added_lines": len(parsed.added),
            "removed_lines": len(parsed.removed),
            "change_class": change_class,
            "finding_rule_source": rule_source,
        }
    }
    return (not reasons), reasons, report


async def verify(
    finding: dict[str, Any],
    change_class: str,
    diff_text: str,
    expected: dict[str, Any],
    llm: Any | None = None,
) -> VerifyResult:
    """Run the deterministic verifier, then (if available) a stricter-only LLM
    second opinion. Disagreement ⇒ reject."""
    rule_ok, reasons, report = _rule_verify(finding, change_class, diff_text, expected)

    # Independent LLM second opinion — only ever makes it stricter.
    llm_view = {
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "rule_source": finding.get("rule_source"),
        "description": finding.get("description"),
        "change_class": change_class,
    }
    llm_report: dict[str, Any] = {"used": False}
    if llm is not None and getattr(llm, "is_enabled", lambda: False)():
        opinion = await llm.verify_second_opinion(llm_view, diff_text)
        if opinion is not None:
            llm_report = {"used": True, **opinion}
            if not opinion.get("addresses_finding") or opinion.get("out_of_scope"):
                reasons.append(
                    "adversarial LLM reviewer disagreed: "
                    + (opinion.get("reason") or "out-of-scope / does not address finding")
                )
    report["llm_verifier"] = llm_report

    ok = rule_ok and not any(r.startswith("adversarial LLM") for r in reasons) and not reasons
    # Recompute strictly: ok only if NO reasons at all.
    ok = not reasons
    verdict = "addresses_finding" if ok else "rejected"
    summary = (
        "addresses the finding; no out-of-scope changes" if ok
        else "; ".join(reasons)
    )
    report["summary"] = summary
    return VerifyResult(ok=ok, verdict=verdict, reasons=reasons, report=report)
