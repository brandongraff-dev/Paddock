# SPDX-License-Identifier: AGPL-3.0-or-later
"""Report writers: text, json, sarif, markdown (contract 3.4, 9.9, 3.11 H5 and H6).

Every string a writer emits passes ``textsafe.clean`` and a length cap, whatever built the report:
a hostile finding is clean in all four formats. Headline wording never says clean, passed or all
clear: the summary line always states how many checks ran and that no findings is not a safety
result (PG-META-002).
"""
from __future__ import annotations

import gzip
import json
import re
from typing import Any

from paddock_cli.guard import GUARD_VERSION, model, registry, textsafe
from paddock_cli.guard.model import GuardFinding, Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_MAX_RESULTS = 5000
SARIF_MAX_GZIP_BYTES = 10 * 1024 * 1024
FORMATS = ("text", "json", "sarif", "markdown")
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_FP = re.compile(r"^[0-9a-f]{16}$")
_ENUM_SEV = frozenset(model.SEVERITIES)


def _s(v: Any, cap: int = 300, *, newlines: bool = False) -> str:
    """Clean, collapse and cap one string (Unicode kept: human channels)."""
    if not isinstance(v, str):
        v = "" if v is None else str(v)
    if newlines:
        text = textsafe.clean(v, keep_newlines=True)
        text = "\n".join(textsafe.collapse_ws(x) for x in text.split("\n"))
        return textsafe.cap(text, cap)
    return textsafe.cap(textsafe.collapse_ws(textsafe.clean(v)), cap)


def _enum(v: Any, allowed: Any, default: str) -> str:
    return v if isinstance(v, str) and v in allowed else default


def _finding_dict(f: GuardFinding) -> dict[str, Any]:
    d = f.to_dict()
    d["fingerprint"] = d["fingerprint"] if isinstance(d["fingerprint"], str) and _FP.match(d["fingerprint"]) else "0" * 16
    d["check_id"] = _s(d["check_id"], 60)
    d["title"] = _s(d["title"], 200)
    d["severity"] = _enum(d["severity"], _ENUM_SEV, "info")
    d["confidence"] = _enum(d["confidence"], model.TIERS, "low")
    d["file"] = _s(d["file"], 300)
    d["evidence"] = _s(d["evidence"], 200)
    d["message"] = _s(d["message"], 200)
    d["fix_hint"] = _s(d["fix_hint"], 1200)
    d["agent_prompt"] = _s(d["agent_prompt"], 1200, newlines=True)
    d["fixer"] = _s(d["fixer"], 40) if d["fixer"] else None
    d["cwe"] = _s(d["cwe"], 40) if d["cwe"] else None
    d["tier_evidence"] = _s(d["tier_evidence"], 20)
    d["status"] = _enum(d["status"], model.STATUSES, "open")
    d["data"] = {_s(k, 40): (v if isinstance(v, (bool, int)) else _s(v, 120)) for k, v in (f.data or {}).items()}
    d["blocking"] = bool(d["blocking"])
    return d


def _sanitize(obj: Any, cap: int = 300) -> Any:
    if isinstance(obj, str):
        return _s(obj, cap)
    if isinstance(obj, list):
        return [_sanitize(x, cap) for x in obj]
    if isinstance(obj, dict):
        return {_s(k, 60): _sanitize(v, cap) for k, v in obj.items()}
    return obj


def report_dict(report: Report) -> dict[str, Any]:
    d = report.to_dict()
    for k in ("notes", "skipped", "errors", "suppressions_added", "config_changes", "mode", "origin", "tool"):
        d[k] = _sanitize(d[k])
    d["checks_run"] = [_s(x, 60) for x in d["checks_run"]]
    d["checks_off_at_tier"] = [_s(x, 60) for x in d["checks_off_at_tier"]]
    d["findings"] = [_finding_dict(f) for f in sorted(report.findings, key=GuardFinding.sort_key)]
    d["summary"] = _sanitize(d["summary"])
    return d


def _meta_note(report: Report) -> str:
    for n in report.notes:
        if n.startswith(model.META_CHECKS_OFF):
            return _s(n, 600)
    off = report.checks_off_at_tier
    shown = ", ".join(off[:12]) + (" and %d more" % (len(off) - 12) if len(off) > 12 else "")
    return _s("%s: %d checks ran at tier %s; %d checks are off at this tier (%s); no findings is not a safety result"
              % (model.META_CHECKS_OFF, len(report.checks_run), report.mode.get("tier", "high"), len(off), shown or "none"), 600)


def exit_code(report: Report) -> int:
    """D12: 0 nothing blocking, 1 blocking finding."""
    return 1 if report.blocking else 0


# ---- text ---------------------------------------------------------------------------------------
def render_text(report: Report, *, show_all: bool = False, max_items: int = 50) -> str:
    s = report.summary()
    mode = report.mode
    out: list[str] = [_s(n, 300) for n in report.first_line_notices]
    out.append("Paddock Guard %s: %d blocking, %d open, %d suppressed, %d baselined (scope %s, tier %s)" % (
        GUARD_VERSION, s["blocking"], s["open"], s["suppressed"], s["baselined"],
        _s(mode.get("scope", "full"), 20), _s(mode.get("tier", "high"), 20)))
    if not report.complete:
        out.append("INCOMPLETE: the scan did not cover everything (see the notes below); this is not a full result")
    out.append(_meta_note(report))
    opened = sorted(report.open_findings(), key=GuardFinding.sort_key)
    if not opened:
        out.append("No open findings at tier %s." % _s(mode.get("tier", "high"), 20))
    shown = opened if show_all else opened[:max_items]
    for f in shown:
        d = _finding_dict(f)
        loc = d["file"] + (":%d" % f.line if f.line else "")
        out.append("  %-8s %s  %s  %s  [%s, %s]" % (d["severity"].upper(), d["check_id"], loc, d["title"],
                                                   d["confidence"], d["tier_evidence"]))
        if d["evidence"]:
            out.append("           evidence: " + d["evidence"])
        if d["fix_hint"]:
            out.append("           fix: " + textsafe.cap(d["fix_hint"], 200))
    if len(opened) > len(shown):
        out.append("  ... and %d more (use --all to list every finding)" % (len(opened) - len(shown)))
    extra = [n for n in report.notes if not n.startswith(model.META_CHECKS_OFF)]
    if extra:
        out.append("Notes:")
        out += ["  - " + _s(n, 300) for n in extra[:30]]
        if len(extra) > 30:
            out.append("  - ... and %d more notes" % (len(extra) - 30))
    if report.errors:
        out.append("Errors:")
        out += ["  - %s %s %s" % (_s(e.get("check", ""), 80), _s(e.get("file", ""), 120), _s(e.get("error", ""), 80))
                for e in report.errors[:20]]
    if report.skipped:
        out.append("Skipped %d file(s):" % len(report.skipped))
        out += ["  - %s (%s)" % (_s(k.get("file", ""), 120), _s(k.get("reason", ""), 40)) for k in report.skipped[:10]]
        if len(report.skipped) > 10:
            out.append("  - ... and %d more" % (len(report.skipped) - 10))
    return "\n".join(out) + "\n"


# ---- json -----------------------------------------------------------------------------------------
def render_json(report: Report) -> str:
    return json.dumps(report_dict(report), indent=2, ensure_ascii=False) + "\n"


# ---- sarif ----------------------------------------------------------------------------------------
def _rule(check_id: str, sample: GuardFinding | None) -> dict[str, Any]:
    title, why, fix, cwe, sev = check_id, "", "", None, "medium"
    if registry.has(check_id):
        c = registry.get(check_id)
        title, why, fix, cwe, sev = c.title, registry.why_text(c), c.fix_hint, c.cwe, c.severity
    elif sample is not None:
        title, fix, cwe, sev = sample.title, sample.fix_hint, sample.cwe, sample.severity
    props: dict[str, Any] = {"security-severity": "%.1f" % model.SECURITY_SEVERITY.get(sev, 5.5)}
    if cwe:
        props["tags"] = ["external/cwe/" + _s(cwe, 20).lower(), _s(cwe, 20)]
    return {
        "id": _s(check_id, 60), "name": _s(check_id, 60),
        "shortDescription": {"text": _s(title, 200)},
        "fullDescription": {"text": _s(why or title, 600)},
        "help": {"text": _s(fix or title, 600)},
        "defaultConfiguration": {"level": _LEVEL.get(sev, "warning")},
        "properties": props,
    }


def _sarif_doc(report: Report, results_findings: list[GuardFinding], truncated: int, notes: list[str]) -> dict[str, Any]:
    ids = sorted(set(report.checks_run) | {f.check_id for f in results_findings})
    by_id: dict[str, GuardFinding] = {}
    for f in results_findings:
        by_id.setdefault(f.check_id, f)
    results = []
    for f in results_findings:
        d = _finding_dict(f)
        loc: dict[str, Any] = {"artifactLocation": {"uri": d["file"].lstrip("/").replace("\\", "/"), "uriBaseId": "%SRCROOT%"}}
        if f.line:
            region: dict[str, Any] = {"startLine": f.line}
            if f.end_line and f.end_line >= f.line:
                region["endLine"] = f.end_line
            loc["region"] = region
        sev = d["severity"]
        results.append({
            "ruleId": d["check_id"], "level": _LEVEL.get(sev, "warning"),
            "message": {"text": _s("%s. %s" % (d["title"], d["fix_hint"]), 400)},
            "locations": [{"physicalLocation": loc}],
            "partialFingerprints": {"paddock-guard/v1": d["fingerprint"]},
            "properties": {"security-severity": "%.1f" % model.SECURITY_SEVERITY.get(sev, 5.5),
                           "confidence": d["confidence"], "tier-evidence": d["tier_evidence"]},
        })
    return {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "paddock-guard", "version": GUARD_VERSION,
                                "rules": [_rule(i, by_id.get(i)) for i in ids]}},
            "results": results,
            "properties": {"notes": [_s(n, 300) for n in notes], "truncated": truncated,
                           "complete": bool(report.complete)},
        }],
    }


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0, open findings only, capped at 5,000 results and 10 MB gzipped (3.4, U-14)."""
    opened = sorted(report.open_findings(), key=lambda f: (-model.severity_rank(f.severity), f.fingerprint))
    notes = [n for n in report.notes if not n.startswith(model.META_CHECKS_OFF)] + [_meta_note(report)]
    kept = opened
    truncated = 0
    if len(kept) > SARIF_MAX_RESULTS:
        truncated = len(kept) - SARIF_MAX_RESULTS
        kept = kept[:SARIF_MAX_RESULTS]
        notes.append("results capped at %d (highest severity first); %d lower-severity result(s) are not in this file"
                     % (SARIF_MAX_RESULTS, truncated))
    while True:
        text = json.dumps(_sarif_doc(report, kept, truncated, notes), indent=1, ensure_ascii=False) + "\n"
        if len(gzip.compress(text.encode("utf-8"), 6)) <= SARIF_MAX_GZIP_BYTES or len(kept) <= 1:
            return text
        drop = max(1, len(kept) // 10)
        kept = kept[: len(kept) - drop]
        truncated += drop
        notes = [n for n in notes if not n.startswith("results capped")] + [
            "results capped to stay under the 10 MB upload limit; %d lower-severity result(s) are not in this file" % truncated]


# ---- markdown ---------------------------------------------------------------------------------------
def _md(v: Any, cap: int = 120) -> str:
    """Untrusted text as a code span: no HTML, link, URL, pipe or backtick can act inside it."""
    t = _s(v, cap)
    t = t.replace("`", "'").replace("|", "\\|").replace("<", "‹").replace(">", "›")
    return "`%s`" % t if t else "``"


def render_markdown(report: Report, *, max_rows: int = 50) -> str:
    s = report.summary()
    mode = report.mode
    lines = ["### Paddock Guard", ""]
    for n in report.first_line_notices:
        lines += [_md(n, 300), ""]
    lines.append("**%d blocking**, %d open, %d suppressed, %d baselined (scope %s, tier %s)." % (
        s["blocking"], s["open"], s["suppressed"], s["baselined"], _md(mode.get("scope", "full"), 20), _md(mode.get("tier", "high"), 20)))
    if not report.complete:
        lines += ["", "**INCOMPLETE:** the scan did not cover everything; this is not a full result."]
    lines += ["", _md(_meta_note(report), 600), ""]
    opened = sorted(report.open_findings(), key=GuardFinding.sort_key)
    if opened:
        lines += ["| Severity | Check | Location | Finding |", "| --- | --- | --- | --- |"]
        for f in opened[:max_rows]:
            d = _finding_dict(f)
            loc = d["file"] + (":%d" % f.line if f.line else "")
            lines.append("| %s | %s | %s | %s |" % (d["severity"], _md(d["check_id"], 60), _md(loc, 120), _md(d["title"], 120)))
        if len(opened) > max_rows:
            lines += ["", "%d more finding(s) not listed; run the check locally for the full list." % (len(opened) - max_rows)]
    else:
        lines.append("No open findings at tier %s." % _md(mode.get("tier", "high"), 20))
    if report.suppressions_added:
        lines += ["", "**Suppressions added versus the base ref:**"]
        for r in report.suppressions_added[:20]:
            lines.append("- %s %s %s %s: %s" % (_md(r.get("kind", ""), 20), _md(r.get("file", ""), 100), _md(r.get("check_id", ""), 40),
                                               _md(r.get("fingerprint", ""), 20), _md(r.get("reason", ""), 120)))
    if report.baseline_growth:
        lines += ["", "**Baseline entries added versus the base ref:** %d" % report.baseline_growth]
    cc = report.config_changes
    if cc.get("disabled_checks"):
        lines += ["", "**Checks disabled by configuration:** " + ", ".join(_md(x, 40) for x in cc["disabled_checks"][:20])]
    if cc.get("ignored_loosening"):
        lines += ["", "**Configuration ignored (it would loosen checks):** " + ", ".join(_md(x, 80) for x in cc["ignored_loosening"][:10])]
    extra = [n for n in report.notes if not n.startswith(model.META_CHECKS_OFF)]
    if extra:
        lines += ["", "**Notes:**"] + ["- " + _md(n, 200) for n in extra[:15]]
    return "\n".join(lines) + "\n"


def render(report: Report, fmt: str, **kw: Any) -> str:
    if fmt == "text":
        return render_text(report, **kw)
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "markdown":
        return render_markdown(report)
    raise ValueError("unknown format %r" % (fmt,))
