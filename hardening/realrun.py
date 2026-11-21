#!/usr/bin/env python3
"""Real-target run + false-positive measurement harness (authorized scope only).

What this does
--------------
1. Ensures the target is an EXPLICITLY AUTHORIZED one (default
   ``scanme.nmap.org`` — Nmap's official legal scan target — plus loopback).
   Any other target is REFUSED, loudly, with the authorization reminder.
2. Invokes the active worker's SAFE modules against the target by importing
   them directly (http_probe, header_check [via http_probe], tls_inspect +
   tls_grade, exposed_file; nuclei only if the `nuclei` binary is installed).
3. Collects findings.
4. Prints a triage table.
5. Computes a CRUDE false-positive rate against the small hand-labeled truth
   set in ``truth_scanme.json`` (for scanme.nmap.org).
6. Writes ``realrun_report.md``.

Honesty contract
----------------
* This harness NEVER fabricates findings or a false-positive number. If live
  execution is impossible (modules unimportable, or no network egress), it
  degrades to a clear report that says so and prints the exact commands to run
  on a real deployment.
* It performs DETECTION only: liveness/fingerprint, security-header analysis,
  TLS posture read, and polite GETs of well-known sensitive paths. No
  exploitation, no evasion, no credential testing.
* The authorization boundary is enforced in-process here (independent of the
  orchestrator) so the harness refuses out-of-scope targets even when run
  standalone. To scan YOUR OWN authorized assets, use the real orchestrator
  scope API (see RUNBOOK.md), not this measurement harness.

Usage
-----
    python3 realrun.py                      # scanme.nmap.org (default)
    python3 realrun.py 127.0.0.1            # loopback
    python3 realrun.py --no-live            # skip network; emit the runbook report
    python3 realrun.py evil.example.com     # REFUSED (not authorized)
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HARDENING_DIR = Path(__file__).resolve().parent
REPO_ROOT = HARDENING_DIR.parent
ACTIVE_WORKER = REPO_ROOT / "workers" / "active"
TRUTH_PATH = HARDENING_DIR / "truth_scanme.json"
REPORT_PATH = HARDENING_DIR / "realrun_report.md"

# --------------------------------------------------------------------------- #
# Authorization boundary — the ONLY targets this harness will ever touch.
# --------------------------------------------------------------------------- #
AUTHORIZED_HOSTS = {"scanme.nmap.org", "localhost", "127.0.0.1", "::1"}
AUTHORIZED_V4_CIDR = ipaddress.ip_network("127.0.0.0/8")

AUTHORIZATION_REMINDER = """\
================================================================================
  AUTHORIZED-SCOPE-ONLY TOOL
--------------------------------------------------------------------------------
  This harness only ever touches targets you are explicitly authorized to test:
      * scanme.nmap.org  (Nmap's official legal scan target —
                           https://nmap.org/book/legal-issues.html)
      * 127.0.0.0/8 / localhost / ::1  (your own machine)
  Scanning any other host without the asset owner's explicit, documented
  authorization is very likely illegal and is NOT supported by this tool.
  To run the platform against YOUR OWN authorized assets, add them to the
  orchestrator scope allowlist (with an authorization note) and drive a scan
  through the scan API — see hardening/RUNBOOK.md.
================================================================================"""


def host_of(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        return urlsplit(t).hostname or t
    return t.split("/", 1)[0].split(":", 1)[0]


def is_authorized(target: str) -> bool:
    host = host_of(target)
    if host in AUTHORIZED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 4 and ip in AUTHORIZED_V4_CIDR:
        return True
    if ip.version == 6 and ip == ipaddress.ip_address("::1"):
        return True
    return False


# --------------------------------------------------------------------------- #
# In-process stand-ins for the orchestrator. The worker modules expect an
# OrchestratorClient (for scope checks + audit sinks). We supply a local one
# whose scope_check enforces the SAME authorization boundary as above, so no
# out-of-scope request can leave this process even via a redirect.
# --------------------------------------------------------------------------- #
class LocalScopeOrchestrator:
    """Implements only what the safe modules call. scope_check is authoritative
    and local; the audit sinks are collected in-memory."""

    def __init__(self) -> None:
        self.outbound: list[dict] = []
        self.tls_grades: list[dict] = []

    async def scope_check(self, target: str) -> dict[str, Any]:
        host = host_of(target)
        allow = is_authorized(target)
        return {
            "allow": allow,
            "normalized": host,
            "matched_entry": 0 if allow else None,
            "reason": "authorized-scope" if allow else "out-of-scope (refused by harness)",
        }

    async def outbound_log(self, row: dict[str, Any]) -> None:
        self.outbound.append(row)

    async def tls_grades_bulk(self, items: list[dict[str, Any]]) -> dict:
        self.tls_grades.extend(items)
        return {"upserted": len(items)}


# --------------------------------------------------------------------------- #
# Module execution
# --------------------------------------------------------------------------- #
def _import_worker():
    """Import the active worker's safe modules. Returns a namespace dict or
    raises ImportError (caught by the caller for honest degradation)."""
    if str(ACTIVE_WORKER) not in sys.path:
        sys.path.insert(0, str(ACTIVE_WORKER))
    from app.modules import http_probe, exposed_file, tls_inspect, tls_grade, nuclei_runner
    from app.scope_guard import ScopeGuard, ScopeDenied
    from app.util.politeness import PolitenessLimiter
    from app.util import runner
    return {
        "http_probe": http_probe,
        "exposed_file": exposed_file,
        "tls_inspect": tls_inspect,
        "tls_grade": tls_grade,
        "nuclei_runner": nuclei_runner,
        "ScopeGuard": ScopeGuard,
        "ScopeDenied": ScopeDenied,
        "PolitenessLimiter": PolitenessLimiter,
        "runner": runner,
    }


async def run_modules(target: str, wk: dict, *, run_nuclei: bool) -> dict[str, Any]:
    """Run the safe modules against an AUTHORIZED target. Returns a result dict
    with findings, module statuses, and the working base URL (or an error)."""
    orch = LocalScopeOrchestrator()
    scope = wk["ScopeGuard"](orch)
    politeness = wk["PolitenessLimiter"]()
    ScopeDenied = wk["ScopeDenied"]

    host = host_of(target)
    findings: list[dict] = []
    module_status: list[dict] = []

    # Decide candidate URLs. Honor an explicit scheme; otherwise try HTTPS then
    # HTTP (scanme is HTTP-only, so the HTTP fallback is what succeeds there).
    if "://" in target:
        candidates = [target]
    else:
        candidates = [f"https://{host}/", f"http://{host}/"]

    # ---- http_probe (also yields header_check findings) ----
    probe_result = None
    working_url = None
    probe_errors = []
    for url in candidates:
        try:
            probe_result = await wk["http_probe"].probe(
                url, scope=scope, politeness=politeness, orchestrator=orch
            )
            working_url = probe_result["summary"]["final_url"]
            break
        except ScopeDenied:
            raise
        except Exception as e:  # network/connect error -> try next candidate
            probe_errors.append(f"{url}: {type(e).__name__}: {e}")

    if probe_result is None:
        return {
            "live": False,
            "reason": "http_probe could not reach the target over any scheme",
            "errors": probe_errors,
            "findings": [],
            "module_status": [{"module": "http_probe", "status": "failed", "detail": "; ".join(probe_errors)}],
        }

    probe_findings = probe_result.get("findings", [])
    findings.extend(probe_findings)
    header_findings = [f for f in probe_findings if f.get("rule_source") == "header_check"]
    module_status.append({
        "module": "http_probe",
        "status": "ok",
        "detail": f"HTTP {probe_result['summary']['status']} at {working_url}; "
                  f"{probe_result['summary'].get('tech_count', 0)} tech fingerprints",
    })
    module_status.append({
        "module": "header_check",
        "status": "ok",
        "detail": f"{len(header_findings)} security-header findings (via http_probe)",
    })

    base_url = working_url or candidates[-1]

    # ---- exposed_file ----
    try:
        ef = await wk["exposed_file"].scan(
            base_url, scope=scope, politeness=politeness, orchestrator=orch
        )
        ef_findings = ef.get("findings", [])
        findings.extend(ef_findings)
        module_status.append({
            "module": "exposed_file",
            "status": "ok",
            "detail": f"{len(ef_findings)} finding(s) across {len(wk['exposed_file'].PATHS)} probed paths",
        })
    except ScopeDenied:
        raise
    except Exception as e:
        module_status.append({"module": "exposed_file", "status": "error", "detail": f"{type(e).__name__}: {e}"})

    # ---- tls_inspect + tls_grade (needs the tlsx binary) ----
    tlsx_present = bool(wk["runner"].resolve_binary("tlsx"))
    try:
        facts = await wk["tls_inspect"].gather_facts(
            host, scope=scope, politeness=politeness, orchestrator=orch
        )
        insp = await wk["tls_inspect"].inspect(
            host, scope=scope, politeness=politeness, orchestrator=orch, facts=facts
        )
        findings.extend(insp.get("findings", []))
        grade = await wk["tls_grade"].grade_host(
            host, scope=scope, politeness=politeness, orchestrator=orch, facts=facts
        )
        findings.extend(grade.get("findings", []))
        if tlsx_present:
            detail = f"graded: {grade.get('summary', {})}"
            status = "ok"
        else:
            detail = "tlsx binary not installed -> emitted tool-unavailable (info) finding, no live handshake"
            status = "degraded"
        module_status.append({"module": "tls_inspect+grade", "status": status, "detail": detail})
    except ScopeDenied:
        raise
    except Exception as e:
        module_status.append({"module": "tls_inspect+grade", "status": "error", "detail": f"{type(e).__name__}: {e}"})

    # ---- nuclei (only if the binary is present) ----
    nuclei_present = bool(wk["runner"].resolve_binary("nuclei"))
    if run_nuclei and nuclei_present:
        try:
            nr = await wk["nuclei_runner"].run_nuclei(
                base_url, scope=scope, politeness=politeness, orchestrator=orch
            )
            nr_findings = nr.get("findings", [])
            findings.extend(nr_findings)
            module_status.append({"module": "nuclei", "status": "ok", "detail": f"{len(nr_findings)} finding(s)"})
        except ScopeDenied:
            raise
        except Exception as e:
            module_status.append({"module": "nuclei", "status": "error", "detail": f"{type(e).__name__}: {e}"})
    else:
        reason = "nuclei binary not installed" if not nuclei_present else "skipped (--no-nuclei)"
        module_status.append({"module": "nuclei", "status": "skipped", "detail": reason})

    return {
        "live": True,
        "working_url": working_url,
        "findings": findings,
        "module_status": module_status,
        "outbound_requests": len(orch.outbound),
    }


# --------------------------------------------------------------------------- #
# False-positive scoring
# --------------------------------------------------------------------------- #
ACTIONABLE = {"low", "medium", "high", "critical"}


def load_truth() -> dict:
    with open(TRUTH_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def classify(findings: list[dict], truth: dict) -> dict:
    labels = truth.get("labels", {})
    rows = []
    for f in findings:
        rule_id = f.get("rule_id", "")
        sev = (f.get("severity") or "info").lower()
        label = labels.get(rule_id, {})
        cls = label.get("class", "unverified")
        is_actionable = sev in ACTIONABLE
        # false positive logic
        if cls == "false_positive_if_present":
            verdict = "FALSE_POSITIVE"
        elif cls == "noise" and is_actionable:
            verdict = "FALSE_POSITIVE"  # benign info escalated to actionable
        elif cls == "signal":
            verdict = "true_positive" if is_actionable else "true_positive_info"
        elif cls == "noise":
            verdict = "benign_info"
        else:
            verdict = "unverified_actionable" if is_actionable else "unverified_info"
        rows.append({
            "severity": sev,
            "rule_id": rule_id,
            "title": f.get("title", ""),
            "host": f.get("target_host", ""),
            "source": f.get("rule_source", ""),
            "class": cls,
            "verdict": verdict,
        })

    actionable = [r for r in rows if r["severity"] in ACTIONABLE]
    fp = [r for r in actionable if r["verdict"] == "FALSE_POSITIVE"]
    unverified = [r for r in actionable if r["verdict"] == "unverified_actionable"]
    fp_rate = (len(fp) / len(actionable)) if actionable else None

    expected = set(truth.get("expected_signal_rule_ids", []))
    present_signals = {r["rule_id"] for r in rows if r["rule_id"] in expected}
    recall = (len(present_signals) / len(expected)) if expected else None

    return {
        "rows": rows,
        "actionable_count": len(actionable),
        "fp": fp,
        "fp_count": len(fp),
        "fp_rate": fp_rate,
        "unverified": unverified,
        "expected_signals": sorted(expected),
        "present_signals": sorted(present_signals),
        "missing_signals": sorted(expected - present_signals),
        "recall": recall,
    }


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def _fmt_table(rows: list[dict]) -> str:
    if not rows:
        return "  (no findings)\n"
    headers = ["severity", "source", "rule_id", "verdict", "title"]
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r.get(h, ""))[:48]))
    line = "  " + "  ".join(h.ljust(widths[h]) for h in headers)
    sep = "  " + "  ".join("-" * widths[h] for h in headers)
    out = [line, sep]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in sorted(rows, key=lambda x: sev_order.get(x["severity"], 9)):
        out.append("  " + "  ".join(str(r.get(h, ""))[:48].ljust(widths[h]) for h in headers))
    return "\n".join(out) + "\n"


EXACT_COMMANDS = """\
# On a real deployment with the stack up and the ProjectDiscovery binaries
# installed in the active worker image, run the full pipeline like this:

# 1. Bring the stack up (dev profile shown; use -f docker-compose.yml for prod):
make up

# 2. Seed the safe authorized scope (localhost + scanme.nmap.org):
make seed-scope

# 3. Confirm scanme is in scope:
make scope-list

# 4. Kick a full authorized recon scan against scanme and read results:
make scan KIND=full_recon TARGET=scanme.nmap.org
make scans-list
curl -fsS "$ORCH_URL/v1/findings?limit=100" | python3 -m json.tool

# 5. Re-run THIS harness for the crude false-positive measurement:
python3 hardening/realrun.py scanme.nmap.org
"""


def write_report(target: str, result: dict, scored: dict | None, truth: dict, *, degraded_reason: str | None) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines = []
    lines.append("# Real-run + false-positive report")
    lines.append("")
    lines.append(f"- Generated: {now}")
    lines.append(f"- Target: `{target}` (authorized)")
    lines.append(f"- Harness: `hardening/realrun.py` — active worker SAFE modules, detection-only")
    lines.append("")
    lines.append("> Authorized-scope-only. This run touched only an explicitly authorized "
                 "target (scanme.nmap.org / loopback). No exploitation, no evasion, no "
                 "credential testing was performed.")
    lines.append("")

    if degraded_reason:
        lines.append("## Result: DEGRADED (could not execute live in this environment)")
        lines.append("")
        lines.append(f"**Reason:** {degraded_reason}")
        lines.append("")
        lines.append("No findings were produced and **no false-positive number is reported** "
                     "(reporting one here would be fabrication). Run the exact commands below "
                     "on a real deployment to produce real findings and a real FP measurement.")
        lines.append("")
        lines.append("```bash")
        lines.append(EXACT_COMMANDS)
        lines.append("```")
        _finish(lines)
        return

    # Live result
    lines.append("## Module execution")
    lines.append("")
    lines.append("| module | status | detail |")
    lines.append("|---|---|---|")
    for m in result["module_status"]:
        lines.append(f"| {m['module']} | {m['status']} | {m['detail'].replace('|', '/')} |")
    lines.append("")
    lines.append(f"Outbound requests made (audited in-process): {result.get('outbound_requests', 0)}")
    lines.append("")

    rows = scored["rows"]
    lines.append(f"## Findings triage ({len(rows)} total, {scored['actionable_count']} actionable)")
    lines.append("")
    if rows:
        lines.append("| severity | source | rule_id | verdict | title |")
        lines.append("|---|---|---|---|---|")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for r in sorted(rows, key=lambda x: sev_order.get(x["severity"], 9)):
            lines.append(f"| {r['severity']} | {r['source']} | {r['rule_id']} | {r['verdict']} | "
                         f"{r['title'].replace('|', '/')} |")
    else:
        lines.append("_No findings._")
    lines.append("")

    lines.append("## Crude false-positive rate (vs hand-labeled truth set)")
    lines.append("")
    lines.append(f"- Truth set: `hardening/truth_scanme.json` (as of {truth.get('as_of')})")
    lines.append(f"- Actionable findings (severity >= low): **{scored['actionable_count']}**")
    lines.append(f"- Flagged false positives: **{scored['fp_count']}**")
    if scored["fp_rate"] is None:
        lines.append("- **False-positive rate: N/A** (no actionable findings to score)")
    else:
        lines.append(f"- **False-positive rate: {scored['fp_rate'] * 100:.1f}%** "
                     f"({scored['fp_count']}/{scored['actionable_count']})")
    if scored["recall"] is not None:
        lines.append(f"- Expected-signal recall: {len(scored['present_signals'])}/"
                     f"{len(scored['expected_signals'])} "
                     f"({scored['recall'] * 100:.0f}%) "
                     f"— present: {scored['present_signals']}; missing: {scored['missing_signals']}")
    lines.append("")
    if scored["fp"]:
        lines.append("### Findings flagged as false positives")
        lines.append("")
        for r in scored["fp"]:
            lines.append(f"- `{r['rule_id']}` ({r['severity']}) — {r['title']}")
        lines.append("")
    if scored["unverified"]:
        lines.append("### Unverified actionable findings (not in truth set — review manually)")
        lines.append("")
        for r in scored["unverified"]:
            lines.append(f"- `{r['rule_id']}` ({r['severity']}) — {r['title']}")
        lines.append("")
    lines.append("> The FP rate is a crude, approximate measure over a small hand-labeled set "
                 "for a single host whose live config can drift. It is meant to catch gross "
                 "regressions (e.g. the exposed-file module firing on a SPA), not to be a "
                 "precise accuracy metric.")
    lines.append("")
    lines.append("## Reproduce / run the full pipeline")
    lines.append("")
    lines.append("```bash")
    lines.append(EXACT_COMMANDS)
    lines.append("```")
    _finish(lines)


def _finish(lines: list[str]) -> None:
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\nreport written -> {REPORT_PATH}")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Authorized-scope real-run + FP harness")
    ap.add_argument("target", nargs="?", default="scanme.nmap.org",
                    help="authorized target (default: scanme.nmap.org)")
    ap.add_argument("--no-live", action="store_true",
                    help="do not touch the network; emit the degraded/runbook report")
    ap.add_argument("--no-nuclei", action="store_true",
                    help="never run nuclei even if the binary is present")
    args = ap.parse_args(argv)

    print(AUTHORIZATION_REMINDER)
    print()

    # 1. Authorization gate — refuse anything not provably authorized.
    if not is_authorized(args.target):
        print(f"REFUSED: {args.target!r} is not in the authorized scope of this harness.")
        print("This tool only touches scanme.nmap.org and loopback. Aborting.")
        return 2

    print(f"Authorized target accepted: {args.target} (host={host_of(args.target)})")
    print()

    truth = load_truth()

    if args.no_live:
        print("--no-live: skipping all network activity; writing degraded report.")
        write_report(args.target, {"module_status": [], "findings": []}, None, truth,
                     degraded_reason="--no-live was requested; no network activity performed.")
        return 0

    # 2. Import worker modules (honest degradation if unavailable).
    try:
        wk = _import_worker()
    except Exception as e:  # noqa: BLE001
        reason = (f"could not import the active worker's modules "
                  f"({type(e).__name__}: {e}). Install the worker's deps "
                  f"(cd workers/active && pip install -e .) or run inside the worker image.")
        print(f"DEGRADED: {reason}")
        write_report(args.target, {"module_status": [], "findings": []}, None, truth,
                     degraded_reason=reason)
        return 0

    # 3. Run modules.
    t0 = time.monotonic()
    result = asyncio.run(run_modules(args.target, wk, run_nuclei=not args.no_nuclei))
    dur = time.monotonic() - t0

    if not result.get("live"):
        reason = result.get("reason", "live execution failed")
        errs = "; ".join(result.get("errors", []))
        full = f"{reason}. {errs}".strip()
        print(f"DEGRADED: {full}")
        write_report(args.target, result, None, truth, degraded_reason=full)
        return 0

    # 4. Score + print triage table.
    scored = classify(result["findings"], truth)
    print("Module execution:")
    for m in result["module_status"]:
        print(f"  [{m['status']:8}] {m['module']:18} {m['detail']}")
    print()
    print(f"Findings triage ({len(scored['rows'])} total, {scored['actionable_count']} actionable), "
          f"run took {dur:.1f}s:")
    print()
    print(_fmt_table(scored["rows"]))

    if scored["fp_rate"] is None:
        print("Crude false-positive rate: N/A (no actionable findings)")
    else:
        print(f"Crude false-positive rate: {scored['fp_rate'] * 100:.1f}% "
              f"({scored['fp_count']}/{scored['actionable_count']} actionable)")
    if scored["recall"] is not None:
        print(f"Expected-signal recall:    {len(scored['present_signals'])}/"
              f"{len(scored['expected_signals'])} ({scored['recall'] * 100:.0f}%)")

    # 5. Write report.
    write_report(args.target, result, scored, truth, degraded_reason=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
