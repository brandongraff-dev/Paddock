# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard check``: run the checks and print the report (contract 3.5, D9, D12, D13)."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("check", help="run the checks over a project (the default command)",
                       description="Run Paddock Guard's checks over PATH. Offline; nothing leaves your machine.")
    p.add_argument("path", nargs="?", default=".", help="project root (default: .)")
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--changed", action="store_true", help="only files changed since HEAD plus untracked files")
    scope.add_argument("--base", metavar="REF", help="report only findings absent from a scan of REF (delta mode)")
    scope.add_argument("--staged", action="store_true", help="scan the git index (pre-commit)")
    p.add_argument("--tier", choices=("high", "medium", "low"), help="minimum confidence tier to run (default: high)")
    p.add_argument("--only", action="append", metavar="IDS", help="comma-separated check ids or packs (repeatable)")
    p.add_argument("--fail-on", dest="fail_on", choices=("info", "low", "medium", "high", "critical"),
                   help="blocking severity threshold (default: high)")
    p.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--offline", action="store_true", help="never use the network")
    p.add_argument("--config-ref", metavar="REF", help="read .paddock/guard.toml from this git ref")
    p.add_argument("--baseline-ref", metavar="REF", help="read .paddock/baseline.json from this git ref")
    p.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")
    p.add_argument("--no-cache", action="store_true", help="write no report, ledger or cache anywhere")
    p.add_argument("--all", action="store_true", help="list every finding (text output caps long lists)")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    from paddock_cli.guard import api, files, ledger as ledger_mod, model, output, textsafe

    result = api.run_scan(
        args.path, tier=args.tier, fail_on=args.fail_on, only=args.only, changed=bool(args.changed), base=args.base,
        staged=args.staged, offline=args.offline, config_ref=args.config_ref, baseline_ref=args.baseline_ref,
        use_baseline=not args.no_baseline, no_cache=args.no_cache)
    report, cfg = result.report, result.cfg
    lg = ledger_mod.Ledger(None if args.no_cache else result.state_dir)
    forced = False

    # PG-META-004: the hook gave up reminding the agent about a finding that is still open.
    approved = set(cfg.ci.approved_suppressions)
    open_fps = {f.fingerprint: f for f in report.open_findings()}
    exhausted: set[str] = set()
    for ev in lg.read():
        if ev.get("event") == "hook_ignored_by_agent":
            exhausted |= {fp for fp in ev.get("fingerprints", []) if fp in open_fps and fp not in approved}
    if exhausted:
        ids = sorted({open_fps[fp].check_id for fp in exhausted})
        report.notes.append("%s: hook reminders were exhausted for %s (still open); a person must review them or list the "
                            "fingerprints in [ci] approved_suppressions" % (model.META_HOOK_EXHAUSTED, ", ".join(ids[:10])))
        forced = True

    # D13: any suppression or baseline entry added versus the base ref fails unless approved.
    if report.suppressions_added and cfg.ci.fail_on_new_suppression:
        unapproved = [r for r in report.suppressions_added if r.get("fingerprint") not in approved]
        if unapproved:
            report.notes.append("%d suppression(s) or baseline entr%s added versus the base ref and not approved in "
                                "[ci] approved_suppressions of the base-ref config" % (len(unapproved), "y" if len(unapproved) == 1 else "ies"))
            forced = True

    text = output.render(report, args.format, **({"show_all": True} if args.all and args.format == "text" else {}))
    if args.output:
        files.write_output_file(args.output, text)
        sys.stderr.write("wrote %s report to %s\n" % (args.format, textsafe.safe_text(args.output, cap=200)))
    else:
        sys.stdout.write(text)
    if result.state_dir and not args.no_cache:
        try:
            files.safe_write(result.state_dir, "last-report.json", output.render_json(report))
        except Exception:  # noqa: BLE001  (a state write must never change the exit code)
            pass
    s = report.summary()
    lg.append("check", tier=report.mode["tier"], scope=report.mode["scope"], blocking=s["blocking"], open=s["open"],
              suppressed=s["suppressed"], baselined=s["baselined"], complete=s["complete"],
              checks=report.checks_run[:100], errors=len(report.errors), skipped=len(report.skipped))
    return 1 if (output.exit_code(report) or forced) else 0
