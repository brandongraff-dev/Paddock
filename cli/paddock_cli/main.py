"""paddock: scan a repo, get real problems and ready-made fixes. Local, no server."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__, fixplan, initcmd, scanner, ui, upload, wargame
from .applyfix import ApplyError, apply_plans, verify_plans
from .gitpr import PrError, open_pr
from .model import SEVERITIES, ScanResult, rank
from .osvclient import OsvClient

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_CATEGORY_ALIASES = {"deps": "deps", "dependencies": "deps", "sca": "deps", "secrets": "secrets",
                     "secret": "secrets", "code": "code", "sast": "code", "config": "config",
                     "iac": "config"}


# --------------------------------------------------------------------------- #
# plumbing
# --------------------------------------------------------------------------- #
class Out:
    """stdout/stderr with a shared style."""

    def __init__(self, args: argparse.Namespace) -> None:
        no_color = bool(getattr(args, "no_color", False))
        self.out = sys.stdout
        self.err = sys.stderr
        self.so = ui.Style(ui.color_enabled(self.out, no_color), ui.unicode_ok(self.out))
        self.se = ui.Style(ui.color_enabled(self.err, no_color), ui.unicode_ok(self.err))
        self.quiet = bool(getattr(args, "quiet", False))

    def p(self, text: str = "") -> None:
        print(text, file=self.out)

    def e(self, text: str = "") -> None:
        print(text, file=self.err)

    def status(self, text: str) -> None:
        if not self.quiet and self.err.isatty():
            self.e(self.se.dim(f"  {text}"))

    def fail(self, text: str) -> int:
        self.e(f"{self.se.red('error:')} {text}")
        return EXIT_ERROR


def _categories(raw: str | None, allowed: set[str]) -> set[str]:
    if not raw:
        return set(allowed)
    out = set()
    for part in raw.split(","):
        key = _CATEGORY_ALIASES.get(part.strip().lower())
        if key is None or key not in allowed:
            raise SystemExit(f"paddock: unknown category {part!r} (choose from "
                             f"{', '.join(sorted(allowed))})")
        out.add(key)
    return out


def _run_scan(a: argparse.Namespace, o: Out, only: set[str] | None = None) -> ScanResult:
    root = Path(a.path)
    if not root.is_dir():
        raise SystemExit(f"paddock: {a.path} is not a directory")
    client = OsvClient(offline=a.offline)
    return scanner.scan(
        root, offline=a.offline, only=only or _categories(a.only, set(scanner.ALL_CATEGORIES)),
        excludes=a.exclude, osv=client, semgrep=a.semgrep, use_git=not a.no_git, log=o.status)


def _annotate(res: ScanResult) -> None:
    """Mark which findings `paddock fix` can handle, without touching the network."""
    try:
        fixplan.plan_fixes(res, res.root, None, recheck=False)
    except Exception:  # noqa: BLE001 - a planner bug must never break a scan
        pass


def _json_report(res: ScanResult) -> dict[str, Any]:
    return {
        "tool": {"name": "paddock-cli", "version": __version__},
        "root": res.root,
        "summary": {"total": len(res.findings), **res.counts()},
        "stats": res.stats,
        "notes": [n for n in res.notes],
        "findings": [f.as_dict() for f in res.findings],
    }


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def cmd_scan(a: argparse.Namespace) -> int:
    o = Out(a)
    if a.json and a.sarif == "-":
        return o.fail("--json and --sarif - both write to stdout; choose one")
    try:
        res = _run_scan(a, o)
    except SystemExit as exc:
        return o.fail(str(exc).removeprefix("paddock: "))
    _annotate(res)

    if a.sarif:
        from .sarif import to_sarif
        doc = json.dumps(to_sarif(res, Path(res.root).name), indent=2)
        if a.sarif == "-":
            o.p(doc)
        else:
            Path(a.sarif).write_text(doc + "\n", encoding="utf-8")
            o.status(f"wrote {a.sarif}")
    if a.json:
        o.p(json.dumps(_json_report(res), indent=2))
    elif a.sarif != "-" and not a.quiet:
        o.p(ui.render_report(res, o.so, __version__, show_all=a.all))
    elif a.quiet and res.findings and a.sarif != "-":
        o.p(ui.summary_line(res, o.so))

    if a.fail_on != "none" and res.at_or_above(a.fail_on):
        n = len(res.at_or_above(a.fail_on))
        o.e(f"{o.se.red(o.se.bad)} {n} finding{'s' if n != 1 else ''} at or above "
            f"'{a.fail_on}': failing (exit {EXIT_FINDINGS})")
        return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- #
# fix
# --------------------------------------------------------------------------- #
def _color_diff(st: ui.Style, diff: str) -> str:
    out = []
    for ln in diff.splitlines():
        if ln.startswith(("+++", "---")):
            out.append(st.bold(ln))
        elif ln.startswith("+"):
            out.append(st.green(ln))
        elif ln.startswith("-"):
            out.append(st.red(ln))
        elif ln.startswith("@@"):
            out.append(st.cyan(ln))
        else:
            out.append(ln)
    return "\n".join(out)


def _confirm(o: Out, question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return ans.strip().lower() in ("y", "yes")


def cmd_fix(a: argparse.Namespace) -> int:
    o = Out(a)
    st = o.so
    try:
        kinds = _categories(a.only, {"deps", "secrets", "config"})
        res = _run_scan(a, o, only=kinds | ({"code"} if "secrets" in kinds else set()))
    except SystemExit as exc:
        return o.fail(str(exc).removeprefix("paddock: "))
    kind_map = {"deps": "dependency", "secrets": "secret", "config": "config"}
    root = Path(res.root)
    client = OsvClient(offline=a.offline)
    plans, skipped = fixplan.plan_fixes(res, root, client, allow_major=a.allow_major,
                                        only={kind_map[k] for k in kinds})
    ok_plans = [p for p in plans if p.gate_ok]
    refused = [p for p in plans if not p.gate_ok]

    if a.json:
        report: dict[str, Any] = {
            "fixes": [{"id": p.id, "kind": p.kind, "title": p.title, "resolves": p.resolves,
                       "gate": {"ok": p.gate_ok, "engine": p.gate_engine, "reasons": p.gate_reasons},
                       "breaking": p.breaking, "notes": p.notes,
                       "files": [e.path for e in p.edits]} for p in plans],
            "skipped": [{"finding": s.finding.id, "title": s.finding.title, "reason": s.reason}
                        for s in skipped]}
    else:
        report = {}
        _print_plans(o, ok_plans, refused, skipped)

    if not ok_plans:
        if a.json:
            o.p(json.dumps(report, indent=2))
        else:
            o.p(f"  {st.dim('Nothing can be fixed automatically.')}" if res.findings
                else f"  {st.green(st.ok)} Nothing to fix.")
            o.p()
        return EXIT_OK

    diff = fixplan.combined_diff(ok_plans)
    if not a.json:
        o.p(_color_diff(st, diff))
        o.p()
    if a.patch:
        Path(a.patch).write_text(diff, encoding="utf-8")
        o.e(f"{st.green(st.ok)} wrote {a.patch}  (apply with: git apply {a.patch})")
        if not a.yes and not a.pr:
            if a.json:
                o.p(json.dumps(report, indent=2))
            return EXIT_OK

    if a.json and not a.yes and not a.pr:       # a machine-readable run is a dry run unless --yes
        o.p(json.dumps(report, indent=2))
        return EXIT_OK

    n = len(ok_plans)
    if a.pr:
        question = f"Open a pull request with these {n} fix{'es' if n != 1 else ''}?"
    else:
        question = f"Apply these {n} fix{'es' if n != 1 else ''}?"
    if not a.yes and not _confirm(o, question):
        if sys.stdin.isatty():
            o.e("Nothing changed.")
            return EXIT_OK
        o.e("Not applying: no terminal to confirm on. Re-run with --yes, or use --patch FILE.")
        return EXIT_ERROR

    verification = None
    try:
        if a.pr:
            token = os.environ.get("GITHUB_TOKEN", "").strip()
            holder: dict[str, Any] = {}

            def after_apply():
                r2 = _run_scan(a, o, only=kinds | ({"code"} if "secrets" in kinds else set()))
                holder["v"] = verify_plans(ok_plans, r2)
                return holder["v"]

            result = open_pr(root, ok_plans, after_apply, token=token, repo=a.repo, draft=a.draft)
            verification = holder.get("v")
            if a.json:
                report["pull_request"] = {"url": result.url, "branch": result.branch,
                                          "base": result.base}
            else:
                o.p(f"  {st.green(st.ok)} Opened {st.bold(result.url or result.branch)}")
                o.p(st.dim(f"    branch {result.branch} {st.arrow} {result.base}; "
                           "not merged, a human reviews it"))
        else:
            written = apply_plans(ok_plans, root)
            if not a.json:
                o.p(f"  {st.green(st.ok)} Applied to {', '.join(written)}")
                o.p(st.dim("    re-running the checks..."))
            verification = verify_plans(ok_plans, _run_scan(
                a, o, only=kinds | ({"code"} if "secrets" in kinds else set())))
    except (ApplyError, PrError) as exc:
        return o.fail(str(exc))

    code = EXIT_OK
    if verification is not None:
        report["verification"] = verification.as_dict()
        if not a.json:
            o.p(f"  {st.bold('verified:')} {verification.fixed} of {verification.total} fixed")
            for oc in verification.outcomes:
                if oc.status != "fixed":
                    o.p(f"    {st.yellow('!')} {oc.plan.title}: {oc.status.replace('_', ' ')} "
                        f"({oc.reason})")
            o.p()
        if verification.fixed != verification.total:
            code = EXIT_FINDINGS
    if a.json:
        o.p(json.dumps(report, indent=2))
    return code


def _print_plans(o: Out, plans, refused, skipped) -> None:
    st = o.so
    o.p()
    o.p(f"  {st.bold('paddock fix')} {st.dim(__version__)}")
    o.p()
    if plans:
        o.p(f"  {st.bold('FIXES READY')} {st.dim(f'({len(plans)})')}")
        for i, p in enumerate(plans, 1):
            tag = st.yellow(" major") if p.breaking else ""
            o.p(f"   {i:>2}. {st.bold(p.title)}{tag}")
            o.p(st.dim(f"       {', '.join(e.path for e in p.edits)}"
                       f" · gate: {p.gate_engine} passed"))
            for n in p.notes:
                o.p(st.dim(st.wrap(n, 7, first="- ")))
        o.p()
    if refused:
        o.p(f"  {st.bold('REFUSED BY THE SAFETY GATE')} {st.dim(f'({len(refused)})')}")
        for p in refused:
            o.p(f"   {st.red(st.bad)} {p.title}")
            for r in p.gate_reasons[:3]:
                o.p(st.dim(st.wrap(r, 7, first="- ")))
        o.p()
    if skipped:
        o.p(f"  {st.bold('NEEDS YOU')} {st.dim(f'({len(skipped)}) not fixable automatically')}")
        for s in skipped[:12]:
            o.p(f"   {st.yellow('-')} {s.finding.title}")
            o.p(st.dim(st.wrap(s.reason, 7)))
        if len(skipped) > 12:
            o.p(st.dim(f"       ... and {len(skipped) - 12} more"))
        o.p()


# --------------------------------------------------------------------------- #
# login / upload / init
# --------------------------------------------------------------------------- #
def cmd_login(a: argparse.Namespace) -> int:
    o = Out(a)
    try:
        server = upload.resolve_server(a.server)
        key = os.environ.get("PADDOCK_API_KEY", "").strip() or None
        me = upload.check_server(server, key)
    except upload.UploadError as exc:
        return o.fail(str(exc))
    path = upload.save_config({**upload.load_config(), "server": server})
    o.p(f"  {o.so.green(o.so.ok)} {server} is reachable" + (
        f"; key accepted for {me.get('username') or me.get('user') or 'this account'}" if me else ""))
    if not key:
        o.p(o.so.dim("    set PADDOCK_API_KEY to upload (the key itself is never saved)"))
    o.p(o.so.dim(f"    saved server to {path}"))
    return EXIT_OK


def cmd_upload(a: argparse.Namespace) -> int:
    o = Out(a)
    try:
        server = upload.resolve_server(a.server)
        key = upload.api_key()
        res = _run_scan(a, o)
        stats = upload.upload(res, server, key, a.project or Path(res.root).name)
    except upload.UploadError as exc:
        return o.fail(str(exc))
    except SystemExit as exc:
        return o.fail(str(exc).removeprefix("paddock: "))
    o.p(f"  {o.so.green(o.so.ok)} uploaded {stats['uploaded']} finding"
        f"{'s' if stats['uploaded'] != 1 else ''} to {server}")
    return EXIT_OK


def cmd_init(a: argparse.Namespace) -> int:
    o = Out(a)
    root = Path(a.path)
    if not root.is_dir():
        return o.fail(f"{a.path} is not a directory")
    results = initcmd.init(root, force=a.force, workflow=not a.no_workflow,
                           precommit=not a.no_pre_commit)
    for path, state in results:
        mark = {"created": o.so.green(o.so.ok), "exists": o.so.dim("="), "snippet": o.so.yellow("!")}[state]
        o.p(f"  {mark} {path}  {o.so.dim(state if state != 'snippet' else 'exists: add this hook yourself')}")
        if state == "snippet":
            o.p(o.so.dim("\n".join("      " + ln for ln in initcmd.PRECOMMIT_HOOK.splitlines())))
    if any(s == "created" for _, s in results):
        o.p(o.so.dim("    commit them, and findings will appear under Security > Code scanning"))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# argparse
# --------------------------------------------------------------------------- #
def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", nargs="?", default=".", help="repository to scan (default: .)")
    p.add_argument("--offline", action="store_true",
                   help="never touch the network: use only the on-disk OSV cache")
    p.add_argument("--only", metavar="LIST", help="comma list: deps,secrets,code,config")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching GLOB (repeatable)")
    p.add_argument("--semgrep", action="store_true",
                   help="use Semgrep for code analysis when installed (default: bundled scanner)")
    p.add_argument("--no-git", action="store_true", help="walk the directory instead of using git ls-files")
    p.add_argument("--no-color", action="store_true", help="disable colour (also: NO_COLOR=1)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="paddock", description="Find real problems in your repo and get ready-made fixes. "
        "Runs locally; nothing leaves your machine unless you run `paddock upload`.")
    ap.add_argument("--version", action="version", version=f"paddock-cli {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    s = sub.add_parser("scan", help="scan a repo: vulnerable deps, secrets, code bugs, misconfig")
    _common(s)
    s.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    s.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 to FILE ('-' for stdout)")
    s.add_argument("--fail-on", choices=("none", *SEVERITIES[1:]), default="none",
                   help="exit 1 when a finding is at or above this severity (default: none)")
    s.add_argument("--all", action="store_true", help="list every finding (default caps long groups)")
    s.add_argument("-q", "--quiet", action="store_true", help="only the summary line")
    s.set_defaults(fn=cmd_scan)

    f = sub.add_parser("fix", help="generate fixes, show the diff, apply on confirmation")
    _common(f)
    f.add_argument("-y", "--yes", action="store_true", help="apply without asking")
    f.add_argument("--patch", metavar="FILE", help="write the diff to FILE (does not apply without --yes)")
    f.add_argument("--pr", action="store_true",
                   help="open a GitHub pull request on a new branch (needs GITHUB_TOKEN); never merges")
    f.add_argument("--draft", action="store_true", help="with --pr: open it as a draft")
    f.add_argument("--repo", metavar="OWNER/NAME", help="with --pr: GitHub repository (default: from origin)")
    f.add_argument("--allow-major", action="store_true",
                   help="include upgrades that cross a major version (skipped by default)")
    f.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    f.add_argument("-q", "--quiet", action="store_true")
    f.set_defaults(fn=cmd_fix)

    lg = sub.add_parser("login", help="remember a Paddock server for `upload` (key stays in PADDOCK_API_KEY)")
    lg.add_argument("--server", metavar="URL")
    lg.set_defaults(fn=cmd_login)

    u = sub.add_parser("upload", help="scan and send findings to a Paddock server (opt-in)")
    _common(u)
    u.add_argument("--server", metavar="URL", help="Paddock server (or PADDOCK_SERVER / `paddock login`)")
    u.add_argument("--project", metavar="NAME", help="project/asset name (default: directory name)")
    u.add_argument("-q", "--quiet", action="store_true")
    u.set_defaults(fn=cmd_upload)

    i = sub.add_parser("init", help="add a GitHub Actions workflow and a pre-commit hook")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--force", action="store_true", help="overwrite an existing workflow")
    i.add_argument("--no-workflow", action="store_true")
    i.add_argument("--no-pre-commit", action="store_true")
    i.add_argument("--no-color", action="store_true")
    i.set_defaults(fn=cmd_init)

    wargame.add_parser(sub)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
