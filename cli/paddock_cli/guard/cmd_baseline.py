# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard baseline create|update|show``: adopt legacy findings (contract 3.10, D13)."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("baseline", help="create, update or show .paddock/baseline.json",
                       description="Baselined findings are shown as baselined and never block.")
    p.add_argument("action", choices=("create", "update", "show"))
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--tier", choices=("high", "medium", "low"), help="tier of the scan that decides what is recorded")
    p.add_argument("--force", action="store_true", help="create: overwrite an existing baseline")
    p.add_argument("--no-cache", action="store_true", help="write no ledger or cache")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    from paddock_cli.guard import api, files, suppress, textsafe
    from paddock_cli.guard.errors import UsageError

    root = files.real_root(args.path)
    existing, notes = suppress.load_baseline(root)
    if args.action == "show":
        if existing is None:
            for n in notes:
                sys.stderr.write(n + "\n")
            raise UsageError("no baseline at .paddock/baseline.json")
        n = len(existing.entries)
        lines = ["%d baseline entr%s (created %s)" % (n, "y" if n == 1 else "ies", textsafe.safe_text(existing.created, cap=20))]
        lines += ["  %s  %s  %s" % (e.fingerprint, textsafe.safe_text(e.check_id, cap=40), textsafe.safe_text(e.file, cap=120))
                  for e in existing.entries[:200]]
        sys.stdout.write("\n".join(lines) + "\n")
        return 0
    result = api.run_scan(root, tier=args.tier, use_baseline=False, no_cache=args.no_cache)
    if args.action == "create":
        if (existing is not None or notes) and not args.force:
            raise UsageError("a baseline already exists; use 'baseline update' or --force")
        found = [f for f in result.report.findings if f.status in ("open", "baselined")]
        b = suppress.create_baseline(found)
        suppress.write_baseline(root, b)
        sys.stdout.write("baseline created: %d finding%s recorded in .paddock/baseline.json\n"
                         % (len(b.entries), "" if len(b.entries) == 1 else "s"))
        return 0
    if existing is None:
        raise UsageError("no baseline to update; run 'baseline create' first")
    updated = suppress.update_baseline(existing, result.report.findings)
    removed = len(existing.entries) - len(updated.entries)
    suppress.write_baseline(root, updated)
    sys.stdout.write("baseline updated: kept %d entr%s, removed %d\n"
                     % (len(updated.entries), "y" if len(updated.entries) == 1 else "ies", removed))
    return 0
