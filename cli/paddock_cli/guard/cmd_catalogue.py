# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard catalogue [--check]``: generate or verify docs/guard/CHECKS.md and TIERS.md."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("catalogue", help="generate or verify the generated check documents",
                       description="Writes CHECKS.md (static columns) and TIERS.md (effective tiers).")
    p.add_argument("--check", action="store_true", help="exit 1 when a generated document is missing or stale")
    p.add_argument("--docs-dir", metavar="DIR", help="documents directory (default: docs/guard of this checkout)")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    import os

    from paddock_cli.guard import catalogue, files, registry
    from paddock_cli.guard.errors import UsageError

    registry.discover()
    docs = args.docs_dir
    if not docs:
        here = os.path.dirname(os.path.abspath(__file__))
        docs = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(here))), "docs", "guard")
    if not os.path.isdir(docs):
        raise UsageError("documents directory not found; pass --docs-dir")
    docs = os.path.realpath(docs)
    checks = registry.all_checks()
    wanted = {"CHECKS.md": catalogue.render_checks_md(checks), "TIERS.md": catalogue.render_tiers_md(checks)}
    if args.check:
        stale = []
        for name, text in wanted.items():
            view, why = files.read_file(docs, name, limit=4 * 1024 * 1024)
            if view is None or view.text != text:
                stale.append(name)
        if stale:
            sys.stdout.write("stale or missing: %s (run: python -m paddock_cli.guard catalogue)\n" % ", ".join(stale))
            return 1
        sys.stdout.write("catalogue is up to date\n")
        return 0
    for name, text in wanted.items():
        files.safe_write(docs, name, text, mode=0o644)
    sys.stdout.write("wrote %s\n" % ", ".join(sorted(wanted)))
    return 0
