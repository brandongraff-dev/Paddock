# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard list``: the registered checks and their effective tiers."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("list", help="list the checks", description="List checks with their declared and effective tiers.")
    p.add_argument("--tier", choices=("high", "medium", "low"), help="only checks that run at this tier")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    import json

    from paddock_cli.guard import api, textsafe

    rows = api.list_checks(args.tier)
    if args.format == "json":
        sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        return 0
    lines = ["%-14s %-9s %-9s %-10s %-15s %s" % ("ID", "SEVERITY", "DECLARED", "EFFECTIVE", "EVIDENCE", "TITLE")]
    for r in rows:
        lines.append("%-14s %-9s %-9s %-10s %-15s %s" % (r["id"], r["severity"], r["declared_tier"], r["effective_tier"],
                                                         r["tier_evidence"], r["title"]))
    lines.append("%d checks" % len(rows))
    sys.stdout.write(textsafe.clean("\n".join(lines), keep_newlines=True) + "\n")
    return 0
