# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard explain ID``: what a check looks for and how it is tiered."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("explain", help="explain one check", description="Explain one check by id.")
    p.add_argument("check_id", metavar="ID")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    import json

    from paddock_cli.guard import api, textsafe

    d = api.explain(args.check_id)
    if args.format == "json":
        sys.stdout.write(json.dumps(d, indent=2) + "\n")
        return 0
    lines = [
        "%s  %s" % (d["id"], d["title"]),
        "  severity: %s   scope: %s   pack: %s" % (d["severity"], d["scope"], d["pack"]),
        "  declared tier: %s   effective tier: %s (%s)" % (d["declared_tier"], d["effective_tier"], d["tier_evidence"]),
        "  inline suppressible: %s   fixer: %s   cwe: %s" % ("yes" if d["inline_suppressible"] else "no", d["fixer"] or "none", d["cwe"] or "none"),
        "  spec status: %s%s" % (d["spec_status"], "  open UNVERIFIED ids: " + ", ".join(d["open_unverified_ids"]) if d["open_unverified_ids"] else ""),
        "  why: " + d["why"],
        "  fix: " + d["fix_hint"],
        "  agent prompt template:",
    ]
    lines += ["    " + ln for ln in d["agent_prompt_template"].splitlines()]
    sys.stdout.write("\n".join(textsafe.clean(x, keep_newlines=True) for x in lines) + "\n")
    return 0
