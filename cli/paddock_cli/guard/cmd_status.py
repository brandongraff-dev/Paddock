# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard status``: version, checks, configuration trust and local state."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("status", help="show version, check counts and local state", description="Show Guard's status.")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    import json

    from paddock_cli.guard import api

    d = api.status(args.path)
    if args.format == "json":
        sys.stdout.write(json.dumps(d, indent=2) + "\n")
        return 0
    c = d["checks"]
    lines = [
        "paddock-guard %s (%s build)" % (d["version"], "release" if d["release_build"] else "development"),
        "checks: %d registered, %d effective-high (default-on), %d medium, %d low" % (
            c["total"], c["effective_high"], c["effective_medium"], c["effective_low"]),
        "measured tiers file (data/tiers.json): %s; closed UNVERIFIED ids: %d" % ("present" if d["tiers_json_present"] else "absent", d["verified_ids"]),
        "user config: %s" % ("trusted" if d["user_config"]["trusted"] else "present but not trusted" if d["user_config"]["present"] else "none"),
        "project config: %s; baseline: %s" % ("yes" if d["project_config"] else "no", "yes" if d["baseline"] else "no"),
        "state directory: %s; ledger events: %d" % ("exists" if d["state_dir_exists"] else "not created", d["ledger_events"]),
    ]
    if d["import_errors"]:
        lines.append("check modules that failed to import: " + ", ".join(d["import_errors"][:5]))
    sys.stdout.write("\n".join(lines) + "\n")
    return 0
