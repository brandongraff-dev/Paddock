# SPDX-License-Identifier: AGPL-3.0-or-later
"""``paddock guard ledger show|clear``: the local, editable event log (contract 3.10, D30)."""
from __future__ import annotations

import argparse
import sys


def register(sub: "argparse._SubParsersAction") -> None:  # type: ignore[type-arg]
    p = sub.add_parser("ledger", help="show or clear the local ledger",
                       description="The ledger is local, editable and not tamper-evident.")
    p.add_argument("action", choices=("show", "clear"))
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--limit", type=int, default=50, help="show: newest N events (default 50)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(gfn=run)


def run(args: argparse.Namespace) -> int:
    import json

    from paddock_cli.guard import files, ledger as ledger_mod, textsafe

    root = files.real_root(args.path)
    state = files.state_dir(root, create=False)
    lg = ledger_mod.Ledger(state)
    if args.action == "clear":
        n = lg.clear()
        sys.stdout.write("removed %d ledger file%s\n" % (n, "" if n == 1 else "s"))
        return 0
    recs = lg.read(limit=max(1, args.limit)) if state else []
    if args.format == "json":
        sys.stdout.write(json.dumps(recs, indent=2) + "\n")
        return 0
    lines = []
    for r in recs:
        extra = " ".join("%s=%s" % (k, json.dumps(v, separators=(",", ":"))) for k, v in r.items()
                         if k not in ("ts", "event", "session", "tool_version"))
        lines.append("%s %-22s %s" % (r.get("ts", "?"), r.get("event", "?"), textsafe.cap(extra, 200)))
    lines.append("%d event%s (self-reported by the local ledger)" % (len(recs), "" if len(recs) == 1 else "s"))
    sys.stdout.write(textsafe.clean("\n".join(lines), keep_newlines=True) + "\n")
    return 0
