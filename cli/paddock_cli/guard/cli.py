# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command line entry points: ``paddock-guard ...`` and ``paddock guard ...`` (contract 3.5, D11, D12).

Command modules (``cmd_*``) register themselves through ``register(subparsers)``; a module that is
not built yet is skipped (``ModuleNotFoundError`` whose ``.name`` is that module), any other error
propagates. ``paddock guard`` with no subcommand runs ``check .``.
"""
from __future__ import annotations

import argparse
import importlib
import sys
from typing import Any, Sequence

from paddock_cli.guard import GUARD_VERSION
from paddock_cli.guard.errors import GuardError

COMMANDS = ("cmd_check", "cmd_explain", "cmd_list", "cmd_status", "cmd_baseline", "cmd_ledger", "cmd_catalogue",
            "cmd_pkg", "cmd_deps", "cmd_shim", "cmd_verify", "cmd_fix", "cmd_url", "cmd_init", "cmd_hook",
            "cmd_receipt", "cmd_badge")
_DESCRIPTION = ("Paddock Guard: static checks, exact repair prompts and re-checks for AI-built apps. "
                "Local and offline by default; nothing leaves your machine unless you run a command that says so.")


def _add_commands(sub: Any) -> None:
    for name in COMMANDS:
        modname = "paddock_cli.guard." + name
        try:
            mod = importlib.import_module(modname)
        except ModuleNotFoundError as exc:
            if exc.name == modname:
                continue
            raise
        mod.register(sub)


def _run(args: argparse.Namespace) -> int:
    fn = getattr(args, "gfn", None)
    if fn is None:
        return 2
    try:
        return int(fn(args))
    except GuardError as exc:
        from paddock_cli.guard import textsafe

        sys.stderr.write("paddock-guard: error: %s\n" % textsafe.safe_text(str(exc), cap=300))
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
    except RecursionError:
        sys.stderr.write("paddock-guard: error: input too deeply nested\n")
        return 2
    except MemoryError:
        sys.stderr.write("paddock-guard: error: out of memory\n")
        return 2


def _with_default_check(argv: Sequence[str], names: Any) -> list[str]:
    args = list(argv)
    if not args or (args[0] not in names and args[0] not in ("-h", "--help", "--version")):
        return ["check"] + args
    return args


def build_parser() -> tuple[argparse.ArgumentParser, Any]:
    ap = argparse.ArgumentParser(prog="paddock-guard", description=_DESCRIPTION)
    ap.add_argument("--version", action="version", version="paddock-guard " + GUARD_VERSION)
    sub = ap.add_subparsers(dest="gcmd", metavar="COMMAND")
    _add_commands(sub)
    return ap, sub.choices


def register(sub: Any) -> argparse.ArgumentParser:
    """Register ``guard`` in the ``paddock`` command tree (the single hunk of main.py calls this)."""
    p = sub.add_parser("guard", help="Paddock Guard: checks for AI-built apps (local, offline)",
                       description=_DESCRIPTION)
    p.add_argument("--version", action="version", version="paddock-guard " + GUARD_VERSION)
    gsub = p.add_subparsers(dest="gcmd", metavar="COMMAND")
    _add_commands(gsub)
    names = gsub.choices
    p.set_defaults(fn=_run)
    original = p.parse_known_args

    def parse_known_args(args: Any = None, namespace: Any = None) -> Any:
        args = _with_default_check(sys.argv[1:] if args is None else args, names)
        return original(args, namespace)

    p.parse_known_args = parse_known_args  # type: ignore[method-assign]
    return p


def main(argv: Sequence[str] | None = None) -> int:
    ap, names = build_parser()
    args_list = _with_default_check(sys.argv[1:] if argv is None else argv, names)
    try:
        args = ap.parse_args(args_list)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else (0 if code is None else 2)
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
