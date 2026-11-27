# SPDX-License-Identifier: AGPL-3.0-or-later
"""Launcher scripts for subprocess tests (contract 3.12).

Pytest's ``pythonpath`` does not reach child processes, so subprocess tests run the guard through
an executable ``paddock-guard`` that sets PYTHONPATH and execs the current interpreter.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
CLI_DIR = REPO / "cli"


def _script(module: str) -> str:
    return (
        "#!/bin/sh\n"
        'PYTHONPATH="%s${PYTHONPATH:+:$PYTHONPATH}" exec "%s" -m %s "$@"\n' % (CLI_DIR, sys.executable, module)
    )


def make_bin(directory: str | Path) -> str:
    """Write ``paddock-guard`` and a ``paddock-guard-mcp`` stub into ``directory``; return it."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    exe = d / "paddock-guard"
    exe.write_text(_script("paddock_cli.guard"), encoding="utf-8")
    stub = d / "paddock-guard-mcp"
    stub.write_text(
        "#!/bin/sh\necho 'paddock-guard-mcp test stub (the server is built by another package)' >&2\nexit 0\n",
        encoding="utf-8")
    for p in (exe, stub):
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)
    return str(d)


def guard_env_dict(tmp: str | Path, bindir: str | Path) -> dict[str, str]:
    t = Path(tmp)
    home = t / "home"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "PADDOCK_", "CLAUDE_"))}
    for sub in ("home", "xdg-config", "xdg-cache", "paddock-config", "paddock-cache"):
        (t / sub).mkdir(parents=True, exist_ok=True)
    env.update({
        "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
        "PYTHONPATH": str(CLI_DIR),
        "PYTHONDONTWRITEBYTECODE": "1",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(t / "xdg-config"),
        "XDG_CACHE_HOME": str(t / "xdg-cache"),
        "PADDOCK_CONFIG_DIR": str(t / "paddock-config"),
        "PADDOCK_CACHE_DIR": str(t / "paddock-cache"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "TERM": "dumb",
    })
    return env
