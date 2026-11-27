# SPDX-License-Identifier: AGPL-3.0-or-later
"""Isolated git for tests (contract 3.12): no ambient config, fixed identity, no signing."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

IDENT = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
}


def git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in ("PADDOCK_GUARD_NO_STATE",)}
    env.update(IDENT)
    env.update({
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    if extra:
        env.update(extra)
    return env


def git(cwd: str | Path, *args: str, check: bool = True, input: str | None = None,  # noqa: A002
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run git in ``cwd`` with the isolated environment; text mode."""
    cmd = ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
           "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=never", *args]
    r = subprocess.run(cmd, cwd=str(cwd), env=git_env(env), input=input, capture_output=True,
                       text=True, timeout=60)
    if check and r.returncode != 0:
        raise AssertionError("git %s failed (%d): %s" % (" ".join(args), r.returncode, r.stderr.strip()))
    return r


def init_repo(path: str | Path) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")


def commit_all(path: str | Path, message: str = "commit") -> str:
    git(path, "add", "-A")
    git(path, "commit", "-q", "--allow-empty", "-m", message)
    return git(path, "rev-parse", "HEAD").stdout.strip()
