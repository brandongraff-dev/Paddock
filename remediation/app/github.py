"""PR opener (THREAT-MODEL LAYER 6): PROPOSED, NEVER auto-merged.

Opening a real PR is OFF by default (``REMEDIATION_OPEN_PR=false``). With it off
the pipeline produces the verified diff + reports WITHOUT pushing anywhere — a
human opens the PR. When it is explicitly enabled AND a repo + ``GITHUB_TOKEN``
are configured, this opens a PR on a NEW branch via the ``gh`` CLI, labels it
``automated-fix`` and puts the verification summary in the body.

This module NEVER merges. There is no merge path, and nothing here enables
auto-merge. A human reviewer always approves.

The PR title/body are injection-scanned by the pipeline BEFORE we are called;
we additionally refuse if the body still looks injected, as a final backstop.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from . import injection
from .config import Config

log = logging.getLogger("remediation.github")

AUTOMATED_FIX_LABEL = "automated-fix"


@dataclass
class PRResult:
    opened: bool
    reason: str
    pr_url: str | None = None
    pr_number: int | None = None
    head_branch: str | None = None


def can_open(cfg: Config) -> tuple[bool, str]:
    """Whether a PR could actually be opened right now."""
    if not cfg.open_pr:
        return False, "REMEDIATION_OPEN_PR is false (default); PR not pushed"
    if not cfg.github_token:
        return False, "GITHUB_TOKEN not configured"
    if not cfg.github_repo:
        return False, "GITHUB_REPO not configured"
    if shutil.which("gh") is None:
        return False, "gh CLI not available"
    return True, "ok"


def open_pr(
    cfg: Config,
    *,
    head_branch: str,
    title: str,
    body: str,
    diff_text: str,
    run: Any = None,
) -> PRResult:
    """Open a PROPOSED PR. Returns a PRResult; never merges.

    ``run`` is an injection point for tests (defaults to subprocess.run). In a
    real deployment this would check out the repo, apply ``diff_text`` on
    ``head_branch``, push, and ``gh pr create``. We keep the shell surface tiny
    and never pass untrusted text as a command argument unquoted.
    """
    ok, reason = can_open(cfg)
    if not ok:
        return PRResult(opened=False, reason=reason, head_branch=head_branch)

    # Final backstop: never let an injected body reach the PR.
    scan = injection.scan_fields({"pr_title": title, "pr_body": body})
    if scan["blocked"]:
        return PRResult(
            opened=False,
            reason="refused: PR body/title flagged by injection scan: " + scan["summary"],
            head_branch=head_branch,
        )

    runner = run or _default_run
    try:
        # NOTE: no merge, no --auto-merge. Create a DRAFT-equivalent proposal.
        args = [
            "gh", "pr", "create",
            "--repo", str(cfg.github_repo),
            "--base", cfg.base_branch,
            "--head", head_branch,
            "--title", title,
            "--body", body,
            "--label", AUTOMATED_FIX_LABEL,
        ]
        completed = runner(args)
        url = (getattr(completed, "stdout", "") or "").strip().splitlines()
        pr_url = url[-1] if url else None
        number = _pr_number_from_url(pr_url)
        return PRResult(
            opened=True, reason="pr opened (awaiting human review)",
            pr_url=pr_url, pr_number=number, head_branch=head_branch,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("gh pr create failed: %s", type(exc).__name__)
        return PRResult(opened=False, reason=f"gh pr create failed: {exc}", head_branch=head_branch)


def _default_run(args: list[str]):  # pragma: no cover - exercised only live
    return subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)


def _pr_number_from_url(url: str | None) -> int | None:
    if not url:
        return None
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return None
