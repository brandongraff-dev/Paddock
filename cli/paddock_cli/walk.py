"""Find and read the files worth scanning.

Inside a git work tree the file list is ``git ls-files`` (tracked plus
untracked-but-not-ignored), so ``.gitignore`` is honoured for free. Elsewhere we
walk the tree and skip the usual build/vendor directories.
"""
from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from pathlib import Path

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv", "env",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build",
    "target", ".next", ".nuxt", ".gradle", ".idea", ".vscode", "site-packages", ".terraform",
    "coverage", ".cache",
})
MAX_TEXT_BYTES = 1_000_000          # source / config files
MAX_LOCK_BYTES = 40_000_000         # lockfiles can be huge


def git_files(root: Path) -> list[str] | None:
    """Relative paths git would consider part of the project, or None."""
    git = shutil.which("git")
    if not git or not root.is_dir():
        return None
    try:
        probe = subprocess.run([git, "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                               capture_output=True, text=True, timeout=10)
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            return None
        out = subprocess.run(
            [git, "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=60, check=True)
    except (subprocess.SubprocessError, OSError):
        return None
    return [p for p in out.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def _walk(root: Path) -> list[str]:
    out: list[str] = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for n in sorted(names):
            out.append(os.path.relpath(os.path.join(base, n), root).replace(os.sep, "/"))
    return out


def _skipped(rel: str, excludes: list[str]) -> bool:
    parts = rel.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat) for p in parts)
               for pat in excludes)


def list_files(root: Path, excludes: list[str] | None = None, use_git: bool = True) -> list[str]:
    excludes = list(excludes or [])
    rels = git_files(root) if use_git else None
    if rels is None:
        rels = _walk(root)
    out = []
    for rel in rels:
        rel = rel.replace(os.sep, "/")
        if _skipped(rel, excludes):
            continue
        p = root / rel
        if p.is_symlink() or not p.is_file():
            continue  # never follow links out of the tree
        out.append(rel)
    return sorted(set(out))


def read_text(path: Path, limit: int = MAX_TEXT_BYTES) -> str | None:
    """File contents as text, or None for binary / oversized / unreadable files."""
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")
