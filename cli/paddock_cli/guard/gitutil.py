# SPDX-License-Identifier: AGPL-3.0-or-later
"""The only module that starts a process (contract 3.11 H2, D31).

Guard runs inside repositories the user has not reviewed, so git is started with a fixed argv,
``shell=False``, a scrubbed environment, repository config that could execute code overridden on
the command line, and refs that are validated and resolved to 40-hex ids before use.
"""
from __future__ import annotations

import atexit
import os
import re
import subprocess
from contextlib import contextmanager
from typing import Any, Iterator

from paddock_cli.guard.errors import ConfigError, GuardError

# Config that could make git run a program, overridden for every call (H2).
_HARDENED = (
    "-c", "core.fsmonitor=",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "protocol.ext.allow=never",
    "-c", "core.sshCommand=false",
)

_REF_BAD = re.compile(r"[\s\x00-\x1f\x7f\\:?*\[\u0080-￿]")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_NAME_OK = re.compile(r"^[A-Za-z0-9_.+-]{1,100}$")

_home_dir: str | None = None


def _reset_for_tests() -> None:
    """Forget the cached empty HOME (tests change PATH or the temp location)."""
    global _home_dir
    _home_dir = None
    _CFG_CACHE.clear()


def _empty_home() -> str:
    global _home_dir
    if _home_dir is None or not os.path.isdir(_home_dir):
        from paddock_cli.guard import files

        _home_dir = files.private_tempdir("paddock-guard-githome-")
        atexit.register(files.remove_tree, _home_dir)
    return _home_dir


def build_env() -> dict[str, str]:
    """Environment of only PATH, an empty HOME and the isolation variables (H2)."""
    return {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "HOME": _empty_home(),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _read_small(path: str, limit: int = 262144) -> str | None:
    """Read a file the repository controls without blocking or following a symlink."""
    from paddock_cli.guard import files

    text, why = files.read_abs_text(path, limit=limit)
    if text is not None:
        return text
    if why in ("symlink", "not-regular", "oversize"):
        raise GuardError("an unusual git file is present (%s); not read by Paddock Guard" % why)
    return None


def _git_dir_config(root: str) -> str | None:
    """Path of the repository's own config file, following a ``gitdir:`` pointer file."""
    dot = os.path.join(root, ".git")
    try:
        if os.path.isdir(dot) and not os.path.islink(dot):
            return os.path.join(dot, "config")
        if os.path.isfile(dot):
            head = (_read_small(dot, 4096) or "").strip()
            if head.startswith("gitdir:"):
                target = head[len("gitdir:"):].strip()
                if not os.path.isabs(target):
                    target = os.path.join(root, target)
                gd = os.path.realpath(target)
                common = _read_small(os.path.join(gd, "commondir"), 4096)
                if common is not None and common.strip():
                    return os.path.join(os.path.realpath(os.path.join(gd, common.strip())), "config")
                return os.path.join(gd, "config")
    except OSError:
        return None
    return None


_CFG_CACHE: dict[tuple[str, tuple[Any, ...]], list[str]] = {}


def _config_signature(root: str, cfg: str | None) -> tuple[Any, ...] | None:
    """Stat signature of the config files git would read for ``root``; None when unknown."""
    if not cfg:
        return None
    sig: list[Any] = []
    for path in (cfg, cfg + ".worktree"):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            sig.append(None)
            continue
        except OSError:
            return None
        sig.append((st.st_mtime_ns, st.st_size, st.st_ino, st.st_mode))
    return tuple(sig)


def _config_keys(root: str) -> list[str]:
    """Every key git itself reads from the repository's config (parsed by git, not by a regex).

    ``git config --list --name-only -z --no-includes`` lists the keys of the repository config and,
    when ``extensions.worktreeConfig`` is on, of ``config.worktree``; the system and global files
    are ``/dev/null`` in the scrubbed environment. Includes are not followed (their keys show up
    as ``include.path`` and the repository is refused), so listing never reads outside the repo.
    """
    argv = ["git", "--no-optional-locks", *_HARDENED, "config", "--list", "--name-only", "-z", "--no-includes"]
    try:
        proc = subprocess.run(  # noqa: S603  (fixed argv, shell=False)
            argv, cwd=root, env=build_env(), capture_output=True, timeout=15, check=False, shell=False)
    except FileNotFoundError:
        raise GuardError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GuardError("git timed out") from None
    except OSError as exc:
        raise GuardError("git could not be started (%s)" % type(exc).__name__) from None
    if proc.returncode != 0:
        raise GuardError("git could not read the repository config; not read by Paddock Guard")
    return [k for k in proc.stdout.decode("utf-8", "replace").split("\x00") if k]


def _neutralise_repo_config(root: str) -> list[str]:
    """Extra ``-c`` arguments that blank filter, textconv and merge-driver commands.

    The repository's own config is read by git even with a scrubbed environment. Commands named
    there (``filter.X.clean``, ``diff.X.textconv``, ``merge.X.driver``) can run when ``status``,
    ``diff`` or ``archive`` handle files, so every driver name git reports is overridden on the
    command line. The key list comes from git (every spelling of a section header, the worktree
    config and sub-section quoting are git's business, not a regex's). A config that uses
    ``include`` or ``includeIf``, a driver name that cannot be written safely as a ``-c`` key, or a
    config that is a symlink, a FIFO or very large makes the repository refused.
    """
    cfg = _git_dir_config(root)
    if cfg:
        # symlink / FIFO / oversize repository files are refused before git is asked to read them
        _read_small(cfg)
        _read_small(cfg + ".worktree")
    sig = _config_signature(root, cfg)
    cache_key = (root, sig) if sig is not None else None
    if cache_key is not None and cache_key in _CFG_CACHE:
        return list(_CFG_CACHE[cache_key])
    args: list[str] = []
    seen: set[tuple[str, str]] = set()
    for key in _config_keys(root):
        parts = key.split(".")
        section = parts[0].lower()
        if section == "include" or section == "includeif":
            raise GuardError("git config uses include sections; not read by Paddock Guard")
        if section not in ("filter", "diff", "merge") or len(parts) < 3:
            continue
        name = ".".join(parts[1:-1])
        if (section, name) in seen:
            continue
        seen.add((section, name))
        if not _NAME_OK.match(name):
            # A name that cannot be written safely on the command line: refuse the repository.
            raise GuardError("git config has an unusual %s name; not read by Paddock Guard" % section)
        if section == "filter":
            for k in ("clean", "smudge", "process"):
                args += ["-c", "filter.%s.%s=" % (name, k)]
            args += ["-c", "filter.%s.required=false" % name]
        elif section == "diff":
            for k in ("textconv", "command", "external"):
                args += ["-c", "diff.%s.%s=" % (name, k)]
        else:
            args += ["-c", "merge.%s.driver=" % name]
    if cache_key is not None:
        if len(_CFG_CACHE) > 64:
            _CFG_CACHE.clear()
        _CFG_CACHE[cache_key] = list(args)
    return args


def validate_ref(ref: object) -> str:
    """Reject refs that could act as options or ranges (H2); return the ref unchanged."""
    if not isinstance(ref, str) or not ref:
        raise ConfigError("invalid ref: empty")
    if ref.startswith("-"):
        raise ConfigError("invalid ref: must not start with '-'")
    if len(ref) > 100:
        raise ConfigError("invalid ref: longer than 100 characters")
    if ".." in ref:
        raise ConfigError("invalid ref: ranges are not accepted")
    if _REF_BAD.search(ref):
        raise ConfigError("invalid ref: contains whitespace, control or special characters")
    return ref


def _argv(args: list[str], root: str) -> list[str]:
    return ["git", "--no-optional-locks", *_HARDENED, *_neutralise_repo_config(root), *args]


def run_git(root: str, args: list[str], *, timeout: float = 30, input: str | bytes | None = None,  # noqa: A002
            binary: bool = False) -> subprocess.CompletedProcess[Any]:
    """Run git in ``root`` with the hardened argv and environment; never raises on exit status.

    Raises ``GuardError`` when git is missing, times out or the repository config is refused.
    Output is text (UTF-8, errors replaced) unless ``binary`` is true.
    """
    root = os.fspath(root)
    argv = _argv(list(args), root)
    data = input.encode("utf-8") if isinstance(input, str) else input
    try:
        proc = subprocess.run(  # noqa: S603  (fixed argv, shell=False)
            argv, cwd=root, env=build_env(), input=data, capture_output=True, timeout=timeout,
            check=False, shell=False)
    except FileNotFoundError:
        raise GuardError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GuardError("git timed out") from None
    except OSError as exc:
        raise GuardError("git could not be started (%s)" % type(exc).__name__) from None
    if binary:
        return proc
    return subprocess.CompletedProcess(
        proc.args, proc.returncode,
        proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace"))


def resolve_ref(root: str, ref: str) -> str:
    """Validate ``ref`` and resolve it to a 40-hex commit id; only that id is used afterwards."""
    validate_ref(ref)
    r = run_git(root, ["rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}"])
    out = r.stdout.strip()
    if r.returncode != 0 or not _SHA40.match(out):
        raise ConfigError("ref does not resolve to a commit")
    return out


def toplevel(root: str) -> str | None:
    """Realpath of the work tree top level when ``root`` is inside one, else None."""
    try:
        r = run_git(root, ["rev-parse", "--show-toplevel"])
    except GuardError:
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return os.path.realpath(r.stdout.strip())


def is_toplevel(root: str) -> bool:
    """True only when the git work tree top level equals the scan root (3.9 item 5)."""
    top = toplevel(root)
    return top is not None and top == os.path.realpath(root)


class GitStream:
    """A running ``git`` whose stdout is read incrementally (for ``git archive``)."""

    def __init__(self, proc: subprocess.Popen[bytes]):
        self._proc = proc
        self.stdout = proc.stdout
        self.returncode: int | None = None

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                if self.stdout is not None:
                    self.stdout.close()
            except OSError:
                pass
            self._proc.kill()
        elif self.stdout is not None:
            try:
                self.stdout.close()
            except OSError:
                pass
        self.returncode = self._proc.wait()


@contextmanager
def archive_stream(root: str, sha: str, *, timeout: float = 120) -> Iterator[GitStream]:
    """``git archive --format=tar <sha>`` as a stream; ``sha`` must already be 40-hex."""
    if not _SHA40.match(sha or ""):
        raise ConfigError("archive needs a resolved 40-hex id")
    root = os.fspath(root)
    argv = _argv(["archive", "--format=tar", "--end-of-options", sha], root)
    try:
        proc = subprocess.Popen(  # noqa: S603
            argv, cwd=root, env=build_env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            shell=False)
    except FileNotFoundError:
        raise GuardError("git is not installed or not on PATH") from None
    except OSError as exc:
        raise GuardError("git could not be started (%s)" % type(exc).__name__) from None
    stream = GitStream(proc)
    try:
        yield stream
    finally:
        # Drain nothing: closing stdout makes git exit; a normal run has already ended.
        if proc.poll() is None:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        stream.close()
