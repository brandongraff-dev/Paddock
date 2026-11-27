# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hardened filesystem access (contract 3.9, 3.10, 3.11 H1, D31).

This is the only Guard module that reads the scanned tree and the only one allowed to create,
replace, rename or remove files. Guard treats the scanned tree as hostile:

* symlinks are never followed (directory file descriptors and ``O_NOFOLLOW`` per component),
* only regular files are read, size-capped, binary files skipped,
* every write goes through ``safe_write`` / ``safe_append`` which refuse symlinked parents,
  symlinked targets and hardlinked append targets,
* archives are extracted by a hand-written hardened extractor.
"""
from __future__ import annotations

import codecs
import errno
import hashlib
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from functools import cached_property
from typing import IO, Iterator

from paddock_cli.guard import gitutil
from paddock_cli.guard.errors import ConfigError, GuardError
from paddock_cli.guard.model import norm_relpath

# ---- limits (contract 3.9 items 3, 7, 9) ------------------------------------------------------
MAX_FILE = 1_000_000
MAX_BIG_FILE = 4_000_000
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 400 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_EXTRACT_BYTES = 400 * 1024 * 1024
MAX_ZIP_RATIO = 100
MIN_FREE_BYTES = 64 * 1024 * 1024
BINARY_PROBE = 4096
MAX_DEPTH = 64
LONG_LINE = 4000

SKIP_DIRS = frozenset(
    ".git .hg .svn node_modules vendor venv .venv env __pycache__ .tox .nox .mypy_cache "
    ".ruff_cache .pytest_cache site-packages .terraform coverage .cache .idea".split()
)
BUILD_DIRS = frozenset("dist build out .next .nuxt .output target".split())

# 4.0.4(b): root-relative paths of the scanned copy that count as non-production.
NON_PROD_PATH = re.compile(
    r"(?:^|/)(?:test|tests|__tests__|spec|specs|e2e|fixtures|__mocks__|mocks|cypress|playwright)/"
    r"|(?:^|/)[^/]*\.(?:test|spec)\.[^/]+$|(?:^|/)test_[^/]*\.py$|(?:^|/)[^/]*_test\.py$"
    r"|(?:^|/)[^/]*_test\.go$|(?:^|/)conftest\.py$"
)


def is_non_prod_path(rel: str) -> bool:
    return NON_PROD_PATH.search(rel) is not None


_HAS_DIRFD = (
    hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd and os.scandir in getattr(os, "supports_fd", set())
)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOCTTY = getattr(os, "O_NOCTTY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


# ---- glob matching ---------------------------------------------------------------------------
_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_regex(pattern: str) -> re.Pattern[str]:
    hit = _GLOB_CACHE.get(pattern)
    if hit is not None:
        return hit
    pat = pattern
    anywhere = "/" not in pat
    out: list[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pat[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pat.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    core = "".join(out)
    rx = re.compile(("(?:.*/)?" if anywhere else "") + core + r"\Z", re.S)
    if len(_GLOB_CACHE) < 2048:
        _GLOB_CACHE[pattern] = rx
    return rx


def match_glob(pattern: str, path: str) -> bool:
    """Match a root-relative posix ``path``; ``**`` crosses directories, ``*`` does not.

    A pattern without ``/`` matches the file name at any depth (gitignore style).
    """
    try:
        return _glob_regex(pattern).match(path) is not None
    except re.error:
        return False


def match_any(patterns, path: str) -> bool:
    return any(match_glob(p, path) for p in patterns)


# ---- views -----------------------------------------------------------------------------------
@dataclass
class FileView:
    """A file read safely: root-relative posix ``path``, decoded ``text`` and its ``size``."""

    path: str
    text: str
    size: int
    bom: bool = False

    @cached_property
    def lines(self) -> list[str]:
        return [ln[:-1] if ln.endswith("\r") else ln for ln in self.text.split("\n")]

    @property
    def ext(self) -> str:
        base = self.path.rsplit("/", 1)[-1]
        return base.rsplit(".", 1)[-1].lower() if "." in base else ""

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Listing:
    paths: list[str] = field(default_factory=list)
    via: str = "walk"
    notes: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    complete: bool = True


# ---- roots -----------------------------------------------------------------------------------
def real_root(root: str) -> str:
    """Realpath of the scan root; it must be an existing directory."""
    rp = os.path.realpath(os.fspath(root))
    if not os.path.isdir(rp):
        raise ConfigError("root is not a directory")
    return rp


def _inside(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def check_root_allowed(root_real: str) -> None:
    """Refuse a root that equals or contains HOME, ~/.ssh, ~/.aws or ``/``, or is not ours (H3)."""
    if root_real == os.sep:
        raise ConfigError("refusing to scan the filesystem root")
    home = os.path.realpath(os.path.expanduser("~"))
    for protected in (home, os.path.join(home, ".ssh"), os.path.join(home, ".aws")):
        if _inside(protected, root_real):
            raise ConfigError("refusing to scan a directory that equals or contains your home or credentials")
    try:
        owner = os.stat(root_real).st_uid
    except OSError:
        raise ConfigError("root is not readable") from None
    if hasattr(os, "geteuid") and owner != os.geteuid():
        raise ConfigError("refusing to scan a directory not owned by the current user")


# ---- reading ---------------------------------------------------------------------------------
class RootHandle:
    """An open directory descriptor for the scan root; reads never follow symlinks."""

    def __init__(self, root_real: str):
        self.root = root_real
        self.fd: int | None = None
        if _HAS_DIRFD:
            try:
                self.fd = os.open(root_real, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
            except OSError:
                self.fd = None

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __enter__(self) -> "RootHandle":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals ------------------------------------------------------------------------
    def _classify(self, dirfd: int, name: str) -> str:
        try:
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        if stat.S_ISLNK(st.st_mode):
            return "symlink"
        return "not-regular" if not stat.S_ISDIR(st.st_mode) else "unreadable"

    def open_file(self, rel: str) -> tuple[int | None, str | None, os.stat_result | None]:
        """Open ``rel`` read-only without following symlinks; returns (fd, reason, stat)."""
        safe = norm_relpath(rel)
        if safe is None:
            return None, "outside-root", None
        comps = safe.split("/")
        if self.fd is None:
            return self._open_path_based(safe)
        cur = self.fd
        opened: list[int] = []
        try:
            for comp in comps[:-1]:
                try:
                    nxt = os.open(comp, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=cur)
                except OSError:
                    return None, self._classify(cur, comp), None
                opened.append(nxt)
                cur = nxt
            name = comps[-1]
            try:
                st = os.stat(name, dir_fd=cur, follow_symlinks=False)
            except FileNotFoundError:
                return None, "missing", None
            except OSError:
                return None, "unreadable", None
            if stat.S_ISLNK(st.st_mode):
                return None, "symlink", None
            if not stat.S_ISREG(st.st_mode):
                return None, "not-regular", None
            try:
                ffd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_NOCTTY | _O_CLOEXEC, dir_fd=cur)
            except OSError as exc:
                return None, "symlink" if exc.errno == errno.ELOOP else "unreadable", None
            st2 = os.fstat(ffd)
            if not stat.S_ISREG(st2.st_mode) or (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
                os.close(ffd)
                return None, "changed", None
            return ffd, None, st2
        finally:
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _open_path_based(self, safe: str) -> tuple[int | None, str | None, os.stat_result | None]:
        """Fallback for platforms without dir_fd support (the race is accepted and documented)."""
        full = os.path.join(self.root, *safe.split("/"))
        cur = self.root
        for comp in safe.split("/"):
            cur = os.path.join(cur, comp)
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                return None, "missing", None
            except OSError:
                return None, "unreadable", None
            if stat.S_ISLNK(st.st_mode):
                return None, "symlink", None
        if not stat.S_ISREG(st.st_mode):
            return None, "not-regular", None
        if not _inside(os.path.realpath(full), self.root):
            return None, "outside-root", None
        try:
            fd = os.open(full, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_NOCTTY | _O_CLOEXEC)
        except OSError:
            return None, "unreadable", None
        return fd, None, os.fstat(fd)

    def read(self, rel: str, *, limit: int = MAX_FILE, binary_ok: bool = False
             ) -> tuple[FileView | None, str | None]:
        fd, why, st = self.open_file(rel)
        if fd is None:
            return None, why
        try:
            fst = os.fstat(fd)
            if fst.st_size > limit:
                return None, "oversize"
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                try:
                    chunk = os.read(fd, min(65536, limit + 1 - total))
                except BlockingIOError:
                    return None, "unreadable"
                except OSError:
                    return None, "unreadable"
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > limit:
                return None, "oversize"
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if not binary_ok and b"\x00" in data[:BINARY_PROBE]:
            return None, "binary"
        text = data.decode("utf-8", errors="replace")
        bom = text.startswith("﻿")
        if bom:
            text = text[1:]
        return FileView(path=norm_relpath(rel) or rel, text=text, size=total, bom=bom), None


def read_file(root_real: str, rel: str, *, limit: int | None = None, big_ok: bool = False,
              ) -> tuple[FileView | None, str | None]:
    """Read one file under the root; returns (view, None) or (None, skip reason)."""
    cap = limit if limit is not None else (MAX_BIG_FILE if big_ok else MAX_FILE)
    with RootHandle(root_real) as h:
        return h.read(rel, limit=cap)


def read_abs_text(path: str, *, limit: int = 100 * 1024) -> tuple[str | None, str | None]:
    """Read one file by absolute path (user-level config): never a symlink, regular, size-capped."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    if stat.S_ISLNK(st.st_mode):
        return None, "symlink"
    if not stat.S_ISREG(st.st_mode):
        return None, "not-regular"
    if st.st_size > limit:
        return None, "oversize"
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_NOCTTY | _O_CLOEXEC)
    except OSError:
        return None, "unreadable"
    try:
        data = os.read(fd, limit + 1)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)
    if len(data) > limit:
        return None, "oversize"
    return data.decode("utf-8", errors="replace"), None


def read_bytes_prefix(root_real: str, rel: str, n: int) -> bytes | None:
    """First ``n`` bytes of a regular file (for sniffing); None when it cannot be read safely."""
    with RootHandle(root_real) as h:
        fd, why, _ = h.open_file(rel)
        if fd is None:
            return None
        try:
            return os.read(fd, n)
        except OSError:
            return None
        finally:
            os.close(fd)


def stream_windows(root_real: str, rel: str, *, window: int = 4000, overlap: int = 300,
                   max_total: int = MAX_BUNDLE_BYTES) -> Iterator[tuple[int, str]]:
    """Yield ``(char_offset, text)`` windows of a big file without reading it whole (3.9 item 3).

    Windows are ``window`` characters long and overlap by ``overlap`` characters, so a token
    cut by one window is whole in the next. At most ``max_total`` bytes are read.
    """
    if overlap >= window or overlap < 0:
        raise ValueError("overlap must be smaller than the window")
    with RootHandle(root_real) as h:
        fd, why, _ = h.open_file(rel)
        if fd is None:
            return
        try:
            dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
            buf = ""
            base = 0
            read_total = 0
            while read_total < max_total:
                chunk = os.read(fd, min(65536, max_total - read_total))
                if not chunk:
                    buf += dec.decode(b"", final=True)
                    break
                read_total += len(chunk)
                buf += dec.decode(chunk)
                while len(buf) >= window + overlap:
                    yield base, buf[:window]
                    step = window - overlap
                    buf = buf[step:]
                    base += step
            if buf:
                yield base, buf
        finally:
            os.close(fd)


# ---- listing ---------------------------------------------------------------------------------
def _clean_entry(entry: str) -> str | None:
    if not entry or "\x00" in entry or "\\" in entry or entry.startswith("/"):
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in entry):
        return None
    safe = norm_relpath(entry)
    if safe is None:
        return None
    return safe


def _dir_skipped(parts: list[str], include_build: bool) -> bool:
    for i, p in enumerate(parts):
        if p in SKIP_DIRS:
            return True
        if not include_build:
            if p in BUILD_DIRS:
                return True
            if p == ".vercel" and i + 1 < len(parts) and parts[i + 1] == "output":
                return True
    return False


def _walk(root_real: str, include_build: bool, limit: int, ignored_dirs: frozenset[str] = frozenset(),
          ignored_files: frozenset[str] = frozenset()) -> tuple[list[str], list[dict[str, str]], bool]:
    """Walk the tree without following symlinks. Returns (paths, skipped, hit_limit)."""
    paths: list[str] = []
    skipped: list[dict[str, str]] = []
    hit = False
    if not _HAS_DIRFD:
        return _walk_fallback(root_real, include_build, limit, ignored_dirs, ignored_files)
    try:
        root_fd = os.open(root_real, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError:
        return paths, [{"file": ".", "reason": "unreadable"}], False

    def visit(fd: int, prefix: str, depth: int) -> None:
        nonlocal hit
        if hit:
            return
        try:
            with os.scandir(fd) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            skipped.append({"file": prefix.rstrip("/") or ".", "reason": "unreadable"})
            return
        for e in entries:
            if hit:
                return
            rel = prefix + e.name
            try:
                is_link = e.is_symlink()
                is_dir = e.is_dir(follow_symlinks=False)
                is_file = e.is_file(follow_symlinks=False)
            except OSError:
                skipped.append({"file": rel, "reason": "unreadable"})
                continue
            if is_link:
                if not _dir_skipped(rel.split("/"), include_build):
                    skipped.append({"file": rel, "reason": "symlink"})
                continue
            if is_dir:
                parts = rel.split("/")
                if _dir_skipped(parts, include_build) or (rel + "/") in ignored_dirs:
                    continue
                if depth >= MAX_DEPTH:
                    skipped.append({"file": rel, "reason": "too-deep"})
                    continue
                try:
                    cfd = os.open(e.name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=fd)
                except OSError:
                    skipped.append({"file": rel, "reason": "unreadable"})
                    continue
                try:
                    visit(cfd, rel + "/", depth + 1)
                finally:
                    os.close(cfd)
                continue
            if is_file:
                if rel in ignored_files:
                    continue
                if len(paths) >= limit:
                    hit = True
                    return
                paths.append(rel)
            else:
                skipped.append({"file": rel, "reason": "not-regular"})

    try:
        visit(root_fd, "", 0)
    finally:
        os.close(root_fd)
    return paths, skipped, hit


def _walk_fallback(root_real, include_build, limit, ignored_dirs, ignored_files):  # pragma: no cover
    paths, skipped, hit = [], [], False
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root_real).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            rel = (rel_dir + "/" + d) if rel_dir else d
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                skipped.append({"file": rel, "reason": "symlink"})
            elif not _dir_skipped(rel.split("/"), include_build) and (rel + "/") not in ignored_dirs:
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            rel = (rel_dir + "/" + f) if rel_dir else f
            full = os.path.join(dirpath, f)
            if os.path.islink(full):
                skipped.append({"file": rel, "reason": "symlink"})
            elif rel in ignored_files:
                continue
            elif len(paths) >= limit:
                return paths, skipped, True
            else:
                paths.append(rel)
    return paths, skipped, hit


def _split_z(out: str) -> list[str]:
    return [p for p in out.split("\0") if p != ""]


def git_tracked_set(root: str) -> set[str] | None:
    """Tracked paths when the git top level equals the root, else None (3.9 item 6)."""
    root_real = os.path.realpath(root)
    try:
        if not gitutil.is_toplevel(root_real):
            return None
        r = gitutil.run_git(root_real, ["ls-files", "-z", "--cached"])
    except GuardError:
        return None
    if r.returncode != 0:
        return None
    return {c for c in (_clean_entry(p) for p in _split_z(r.stdout)) if c}


def git_ignored_check(root: str, rel: str) -> bool | None:
    """True when git ignores ``rel``; None outside the git conditions of 3.9 item 5."""
    root_real = os.path.realpath(root)
    try:
        if not gitutil.is_toplevel(root_real):
            return None
        r = gitutil.run_git(root_real, ["check-ignore", "-q", "--end-of-options", rel])
    except GuardError:
        return None
    if r.returncode == 0:
        return True
    if r.returncode == 1:
        return False
    return None


def _git_listing(root_real: str, staged: bool) -> tuple[list[str], bool]:
    args = ["ls-files", "-z", "--cached"] if staged else ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    r = gitutil.run_git(root_real, args, timeout=30)
    if r.returncode != 0:
        raise GuardError("git ls-files failed")
    out: list[str] = []
    seen: set[str] = set()
    for entry in _split_z(r.stdout):
        c = _clean_entry(entry)
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out, True


def _git_ignored(root_real: str) -> tuple[frozenset[str], frozenset[str]]:
    try:
        r = gitutil.run_git(root_real, ["ls-files", "-z", "--others", "--ignored", "--exclude-standard",
                                        "--directory"], timeout=30)
    except GuardError:
        return frozenset(), frozenset()
    dirs: set[str] = set()
    fls: set[str] = set()
    if r.returncode == 0:
        for p in _split_z(r.stdout):
            (dirs if p.endswith("/") else fls).add(p)
    return frozenset(dirs), frozenset(fls)


def list_files(root: str, *, include_build: bool = False, use_git: bool = True, staged: bool = False
               ) -> Listing:
    """List scannable files (3.9 item 5 and 7). Never raises; incompleteness is reported."""
    root_real = os.path.realpath(os.fspath(root))
    lst = Listing()
    git_paths: list[str] | None = None
    if use_git:
        try:
            if gitutil.is_toplevel(root_real):
                git_paths, _ = _git_listing(root_real, staged)
        except GuardError:
            git_paths = None
    if git_paths is not None:
        lst.via = "git-index" if staged else "git"
        kept: list[str] = []
        for p in git_paths:
            if _dir_skipped(p.split("/")[:-1], include_build):
                continue
            kept.append(p)
        if len(kept) > MAX_FILES:
            kept = kept[:MAX_FILES]
            lst.notes.append("file limit reached")
            lst.complete = False
        lst.paths = sorted(kept)
        if not staged:
            ig_dirs, ig_files = _git_ignored(root_real)
            disk, _skipped, hit = _walk(root_real, include_build, MAX_FILES + 1, ig_dirs, ig_files)
            if disk:
                covered = len(set(lst.paths) & set(disk))
                if covered < 0.9 * len(disk):
                    lst.notes.append("listing-incomplete")
                    lst.complete = False
        return lst
    lst.notes.append("git-unavailable")
    paths, skipped, hit = _walk(root_real, include_build, MAX_FILES)
    lst.paths = sorted(paths)
    lst.skipped.extend(skipped)
    if hit:
        lst.notes.append("file limit reached")
        lst.complete = False
    return lst


# ---- writing ---------------------------------------------------------------------------------
def _rel_for_write(relpath: str) -> list[str]:
    safe = norm_relpath(relpath) if isinstance(relpath, str) else None
    if safe is None:
        raise GuardError("refusing unsafe path")
    return safe.split("/")


def _open_dir_chain(base_real: str, comps: list[str], *, create: bool) -> tuple[int, list[int]]:
    """Open ``base_real`` then each component with O_NOFOLLOW; return (last fd, fds to close)."""
    if not _HAS_DIRFD:
        return _open_dir_chain_fallback(base_real, comps, create)
    try:
        cur = os.open(base_real, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError:
        raise GuardError("base directory is not accessible") from None
    fds = [cur]
    try:
        for comp in comps:
            try:
                st = os.stat(comp, dir_fd=cur, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise GuardError("path does not exist") from None
                try:
                    os.mkdir(comp, 0o700, dir_fd=cur)
                except FileExistsError:
                    pass
                except OSError:
                    raise GuardError("cannot create directory") from None
                st = os.stat(comp, dir_fd=cur, follow_symlinks=False)
            except OSError:
                raise GuardError("path is not accessible") from None
            if stat.S_ISLNK(st.st_mode):
                raise GuardError("refusing to write through a symlink: %s" % comp)
            if not stat.S_ISDIR(st.st_mode):
                raise GuardError("path component is not a directory: %s" % comp)
            try:
                nxt = os.open(comp, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=cur)
            except OSError:
                raise GuardError("refusing to write through a symlink: %s" % comp) from None
            fds.append(nxt)
            cur = nxt
        return cur, fds
    except BaseException:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _open_dir_chain_fallback(base_real, comps, create):  # pragma: no cover
    cur = base_real
    for comp in comps:
        cur = os.path.join(cur, comp)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            if not create:
                raise GuardError("path does not exist") from None
            os.mkdir(cur, 0o700)
            st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise GuardError("refusing to write through a symlink: %s" % comp)
    raise GuardError("directory file descriptors are required for writing on this platform")


def _close_all(fds: list[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _as_bytes(data: str | bytes) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else bytes(data)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def safe_write(root: str, relpath: str, data: str | bytes, *, mode: int = 0o600,
               exclusive: bool = False) -> str:
    """Create or atomically replace ``root/relpath`` (3.11 H1); returns the real path written.

    Every directory component is lstat-ed and a symlink anywhere refuses the write. New
    directories are 0700. A rewrite goes through a temp file, ``fsync`` and ``os.replace``.
    """
    comps = _rel_for_write(relpath)
    base_real = os.path.realpath(os.fspath(root))
    payload = _as_bytes(data)
    dfd, fds = _open_dir_chain(base_real, comps[:-1], create=True)
    name = comps[-1]
    tmp = None
    try:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        except OSError:
            raise GuardError("target is not accessible") from None
        if st is not None:
            if stat.S_ISLNK(st.st_mode):
                raise GuardError("refusing to write through a symlink: %s" % name)
            if not stat.S_ISREG(st.st_mode):
                raise GuardError("target is not a regular file: %s" % name)
        if exclusive:
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, mode, dir_fd=dfd)
            except FileExistsError:
                raise GuardError("file already exists: %s" % name) from None
            except OSError:
                raise GuardError("cannot create file: %s" % name) from None
            try:
                _write_all(fd, payload)
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            tmp = ".%s.pgtmp.%d.%s" % (name, os.getpid(), os.urandom(4).hex())
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600, dir_fd=dfd)
            except OSError:
                tmp = None
                raise GuardError("cannot create temporary file") from None
            try:
                _write_all(fd, payload)
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except OSError:
                raise GuardError("cannot replace file: %s" % name) from None
            tmp = None
            try:
                os.fsync(dfd)
            except OSError:
                pass
    except GuardError:
        raise
    except OSError:
        raise GuardError("write failed: %s" % name) from None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        _close_all(fds)
    return os.path.join(base_real, *comps)


def safe_append(root: str, relpath: str, data: str | bytes, *, mode: int = 0o600) -> str:
    """Append to ``root/relpath``; refuses symlinks and hardlinked targets (3.11 H1)."""
    comps = _rel_for_write(relpath)
    base_real = os.path.realpath(os.fspath(root))
    payload = _as_bytes(data)
    dfd, fds = _open_dir_chain(base_real, comps[:-1], create=True)
    name = comps[-1]
    try:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
                         mode, dir_fd=dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise GuardError("refusing to write through a symlink: %s" % name) from None
            raise GuardError("cannot open file for append: %s" % name) from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise GuardError("target is not a regular file: %s" % name)
            if st.st_nlink > 1:
                raise GuardError("refusing to append to a hardlinked file: %s" % name)
            os.fchmod(fd, mode)
            _write_all(fd, payload)
        except GuardError:
            raise
        except OSError:
            raise GuardError("append failed: %s" % name) from None
        finally:
            os.close(fd)
    finally:
        _close_all(fds)
    return os.path.join(base_real, *comps)


def safe_rename(root: str, src_rel: str, dst_rel: str) -> None:
    """Rename inside ``root`` (ledger rotation); refuses symlinks on either side."""
    sc, dc = _rel_for_write(src_rel), _rel_for_write(dst_rel)
    if sc[:-1] != dc[:-1]:
        raise GuardError("rename must stay in one directory")
    base_real = os.path.realpath(os.fspath(root))
    dfd, fds = _open_dir_chain(base_real, sc[:-1], create=False)
    try:
        for n in (sc[-1], dc[-1]):
            try:
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise GuardError("refusing to rename a symlink: %s" % n)
        try:
            os.replace(sc[-1], dc[-1], src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError:
            raise GuardError("rename failed") from None
    finally:
        _close_all(fds)


def safe_remove(root: str, relpath: str) -> bool:
    """Remove a regular file inside ``root``; a missing file is fine; a symlink is refused."""
    comps = _rel_for_write(relpath)
    base_real = os.path.realpath(os.fspath(root))
    try:
        dfd, fds = _open_dir_chain(base_real, comps[:-1], create=False)
    except GuardError as exc:
        if "does not exist" in str(exc):
            return False
        raise
    try:
        try:
            st = os.stat(comps[-1], dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode):
            raise GuardError("refusing to remove a symlink: %s" % comps[-1])
        if not stat.S_ISREG(st.st_mode):
            raise GuardError("target is not a regular file: %s" % comps[-1])
        try:
            os.unlink(comps[-1], dir_fd=dfd)
        except OSError:
            raise GuardError("remove failed") from None
        return True
    finally:
        _close_all(fds)


def write_output_file(path: str, data: str | bytes, *, mode: int = 0o600) -> str:
    """Write a user-named output file (``-o FILE``); never through a symlink."""
    p = os.path.abspath(os.fspath(path))
    parent, name = os.path.split(p)
    if not name:
        raise GuardError("output path has no file name")
    os.makedirs(parent, mode=0o755, exist_ok=True)
    return safe_write(parent, name, data, mode=mode)


def private_tempdir(prefix: str = "paddock-guard-", parent: str | None = None) -> str:
    """A new 0700 directory (system temporary directory unless ``parent`` is given)."""
    d = tempfile.mkdtemp(prefix=prefix, dir=parent)
    os.chmod(d, 0o700)
    return d


def remove_tree(path: str) -> None:
    """Remove a directory tree created by Guard (symlinks inside are unlinked, not followed)."""
    try:
        if os.path.islink(path):
            return
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def ensure_private_dir(path: str) -> str:
    """Create ``path`` (and missing parents) with mode 0700 if absent; return its realpath."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    return os.path.realpath(path)


# ---- state directory (3.10) -------------------------------------------------------------------
def state_dir(root: str, *, no_state: bool = False, env: dict[str, str] | None = None,
              create: bool = True) -> str | None:
    """``<cache>/guard/projects/<sha256(realpath root)[:32]>``, outside the repository, 0700.

    None when state is disabled (``--no-cache`` or ``PADDOCK_GUARD_NO_STATE=1``), when the
    cache location resolves inside the scanned tree, or when a component is a symlink.
    """
    e = os.environ if env is None else env
    if no_state or e.get("PADDOCK_GUARD_NO_STATE") == "1":
        return None
    root_real = os.path.realpath(os.fspath(root))
    base = e.get("PADDOCK_CACHE_DIR")
    if not base:
        xdg = e.get("XDG_CACHE_HOME")
        base = os.path.join(xdg, "paddock") if xdg else os.path.join(os.path.expanduser("~"), ".cache", "paddock")
    base_real = os.path.realpath(base)
    if _inside(base_real, root_real):
        return None
    h = hashlib.sha256(root_real.encode("utf-8", "replace")).hexdigest()[:32]
    target = os.path.join(base_real, "guard", "projects", h)
    if not create:
        return target
    try:
        ensure_private_dir(base_real)
        fd, fds = _open_dir_chain(base_real, ["guard", "projects", h], create=True)
        try:
            os.fchmod(fd, 0o700)
        finally:
            _close_all(fds)
    except (GuardError, OSError):
        return None
    return target


# ---- archive extraction (3.9 item 9) -----------------------------------------------------------
_NAME_BAD = re.compile(r"[\x00-\x1f\x7f\\]")


def _member_name(raw: str) -> str:
    name = raw
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name or _NAME_BAD.search(name) or name.startswith("/") or len(name) > 4096:
        raise GuardError("archive member has an unsafe name")
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise GuardError("archive member has an unsafe name")
    return name


def _fold(name: str) -> str:
    import unicodedata

    return unicodedata.normalize("NFC", name).casefold()


def _check_free(dest_parent: str, needed: int) -> None:
    try:
        free = shutil.disk_usage(dest_parent).free
    except OSError:
        raise GuardError("cannot determine free disk space") from None
    if free < needed:
        raise GuardError("not enough free disk space to extract the archive")


def _prepare_dest(dest: str) -> str:
    os.makedirs(dest, mode=0o700, exist_ok=True)
    os.chmod(dest, 0o700)
    dest_real = os.path.realpath(dest)
    if os.listdir(dest_real):
        raise GuardError("extraction directory is not empty")
    return dest_real


def _write_member(dest_real: str, name: str, source: IO[bytes], is_exec: bool, budget: list[int],
                  declared: int | None) -> None:
    parent = name.rsplit("/", 1)[0].split("/") if "/" in name else []
    dfd, fds = _open_dir_chain(dest_real, parent, create=True)
    try:
        try:
            fd = os.open(name.rsplit("/", 1)[-1],
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                         0o700 if is_exec else 0o600, dir_fd=dfd)
        except OSError:
            raise GuardError("cannot create extracted file") from None
        try:
            written = 0
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                budget[0] -= len(chunk)
                if budget[0] < 0:
                    raise GuardError("archive is larger than the extraction limit")
                if declared is not None and written > declared:
                    raise GuardError("archive member is larger than its header says")
                _write_all(fd, chunk)
            os.fchmod(fd, 0o700 if is_exec else 0o600)
        finally:
            os.close(fd)
    finally:
        _close_all(fds)


class _StrictTarInfo(tarfile.TarInfo):
    """TarInfo that records a malformed header: stock tarfile treats one as end of archive."""

    @classmethod
    def fromtarfile(cls, tf):  # type: ignore[no-untyped-def]
        try:
            return super().fromtarfile(tf)
        except tarfile.EOFHeaderError:
            raise
        except tarfile.HeaderError:
            tf._pg_bad_header = True  # type: ignore[attr-defined]
            raise


def extract_tar_stream(fileobj: IO[bytes], dest: str, *, max_members: int = MAX_MEMBERS,
                       max_bytes: int = MAX_EXTRACT_BYTES) -> int:
    """Extract a tar stream with the hardened rules of 3.9 item 9; returns the file count.

    Rejects absolute names, ``..``, NUL or backslash in names, symlinks, hardlinks, devices,
    FIFOs, duplicate and case-colliding names; strips setuid, setgid and sticky bits and sets
    modes to 0600 or 0700; counts bytes actually written while streaming (header sizes are not
    trusted); refuses a malformed header instead of treating it as the end of the archive.
    """
    parent = os.path.dirname(os.path.abspath(dest)) or "."
    os.makedirs(parent, exist_ok=True)
    _check_free(parent, MIN_FREE_BYTES)
    dest_real = _prepare_dest(dest)
    budget = [max_bytes]
    seen: set[str] = set()
    files_written = 0
    count = 0
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r|", tarinfo=_StrictTarInfo)
    except (tarfile.TarError, EOFError, OSError, ValueError):
        raise GuardError("archive is not a readable tar stream") from None
    try:
        for member in tf:
            count += 1
            if count > max_members:
                raise GuardError("archive has too many members")
            name = _member_name(member.name)
            key = _fold(name)
            if key in seen:
                raise GuardError("archive has duplicate or case-colliding names")
            seen.add(key)
            if member.isdir():
                dfd, fds = _open_dir_chain(dest_real, name.split("/"), create=True)
                _close_all(fds)
                continue
            if not member.isreg():
                raise GuardError("archive member is not a regular file or directory")
            src = tf.extractfile(member)
            if src is None:
                raise GuardError("archive member cannot be read")
            _write_member(dest_real, name, src, bool(member.mode & 0o111), budget, member.size)
            files_written += 1
        if getattr(tf, "_pg_bad_header", False):
            raise GuardError("archive has a malformed header")
    except GuardError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError, UnicodeError, OverflowError):
        raise GuardError("archive could not be extracted") from None
    finally:
        try:
            tf.close()
        except Exception:  # noqa: BLE001  (closing a half-read stream must not mask the error)
            pass
    return files_written


def extract_zip(fileobj: IO[bytes], dest: str, *, max_members: int = MAX_MEMBERS,
                max_bytes: int = MAX_EXTRACT_BYTES, max_ratio: int = MAX_ZIP_RATIO) -> int:
    """Extract a zip with the same rules as ``extract_tar_stream`` plus a compression-ratio cap."""
    try:
        zf = zipfile.ZipFile(fileobj)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        raise GuardError("archive is not a readable zip file") from None
    parent = os.path.dirname(os.path.abspath(dest)) or "."
    os.makedirs(parent, exist_ok=True)
    infos = zf.infolist()
    if len(infos) > max_members:
        raise GuardError("archive has too many members")
    declared = sum(i.file_size for i in infos)
    if declared > max_bytes:
        raise GuardError("archive is larger than the extraction limit")
    _check_free(parent, declared + MIN_FREE_BYTES if declared else MIN_FREE_BYTES)
    dest_real = _prepare_dest(dest)
    budget = [max_bytes]
    seen: set[str] = set()
    n = 0
    try:
        for info in infos:
            name = _member_name(info.filename)
            key = _fold(name)
            if key in seen:
                raise GuardError("archive has duplicate or case-colliding names")
            seen.add(key)
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise GuardError("archive member is a symlink")
            if unix_mode and unix_mode not in (stat.S_IFREG, stat.S_IFDIR):
                raise GuardError("archive member is not a regular file or directory")
            if info.is_dir():
                dfd, fds = _open_dir_chain(dest_real, name.split("/"), create=True)
                _close_all(fds)
                continue
            if info.file_size and info.compress_size and info.file_size / info.compress_size > max_ratio:
                raise GuardError("archive compression ratio is suspicious")
            with zf.open(info) as src:
                _write_member(dest_real, name, src, bool((info.external_attr >> 16) & 0o111), budget,
                              info.file_size)
            n += 1
    except GuardError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError, NotImplementedError,
            OverflowError):
        raise GuardError("archive could not be extracted") from None
    finally:
        zf.close()
    return n
