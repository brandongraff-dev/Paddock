# SPDX-License-Identifier: AGPL-3.0-or-later
"""ScanContext, ProjectInfo and BaseTree (contract 3.3, 3.9).

``ScanContext`` is what a check sees: it lists and reads files through ``files.py`` only,
records every skip, note and limit, and reads the git index instead of the working tree in
``--staged`` mode. ``BaseTree`` is the base ref extracted by ``git archive`` and the hardened
extractor, used for delta mode.
"""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterator

from paddock_cli.guard import files, gitutil, textsafe
from paddock_cli.guard.config import Config
from paddock_cli.guard.errors import ConfigError, GuardError
from paddock_cli.guard.files import FileView
from paddock_cli.guard.model import norm_relpath

MAX_TOTAL_BYTES = files.MAX_TOTAL_BYTES
MAX_BUNDLE_BYTES = files.MAX_BUNDLE_BYTES
_CACHE_CHARS = 32 * 1024 * 1024
_SERVER_FRAMEWORKS = frozenset({"next", "express", "fastify", "hono", "koa", "nuxt", "@sveltejs/kit", "remix"})
_SPA_TOOLS = frozenset({"vite", "react-scripts", "parcel"})
_JS_FRAMEWORKS = frozenset({"next", "vite", "react-scripts", "parcel", "express", "fastify", "hono", "koa",
                            "nuxt", "@sveltejs/kit", "remix", "react", "vue", "svelte", "@angular/core"})
_PY_FRAMEWORKS = ("flask", "django", "fastapi", "starlette")
_PY_DEP = re.compile(r"^\s*[\"']?(flask|django|fastapi|starlette)\b", re.I | re.M)


@dataclass(frozen=True)
class ProjectInfo:
    """Framework facts read from the root manifests (used by PG-SEC-008 and friends)."""

    has_package_json: bool = False
    deps: frozenset[str] = frozenset()
    dev_deps: frozenset[str] = frozenset()
    frameworks: tuple[str, ...] = ()
    spa: bool = False
    python: bool = False


def _dep_names(obj: object) -> frozenset[str]:
    if isinstance(obj, dict):
        return frozenset(k for k in obj if isinstance(k, str))
    return frozenset()


def _detect_project(ctx: "ScanContext") -> ProjectInfo:
    deps: frozenset[str] = frozenset()
    dev: frozenset[str] = frozenset()
    has_pkg = False
    view = ctx.read("package.json")
    if view is not None:
        try:
            doc = textsafe.loads_bounded(view.text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            has_pkg = True
            deps = _dep_names(doc.get("dependencies")) | _dep_names(doc.get("peerDependencies"))
            dev = _dep_names(doc.get("devDependencies"))
    allnames = deps | dev
    fw: list[str] = [n for n in sorted(allnames) if n in _JS_FRAMEWORKS or n.startswith("@remix-run/")]
    server = bool(allnames & _SERVER_FRAMEWORKS) or any(n.startswith("@remix-run/") for n in allnames)
    spa = bool(allnames & _SPA_TOOLS) and not server
    python = False
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"):
        pv = ctx.read(name)
        if pv is None:
            continue
        python = True
        for m in _PY_DEP.finditer(pv.text):
            if m.group(1).lower() not in fw:
                fw.append(m.group(1).lower())
    return ProjectInfo(has_pkg, deps, dev, tuple(fw), spa, python)


class BaseTree:
    """The base ref extracted into a private temporary directory (delta mode)."""

    def __init__(self, sha: str, path: str, tmp: str, partial_missing: list[str]):
        self.sha = sha
        self.path = path
        self._tmp = tmp
        self.partial_missing = partial_missing

    def close(self) -> None:
        if self._tmp:
            files.remove_tree(self._tmp)
            self._tmp = ""

    @classmethod
    def extract(cls, root_real: str, sha: str, state_dir: str | None) -> "BaseTree":
        expected = _expected_blobs(root_real, sha)
        tmp = files.private_tempdir("paddock-guard-base-", parent=state_dir)
        dest = os.path.join(tmp, "tree")
        collected: list[str] = []
        try:
            with gitutil.archive_stream(root_real, sha) as stream:
                files.extract_tar_stream(stream.stdout, dest, collect=collected)
            if stream.returncode not in (0, None):
                raise GuardError("git archive failed for the base ref")
        except BaseException:
            files.remove_tree(tmp)
            raise
        got = set(collected)
        return cls(sha, dest, tmp, sorted(p for p in expected if p not in got))


def _expected_blobs(root_real: str, sha: str) -> set[str]:
    r = gitutil.run_git(root_real, ["ls-tree", "-r", "-z", "--full-tree", "--end-of-options", sha], timeout=60)
    if r.returncode != 0:
        raise GuardError("cannot list the base ref")
    out: set[str] = set()
    for entry in r.stdout.split("\0"):
        if not entry or "\t" not in entry:
            continue
        meta, path = entry.split("\t", 1)
        mode = meta.split(" ", 1)[0]
        if mode in ("100644", "100755"):
            c = norm_relpath(path)
            if c:
                out.add(c)
    return out


class ScanContext:
    """Everything a check may touch: files, git facts, project info, and the run's bookkeeping."""

    def __init__(self, root_real: str, cfg: Config, *, base_sha: str | None, staged: bool, offline: bool,
                 no_state: bool):
        self.root = root_real
        self.cfg = cfg
        self.base = base_sha
        self.staged = staged
        self.offline = offline or cfg.offline
        self._no_state = no_state
        self.notes: list[str] = []
        self.skipped: list[dict[str, str]] = []
        self.errors: list[dict[str, str]] = []
        self.incomplete_reasons: list[str] = []
        self._skip_seen: set[tuple[str, str]] = set()
        self._cache: "OrderedDict[tuple[str, bool], FileView | None]" = OrderedDict()
        self._cache_chars = 0
        self._bytes_read = 0
        self._bundle_bytes = 0
        self._limit_hit = False
        self._listing: dict[bool, files.Listing] = {}
        self._tracked: set[str] | None | bool = False  # False = not loaded
        self._ignored: dict[str, bool | None] = {}
        self._index: dict[str, tuple[str, str]] | None = None
        self._project: ProjectInfo | None = None
        self._base_tree: BaseTree | None = None
        self._state: str | None | bool = False
        self._handle = files.RootHandle(root_real)

    # ---- construction ---------------------------------------------------------------------
    @classmethod
    def open(cls, root: str, cfg: Config, *, base: str | None = None, staged: bool = False,
             offline: bool = False, no_state: bool = False) -> "ScanContext":
        root_real = files.real_root(root)
        files.check_root_allowed(root_real)
        sha = gitutil.resolve_ref(root_real, base) if base is not None else None
        if staged and not gitutil.is_toplevel(root_real):
            raise ConfigError("--staged needs the root of a git work tree")
        return cls(root_real, cfg, base_sha=sha, staged=staged, offline=offline, no_state=no_state)

    def __enter__(self) -> "ScanContext":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._handle.close()
        if self._base_tree is not None:
            self._base_tree.close()
            self._base_tree = None

    # ---- bookkeeping -------------------------------------------------------------------------
    @property
    def complete(self) -> bool:
        return not self.incomplete_reasons

    def add_note(self, note: str, *, incomplete: bool = False) -> None:
        if note not in self.notes:
            self.notes.append(note)
        if incomplete and note not in self.incomplete_reasons:
            self.incomplete_reasons.append(note)

    def skip(self, file: str, reason: str, *, incomplete: bool = False) -> None:
        key = (file, reason)
        if key not in self._skip_seen:
            self._skip_seen.add(key)
            self.skipped.append({"file": file, "reason": reason})
        if incomplete and reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def error(self, check: str, file: str, error: str) -> None:
        self.errors.append({"check": check, "file": file, "error": error})
        if error not in self.incomplete_reasons:
            self.incomplete_reasons.append(error)

    @property
    def state_dir(self) -> str | None:
        if self._state is False:
            self._state = files.state_dir(self.root, no_state=self._no_state)
        return self._state  # type: ignore[return-value]

    @property
    def base_tree(self) -> BaseTree | None:
        if self.base is None:
            return None
        if self._base_tree is None:
            self._base_tree = BaseTree.extract(self.root, self.base, self.state_dir)
        return self._base_tree

    @property
    def project(self) -> ProjectInfo:
        if self._project is None:
            self._project = _detect_project(self)
        return self._project

    # ---- listing -----------------------------------------------------------------------------
    def list_paths(self, include_build: bool = False) -> list[str]:
        lst = self._listing.get(include_build)
        if lst is None:
            lst = files.list_files(self.root, include_build=include_build, staged=self.staged)
            for n in lst.notes:
                self.add_note(n, incomplete=n in ("file limit reached", "listing-incomplete"))
            for s in lst.skipped:
                self.skip(s["file"], s["reason"])
            self._listing[include_build] = lst
        ex = self.cfg.exclude
        return [p for p in lst.paths if not (ex and files.match_any(ex, p))]

    def exists(self, rel: str) -> bool:
        if self.staged:
            return rel in self._index_entries()
        safe = norm_relpath(rel)
        if safe is None:
            return False
        fd, _why, _st = self._handle.open_file(safe)
        if fd is None:
            return False
        os.close(fd)
        return True

    # ---- reading -----------------------------------------------------------------------------
    def read(self, rel: str, *, big_ok: bool = False) -> FileView | None:
        """Read one file (cached). Skips are recorded; the total read volume is capped."""
        safe = norm_relpath(rel) if isinstance(rel, str) else None
        if safe is None:
            return None
        key = (safe, big_ok)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        if self._bytes_read > MAX_TOTAL_BYTES:
            if not self._limit_hit:
                self._limit_hit = True
                self.add_note("file limit reached", incomplete=True)
            return None
        view: FileView | None
        why: str | None
        if self.staged:
            view, why = self._read_index(safe, big_ok)
        else:
            view, why = files.read_file(self.root, safe, big_ok=big_ok)
        if view is None and why not in (None, "missing"):
            self.skip(safe, why or "unreadable")
        if view is not None:
            self._bytes_read += view.size
            self._cache_chars += len(view.text)
        self._cache[key] = view
        while self._cache_chars > _CACHE_CHARS and len(self._cache) > 1:
            _k, old = self._cache.popitem(last=False)
            if old is not None:
                self._cache_chars -= len(old.text)
        return view

    def files(self, *globs: str, include_build: bool = False, big_ok: bool = False,
              changed: list[str] | None = None) -> Iterator[FileView]:
        """Yield matching files in path order. With ``changed``, only those paths."""
        only = set(changed) if changed is not None else None
        for p in self.list_paths(include_build=include_build):
            if only is not None and p not in only:
                continue
            if globs and not files.match_any(globs, p):
                continue
            if not include_build and _is_build_path(p):
                continue
            v = self.read(p, big_ok=big_ok)
            if v is not None:
                yield v
            elif self._limit_hit:
                return

    def windows(self, rel: str, *, window: int = 4000, overlap: int = 300) -> Iterator[tuple[int, str]]:
        """Stream a big file in overlapping windows; at most 64 MB per run for bundle scanning."""
        remaining = MAX_BUNDLE_BYTES - self._bundle_bytes
        if remaining <= 0:
            self.add_note("bundle read limit reached", incomplete=True)
            return
        if self.staged:
            v = self.read(rel, big_ok=True)
            if v is None:
                return
            text = v.text
            step = window - overlap
            for off in range(0, max(len(text), 1), step):
                yield off, text[off:off + window]
            return
        for off, text in files.stream_windows(self.root, rel, window=window, overlap=overlap, max_total=remaining):
            self._bundle_bytes += len(text.encode("utf-8", "replace")) * (window - overlap) // window
            yield off, text

    # ---- git facts ---------------------------------------------------------------------------
    def tracked(self, rel: str) -> bool | None:
        if self._tracked is False:
            self._tracked = files.git_tracked_set(self.root)
            if self._tracked is None:
                self.add_note("git-unavailable")
        if self._tracked is None:
            return None
        return rel in self._tracked  # type: ignore[operator]

    def ignored(self, rel: str) -> bool | None:
        if rel not in self._ignored:
            val = files.git_ignored_check(self.root, rel)
            if val is None:
                self.add_note("git-unavailable")
            self._ignored[rel] = val
        return self._ignored[rel]

    def changed_files(self) -> list[str] | None:
        """Files changed since HEAD plus untracked files (``git status --porcelain``), or None."""
        try:
            if not gitutil.is_toplevel(self.root):
                return None
            r = gitutil.run_git(self.root, ["status", "--porcelain", "-z", "--untracked-files=all"])
        except GuardError:
            return None
        if r.returncode != 0:
            return None
        out: list[str] = []
        parts = r.stdout.split("\0")
        i = 0
        while i < len(parts):
            ent = parts[i]
            i += 1
            if len(ent) < 4:
                continue
            xy, path = ent[:2], ent[3:]
            if xy[0] in "RC":
                i += 1  # the original path follows
            if "D" in xy:
                continue
            c = norm_relpath(path)
            if c:
                out.append(c)
        return sorted(set(out))

    def staged_files(self) -> list[str]:
        """Paths added, copied, modified or renamed in the index (``git diff --cached``)."""
        try:
            r = gitutil.run_git(self.root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"])
        except GuardError:
            return []
        if r.returncode != 0:
            return []
        return sorted({c for c in (norm_relpath(p) for p in r.stdout.split("\0") if p) if c})

    # ---- index (staged mode) --------------------------------------------------------------------
    def _index_entries(self) -> dict[str, tuple[str, str]]:
        if self._index is None:
            self._index = {}
            r = gitutil.run_git(self.root, ["ls-files", "-s", "-z"], timeout=30)
            if r.returncode == 0:
                for ent in r.stdout.split("\0"):
                    if "\t" not in ent:
                        continue
                    meta, path = ent.split("\t", 1)
                    bits = meta.split()
                    c = norm_relpath(path)
                    if len(bits) == 3 and c and bits[2] == "0":
                        self._index[c] = (bits[0], bits[1])
        return self._index

    def _read_index(self, rel: str, big_ok: bool) -> tuple[FileView | None, str | None]:
        ent = self._index_entries().get(rel)
        if ent is None:
            return None, "missing"
        mode, blob = ent
        if mode == "120000":
            return None, "symlink"
        if mode not in ("100644", "100755"):
            return None, "not-regular"
        cap = files.MAX_BIG_FILE if big_ok else files.MAX_FILE
        sz = gitutil.run_git(self.root, ["cat-file", "-s", "--end-of-options", blob])
        try:
            size = int(sz.stdout.strip())
        except ValueError:
            return None, "unreadable"
        if size > cap:
            return None, "oversize"
        r = gitutil.run_git(self.root, ["cat-file", "blob", "--end-of-options", blob], binary=True)
        if r.returncode != 0:
            return None, "unreadable"
        data = r.stdout
        if b"\x00" in data[: files.BINARY_PROBE]:
            return None, "binary"
        text = data.decode("utf-8", errors="replace")
        bom = text.startswith("﻿")
        if bom:
            text = text[1:]
        return FileView(path=rel, text=text, size=len(data), bom=bom), None


_BUILD_RX = re.compile(r"(?:^|/)(?:%s)/|^\.vercel/output/" % "|".join(sorted(re.escape(d) for d in files.BUILD_DIRS)))


def _is_build_path(path: str) -> bool:
    """True when ``path`` lives under a build output directory (hidden from non-bundle checks)."""
    return _BUILD_RX.search(path) is not None
