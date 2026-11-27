# SPDX-License-Identifier: AGPL-3.0-or-later
"""ScanContext, ProjectInfo and BaseTree (contract 3.3, 3.9)."""
from __future__ import annotations

import io
import json
import os
import tarfile

import pytest

from paddock_cli.guard import config, context, errors, files, gitutil
from support import gitenv


def _w(root, rel, text="x\n"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    return p


def _open(root, **kw):
    cfg = kw.pop("cfg", None) or config.load_config(str(root))
    return context.ScanContext.open(str(root), cfg, **kw)


def test_open_resolves_root_and_refuses_home_and_foreign_roots(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    with _open(root) as ctx:
        assert ctx.root == os.path.realpath(root) and ctx.base_tree is None and ctx.staged is False
    link = tmp_path / "link"
    os.symlink(root, link)
    with _open(link) as ctx:
        assert ctx.root == os.path.realpath(root)
    with pytest.raises(errors.ConfigError):
        _open(os.environ["HOME"])
    with pytest.raises(errors.ConfigError):
        _open("/")
    with pytest.raises(errors.ConfigError):
        _open(tmp_path / "does-not-exist")


def test_files_iterates_matching_globs_once_and_records_skips(tmp_path):
    _w(tmp_path, "a.py", "x = 1\n")
    _w(tmp_path, "src/b.py", "y = 2\n")
    _w(tmp_path, "c.txt", "t\n")
    _w(tmp_path, "bin.dat", b"\x00\x01")
    os.symlink(tmp_path / "a.py", tmp_path / "ln.py")
    with _open(tmp_path) as ctx:
        got = [fv.path for fv in ctx.files("**/*.py")]
        assert got == ["a.py", "src/b.py"]
        assert [fv.path for fv in ctx.files("*.dat")] == []
        assert {(s["file"], s["reason"]) for s in ctx.skipped} >= {("bin.dat", "binary"), ("ln.py", "symlink")}
        assert len(ctx.skipped) == len({(s["file"], s["reason"]) for s in ctx.skipped})  # no duplicates
        assert ctx.read("a.py") is ctx.read("a.py")  # cached view
        assert ctx.read("missing.py") is None and ctx.exists("a.py") and not ctx.exists("missing.py")


def test_exclude_globs_remove_paths_from_listing(tmp_path):
    _w(tmp_path, "docs/a.md")
    _w(tmp_path, "src/a.py")
    cfg = config.load_config(str(tmp_path), cli={"exclude": ["docs/**"]})
    with _open(tmp_path, cfg=cfg) as ctx:
        assert ctx.list_paths() == ["src/a.py"]


def test_build_dirs_only_with_include_build(tmp_path):
    _w(tmp_path, "src/a.js")
    _w(tmp_path, "dist/b.js")
    with _open(tmp_path) as ctx:
        assert [f.path for f in ctx.files("**/*.js")] == ["src/a.js"]
        assert [f.path for f in ctx.files("**/*.js", include_build=True)] == ["dist/b.js", "src/a.js"]


def test_total_bytes_limit_makes_the_run_incomplete(tmp_path, monkeypatch):
    for i in range(5):
        _w(tmp_path, "f%d.txt" % i, "a" * 100)
    monkeypatch.setattr(context, "MAX_TOTAL_BYTES", 250)
    with _open(tmp_path) as ctx:
        got = [f.path for f in ctx.files("*.txt")]
        assert len(got) == 3 and ctx.complete is False and "file limit reached" in ctx.notes


def test_listing_notes_flow_into_the_context(tmp_path):
    _w(tmp_path, "a.py")
    with _open(tmp_path) as ctx:
        ctx.list_paths()
        assert "git-unavailable" in ctx.notes and ctx.complete is True
        assert ctx.tracked("a.py") is None and ctx.ignored("a.py") is None


def test_tracked_and_ignored_use_git_only_at_the_toplevel(repo):
    _w(repo, ".gitignore", "secret.env\n")
    _w(repo, "a.py")
    _w(repo, "secret.env", "S=1")
    _w(repo, "untracked.py")
    gitenv.git(repo, "add", "a.py", ".gitignore")
    with _open(repo) as ctx:
        assert ctx.tracked("a.py") is True and ctx.tracked("untracked.py") is False
        assert ctx.ignored("secret.env") is True and ctx.ignored("a.py") is False
        assert "git-unavailable" not in ctx.notes
    sub = repo / "pkg"
    sub.mkdir()
    with _open(sub) as ctx:
        assert ctx.tracked("x") is None and ctx.ignored("x") is None


def test_changed_files_is_status_porcelain(repo):
    _w(repo, "a.py", "1\n")
    _w(repo, "b.py", "1\n")
    gitenv.commit_all(repo)
    _w(repo, "a.py", "2\n")
    _w(repo, "new dir/c.py", "3\n")
    (repo / "b.py").unlink()
    gitenv.git(repo, "mv", "a.py", "renamed.py") if False else None
    with _open(repo) as ctx:
        assert ctx.changed_files() == ["a.py", "new dir/c.py"]


def test_staged_mode_reads_index_content_not_the_working_tree(repo):
    _w(repo, "a.py", "SAFE = 1\n")
    gitenv.commit_all(repo)
    _w(repo, "a.py", "STAGED = 2\n")
    gitenv.git(repo, "add", "a.py")
    _w(repo, "a.py", "WORKTREE = 3\n")
    _w(repo, "unstaged.py", "U = 4\n")
    with _open(repo, staged=True) as ctx:
        assert ctx.staged is True and ctx.staged_files() == ["a.py"]
        assert ctx.read("a.py").text == "STAGED = 2\n"
        assert [f.path for f in ctx.files("**/*.py")] == ["a.py"]
        assert ctx.read("unstaged.py") is None


def test_staged_mode_skips_symlinks_and_oversize(repo):
    os.symlink("/etc/passwd", repo / "link")
    _w(repo, "big.txt", b"a" * 1_000_001)
    _w(repo, "ok.txt", "fine\n")
    gitenv.git(repo, "add", "-A")
    with _open(repo, staged=True) as ctx:
        got = [f.path for f in ctx.files("*")]
        assert got == ["ok.txt"]
        reasons = {(s["file"], s["reason"]) for s in ctx.skipped}
        assert ("link", "symlink") in reasons and ("big.txt", "oversize") in reasons


def test_staged_requires_a_git_work_tree(tmp_path):
    with pytest.raises(errors.ConfigError):
        _open(tmp_path, staged=True)


# ---- ProjectInfo --------------------------------------------------------------------------------
def test_project_info_detects_spa_and_frameworks(tmp_path):
    _w(tmp_path, "package.json", json.dumps({"name": "x", "dependencies": {"react": "18", "vite": "5"}, "devDependencies": {"typescript": "5"}}))
    with _open(tmp_path) as ctx:
        p = ctx.project
        assert p.has_package_json and p.spa is True and "vite" in p.frameworks and "react" in p.deps
    _w(tmp_path, "package.json", json.dumps({"dependencies": {"vite": "5", "express": "4"}}))
    with _open(tmp_path) as ctx:
        assert ctx.project.spa is False and "express" in ctx.project.frameworks
    _w(tmp_path, "package.json", json.dumps({"dependencies": {"next": "14"}}))
    with _open(tmp_path) as ctx:
        assert ctx.project.spa is False and "next" in ctx.project.frameworks


def test_project_info_python_and_hostile_manifests(tmp_path):
    _w(tmp_path, "requirements.txt", "flask==3.0\nfastapi>=0.1\n")
    _w(tmp_path, "package.json", "[" * 100000)
    with _open(tmp_path) as ctx:
        assert "flask" in ctx.project.frameworks and "fastapi" in ctx.project.frameworks and ctx.project.python is True
        assert ctx.project.has_package_json is False  # unparsable
    _w(tmp_path, "package.json", '{"dependencies": ["not", "a", "map"]}')
    with _open(tmp_path) as ctx:
        assert ctx.project.deps == frozenset()


# ---- BaseTree -----------------------------------------------------------------------------------
def test_base_tree_extracts_the_ref_into_a_private_temp_dir_and_cleans_up(repo, tmp_path):
    _w(repo, "a.py", "OLD = 1\n")
    _w(repo, "sub/b.py", "B = 1\n")
    base = gitenv.commit_all(repo)
    _w(repo, "a.py", "NEW = 2\n")
    gitenv.commit_all(repo)
    with _open(repo, base=base) as ctx:
        bt = ctx.base_tree
        assert bt is not None and bt.sha == base and bt.partial_missing == []
        assert (open(os.path.join(bt.path, "a.py")).read()) == "OLD = 1\n"
        assert oct(os.stat(bt.path).st_mode & 0o777) == "0o700"
        assert not bt.path.startswith(str(repo))
        path = bt.path
    assert not os.path.exists(path)


def test_base_tree_rejects_option_like_refs(repo):
    _w(repo, "a.py")
    gitenv.commit_all(repo)
    for bad in ("--output=/tmp/x", "-p", "--upload-pack=x"):
        with pytest.raises(errors.ConfigError):
            _open(repo, base=bad)


def test_base_tree_reports_export_ignore_as_partial(repo):
    _w(repo, ".gitattributes", "legacy/** export-ignore\n")
    _w(repo, "legacy/old.py", "OLD = 1\n")
    _w(repo, "keep.py", "K = 1\n")
    base = gitenv.commit_all(repo)
    with _open(repo, base=base) as ctx:
        assert ctx.base_tree.partial_missing == ["legacy/old.py"]
        assert not os.path.exists(os.path.join(ctx.base_tree.path, "legacy", "old.py"))


def test_base_tree_hostile_archive_is_a_guard_error_and_leaves_no_temp(repo, monkeypatch):
    _w(repo, "a.py")
    base = gitenv.commit_all(repo)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("../escape.txt")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    data = buf.getvalue()

    class FakeStream:
        stdout = io.BytesIO(data)
        returncode = 0

        def close(self):
            pass

    from contextlib import contextmanager

    @contextmanager
    def fake_stream(root, sha, **kw):
        yield FakeStream()

    monkeypatch.setattr(context.gitutil, "archive_stream", fake_stream)
    before = set(os.listdir(os.path.dirname(files.private_tempdir("probe-"))))
    cfg = config.load_config(str(repo))
    with pytest.raises(errors.GuardError):
        context.ScanContext.open(str(repo), cfg, base=base).base_tree
    assert not (repo.parent / "escape.txt").exists()
    after = set(os.listdir(os.path.dirname(files.private_tempdir("probe-"))))
    assert not [n for n in after - before if n.startswith("paddock-guard-base-")]


def test_base_tree_goes_under_the_state_directory_when_there_is_one(repo, tmp_path, monkeypatch):
    _w(repo, "a.py")
    base = gitenv.commit_all(repo)
    cache = tmp_path / "c"
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(cache))
    with _open(repo, base=base) as ctx:
        assert ctx.base_tree.path.startswith(str(cache))
    monkeypatch.setenv("PADDOCK_GUARD_NO_STATE", "1")
    with _open(repo, base=base) as ctx:
        assert not ctx.base_tree.path.startswith(str(cache))


def test_state_dir_is_none_with_no_state_and_outside_the_repo_otherwise(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    with _open(repo, no_state=True) as ctx:
        assert ctx.state_dir is None
    with _open(repo) as ctx:
        assert ctx.state_dir and not ctx.state_dir.startswith(str(repo))
    assert gitutil.is_toplevel(str(repo))
