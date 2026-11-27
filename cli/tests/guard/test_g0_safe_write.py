# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write primitives (contract 3.11 H1, 3.10 state directory; test_safe_write)."""
from __future__ import annotations

import os
import stat

import pytest

from paddock_cli.guard import errors, files


def _mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


def test_safe_write_creates_file_0600_and_dirs_0700(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    out = files.safe_write(str(root), "a/b/c.txt", "hello\n")
    assert (root / "a" / "b" / "c.txt").read_text() == "hello\n"
    assert _mode(root / "a" / "b" / "c.txt") == 0o600
    assert _mode(root / "a") == 0o700 and _mode(root / "a" / "b") == 0o700
    assert out.endswith("a/b/c.txt")


def test_safe_write_replaces_atomically_and_keeps_requested_mode(tmp_path):
    (tmp_path / "f.txt").write_text("old")
    files.safe_write(str(tmp_path), "f.txt", b"new", mode=0o640)
    assert (tmp_path / "f.txt").read_text() == "new" and _mode(tmp_path / "f.txt") == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]  # no temp file left behind


def test_safe_write_failure_leaves_original(tmp_path, monkeypatch):
    (tmp_path / "f.txt").write_text("original")

    def boom(*a, **k):
        raise OSError("simulated crash")

    monkeypatch.setattr(files.os, "replace", boom)
    with pytest.raises(errors.GuardError):
        files.safe_write(str(tmp_path), "f.txt", "new")
    assert (tmp_path / "f.txt").read_text() == "original"
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]


def test_safe_write_exclusive_refuses_existing(tmp_path):
    files.safe_write(str(tmp_path), "x.txt", "1", exclusive=True)
    with pytest.raises(errors.GuardError):
        files.safe_write(str(tmp_path), "x.txt", "2", exclusive=True)
    assert (tmp_path / "x.txt").read_text() == "1"


@pytest.mark.parametrize("rel", ["../escape.txt", "/abs.txt", "a/../../b", "a\\b", "", "a\x00b", "."])
def test_safe_write_rejects_bad_relpaths(tmp_path, rel):
    with pytest.raises(errors.GuardError):
        files.safe_write(str(tmp_path), rel, "x")


@pytest.mark.parametrize("target", [".gitignore", "CLAUDE.md", "AGENTS.md", ".paddock/ledger.jsonl", "ledger.jsonl"])
def test_symlinked_targets_are_refused_for_write_and_append(tmp_path, target):
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch")
    root = tmp_path / "root"
    root.mkdir()
    link = root / target
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, link)
    with pytest.raises(errors.GuardError):
        files.safe_write(str(root), target, "pwned")
    with pytest.raises(errors.GuardError):
        files.safe_append(str(root), target, "pwned")
    assert outside.read_text() == "do not touch"


def test_symlinked_paddock_directory_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / ".paddock")
    with pytest.raises(errors.GuardError):
        files.safe_write(str(root), ".paddock/guard.toml", "x")
    with pytest.raises(errors.GuardError):
        files.safe_append(str(root), ".paddock/ledger.jsonl", "x")
    assert list(outside.iterdir()) == []


def test_symlinked_parent_in_the_middle_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    os.symlink(outside, root / "a" / "b")
    with pytest.raises(errors.GuardError):
        files.safe_write(str(root), "a/b/c.txt", "x")
    assert list(outside.iterdir()) == []


def test_safe_append_appends_and_sets_mode(tmp_path):
    files.safe_append(str(tmp_path), "log/ledger.jsonl", "one\n")
    files.safe_append(str(tmp_path), "log/ledger.jsonl", b"two\n")
    p = tmp_path / "log" / "ledger.jsonl"
    assert p.read_text() == "one\ntwo\n" and _mode(p) == 0o600


def test_safe_append_refuses_hardlinked_file(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("v")
    root = tmp_path / "root"
    root.mkdir()
    os.link(victim, root / "ledger.jsonl")
    with pytest.raises(errors.GuardError):
        files.safe_append(str(root), "ledger.jsonl", "x\n")
    assert victim.read_text() == "v"


def test_safe_rename_and_remove_stay_inside_base(tmp_path):
    files.safe_write(str(tmp_path), "a.txt", "1")
    files.safe_rename(str(tmp_path), "a.txt", "a.txt.1")
    assert not (tmp_path / "a.txt").exists() and (tmp_path / "a.txt.1").read_text() == "1"
    files.safe_remove(str(tmp_path), "a.txt.1")
    assert not (tmp_path / "a.txt.1").exists()
    files.safe_remove(str(tmp_path), "missing.txt")  # no error
    with pytest.raises(errors.GuardError):
        files.safe_remove(str(tmp_path), "../x")


def test_safe_remove_refuses_symlink_target_but_unlinks_the_link_only_when_asked(tmp_path):
    outside = tmp_path / "o.txt"
    outside.write_text("keep")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / "l")
    with pytest.raises(errors.GuardError):
        files.safe_remove(str(root), "l")
    assert outside.read_text() == "keep"


def test_state_dir_is_outside_the_repo_and_private(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    cache = tmp_path / "cache"
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(cache))
    st = files.state_dir(str(root))
    assert st and st.startswith(str(cache)) and not st.startswith(str(root))
    assert _mode(st) == 0o700
    rel = os.path.relpath(st, cache).split(os.sep)
    assert rel[0] == "guard" and rel[1] == "projects" and len(rel[2]) == 32
    assert files.state_dir(str(root)) == st


def test_state_dir_falls_back_to_xdg_then_home(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.delenv("PADDOCK_CACHE_DIR")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert files.state_dir(str(root)).startswith(str(tmp_path / "xdg" / "paddock"))
    monkeypatch.delenv("XDG_CACHE_HOME")
    home = os.environ["HOME"]
    assert files.state_dir(str(root)).startswith(os.path.join(home, ".cache", "paddock"))


def test_no_state_writes_nothing(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setenv("PADDOCK_GUARD_NO_STATE", "1")
    assert files.state_dir(str(root)) is None
    assert not (tmp_path / "guard-cache").exists()
    monkeypatch.delenv("PADDOCK_GUARD_NO_STATE")
    assert files.state_dir(str(root), no_state=True) is None
    assert not (tmp_path / "guard-cache").exists()


def test_state_dir_inside_the_project_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(root / ".cache"))
    assert files.state_dir(str(root)) is None
    assert not (root / ".cache").exists()


def test_state_dir_symlinked_component_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    cache = tmp_path / "cache"
    (cache / "guard").mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    os.symlink(victim, cache / "guard" / "projects")
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(cache))
    assert files.state_dir(str(root)) is None
    assert list(victim.iterdir()) == []


def test_write_output_file_refuses_symlink_and_writes_regular(tmp_path):
    files.write_output_file(str(tmp_path / "out.json"), "{}")
    assert (tmp_path / "out.json").read_text() == "{}" and _mode(tmp_path / "out.json") == 0o600
    outside = tmp_path / "t.txt"
    outside.write_text("keep")
    os.symlink(outside, tmp_path / "link.json")
    with pytest.raises(errors.GuardError):
        files.write_output_file(str(tmp_path / "link.json"), "x")
    assert outside.read_text() == "keep"


def test_private_tempdir_is_0700_and_removable(tmp_path):
    d = files.private_tempdir("guard-test-")
    assert _mode(d) == 0o700
    files.safe_write(d, "x/y.txt", "1")
    files.remove_tree(d)
    assert not os.path.exists(d)


def test_state_dir_inside_the_project_through_a_symlink_or_equal_to_it_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    link = tmp_path / "cachelink"
    os.symlink(root / "sub", link)
    for base in (link, root, root / "sub" / "deeper"):
        monkeypatch.setenv("PADDOCK_CACHE_DIR", str(base))
        assert files.state_dir(str(root)) is None, base
    assert not (root / "sub" / "guard").exists() and not (root / "guard").exists()


def test_state_dir_in_a_parent_of_the_project_is_allowed(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    assert files.state_dir(str(root)) is not None
