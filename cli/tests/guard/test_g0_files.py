# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hardened reading, listing and extraction (contract 3.9; acceptance 6)."""
from __future__ import annotations

import io
import os
import signal
import stat
import subprocess
import tarfile
import zipfile

import pytest

from paddock_cli.guard import errors, files
from support import gitenv


def _w(root, rel, text="x\n", mode=None):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    if mode:
        p.chmod(mode)
    return p


# ---------------------------------------------------------------- reading --------------------
def test_read_regular_file_lines_and_bom(tmp_path):
    _w(tmp_path, "a.py", "﻿x = 1\r\ny = 2\r\n")
    fv, why = files.read_file(str(tmp_path), "a.py")
    assert why is None and fv.path == "a.py" and fv.bom is True
    assert fv.text.startswith("x = 1")
    assert fv.lines[:3] == ["x = 1", "y = 2", ""]
    assert fv.size == len("﻿x = 1\r\ny = 2\r\n".encode())


def test_symlink_to_file_is_never_read(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(secret, root / "link.txt")
    fv, why = files.read_file(str(root), "link.txt")
    assert fv is None and why == "symlink"


def test_symlink_directory_component_is_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwd").write_text("root:x")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / "dir")
    os.symlink("/etc", root / "etc")
    os.symlink("..", root / "up")
    for rel in ("dir/passwd", "etc/passwd", "up/outside/passwd"):
        fv, why = files.read_file(str(root), rel)
        assert fv is None and why in ("symlink", "outside-root"), rel


def test_fifo_is_skipped_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe")

    def on_alarm(*_):
        raise AssertionError("read blocked on a FIFO")

    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(5)
    try:
        fv, why = files.read_file(str(tmp_path), "pipe")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    assert fv is None and why == "not-regular"


def test_directory_and_missing_are_not_read(tmp_path):
    (tmp_path / "d").mkdir()
    assert files.read_file(str(tmp_path), "d")[1] == "not-regular"
    assert files.read_file(str(tmp_path), "nope.txt")[1] == "missing"


def test_oversize_file_is_skipped_and_big_ok_raises_the_cap(tmp_path):
    _w(tmp_path, "big.js", b"a" * 1_000_001)
    fv, why = files.read_file(str(tmp_path), "big.js")
    assert fv is None and why == "oversize"
    fv, why = files.read_file(str(tmp_path), "big.js", big_ok=True)
    assert why is None and fv.size == 1_000_001
    _w(tmp_path, "huge.js", b"a" * 4_000_001)
    assert files.read_file(str(tmp_path), "huge.js", big_ok=True)[1] == "oversize"


def test_file_that_grows_after_fstat_cannot_exceed_the_cap(tmp_path, monkeypatch):
    _w(tmp_path, "g.txt", b"a" * 50)
    real = os.fstat

    class Fake:
        def __init__(self, st):
            self._st = st
            self.st_size = 5

        def __getattr__(self, k):
            return getattr(self._st, k)

    monkeypatch.setattr(files.os, "fstat", lambda fd: Fake(real(fd)))
    fv, why = files.read_file(str(tmp_path), "g.txt", limit=10)
    assert fv is None and why == "oversize"


def test_binary_file_is_skipped(tmp_path):
    _w(tmp_path, "b.bin", b"abc\x00def")
    assert files.read_file(str(tmp_path), "b.bin") == (None, "binary")
    _w(tmp_path, "late.txt", b"a" * 5000 + b"\x00")
    assert files.read_file(str(tmp_path), "late.txt")[1] is None  # NUL only counts in the first 4096


def test_invalid_utf8_is_replaced_not_fatal(tmp_path):
    _w(tmp_path, "l1.txt", b"caf\xe9 ok\n")
    fv, why = files.read_file(str(tmp_path), "l1.txt")
    assert why is None and "caf" in fv.text and "�" in fv.text


@pytest.mark.parametrize("rel", ["../x", "/etc/passwd", "a/../../x", "a\\b", "a\x00b", ""])
def test_unsafe_paths_are_refused_by_the_reader(tmp_path, rel):
    fv, why = files.read_file(str(tmp_path), rel)
    assert fv is None and why == "outside-root"


# ---------------------------------------------------------------- listing -------------------
def test_walk_listing_skips_dirs_symlinks_and_reports_them(tmp_path):
    _w(tmp_path, "src/a.py")
    _w(tmp_path, ".github/workflows/ci.yml")
    _w(tmp_path, ".cursor/rules/x.mdc")
    _w(tmp_path, "node_modules/p/index.js")
    _w(tmp_path, ".git/config", "x")
    _w(tmp_path, "__pycache__/a.pyc")
    _w(tmp_path, "venv/lib/x.py")
    _w(tmp_path, "dist/bundle.js")
    _w(tmp_path, ".vercel/output/x.js")
    os.symlink(tmp_path / "src", tmp_path / "linkdir")
    os.symlink(tmp_path / "src" / "a.py", tmp_path / "linkfile")
    lst = files.list_files(str(tmp_path))
    assert lst.paths == [".cursor/rules/x.mdc", ".github/workflows/ci.yml", "src/a.py"]
    assert lst.via == "walk" and "git-unavailable" in lst.notes and lst.complete
    reasons = {(s["file"], s["reason"]) for s in lst.skipped}
    assert ("linkdir", "symlink") in reasons and ("linkfile", "symlink") in reasons
    inc = files.list_files(str(tmp_path), include_build=True)
    assert "dist/bundle.js" in inc.paths and ".vercel/output/x.js" in inc.paths
    assert "node_modules/p/index.js" not in inc.paths


def test_git_listing_cached_and_untracked_but_not_ignored(repo):
    _w(repo, "a.py")
    _w(repo, "dot-ignored.txt", "x")
    _w(repo, ".gitignore", "secret.env\nbuild-out/\n")
    _w(repo, "secret.env", "S=1")
    _w(repo, "build-out/x.js")
    gitenv.git(repo, "add", "a.py", ".gitignore")
    _w(repo, "new.py")
    lst = files.list_files(str(repo))
    assert lst.via == "git" and lst.paths == [".gitignore", "a.py", "dot-ignored.txt", "new.py"]
    assert "git-unavailable" not in lst.notes and lst.complete


def test_subdirectory_of_a_repo_that_ignores_it_falls_back_to_walk(repo):
    _w(repo, ".gitignore", "corpus/\n")
    _w(repo, "corpus/entry/a.py")
    _w(repo, "corpus/entry/b.py")
    gitenv.git(repo, "add", ".gitignore")
    lst = files.list_files(str(repo / "corpus" / "entry"))
    assert lst.via == "walk" and lst.paths == ["a.py", "b.py"]
    assert "git-unavailable" in lst.notes and lst.complete
    assert files.git_tracked_set(str(repo / "corpus" / "entry")) is None


def test_hostile_entries_in_a_faked_git_listing_are_dropped(repo, monkeypatch):
    _w(repo, "ok.py")
    _w(repo, "sub/also.py")
    gitenv.git(repo, "add", "-A")
    fake = "\0".join(["ok.py", "../etc/passwd", "/etc/passwd", "a/../../b", "x\\y", "sub/also.py", "", "sub/./also.py",
                      "nul\x01ctl.py"]) + "\0"
    real = files.gitutil.run_git

    def fake_run(root, args, **kw):
        if args[:1] == ["ls-files"] and "--cached" in args and "--others" in args:
            return subprocess.CompletedProcess(args, 0, fake, "")
        return real(root, args, **kw)

    monkeypatch.setattr(files.gitutil, "run_git", fake_run)
    lst = files.list_files(str(repo))
    assert lst.paths == ["ok.py", "sub/also.py"]


def test_file_limit_gives_incomplete(tmp_path, monkeypatch):
    for i in range(12):
        _w(tmp_path, "f%02d.txt" % i)
    monkeypatch.setattr(files, "MAX_FILES", 5)
    lst = files.list_files(str(tmp_path))
    assert len(lst.paths) == 5 and not lst.complete and "file limit reached" in lst.notes


def test_listing_fewer_than_ninety_percent_is_incomplete(repo, monkeypatch):
    for i in range(10):
        _w(repo, "f%d.py" % i)
    gitenv.git(repo, "add", "-A")
    real = files.gitutil.run_git

    def partial(root, args, **kw):
        if args[:1] == ["ls-files"] and "--cached" in args and "--others" in args:
            return subprocess.CompletedProcess(args, 0, "f0.py\0f1.py\0", "")
        return real(root, args, **kw)

    monkeypatch.setattr(files.gitutil, "run_git", partial)
    lst = files.list_files(str(repo))
    assert not lst.complete and "listing-incomplete" in lst.notes


def test_empty_listing_with_files_on_disk_is_incomplete(repo, monkeypatch):
    _w(repo, "a.py")
    gitenv.git(repo, "add", "-A")
    real = files.gitutil.run_git

    def empty(root, args, **kw):
        if args[:1] == ["ls-files"] and "--cached" in args and "--others" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        return real(root, args, **kw)

    monkeypatch.setattr(files.gitutil, "run_git", empty)
    lst = files.list_files(str(repo))
    assert not lst.complete and "listing-incomplete" in lst.notes


def test_git_unavailable_for_include_config_falls_back_to_walk(repo):
    _w(repo, "a.py")
    gitenv.git(repo, "add", "-A")
    with open(repo / ".git" / "config", "a") as fh:
        fh.write("\n[include]\n\tpath = /nonexistent\n")
    lst = files.list_files(str(repo))
    assert lst.via == "walk" and "git-unavailable" in lst.notes and "a.py" in lst.paths


def test_root_checks_refuse_home_and_ancestors(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".aws").mkdir()
    (home / "proj").mkdir()
    monkeypatch.setenv("HOME", str(home))
    for bad in (str(home), str(tmp_path), "/", str(home / ".ssh"), str(home / ".aws")):
        with pytest.raises(errors.ConfigError):
            files.check_root_allowed(bad)
    files.check_root_allowed(str(home / "proj"))


def test_root_not_owned_by_current_user_is_refused(tmp_path, monkeypatch):
    (tmp_path / "p").mkdir()
    monkeypatch.setattr(files.os, "geteuid", lambda: os.stat(tmp_path / "p").st_uid + 1)
    with pytest.raises(errors.ConfigError):
        files.check_root_allowed(str(tmp_path / "p"))


# ---------------------------------------------------------------- extraction ----------------
def _tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for spec in entries:
            name = spec["name"]
            ti = tarfile.TarInfo(name)
            ti.type = spec.get("type", tarfile.REGTYPE)
            data = spec.get("data", b"")
            ti.mode = spec.get("mode", 0o644)
            if ti.type == tarfile.REGTYPE:
                ti.size = len(data)
            if "linkname" in spec:
                ti.linkname = spec["linkname"]
            if ti.type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                ti.devmajor, ti.devminor = 1, 3
            tf.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
    buf.seek(0)
    return buf


def _extract(entries, dest, **kw):
    return files.extract_tar_stream(_tar(entries), str(dest), **kw)


def test_extract_tar_good_archive_strips_special_bits(tmp_path):
    n = _extract([
        {"name": "a.txt", "data": b"hi"},
        {"name": "sub/run.sh", "data": b"#!/bin/sh\n", "mode": 0o4755},
        {"name": "sub/", "type": tarfile.DIRTYPE, "mode": 0o2755},
        {"name": "sub/g.txt", "data": b"g", "mode": 0o2644},
    ], tmp_path / "out")
    assert n == 3
    out = tmp_path / "out"
    assert (out / "a.txt").read_bytes() == b"hi"
    assert stat.S_IMODE(os.stat(out / "a.txt").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(out / "sub" / "run.sh").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(out / "sub" / "g.txt").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(out / "sub").st_mode) == 0o700


@pytest.mark.parametrize("spec", [
    {"name": "/abs.txt", "data": b"x"},
    {"name": "../up.txt", "data": b"x"},
    {"name": "a/../../up.txt", "data": b"x"},
    {"name": "a\\b.txt", "data": b"x"},
    {"name": "bad\x00name.txt", "data": b"x"},
    {"name": "sym", "type": tarfile.SYMTYPE, "linkname": "/etc/passwd"},
    {"name": "hard", "type": tarfile.LNKTYPE, "linkname": "a.txt"},
    {"name": "dev", "type": tarfile.CHRTYPE},
    {"name": "blk", "type": tarfile.BLKTYPE},
    {"name": "fifo", "type": tarfile.FIFOTYPE},
])
def test_extract_tar_rejects_hostile_member(tmp_path, spec):
    with pytest.raises(errors.GuardError):
        _extract([{"name": "a.txt", "data": b"ok"}, spec], tmp_path / "out")
    assert not (tmp_path / "up.txt").exists()


def test_extract_tar_rejects_duplicate_and_case_colliding_names(tmp_path):
    with pytest.raises(errors.GuardError):
        _extract([{"name": "a.txt", "data": b"1"}, {"name": "a.txt", "data": b"2"}], tmp_path / "o1")
    with pytest.raises(errors.GuardError):
        _extract([{"name": "A.txt", "data": b"1"}, {"name": "a.TXT", "data": b"2"}], tmp_path / "o2")


def test_extract_tar_member_count_and_byte_limits(tmp_path):
    many = [{"name": "f%d.txt" % i, "data": b"x"} for i in range(6)]
    with pytest.raises(errors.GuardError):
        _extract(many, tmp_path / "o1", max_members=5)
    with pytest.raises(errors.GuardError):
        _extract([{"name": "a.txt", "data": b"x" * 100}, {"name": "b.txt", "data": b"y" * 100}], tmp_path / "o2",
                 max_bytes=150)


def test_extract_tar_header_size_that_lies_is_rejected(tmp_path):
    raw = _tar([{"name": "a.txt", "data": b"hello"}]).getvalue()
    # header claims 5 bytes; append garbage in the place of the following header
    tampered = raw[:512] + b"hello" + b"\0" * 507 + b"JUNKJUNK" * 64 + raw[1024:]
    with pytest.raises(errors.GuardError):
        files.extract_tar_stream(io.BytesIO(tampered), str(tmp_path / "out"))
    # header claims far more bytes than the stream holds
    ti = tarfile.TarInfo("big.bin")
    ti.size = 10_000_000
    hdr = ti.tobytes()
    with pytest.raises(errors.GuardError):
        files.extract_tar_stream(io.BytesIO(hdr + b"short"), str(tmp_path / "out2"))


def test_extract_tar_garbage_is_a_guard_error(tmp_path):
    with pytest.raises(errors.GuardError):
        files.extract_tar_stream(io.BytesIO(b"this is not a tar archive" * 100), str(tmp_path / "o"))


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, *rest in entries:
            zi = zipfile.ZipInfo(name)
            if rest:
                zi.external_attr = rest[0]
            zf.writestr(zi, data)
    buf.seek(0)
    return buf


def test_extract_zip_good_and_hostile(tmp_path):
    assert files.extract_zip(_zip([("a.txt", b"hi"), ("d/b.txt", b"yo")]), str(tmp_path / "ok")) == 2
    assert (tmp_path / "ok" / "d" / "b.txt").read_bytes() == b"yo"
    for name in ("/abs.txt", "../up.txt", "a\\b.txt", "x/../../y"):
        with pytest.raises(errors.GuardError):
            files.extract_zip(_zip([(name, b"x")]), str(tmp_path / "bad"))
    link = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(errors.GuardError):
        files.extract_zip(_zip([("l", b"/etc/passwd", link)]), str(tmp_path / "bad2"))
    with pytest.raises(errors.GuardError):
        files.extract_zip(_zip([("a.txt", b"1"), ("A.TXT", b"2")]), str(tmp_path / "bad3"))
    with pytest.raises(errors.GuardError):
        files.extract_zip(_zip([("a%d" % i, b"1") for i in range(6)]), str(tmp_path / "bad4"), max_members=5)


def test_extract_zip_ratio_bomb_is_rejected(tmp_path):
    bomb = _zip([("zeros.txt", b"\0" * 5_000_000)])
    with pytest.raises(errors.GuardError):
        files.extract_zip(bomb, str(tmp_path / "o"), max_ratio=50)


def test_extract_checks_free_disk_space_first(tmp_path, monkeypatch):
    monkeypatch.setattr(files.shutil, "disk_usage", lambda p: (100, 99, 1))
    with pytest.raises(errors.GuardError):
        files.extract_zip(_zip([("a.txt", b"x" * 1000)]), str(tmp_path / "o"))
