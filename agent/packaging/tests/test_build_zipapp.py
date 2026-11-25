"""The zipapp builder: deterministic, minimal, and its exit status survives (Python 3.8 compatible)."""
import ast
import os
import subprocess
import sys
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGING = os.path.dirname(HERE)
AGENT = os.path.dirname(PACKAGING)
sys.path.insert(0, PACKAGING)

import build_zipapp as bz  # noqa: E402


def run_pyz(pyz, *args, **kw):
    env = dict(os.environ)
    env.pop("PADDOCK_ENROLL_TOKEN", None)
    env.update(kw.pop("env", {}))
    return subprocess.run([sys.executable, "-I", str(pyz)] + list(args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60, **kw)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("pyz") / "paddock-agent.pyz"
    digest = bz.build(str(out))
    return out, digest


def test_build_is_byte_reproducible_across_time_zone_umask_location_and_mtime(built, tmp_path):
    first, digest = built
    # a different checkout location of the same sources, touched later, other TZ/umask
    env = dict(os.environ, TZ="Pacific/Auckland", SOURCE_DATE_EPOCH="")
    old_umask = os.umask(0o077)
    try:
        other = tmp_path / "elsewhere" / "paddock-agent.pyz"
        res = subprocess.run([sys.executable, os.path.join(PACKAGING, "build_zipapp.py"), "--out", str(other)],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    finally:
        os.umask(old_umask)
    assert res.returncode == 0, res.stderr
    assert first.read_bytes() == other.read_bytes()
    assert res.stdout.decode().split()[0] == digest == bz.sha256_file(str(first))


def test_every_python_version_available_builds_the_same_bytes(built, tmp_path):
    """3.8 .. 3.13 must agree (zipapp's directory mode does not: it changed in 3.12)."""
    seen = {}
    for name in ("python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3"):
        for d in [os.path.expanduser("~/.local/bin")] + os.environ.get("PATH", "").split(os.pathsep):
            cand = os.path.join(d, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                seen.setdefault(os.path.realpath(cand), cand)
                break
    seen.setdefault(os.path.realpath(sys.executable), sys.executable)
    if len(seen) < 2:
        pytest.skip("only one interpreter available")
    digests = {}
    for real, cand in sorted(seen.items()):
        out = tmp_path / ("x-%d.pyz" % len(digests))
        res = subprocess.run([cand, os.path.join(PACKAGING, "build_zipapp.py"), "--out", str(out)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        assert res.returncode == 0, (cand, res.stderr)
        digests[real] = bz.sha256_file(str(out))
    assert set(digests.values()) == {built[1]}, digests


def test_a_source_change_changes_the_archive(tmp_path):
    root = tmp_path / "agent"
    pkg = root / "paddock_agent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = '1'\n")
    (pkg / "cli.py").write_text("def main():\n    return 0\n")
    a = bz.build(str(tmp_path / "a.pyz"), agent_dir=str(root))
    (pkg / "cli.py").write_text("def main():\n    return 1\n")
    b = bz.build(str(tmp_path / "b.pyz"), agent_dir=str(root))
    assert a != b


def test_archive_holds_only_the_package_plus_a_generated_main(built):
    pyz, _ = built
    with zipfile.ZipFile(str(pyz)) as zf:
        names = [i.filename for i in zf.infolist()]
        assert not any(n.endswith("/") for n in names)            # files only: no directory entries to vary
        assert "__main__.py" in names
        for n in names:
            assert n == "__main__.py" or n.startswith("paddock_agent/"), n
            assert n.endswith(".py"), n
            assert "__pycache__" not in n and "/tests" not in n and "fixtures" not in n
        assert "paddock_agent/cli.py" in names and "paddock_agent/collectors/__init__.py" in names
        assert "paddock_agent/ed25519_pure.py" in names
        main = zf.read("__main__.py").decode()
        assert "sys.exit(main())" in main
        # every module in the package tree is in the archive (nothing silently skipped)
        want = sorted(rel for rel, _full in bz.package_files(AGENT))
        assert sorted(n for n in names if n != "__main__.py") == want
    assert open(str(pyz), "rb").read(2) == b"#!"
    assert open(str(pyz), "rb").readline().strip() == b"#!/usr/bin/env python3"


def test_every_member_has_one_fixed_timestamp_mode_and_is_stored(built):
    pyz, _ = built
    with zipfile.ZipFile(str(pyz)) as zf:
        for info in zf.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0), (info.filename, info.date_time)
            assert info.compress_type == zipfile.ZIP_STORED, info.filename
            mode = (info.external_attr >> 16) & 0o7777
            assert mode in (0o644, 0o755), (info.filename, oct(mode))
            assert mode == 0o644 and info.create_system == 3
    assert os.stat(str(pyz)).st_mode & 0o777 == 0o755


def test_source_date_epoch_is_honoured_and_validated(tmp_path, monkeypatch):
    out = tmp_path / "x.pyz"
    bz.build(str(out), epoch=1700000000)
    with zipfile.ZipFile(str(out)) as zf:
        assert {i.date_time for i in zf.infolist()} == {(2023, 11, 14, 22, 13, 20)}
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "12")
    with pytest.raises(bz.BuildError):
        bz.source_date_epoch()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "soon")
    with pytest.raises(bz.BuildError):
        bz.source_date_epoch()
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert bz.source_date_epoch() == bz.DEFAULT_EPOCH


def test_the_real_archive_runs_and_exit_status_is_propagated(built):
    """zipapp's own main= shortcut would turn every status into 0 (and exit 7 must stop systemd restarts)."""
    pyz, _ = built
    res = run_pyz(pyz, "--version")
    assert res.returncode == 0 and res.stdout.decode().startswith("paddock 0.")
    res = run_pyz(pyz, "enroll")                    # no token, no server: the CLI's "not enrolled" status
    assert res.returncode == 2, res.stderr
    assert b"no enrollment token" in res.stderr
    # the same archive never accepts the token as an argument
    res = run_pyz(pyz, "enroll", "--token", "fet_0123456789ab_" + "x" * 24)
    assert res.returncode != 0 and b"fet_0123456789ab" not in res.stdout + res.stderr


def test_a_minimal_package_exit_status_is_the_return_of_main(tmp_path):
    root = tmp_path / "agent"
    pkg = root / "paddock_agent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("def main():\n    return 7\n")
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "cli.cpython-38.pyc").write_bytes(b"junk")
    (pkg / "__pycache__" / "junk.py").write_text("x = 1\n")        # a stray .py inside a cache dir
    (pkg / ".hidden").mkdir()
    (pkg / ".hidden" / "secret.py").write_text("SECRET = 1\n")        # and one inside a dot directory
    (pkg / "notes.txt").write_text("not code")
    out = tmp_path / "m.pyz"
    bz.build(str(out), agent_dir=str(root))
    with zipfile.ZipFile(str(out)) as zf:
        assert zf.namelist() == ["__main__.py", "paddock_agent/__init__.py", "paddock_agent/cli.py"]
    assert run_pyz(out).returncode == 7


def test_a_symlink_in_the_tree_is_refused(tmp_path):
    root = tmp_path / "agent"
    pkg = root / "paddock_agent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (tmp_path / "secret.py").write_text("x = 1\n")
    os.symlink(str(tmp_path / "secret.py"), str(pkg / "linked.py"))
    with pytest.raises(bz.BuildError):
        bz.build(str(tmp_path / "s.pyz"), agent_dir=str(root))


def test_not_an_agent_tree_is_refused(tmp_path):
    with pytest.raises(bz.BuildError):
        bz.build(str(tmp_path / "s.pyz"), agent_dir=str(tmp_path))


def test_sums_manifest_is_sha256sum_format(tmp_path):
    out, sums = tmp_path / "paddock-agent.pyz", tmp_path / "SHA256SUMS"
    extra = tmp_path / "install-agent.sh"
    extra.write_text("#!/bin/sh\n")
    assert bz.main(["--out", str(out), "--sums", str(sums), "--also", str(extra)]) == 0
    lines = sums.read_text().splitlines()
    assert [ln.split("  ")[1] for ln in lines] == ["install-agent.sh", "paddock-agent.pyz"]
    assert lines[1].split("  ")[0] == bz.sha256_file(str(out))
    assert lines[0].split("  ")[0] == bz.sha256_file(str(extra))
    if sys.platform.startswith("linux"):
        assert subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=str(tmp_path), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).returncode == 0


def test_the_builder_is_python38_syntax():
    src = open(os.path.join(PACKAGING, "build_zipapp.py")).read()
    ast.parse(src, feature_version=(3, 8))
    for banned in ("removeprefix", "removesuffix", "zoneinfo", ":="):
        assert banned not in src.replace('":="', "")
