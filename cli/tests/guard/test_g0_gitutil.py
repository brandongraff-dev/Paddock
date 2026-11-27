# SPDX-License-Identifier: AGPL-3.0-or-later
"""run_git hardening and ref validation (contract 3.11 H2, 3.9 item 5; test_run_git_hardening)."""
from __future__ import annotations

import os
import re
import stat

import pytest

from paddock_cli.guard import errors, gitutil
from support import gitenv


def _commit(repo, name="a.txt", text="1\n", msg="c"):
    (repo / name).write_text(text)
    return gitenv.commit_all(repo, msg)


def test_run_git_basic_and_text_output(repo):
    sha = _commit(repo)
    r = gitutil.run_git(repo, ["rev-parse", "HEAD"])
    assert r.returncode == 0 and r.stdout.strip() == sha


def test_run_git_environment_is_scrubbed(repo, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/nonexistent")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "touch /tmp/never")
    monkeypatch.setenv("SECRET_TOKEN", "abc")
    env = gitutil.build_env()
    assert set(env) == {
        "PATH", "HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT", "GIT_ALLOW_PROTOCOL", "GIT_OPTIONAL_LOCKS",
    }
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ALLOW_PROTOCOL"] == "https" and env["GIT_OPTIONAL_LOCKS"] == "0"
    assert os.listdir(env["HOME"]) == []
    assert stat.S_IMODE(os.stat(env["HOME"]).st_mode) == 0o700
    _commit(repo)
    assert gitutil.run_git(repo, ["rev-parse", "HEAD"]).returncode == 0


def test_run_git_argv_is_fixed_and_never_shell(repo, monkeypatch):
    seen = {}
    real = gitutil.subprocess.run

    def spy(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        return real(argv, **kw)

    monkeypatch.setattr(gitutil.subprocess, "run", spy)
    _commit(repo)
    gitutil.run_git(repo, ["status", "--porcelain"])
    argv = seen["argv"]
    assert isinstance(argv, list) and argv[0] == "git" and not seen["kw"].get("shell")
    assert argv[1] == "--no-optional-locks"
    joined = " ".join(argv)
    for frag in ("core.fsmonitor=", "core.hooksPath=/dev/null", "core.pager=cat", "diff.external=",
                 "protocol.ext.allow=never", "core.sshCommand=false"):
        assert "-c %s" % frag in joined, frag
    assert argv[-2:] == ["status", "--porcelain"]


def test_hostile_git_config_fsmonitor_runs_nothing(repo, tmp_path):
    _commit(repo)
    sentinel = tmp_path / "fsmonitor-ran"
    hook = tmp_path / "fsmon.sh"
    hook.write_text("#!/bin/sh\ntouch %s\nexit 0\n" % sentinel)
    hook.chmod(0o755)
    with open(repo / ".git" / "config", "a") as fh:
        fh.write("\n[core]\n\tfsmonitor = %s\n\tsshCommand = touch %s\n\thooksPath = %s\n" % (hook, sentinel, tmp_path))
    for args in (["status", "--porcelain"], ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                 ["diff", "--name-only"], ["rev-parse", "--show-toplevel"]):
        gitutil.run_git(repo, args)
    assert not sentinel.exists()


def test_hostile_git_config_filter_and_textconv_run_nothing(repo, tmp_path):
    _commit(repo)
    sentinel = tmp_path / "filter-ran"
    (repo / ".gitattributes").write_text("*.txt filter=evil diff=evil\n")
    with open(repo / ".git" / "config", "a") as fh:
        fh.write('\n[filter "evil"]\n\tclean = touch %s\n\tsmudge = touch %s\n\tprocess = touch %s\n'
                 '[diff "evil"]\n\ttextconv = touch %s\n\tcommand = touch %s\n' % ((sentinel,) * 5))
    (repo / "a.txt").write_text("changed content with a different size\n")
    for args in (["status", "--porcelain"], ["diff", "--name-only"], ["ls-files", "-m"], ["diff", "--cached"]):
        gitutil.run_git(repo, args)
    assert not sentinel.exists()


def test_git_config_with_includes_is_refused_not_followed(repo, tmp_path):
    _commit(repo)
    extra = tmp_path / "extra.cfg"
    extra.write_text("[core]\n\tfsmonitor = touch %s\n" % (tmp_path / "x"))
    with open(repo / ".git" / "config", "a") as fh:
        fh.write("\n[include]\n\tpath = %s\n" % extra)
    with pytest.raises(errors.GuardError):
        gitutil.run_git(repo, ["status", "--porcelain"])


@pytest.mark.parametrize("ref", [
    "--output=/tmp/x", "--upload-pack=touch /tmp/x", "-p", "-", "", " ", "a b", "a\tb", "x\x00y",
    "main..other", "a" * 101, "HEAD:path", "a\\b", "ref*", "ref?", "ref[1]", "‮main", "a\nb",
])
def test_validate_ref_rejects(ref):
    with pytest.raises(errors.ConfigError):
        gitutil.validate_ref(ref)


@pytest.mark.parametrize("ref", ["main", "HEAD", "HEAD~1", "HEAD^", "origin/main", "v1.0.0", "feature/x-y_z", "a" * 40, "@"])
def test_validate_ref_accepts(ref):
    assert gitutil.validate_ref(ref) == ref


def test_resolve_ref_returns_40_hex(repo):
    sha = _commit(repo)
    _commit(repo, "b.txt", "2\n", "second")
    out = gitutil.resolve_ref(repo, "HEAD~1")
    assert re.fullmatch(r"[0-9a-f]{40}", out) and out == sha
    assert gitutil.resolve_ref(repo, "main") != sha


def test_resolve_ref_refuses_option_like_refs_and_unknown_refs(repo):
    _commit(repo)
    for bad in ("--output=" + str(repo / "pwned"), "--upload-pack=x", "-p"):
        with pytest.raises(errors.ConfigError):
            gitutil.resolve_ref(repo, bad)
    assert not (repo / "pwned").exists()
    with pytest.raises(errors.ConfigError):
        gitutil.resolve_ref(repo, "no-such-ref")


def test_resolve_ref_passes_end_of_options(repo, monkeypatch):
    _commit(repo)
    calls = []
    real = gitutil.run_git

    def spy(root, args, **kw):
        calls.append(list(args))
        return real(root, args, **kw)

    monkeypatch.setattr(gitutil, "run_git", spy)
    gitutil.resolve_ref(repo, "HEAD")
    assert any("--end-of-options" in c and c.index("--end-of-options") < len(c) - 1 for c in calls)


def test_toplevel_equals_root_only_for_the_work_tree_root(repo, tmp_path):
    _commit(repo)
    sub = repo / "sub"
    sub.mkdir()
    (sub / "f.txt").write_text("x")
    assert gitutil.is_toplevel(str(repo))
    assert not gitutil.is_toplevel(str(sub))
    plain = tmp_path / "plain"
    plain.mkdir()
    assert not gitutil.is_toplevel(str(plain))


def test_git_missing_is_a_guard_error(repo, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    gitutil._reset_for_tests()
    with pytest.raises(errors.GuardError):
        gitutil.run_git(repo, ["status"])
    gitutil._reset_for_tests()


def test_timeout_is_a_guard_error(repo):
    with pytest.raises(errors.GuardError):
        gitutil.run_git(repo, ["status"], timeout=0.0000001)


def test_archive_stream_yields_a_tar(repo):
    import tarfile

    _commit(repo, "x.txt", "hello\n")
    sha = gitutil.resolve_ref(repo, "HEAD")
    with gitutil.archive_stream(repo, sha) as stream:
        with tarfile.open(fileobj=stream.stdout, mode="r|") as tf:
            names = [m.name for m in tf]
    assert "x.txt" in names
    assert stream.returncode == 0
