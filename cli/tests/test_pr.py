import subprocess

import pytest

from conftest import run
from paddock_cli import gitpr

TOKEN = "test-token-not-real"


def git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), *a], check=True, capture_output=True,
                          text=True).stdout.strip()


class FakeGitHub:
    def __init__(self, default_branch="main"):
        self.calls = []
        self.default_branch = default_branch

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/repos/acme/demo":
            return {"default_branch": self.default_branch}
        if method == "POST" and path == "/repos/acme/demo/pulls":
            return {"html_url": "https://github.com/acme/demo/pull/7", "number": 7}
        raise AssertionError(f"unexpected GitHub call {method} {path}")


@pytest.fixture
def origin(git_repo, tmp_path):
    bare = tmp_path / "origin.git"
    git(tmp_path, "init", "-q", "--bare", str(bare))
    git(git_repo, "remote", "add", "origin", str(bare))
    git(git_repo, "push", "-q", "origin", "main")
    return bare


@pytest.fixture
def gh(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(gitpr, "github_api", lambda token, base_url=None: fake)
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    return fake


def test_pr_goes_to_a_new_branch_and_never_touches_the_default_branch(
        capsys, git_repo, origin, gh, patch_osv):
    main_before = git(origin, "rev-parse", "main")
    code, out, err = run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo")
    assert code == 0, out + err
    assert "pull/7" in out and "verified: 8 of 8 fixed" in out

    assert git(origin, "rev-parse", "main") == main_before, "the default branch must not move"
    branches = git(origin, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()
    pushed = [b for b in branches if b != "main"]
    assert len(pushed) == 1 and pushed[0].startswith("paddock/fix-")
    assert "requests==2.31.0" in git(origin, "show", f"{pushed[0]}:requirements.txt")
    assert git(origin, "log", "-1", "--format=%s", pushed[0]).startswith("paddock: fix 8")

    # the developer's checkout is exactly as it was
    assert git(git_repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(git_repo, "status", "--porcelain") == ""
    assert "requests==2.19.0" in (git_repo / "requirements.txt").read_text()


def test_pr_only_opens_never_merges_and_explains_each_fix(capsys, git_repo, origin, gh, patch_osv):
    run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo", "--draft")
    assert [(m, p) for m, p, _ in gh.calls] == [("GET", "/repos/acme/demo"),
                                                ("POST", "/repos/acme/demo/pulls")]
    body = gh.calls[1][2]
    assert body["base"] == "main" and body["head"].startswith("paddock/") and body["draft"] is True
    text = body["body"]
    assert "Nothing here is merged automatically" in text
    for needle in ("Upgrade lodash 4.17.20 -> 4.17.21", "GHSA-35jh-r3h4-6jhm",
                   "Read DB_PASSWORD from the environment", "Safety gate: passed",
                   "verified 8 of 8 fixed", "rotate it"):
        assert needle in text, needle
    assert "Zx9Kp2Lm8Qr4Vt7Wb3Nd" not in text and TOKEN not in text
    assert not any("merge" in p for _, p, _ in gh.calls)


def test_token_is_never_persisted_or_logged(capsys, git_repo, origin, gh, patch_osv):
    code, out, err = run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo")
    assert TOKEN not in out + err
    assert TOKEN not in (git_repo / ".git" / "config").read_text()
    assert TOKEN not in git(git_repo, "log", "--all", "--format=%B")


def test_pr_needs_a_token_and_leaves_the_repo_alone(capsys, git_repo, origin, patch_osv, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    code, out, err = run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo")
    assert code == 2 and "GITHUB_TOKEN" in err
    assert git(git_repo, "branch", "--list").split() == ["*", "main"]
    assert git(git_repo, "status", "--porcelain") == ""


def test_pr_refuses_files_with_uncommitted_changes(capsys, git_repo, origin, gh, patch_osv):
    (git_repo / "requirements.txt").write_text("requests==2.19.0\n# local edit\n")
    code, out, err = run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo")
    assert code == 2 and "uncommitted" in err
    assert not gh.calls or all(m == "GET" for m, _, _ in gh.calls)


def test_failed_push_restores_the_working_tree(capsys, git_repo, origin, gh, patch_osv, tmp_path):
    git(git_repo, "remote", "set-url", "origin", str(tmp_path / "does-not-exist.git"))
    code, out, err = run(capsys, "fix", git_repo, "--yes", "--pr", "--repo", "acme/demo")
    assert code == 2 and "push" in err
    assert git(git_repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(git_repo, "status", "--porcelain") == ""
    assert not [c for c in gh.calls if c[0] == "POST"], "no PR when the push failed"


def test_repo_url_parsing():
    assert gitpr.BRANCH_PREFIX == "paddock/"
    assert gitpr.parse_repo("git@github.com:acme/demo.git") == "acme/demo"
    assert gitpr.parse_repo("https://github.com/acme/demo") == "acme/demo"
    assert gitpr.parse_repo("/tmp/origin.git") is None
