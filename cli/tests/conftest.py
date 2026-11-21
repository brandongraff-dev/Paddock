from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fake_osv import FakeOsv
from paddock_cli import main as cli_main
from paddock_cli.osvclient import OsvClient

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "vuln-repo"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """No test may touch the real cache, config, colour settings or network."""
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("PADDOCK_CONFIG_DIR", str(tmp_path / "config"))
    for var in ("NO_COLOR", "FORCE_COLOR", "PADDOCK_API_KEY", "PADDOCK_SERVER", "GITHUB_TOKEN",
                "GITHUB_REPOSITORY", "PADDOCK_OSV_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TERM", "xterm")


@pytest.fixture
def osv():
    return FakeOsv()


@pytest.fixture
def patch_osv(monkeypatch, osv, tmp_path):
    """Make the CLI talk to the in-process fake instead of api.osv.dev."""
    cache = tmp_path / "cache"

    def factory(**kw):
        return OsvClient(transport=osv, cache=cache, **kw)

    monkeypatch.setattr(cli_main, "OsvClient", factory)
    return factory


@pytest.fixture
def repo(tmp_path) -> Path:
    dst = tmp_path / "repo"
    shutil.copytree(FIXTURE, dst)
    return dst


@pytest.fixture
def git_repo(repo) -> Path:
    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "dev@example.test")
    git("config", "user.name", "dev")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return repo


def run(capsys, *argv):
    """Run the CLI; return (exit_code, stdout, stderr)."""
    code = cli_main.main([str(a) for a in argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err
