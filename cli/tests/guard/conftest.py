# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures for the Guard tests (contract 3.12).

Fixtures under ``fixtures/`` contain ``tests/``, ``test_*.py`` and ``conftest.py`` files on
purpose, so they are never collected. Conftest files import nothing by bare name from another
conftest.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

collect_ignore_glob = ["fixtures/*"]

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Imported after the path tweak above so ``support`` and ``fakes`` resolve under every runner.
import support  # noqa: E402
from support import gitenv, launcher  # noqa: E402

REPO = HERE.parents[2]
FIXTURES = HERE / "fixtures"


@pytest.fixture(autouse=True)
def _guard_isolation(monkeypatch, tmp_path):
    """No Guard test may see the real home, git config, state directory or network switches."""
    for var in list(os.environ):
        if var.startswith(("PADDOCK_GUARD_", "CLAUDE_")) or var in (
            "PADDOCK_NO_PROMPT", "GITHUB_ACTIONS", "CI", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
        ):
            monkeypatch.delenv(var, raising=False)
    home = tmp_path / "guard-home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "guard-cache"))
    monkeypatch.setenv("PADDOCK_CONFIG_DIR", str(tmp_path / "guard-config"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def guard_env(tmp_path):
    """Environment for subprocess tests: launcher first on PATH, everything inside tmp."""
    bindir = launcher.make_bin(tmp_path / "bin")
    return launcher.guard_env_dict(tmp_path, bindir)


@pytest.fixture
def dev_tiers(monkeypatch):
    """Behave like a ``.dev`` tree: a check without a tiers.json entry keeps its proposed tier.

    GUARD_VERSION is ``0.1.0`` (a release), so by D8 a check with no ``tiers.json`` entry is
    ``medium``. Tests that need a blocking ``high`` check without writing tiers.json use this.
    """
    from paddock_cli.guard import model, registry

    monkeypatch.setattr(model, "REQUIRE_TIERS", False)
    registry.reset_caches()
    yield
    registry.reset_caches()


@pytest.fixture
def registry_sandbox():
    """Run with an empty registry; restore the previous contents afterwards."""
    from paddock_cli.guard import registry

    with registry.sandbox() as reg:
        yield reg


@pytest.fixture
def repo(tmp_path):
    """A fresh git repository (isolated config) with a helper to commit."""
    root = tmp_path / "repo"
    gitenv.init_repo(root)
    return root


@pytest.fixture
def clean_app():
    return FIXTURES / "apps" / "clean-app"
