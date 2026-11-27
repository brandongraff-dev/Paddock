# SPDX-License-Identifier: AGPL-3.0-or-later
"""The built wheel carries the TOML pack, has no third-party dependency and works (contract 3.1, 10 G0 acceptance 11)."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[2]


def _build(tmp: Path) -> Path:
    src = tmp / "clisrc"
    shutil.copytree(CLI, src, ignore=shutil.ignore_patterns("tests", "build", "*.egg-info", "__pycache__", ".pytest_cache"))
    out = tmp / "wheelhouse"
    env = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    last = ""
    for extra in (["--no-build-isolation"], []):
        r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", *extra, "-w", str(out), str(src)],
                           capture_output=True, text=True, env=env, timeout=280)
        if r.returncode == 0:
            wheels = sorted(out.glob("paddock_cli-*.whl"))
            if wheels:
                return wheels[0]
        last = (r.stdout + r.stderr)[-300:]
    pytest.skip("cannot build a wheel here (needs setuptools or a network for build isolation): " + last.strip())


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    return _build(tmp_path_factory.mktemp("wheel"))


def test_wheel_lists_the_toml_pack_and_the_guard_packages(wheel):
    names = set(zipfile.ZipFile(wheel).namelist())
    for want in ("paddock_cli/guard/packs/example.toml", "paddock_cli/guard/packs/__init__.py",
                 "paddock_cli/guard/data/__init__.py", "paddock_cli/guard/checks/__init__.py",
                 "paddock_cli/guard/fixers/__init__.py", "paddock_cli/guard/cli.py", "paddock_cli/guard/engine.py"):
        assert want in names, want
    assert not [n for n in names if "/fixtures/" in n or n.startswith("tests/")]
    entry = zipfile.ZipFile(wheel).read([n for n in names if n.endswith("entry_points.txt")][0]).decode()
    assert "paddock-guard = paddock_cli.guard.cli:main" in entry and "paddock = paddock_cli.main:main" in entry


def test_wheel_installs_in_a_clean_venv_with_no_third_party_package(wheel, tmp_path):
    env_dir = tmp_path / "clean"
    venv.EnvBuilder(with_pip=True).create(env_dir)
    py = env_dir / "bin" / "python"
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH",)}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    r = subprocess.run([str(py), "-m", "pip", "install", "-q", "--no-index", str(wheel)], capture_output=True, text=True, env=env, timeout=280)
    assert r.returncode == 0, r.stderr[-500:]
    freeze = subprocess.run([str(py), "-m", "pip", "list", "--format=freeze"], capture_output=True, text=True, env=env, timeout=120).stdout
    extra = [ln for ln in freeze.splitlines() if not ln.lower().startswith(("pip==", "setuptools==", "paddock-cli=="))]
    assert extra == []
    v = subprocess.run([str(env_dir / "bin" / "paddock-guard"), "--version"], capture_output=True, text=True, env=env, timeout=60)
    assert v.returncode == 0 and v.stdout.strip() == "paddock-guard 0.1.0"
    lst = subprocess.run([str(env_dir / "bin" / "paddock"), "guard", "list"], capture_output=True, text=True, env=env, timeout=60)
    assert lst.returncode == 0 and "ID" in lst.stdout
    # the existing paddock commands still start in the same wheel
    h = subprocess.run([str(env_dir / "bin" / "paddock"), "--help"], capture_output=True, text=True, env=env, timeout=60)
    assert h.returncode == 0 and "guard" in h.stdout and "scan" in h.stdout
