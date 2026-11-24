"""installer/scripts/prepare_resources.py: what Paddock Setup embeds in its .exe.

Run from the repo root:  pytest -q scripts/tests/test_installer_resources.py
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "installer" / "scripts" / "prepare_resources.py"


def prepare(out: Path, *args: str):
    return subprocess.run(["python3", str(TOOL), "--out", str(out), *args], capture_output=True, text=True)


def test_resources_match_the_release_zip_layout_so_install_ps1_finds_its_files(tmp_path):
    out = tmp_path / "res"
    r = prepare(out, "--version", "1.2.3")
    assert r.returncode == 0, r.stderr
    for f in ("install.ps1", "docker-compose.lite.yml", ".env.example", "VERSION", "schema/001_scope.sql", "schema/100_app_role.sh"):
        assert (out / f).is_file(), f
    # install.ps1 looks for the compose file NEXT TO ITSELF (Get-BundleDir): that is the zip layout
    assert (out / "install.ps1").parent == (out / "docker-compose.lite.yml").parent
    assert not (out / "install.bat").exists()          # the wizard replaces the double-click launcher


def test_a_release_build_is_stamped_and_a_dev_build_is_not(tmp_path):
    prepare(tmp_path / "rel", "--version", "1.2.3")
    assert "$StampedVersion = '1.2.3'" in (tmp_path / "rel" / "install.ps1").read_text()
    assert (tmp_path / "rel" / "VERSION").read_text().strip() == "1.2.3"
    prepare(tmp_path / "dev")
    assert "$StampedVersion = ''" in (tmp_path / "dev" / "install.ps1").read_text()
    assert (tmp_path / "dev" / "VERSION").read_text().strip() == "dev"
    # the checked-in script is never modified
    assert "$StampedVersion = ''" in (ROOT / "scripts" / "install.ps1").read_text()


def test_the_embedded_script_is_byte_identical_to_the_release_asset(tmp_path):
    prepare(tmp_path / "res", "--version", "2.0.0")
    r = subprocess.run(["python3", str(ROOT / "scripts" / "make_release_bundle.py"), "--version", "2.0.0", "--out", str(tmp_path / "dist")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "res" / "install.ps1").read_bytes() == (tmp_path / "dist" / "install.ps1").read_bytes()
    assert (tmp_path / "res" / "docker-compose.lite.yml").read_bytes() == (ROOT / "docker-compose.lite.yml").read_bytes()


@pytest.mark.parametrize("bad", ["v1.2.3", "1.2", "latest", "1.2.3; calc"])
def test_rejects_bad_versions_without_touching_the_output(tmp_path, bad):
    out = tmp_path / "res"
    r = prepare(out, "--version", bad)
    assert r.returncode != 0 and not out.exists()


def test_is_idempotent_and_clears_stale_files(tmp_path):
    out = tmp_path / "res"
    prepare(out, "--version", "1.0.0")
    (out / "stale.txt").write_text("x")
    prepare(out, "--version", "1.0.1")
    assert not (out / "stale.txt").exists()
    assert (out / "VERSION").read_text().strip() == "1.0.1"
