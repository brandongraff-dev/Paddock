"""scripts/make_release_bundle.py: the zip, the stamped installers and the checksums.

Run from the repo root:  pytest -q scripts/tests/test_release_bundle.py
"""
from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "make_release_bundle.py"


def build(out: Path, version="1.2.3"):
    return subprocess.run(["python3", str(TOOL), "--version", version, "--out", str(out)],
                          capture_output=True, text=True)


@pytest.fixture
def bundle(tmp_path):
    r = build(tmp_path / "dist")
    assert r.returncode == 0, r.stderr
    return tmp_path / "dist"


def test_zip_contains_everything_a_non_technical_user_needs(bundle):
    z = zipfile.ZipFile(bundle / "paddock-lite-1.2.3.zip")
    names = set(z.namelist())
    top = "paddock-lite-1.2.3/"
    for f in ("docker-compose.lite.yml", ".env.example", "install.bat", "install.ps1", "install.sh", "README.txt"):
        assert top + f in names, f
    assert top + "schema/001_scope.sql" in names                # mounted into Postgres on first start
    assert all(n.startswith(top) for n in names)                # one folder, no zip-bomb at the extract root
    assert not [n for n in names if "/." in n and not n.endswith(".env.example")]
    assert not [n for n in names if n.endswith((".git", "dashboard/", "orchestrator/"))]   # no sources


def test_installers_are_stamped_in_zip_and_standalone_but_not_in_the_repo(bundle):
    z = zipfile.ZipFile(bundle / "paddock-lite-1.2.3.zip")
    assert 'STAMPED_VERSION="1.2.3"' in z.read("paddock-lite-1.2.3/install.sh").decode()
    assert "$StampedVersion = '1.2.3'" in z.read("paddock-lite-1.2.3/install.ps1").decode()
    assert 'STAMPED_VERSION="1.2.3"' in (bundle / "install.sh").read_text()
    assert "$StampedVersion = '1.2.3'" in (bundle / "install.ps1").read_text()
    # the checked-in copies stay unstamped: a branch checkout builds from source
    assert 'STAMPED_VERSION=""' in (ROOT / "scripts" / "install.sh").read_text()
    assert "$StampedVersion = ''" in (ROOT / "scripts" / "install.ps1").read_text()


def test_windows_files_have_windows_line_endings_and_ps1_is_ascii(bundle):
    z = zipfile.ZipFile(bundle / "paddock-lite-1.2.3.zip")
    for f in ("install.bat", "README.txt"):
        data = z.read(f"paddock-lite-1.2.3/{f}")
        assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b""), f
    assert z.read("paddock-lite-1.2.3/install.ps1").isascii()
    assert b"\r" not in z.read("paddock-lite-1.2.3/install.sh")              # LF only: /bin/sh chokes on CR
    assert b"\r" not in z.read("paddock-lite-1.2.3/schema/100_app_role.sh")  # mounted into the Postgres container
    bat = z.read("paddock-lite-1.2.3/install.bat").decode()
    assert "-ExecutionPolicy Bypass" in bat and "install.ps1" in bat and "pause" in bat
    assert "1.2.3" in z.read("paddock-lite-1.2.3/README.txt").decode()
    assert "{{" not in z.read("paddock-lite-1.2.3/README.txt").decode()


def test_checksums_match_and_the_build_is_reproducible(tmp_path):
    assert build(tmp_path / "a").returncode == 0 and build(tmp_path / "b").returncode == 0
    a, b = tmp_path / "a", tmp_path / "b"
    for name in ("paddock-lite-1.2.3.zip", "install.sh", "install.ps1", "BUNDLE_SHA256SUMS.txt"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name
    for line in (a / "BUNDLE_SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((a / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("bad", ["v1.2.3", "1.2", "1.2.3; rm -rf /", "latest", ""])
def test_rejects_bad_versions(tmp_path, bad):
    r = build(tmp_path / "x", bad)
    assert r.returncode != 0 and not (tmp_path / "x" / "install.sh").exists()


def test_prerelease_versions_are_allowed(tmp_path):
    assert build(tmp_path / "x", "1.0.0-rc.1").returncode == 0


def test_stamped_install_sh_runs_in_release_mode(bundle, tmp_path):
    r = subprocess.run(["sh", str(bundle / "install.sh"), "--dry-run", "--dir", str(tmp_path / "p")],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    assert "release 1.2.3" in r.stdout and "tar.gz/v1.2.3" in r.stdout and "up -d --no-build" in r.stdout


# --------------------------------------------------------------------------- #
# the compose file the zip ships

def test_lite_compose_images_match_what_release_yml_publishes():
    compose = yaml.safe_load((ROOT / "docker-compose.lite.yml").read_text())
    release = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    published = {m["service"] for m in release["jobs"]["images"]["strategy"]["matrix"]["include"]}
    for name, svc in compose["services"].items():
        img = svc.get("image", "")
        if "paddock-" not in img:
            continue
        assert "PADDOCK_VERSION" in img and "build" in svc, name          # source builds keep working
        repo = img.split("/paddock-")[1].split(":")[0]
        assert repo in published, f"{name}: image paddock-{repo} is not built by release.yml"
