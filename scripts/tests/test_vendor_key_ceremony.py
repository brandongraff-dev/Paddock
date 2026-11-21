"""Vendor key ceremony script: offline keygen, public-key embedding, safety refusals.

Every key here is a throwaway generated inside ``tmp_path``; no real vendor key
exists in (or is ever written to) the repository.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "vendor_key_ceremony.py"
LICENSING = ROOT / "orchestrator" / "app" / "licensing.py"
PASS = "correct horse battery staple 42"


def load():
    spec = importlib.util.spec_from_file_location("vendor_key_ceremony", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vendor_key_ceremony"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def vkc():
    return load()


@pytest.fixture
def pw(monkeypatch):
    monkeypatch.setenv("PADDOCK_VENDOR_KEY_PASSPHRASE", PASS)


@pytest.fixture
def ceremony(vkc, pw, tmp_path):
    out = tmp_path / "usb" / "ceremony"
    assert vkc.main(["generate", "--out-dir", str(out)]) == 0
    return out


def test_generate_writes_encrypted_private_key_and_public_files(vkc, ceremony):
    priv = ceremony / "paddock-vendor.pem"
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert b"ENCRYPTED PRIVATE KEY" in priv.read_bytes()
    pub = (ceremony / "paddock-vendor.pub").read_text().strip()
    assert len(vkc.base64.b64decode(pub)) == 32
    record = (ceremony / "ceremony-record.txt").read_text()
    assert vkc.fingerprint(pub) in record and "BEGIN" not in record and "PRIVATE" not in record.split("private key :")[0]


def test_generated_pair_signs_licenses_the_orchestrator_accepts(vkc, ceremony):
    from cryptography.hazmat.primitives import serialization

    sys.path.insert(0, str(ROOT / "orchestrator"))
    from app import licensing

    key = serialization.load_pem_private_key((ceremony / "paddock-vendor.pem").read_bytes(), PASS.encode())
    pub = (ceremony / "paddock-vendor.pub").read_text().strip()
    token = licensing.sign_license({"v": 1, "license_id": "L-1", "edition": "team"}, key)
    got = licensing.verify_license_key(token, public_keys=licensing.parse_public_keys([pub]))
    assert got.edition == "team" and got.status == "active"
    with pytest.raises(Exception):  # the wrong passphrase cannot open the key
        serialization.load_pem_private_key((ceremony / "paddock-vendor.pem").read_bytes(), b"wrong-passphrase")


def test_generate_refuses_repo_paths_overwrite_and_weak_or_missing_passphrase(vkc, pw, tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as e:
        vkc.main(["generate", "--out-dir", str(ROOT / "keys-oops")])
    assert "inside the repository" in str(e.value) and not (ROOT / "keys-oops").exists()
    out = tmp_path / "once"
    assert vkc.main(["generate", "--out-dir", str(out)]) == 0
    with pytest.raises(SystemExit) as e:
        vkc.main(["generate", "--out-dir", str(out)])
    assert "never overwrite" in str(e.value)
    monkeypatch.setenv("PADDOCK_VENDOR_KEY_PASSPHRASE", "short")
    with pytest.raises(SystemExit) as e:
        vkc.main(["generate", "--out-dir", str(tmp_path / "weak")])
    assert "at least" in str(e.value)
    monkeypatch.delenv("PADDOCK_VENDOR_KEY_PASSPHRASE")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as e:
        vkc.main(["generate", "--out-dir", str(tmp_path / "nopw")])
    assert "unencrypted vendor key is refused" in str(e.value)
    assert not (tmp_path / "weak").exists() and not (tmp_path / "nopw").exists()


def test_embed_check_roundtrip_on_a_copy(vkc, ceremony, tmp_path):
    src = tmp_path / "licensing.py"
    shutil.copy(LICENSING, src)
    pubfile = str(ceremony / "paddock-vendor.pub")
    pub = (ceremony / "paddock-vendor.pub").read_text().strip()
    assert vkc.main(["check", "--source", str(src)]) == 0                       # nothing embedded yet
    assert vkc.main(["check", "--source", str(src), "--public-key-file", pubfile]) == 1
    assert vkc.main(["embed", "--source", str(src), "--public-key-file", pubfile]) == 0
    assert f'"{pub}"' in src.read_text()
    assert vkc.main(["check", "--source", str(src), "--public-key-file", pubfile, "--exact"]) == 0
    # idempotent
    before = src.read_text()
    assert vkc.main(["embed", "--source", str(src), "--public-key-file", pubfile]) == 0
    assert src.read_text() == before
    # the edited module is still valid Python with a one-key tuple
    compile(src.read_text(), str(src), "exec")
    assert re.search(r"VENDOR_PUBLIC_KEYS: tuple\[str, \.\.\.\] = \(\n", src.read_text())


def test_embed_supports_rotation_and_replace(vkc, pw, tmp_path):
    src = tmp_path / "licensing.py"
    shutil.copy(LICENSING, src)
    keys = []
    for n in ("a", "b"):
        out = tmp_path / n
        assert vkc.main(["generate", "--out-dir", str(out)]) == 0
        keys.append(str(out / "paddock-vendor.pub"))
    assert vkc.main(["embed", "--source", str(src), "--public-key-file", keys[0]]) == 0
    assert vkc.main(["embed", "--source", str(src), "--public-key-file", keys[1]]) == 0
    assert vkc.main(["check", "--source", str(src), "--public-key-file", keys[0], "--public-key-file", keys[1], "--exact"]) == 0
    assert vkc.main(["embed", "--source", str(src), "--public-key-file", keys[1], "--replace"]) == 0
    assert vkc.main(["check", "--source", str(src), "--public-key-file", keys[0]]) == 1
    assert vkc.main(["check", "--source", str(src), "--public-key-file", keys[1], "--exact"]) == 0


def test_embed_refuses_private_or_malformed_key_files_and_repo_edits(vkc, ceremony, tmp_path):
    src = tmp_path / "licensing.py"
    shutil.copy(LICENSING, src)
    with pytest.raises(SystemExit) as e:
        vkc.main(["embed", "--source", str(src), "--public-key-file", str(ceremony / "paddock-vendor.pem")])
    assert "PRIVATE" in str(e.value)
    bad = tmp_path / "bad.pub"
    bad.write_text("AAAA\n")
    with pytest.raises(SystemExit):
        vkc.main(["embed", "--source", str(src), "--public-key-file", str(bad)])
    # editing the real checkout needs an explicit release-checkout acknowledgement
    with pytest.raises(SystemExit) as e:
        vkc.main(["embed", "--public-key-file", str(ceremony / "paddock-vendor.pub")])
    assert "release" in str(e.value)
    assert "VENDOR_PUBLIC_KEYS: tuple[str, ...] = ()" in LICENSING.read_text()


def test_dry_run_does_not_write(vkc, ceremony, tmp_path, capsys):
    src = tmp_path / "licensing.py"
    shutil.copy(LICENSING, src)
    before = src.read_text()
    vkc.main(["embed", "--source", str(src), "--public-key-file", str(ceremony / "paddock-vendor.pub"), "--dry-run"])
    assert src.read_text() == before and "VENDOR_PUBLIC_KEYS" in capsys.readouterr().out


def test_cli_entrypoint_runs(ceremony):
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "fingerprint", "--public-key-file", str(ceremony / "paddock-vendor.pub")],
        capture_output=True, text=True, env={**os.environ},
    )
    assert r.returncode == 0 and re.fullmatch(r"([0-9a-f]{4}:){7}[0-9a-f]{4}", r.stdout.strip())


def test_repository_ships_no_embedded_vendor_key_and_no_private_key_material():
    """Guard for the open-source tree: the PUBLIC key is injected at release
    time only, and no private key may ever be committed."""
    assert "VENDOR_PUBLIC_KEYS: tuple[str, ...] = ()" in LICENSING.read_text()
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if tracked.returncode != 0:
        pytest.skip("not a git checkout")
    hits = []
    for rel in tracked.stdout.splitlines():
        p = ROOT / rel
        if not p.is_file() or p.stat().st_size > 2_000_000 or p.suffix in {".png", ".jpg", ".woff2", ".gz", ".zip"}:
            continue
        if "vendor_key_ceremony" in rel or rel.startswith(("dashboard/node_modules", "docs/api/")):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if re.search(r"-----BEGIN (ENCRYPTED |EC |RSA |OPENSSH )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40,}", text):
            hits.append(rel)
    assert not hits, f"private key material committed: {hits}"
