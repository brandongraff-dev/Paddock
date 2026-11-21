from __future__ import annotations

import pathlib

import app
from app import config as config_module
from app.main import ScaService


def test_safety_invariant_documented():
    doc = (app.__doc__ or "").lower()
    assert "defensive" in doc or "detection-only" in doc
    assert "must not" in doc
    # the hard prohibitions are spelled out
    assert "publish" in doc and "claim" in doc
    assert "execute" in doc


def test_no_eval_or_exec_in_parsers():
    root = pathlib.Path(app.__file__).parent
    for py in (root / "parsers").glob("*.py"):
        src = py.read_text()
        assert "eval(" not in src
        assert "exec(" not in src
        assert "subprocess" not in src


def test_read_dir_reads_supported_lockfiles(tmp_path, monkeypatch):
    # copy a couple of fixtures into a temp dir and confirm read_dir finds them
    fixtures = pathlib.Path(__file__).parent / "fixtures"
    (tmp_path / "requirements.txt").write_text((fixtures / "requirements.txt").read_text())
    (tmp_path / "Cargo.lock").write_text((fixtures / "Cargo.lock").read_text())
    (tmp_path / "ignore.me").write_text("nope")
    sub = tmp_path / "node_modules"
    sub.mkdir()
    (sub / "package-lock.json").write_text("{}")  # vendored tree must be skipped

    svc = ScaService(config_module.load())
    files = svc.read_dir(str(tmp_path))
    names = {pathlib.Path(k).name for k in files}
    assert "requirements.txt" in names
    assert "Cargo.lock" in names
    assert "ignore.me" not in names
    # node_modules was pruned
    assert not any("node_modules" in k for k in files)
