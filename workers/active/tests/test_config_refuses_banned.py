"""The service hard-refuses to start if an evasion-flavored env var is set."""
from __future__ import annotations

import importlib
import os
import sys

import pytest


def test_banned_env_var_refused(monkeypatch):
    monkeypatch.setenv("SCANNER_STEALTH_MODE", "1")
    # Force a fresh import so the module-level _refuse_banned_env() runs.
    sys.modules.pop("app.config", None)
    with pytest.raises(RuntimeError, match="refused env var"):
        importlib.import_module("app.config")


def test_clean_env_imports_fine(monkeypatch):
    for key in list(os.environ):
        if any(b in key.lower() for b in ("bypass", "evade", "stealth", "hidden", "cloak", "decoy")):
            monkeypatch.delenv(key, raising=False)
    sys.modules.pop("app.config", None)
    cfg = importlib.import_module("app.config")
    assert cfg.settings.user_agent.startswith("palantir-asm-scanner/")
