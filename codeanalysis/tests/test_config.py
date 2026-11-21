from __future__ import annotations

import os

from app import config as config_module


def test_normalize_dsn_strips_sqlalchemy_tag():
    assert config_module._normalize_dsn(
        "postgresql+asyncpg://u:p@h:5432/db"
    ) == "postgresql://u:p@h:5432/db"
    assert config_module._normalize_dsn(
        "postgres+asyncpg://u:p@h:5432/db"
    ) == "postgres://u:p@h:5432/db"
    plain = "postgresql://u:p@h:5432/db"
    assert config_module._normalize_dsn(plain) == plain


def test_config_reads_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@z:5432/w")
    monkeypatch.setenv("CODEANALYSIS_HTTP_PORT", "9999")
    monkeypatch.setenv("ENABLE_SEMGREP", "false")
    cfg = config_module.load()
    assert cfg.database_url.startswith("postgresql://")
    assert cfg.http_port == 9999
    assert cfg.enable_semgrep is False


def test_config_defaults():
    for name in ["DATABASE_URL", "CODEANALYSIS_HTTP_PORT", "ENABLE_SEMGREP",
                 "ORCHESTRATOR_URL"]:
        os.environ.pop(name, None)
    cfg = config_module.load()
    assert cfg.http_port == 8097
    assert cfg.orchestrator_url == "http://orchestrator:8080"
    assert cfg.enable_semgrep is True
    assert cfg.semgrep_config == "auto"
