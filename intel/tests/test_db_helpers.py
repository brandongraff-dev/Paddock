"""DB config/helper tests that don't need a real postgres."""
from __future__ import annotations

import os

from app import config as config_module


def test_normalise_dsn_strips_sqlalchemy_tag() -> None:
    dsn = "postgresql+asyncpg://u:p@h:5432/db"
    assert config_module._normalize_dsn(dsn) == "postgresql://u:p@h:5432/db"
    dsn2 = "postgres+asyncpg://u:p@h:5432/db"
    assert config_module._normalize_dsn(dsn2) == "postgres://u:p@h:5432/db"
    plain = "postgresql://u:p@h:5432/db"
    assert config_module._normalize_dsn(plain) == plain


def test_config_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@z:5432/w")
    monkeypatch.setenv("SYNC_INTERVAL_MIN", "7")
    monkeypatch.setenv("NVD_API_KEY", "abc")
    cfg = config_module.load()
    assert cfg.database_url.startswith("postgresql://")
    assert cfg.sync_interval_min == 7
    assert cfg.nvd_api_key == "abc"


def test_config_defaults() -> None:
    for name in [
        "DATABASE_URL", "REDIS_URL", "ORCHESTRATOR_URL", "SYNC_INTERVAL_MIN",
        "LINKER_INTERVAL_MIN", "NVD_API_KEY", "FINDING_MIN_CONFIDENCE",
    ]:
        os.environ.pop(name, None)
    cfg = config_module.load()
    assert cfg.sync_interval_min == 60
    assert cfg.linker_interval_min == 15
    assert cfg.finding_min_confidence == 60
    assert cfg.nvd_api_key is None
