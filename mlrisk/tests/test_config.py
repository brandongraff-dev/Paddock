"""Config helper tests — no real postgres needed."""
from __future__ import annotations

import os

from app import config as config_module


def test_normalise_dsn_strips_sqlalchemy_tag() -> None:
    assert config_module._normalize_dsn(
        "postgresql+asyncpg://u:p@h:5432/db"
    ) == "postgresql://u:p@h:5432/db"
    assert config_module._normalize_dsn(
        "postgres+asyncpg://u:p@h:5432/db"
    ) == "postgres://u:p@h:5432/db"
    plain = "postgresql://u:p@h:5432/db"
    assert config_module._normalize_dsn(plain) == plain


def test_config_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@z:5432/w")
    monkeypatch.setenv("MLRISK_INTERVAL_MIN", "7")
    monkeypatch.setenv("MIN_LABELS", "4")
    monkeypatch.setenv("CONTAMINATION", "0.25")
    cfg = config_module.load()
    assert cfg.database_url.startswith("postgresql://")
    assert cfg.interval_min == 7
    assert cfg.min_labels == 4
    assert cfg.contamination == 0.25


def test_config_defaults() -> None:
    for name in [
        "DATABASE_URL", "MLRISK_INTERVAL_MIN", "MIN_LABELS", "CONTAMINATION",
        "MLRISK_HTTP_PORT", "RATIONALE_TOP_K",
    ]:
        os.environ.pop(name, None)
    cfg = config_module.load()
    assert cfg.interval_min == 30
    assert cfg.min_labels == 12
    assert cfg.contamination == 0.1
    assert cfg.http_port == 8098
    assert cfg.top_k == 4
