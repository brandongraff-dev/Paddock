"""Config / DSN tests (no external services)."""
from __future__ import annotations

import os

from app import config as config_module


def test_normalize_dsn_strips_sqlalchemy_tag() -> None:
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
    monkeypatch.setenv("NEO4J_URI", "bolt://neo:7687")
    monkeypatch.setenv("NEO4J_PASSWORD", "secret")
    monkeypatch.setenv("SYNC_INTERVAL_MIN", "9")
    cfg = config_module.load()
    assert cfg.database_url.startswith("postgresql://")
    assert cfg.neo4j_uri == "bolt://neo:7687"
    assert cfg.neo4j_password == "secret"
    assert cfg.sync_interval_min == 9


def test_config_defaults() -> None:
    for name in ["DATABASE_URL", "NEO4J_URI", "NEO4J_PASSWORD", "SYNC_INTERVAL_MIN",
                 "GRAPHSYNC_HTTP_PORT"]:
        os.environ.pop(name, None)
    cfg = config_module.load()
    assert cfg.sync_interval_min == 5
    assert cfg.http_port == 8096
    assert cfg.max_path_hops == 8
    assert cfg.neighborhood_cap == 500
