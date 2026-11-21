from __future__ import annotations

import os

from app import config as config_module
from app.parsers._util import component, dedupe, resolve_graph


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
    monkeypatch.setenv("SCA_INTERVAL_MIN", "15")
    monkeypatch.setenv("TYPOSQUAT_DISTANCE", "1")
    cfg = config_module.load()
    assert cfg.database_url.startswith("postgresql://")
    assert cfg.scan_interval_min == 15
    assert cfg.typosquat_distance == 1
    assert cfg.http_port == 8094


def test_config_defaults():
    for name in ["DATABASE_URL", "SCA_INTERVAL_MIN", "TYPOSQUAT_DISTANCE",
                 "ABANDONED_DAYS", "SCA_HTTP_PORT"]:
        os.environ.pop(name, None)
    cfg = config_module.load()
    assert cfg.http_port == 8094
    assert cfg.abandoned_days == 730
    assert cfg.typosquat_distance == 2
    assert cfg.enable_osv is True


def test_resolve_graph_depth_and_paths():
    versions = {"root": "1.0", "mid": "2.0", "leaf": "3.0"}
    edges = {"root": ["mid"], "mid": ["leaf"]}
    comps = {c["name"]: c for c in resolve_graph("npm", versions, edges, roots=["root"])}
    assert comps["root"]["direct"] is True and comps["root"]["depth"] == 0
    assert comps["mid"]["depth"] == 1
    assert comps["leaf"]["depth"] == 2
    assert comps["leaf"]["paths"] == ["mid"]


def test_dedupe_merges_direct_and_depth():
    comps = [
        component("npm", "a", "1", direct=False, depth=3, paths=["x"]),
        component("npm", "a", "1", direct=True, depth=1, paths=["y"]),
    ]
    out = dedupe(comps)
    assert len(out) == 1
    assert out[0]["direct"] is True
    assert out[0]["depth"] == 1
    assert set(out[0]["paths"]) == {"x", "y"}
