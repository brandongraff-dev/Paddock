"""Tests for the GitHub-search module."""
from __future__ import annotations

from aioresponses import aioresponses

from app.modules import github_search
from app.modules.github_search import _is_config_path, _parse_items
from .conftest import load_fixture


def test_is_config_path_matches_env_and_compose() -> None:
    assert _is_config_path("deploy/.env") is True
    assert _is_config_path("docker-compose.prod.yaml") is True
    assert _is_config_path("terraform.tfstate") is True
    assert _is_config_path(".aws/credentials") is True
    assert _is_config_path("README.md") is False
    assert _is_config_path("src/app.py") is False


def test_parse_items_emits_repo_and_secret_candidate() -> None:
    body = load_fixture("github_code_search.json")
    r = _parse_items(body["items"], "example.com")
    kinds = [a["kind"] for a in r.assets]
    assert kinds.count("repository") == 1   # deduped
    assert "secret_candidate" in kinds
    # README should NOT trigger a secret_candidate
    secret_paths = [a["metadata"]["path"] for a in r.assets
                    if a["kind"] == "secret_candidate"]
    assert secret_paths == ["deploy/.env"]


async def test_github_search_skips_when_no_token(ctx) -> None:
    ctx.settings.github_token = None
    r = await github_search.run("example.com", ctx)
    assert r.assets == []


async def test_github_search_with_token(ctx) -> None:
    ctx.settings.github_token = "ghp_test"
    body = load_fixture("github_code_search.json")
    with aioresponses() as m:
        m.get(
            "https://api.github.com/search/code?q=%22example.com%22&per_page=100",
            payload=body,
        )
        r = await github_search.run("example.com", ctx)
    assert any(a["kind"] == "repository" for a in r.assets)
    assert any(a["kind"] == "secret_candidate" for a in r.assets)
