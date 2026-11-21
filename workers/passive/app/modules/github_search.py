"""GitHub code-search passive recon.

We never clone a repo. We ask the search index for matches of the target
domain (optionally OR'd with an org slug from the job config) and surface:
  - a `repository` asset for each hit
  - a `secret_candidate` asset when the match is in a config-shaped path
    (.env, docker-compose.yml, config.*, .npmrc, .pypirc, terraform state,
    etc.) so the correlation service can promote high-confidence ones.

GITHUB_TOKEN is required (REST code search is auth-gated). Without it we
return an empty result rather than failing.
"""
from __future__ import annotations

import re
from typing import Any

from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


GITHUB_SOURCE = "github"

# Path fragments that look like configuration or secrets. Case-insensitive.
CONFIG_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(re.compile(p, re.I) for p in (
    r"(^|/)\.env($|\.)",
    r"(^|/)docker-compose(\.[\w.-]+)?\.ya?ml$",
    r"(^|/)config\.ya?ml$",
    r"(^|/)secrets?\.(ya?ml|json|env)$",
    r"(^|/)credentials?(\.|$)",
    r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$",
    r"(^|/)id_rsa($|\.)",
    r"(^|/)terraform\.tfstate(\.backup)?$",
    r"(^|/)\.aws/credentials$",
    r"(^|/)\.htpasswd$",
    r"(^|/)appsettings\.[\w.-]+\.json$",
))


def _is_config_path(path: str) -> bool:
    if not path:
        return False
    return any(p.search(path) for p in CONFIG_PATH_PATTERNS)


async def _search(ctx: ModuleContext, query: str, token: str) -> list[dict[str, Any]]:
    url = "https://api.github.com/search/code"
    status, body = await ctx.get_json(
        url,
        source=GITHUB_SOURCE,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params={"q": query, "per_page": 100},
    )
    if status >= 400 or not isinstance(body, dict):
        logger.warning("github code search returned status={}", status)
        return []
    return body.get("items", []) or []


def _parse_items(items: list[dict[str, Any]], domain: str) -> ModuleResult:
    result = ModuleResult(module="github_search")
    seen_repos: set[str] = set()
    for item in items:
        repo = item.get("repository") or {}
        repo_full = repo.get("full_name") or ""
        path = item.get("path") or ""
        html_url = item.get("html_url") or ""
        if not repo_full:
            continue
        if repo_full not in seen_repos:
            seen_repos.add(repo_full)
            result.assets.append({
                "kind": "repository",
                "value": f"github.com/{repo_full}",
                "source": "github",
                "metadata": {
                    "owner": repo.get("owner", {}).get("login"),
                    "name": repo.get("name"),
                    "private": repo.get("private", False),
                    "html_url": repo.get("html_url"),
                    "description": repo.get("description"),
                    "mention": domain,
                },
            })
        if _is_config_path(path):
            # Severity metadata only — correlation decides whether to promote.
            result.assets.append({
                "kind": "secret_candidate",
                "value": f"github.com/{repo_full}:{path}",
                "source": "github",
                "metadata": {
                    "repository": repo_full,
                    "path": path,
                    "html_url": html_url,
                    "severity_hint": "high" if ".env" in path or "credential" in path.lower() else "medium",
                    "match_domain": domain,
                    "match_type": "config_file_mentioning_domain",
                },
            })
            result.edges.append({
                "src_kind": "secret_candidate",
                "src_value": f"github.com/{repo_full}:{path}",
                "dst_kind": "repository",
                "dst_value": f"github.com/{repo_full}",
                "kind": "contained_in",
            })
    return result


async def run(domain: str, ctx: ModuleContext, *, org: str | None = None) -> ModuleResult:
    token = ctx.settings.github_token
    if not token:
        logger.info("github_search skipped: GITHUB_TOKEN not set")
        return ModuleResult(module="github_search")

    # Build the query. We do an OR when we have an org slug — the API accepts it.
    parts = [f'"{domain}"']
    if org:
        parts.append(f'"{org}"')
    query = " OR ".join(parts)

    items = await _search(ctx, query, token)
    result = _parse_items(items, domain)
    result.source_calls = 1
    return result
