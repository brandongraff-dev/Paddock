"""Wayback Machine CDX passive endpoint enumeration.

We ask the Wayback CDX API for every unique URL ever archived under
`*.{domain}`. The response format is a JSON "table": first row = header,
subsequent rows = values. We request:
   fl=original,timestamp,mimetype
   collapse=urlkey
   limit=5000

We emit `endpoint` assets with metadata {first_seen_wayback, mimetype}.
URLs whose host isn't under the scope domain are dropped during scope
filtering by the main loop; we also pre-filter here so that the bulk-post
payload isn't gigantic.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


WAYBACK_SOURCE = "wayback"


def _parse_cdx(rows: list[list[Any]], domain: str) -> dict[str, dict[str, Any]]:
    """Return mapping url -> {timestamp, mimetype}, filtered to the domain."""
    if not rows or len(rows) < 2:
        return {}
    header = [h.lower() for h in rows[0]]
    try:
        i_url = header.index("original")
        i_ts = header.index("timestamp")
        i_mt = header.index("mimetype")
    except ValueError:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows[1:]:
        if len(row) <= max(i_url, i_ts, i_mt):
            continue
        url = str(row[i_url])
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        host = host.lower().rstrip(".")
        if not host:
            continue
        if host != domain and not host.endswith("." + domain):
            continue
        if url in out:
            # keep the earliest timestamp we see
            existing = out[url]["first_seen_wayback"]
            if str(row[i_ts]) < str(existing):
                out[url]["first_seen_wayback"] = str(row[i_ts])
            continue
        out[url] = {
            "first_seen_wayback": str(row[i_ts]),
            "mimetype": str(row[i_mt]),
            "host": host,
        }
    return out


async def run(domain: str, ctx: ModuleContext) -> ModuleResult:
    domain = domain.strip().lower().rstrip(".")
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}",
        "output": "json",
        "fl": "original,timestamp,mimetype",
        "collapse": "urlkey",
        "limit": 5000,
    }
    status, body = await ctx.get_json(url, source=WAYBACK_SOURCE, params=params)
    if status >= 400 or not isinstance(body, list):
        logger.warning("wayback returned status={}", status)
        return ModuleResult(module="wayback")

    endpoints = _parse_cdx(body, domain)
    result = ModuleResult(module="wayback")
    for u, meta in endpoints.items():
        host = meta["host"]
        result.assets.append({
            "kind": "endpoint",
            "value": u,
            "source": "wayback",
            "metadata": {
                "first_seen_wayback": meta["first_seen_wayback"],
                "mimetype": meta["mimetype"],
                "host": host,
            },
        })
        # tie endpoint to the host subdomain/domain
        result.edges.append({
            "src_kind": "endpoint", "src_value": u,
            "dst_kind": "subdomain" if host != domain else "domain",
            "dst_value": host,
            "kind": "references",
        })
    result.source_calls = 1
    return result
