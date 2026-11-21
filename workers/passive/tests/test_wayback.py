"""Tests for the Wayback module."""
from __future__ import annotations

from aioresponses import aioresponses

from app.modules import wayback
from app.modules.wayback import _parse_cdx
from .conftest import load_fixture


def test_parse_cdx_filters_to_domain_and_dedupes() -> None:
    rows = load_fixture("wayback_example.json")
    parsed = _parse_cdx(rows, "example.com")
    # drops evil.net
    hosts = {v["host"] for v in parsed.values()}
    assert "evil.net" not in hosts
    assert {"www.example.com", "api.example.com", "cdn.example.com"} <= hosts


async def test_wayback_run_emits_endpoint_assets(ctx) -> None:
    rows = load_fixture("wayback_example.json")
    with aioresponses() as m:
        m.get(
            "https://web.archive.org/cdx/search/cdx?"
            "url=%2A.example.com&output=json&fl=original%2Ctimestamp%2Cmimetype"
            "&collapse=urlkey&limit=5000",
            payload=rows,
        )
        r = await wayback.run("example.com", ctx)

    endpoint_values = {a["value"] for a in r.assets if a["kind"] == "endpoint"}
    assert "https://www.example.com/login" in endpoint_values
    assert "https://evil.net/phish" not in endpoint_values
    assert all(a["metadata"].get("first_seen_wayback") for a in r.assets
               if a["kind"] == "endpoint")
