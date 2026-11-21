"""Tests for the CT-logs module."""
from __future__ import annotations

from aioresponses import aioresponses

from app.modules import ct_logs
from app.modules.ct_logs import (
    _extract_names,
    _normalize_name,
    _parse_crtsh_rows,
)
from .conftest import load_fixture


def test_normalize_name_strips_wildcard_and_case() -> None:
    assert _normalize_name(" *.API.Example.com. ") == "api.example.com"
    assert _normalize_name("Example.COM") == "example.com"
    assert _normalize_name("") == ""


def test_extract_names_filters_to_apex() -> None:
    raw = "api.example.com\n*.example.com\nunrelated.net\nfoo.example.com"
    names = _extract_names(raw, "example.com")
    assert "api.example.com" in names
    assert "foo.example.com" in names
    assert "example.com" in names      # wildcard stripped
    assert "unrelated.net" not in names


def test_parse_crtsh_rows_fixture() -> None:
    rows = load_fixture("crtsh_example.json")
    subs, certs = _parse_crtsh_rows(rows, "example.com")
    assert "api.example.com" in subs
    assert "www.api.example.com" in subs
    assert "example.com" in subs
    assert "unrelated.net" not in subs
    assert "foo.unrelated.net" not in subs
    # certs dedup by serial_number
    serials = {c["serial_number"] for c in certs}
    assert serials == {"03abcd", "04ef01", "deadbeef"}


async def test_ct_logs_run_builds_assets_and_edges(ctx) -> None:
    rows = load_fixture("crtsh_example.json")
    with aioresponses() as m:
        m.get("https://crt.sh/?q=%25.example.com&output=json", payload=rows)
        result = await ct_logs.run("example.com", ctx)

    kinds = {a["kind"] for a in result.assets}
    assert "domain" in kinds
    assert "subdomain" in kinds
    assert "certificate" in kinds

    sub_values = {a["value"] for a in result.assets if a["kind"] == "subdomain"}
    assert "api.example.com" in sub_values
    assert "www.api.example.com" in sub_values

    # edges: subdomain -> domain (contains), cert -> subdomain (issued_for)
    edge_kinds = {e["kind"] for e in result.edges}
    assert "contains" in edge_kinds
    assert "issued_for" in edge_kinds

    # no cross-domain leakage
    assert not any("unrelated.net" in a["value"] for a in result.assets)


async def test_ct_logs_handles_404_and_falls_back_to_empty(ctx) -> None:
    with aioresponses() as m:
        m.get("https://crt.sh/?q=%25.example.com&output=json", status=503)
        # No Censys creds configured → fallback returns []
        result = await ct_logs.run("example.com", ctx)
    # Only the "root" domain asset is emitted; no subdomains or certs.
    assert [a for a in result.assets if a["kind"] == "subdomain"] == []
    assert [a for a in result.assets if a["kind"] == "certificate"] == []
    assert result.source_calls == 0
