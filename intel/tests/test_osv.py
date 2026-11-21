from __future__ import annotations

from app.sources import osv


def test_build_queries_includes_version() -> None:
    body = osv.build_queries([("npm", "left-pad", "1.0.0"), ("PyPI", "django", "4.1")])
    assert body["queries"][0]["package"]["ecosystem"] == "npm"
    assert body["queries"][0]["version"] == "1.0.0"
    assert body["queries"][1]["package"]["name"] == "django"


def test_build_queries_omits_empty_version() -> None:
    body = osv.build_queries([("npm", "left-pad", "")])
    assert "version" not in body["queries"][0]


def test_extract_ids_handles_missing_results() -> None:
    assert osv.extract_ids({}) == []
    assert osv.extract_ids({"results": [{}, {"vulns": []}]}) == [[], []]
    assert osv.extract_ids({"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]}) \
        == [["GHSA-1", "GHSA-2"]]


def test_cve_or_osv_prefers_cve_alias() -> None:
    assert osv.cve_or_osv_id({"id": "GHSA-abc", "aliases": ["CVE-2024-1111", "OTHER"]}) \
        == "CVE-2024-1111"
    assert osv.cve_or_osv_id({"id": "GHSA-xyz", "aliases": []}) == "GHSA-xyz"
    assert osv.cve_or_osv_id({}) is None
