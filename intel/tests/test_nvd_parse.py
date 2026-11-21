"""NVD JSON parser tests."""
from __future__ import annotations

import json

from app.sources import nvd
from tests.conftest import load_fixture


def test_parses_a_full_nvd_record() -> None:
    payload = load_fixture("nvd_sample.json")
    first = payload["vulnerabilities"][0]
    parsed = nvd.parse_cve(first)
    assert parsed is not None
    assert parsed["id"] == "CVE-2024-1234"
    assert parsed["cvss_v3"] == 7.5
    assert parsed["cvss_v3_vector"].startswith("CVSS:3.1/")
    assert parsed["cvss_v2"] == 5.0
    assert "buffer overflow" in parsed["description"].lower()
    assert parsed["cwe_ids"] == ["CWE-120"]
    assert len(parsed["refs"]) == 2
    assert parsed["cpe_affected"] and parsed["cpe_affected"][0]["product"] == "example-lib"
    assert parsed["cpe_affected"][0]["versionStartIncluding"] == "1.0.0"
    assert parsed["cpe_affected"][0]["versionEndExcluding"] == "1.4.2"


def test_parses_a_record_with_exact_version_cpe() -> None:
    payload = load_fixture("nvd_sample.json")
    second = payload["vulnerabilities"][1]
    parsed = nvd.parse_cve(second)
    assert parsed is not None
    assert parsed["id"] == "CVE-2024-5678"
    assert parsed["cvss_v3"] == 9.1
    assert parsed["cpe_affected"][0]["vendor"] == "nginx"
    assert parsed["cpe_affected"][0]["version"] == "1.18.0"


def test_missing_optional_fields_dont_crash() -> None:
    raw = {"cve": {
        "id": "CVE-2000-0000",
        # no descriptions, no metrics, no configurations, no weaknesses
    }}
    parsed = nvd.parse_cve(raw)
    assert parsed is not None
    assert parsed["id"] == "CVE-2000-0000"
    assert parsed["cvss_v3"] is None
    assert parsed["cvss_v3_vector"] is None
    assert parsed["cvss_v2"] is None
    assert parsed["description"] is None
    assert parsed["refs"] == []
    assert parsed["cpe_affected"] == []
    assert parsed["cwe_ids"] == []


def test_returns_none_for_junk_input() -> None:
    assert nvd.parse_cve({}) is None
    assert nvd.parse_cve({"cve": {}}) is None
    assert nvd.parse_cve(None) is None  # type: ignore[arg-type]


def test_window_split_respects_max_days() -> None:
    from datetime import datetime, timedelta, timezone
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=250)
    windows = nvd.iter_windows(start, end, max_days=110)
    assert len(windows) == 3
    # No gaps, no overlaps
    assert windows[0][1] == windows[1][0]
    assert windows[1][1] == windows[2][0]
    assert windows[-1][1] == end


def test_window_split_handles_empty_range() -> None:
    from datetime import datetime, timezone
    t = datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert nvd.iter_windows(t, t) == []
