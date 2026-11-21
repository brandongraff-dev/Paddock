"""CVE matching of a fingerprinted device against the shared feed (+ KEV)."""
from __future__ import annotations

import pytest

from app import cvematch
from app.fingerprint.device import Device


def _siemens_plc() -> Device:
    return Device(
        key="mac:00:1b:1b:00:00:10",
        mac="00:1b:1b:00:00:10",
        ips={"10.0.5.10"},
        vendor="Siemens",
        model="SIMATIC S7-1200",
        type="plc",
        role="ot",
        confidence=92,
    )


def _hp_printer() -> Device:
    return Device(
        key="mac:00:1b:78:00:00:60", mac="00:1b:78:00:00:60",
        ips={"10.0.0.60"}, vendor="Hewlett-Packard", model="OfficeJet",
        type="printer", role="iot", confidence=60,
    )


CVES = [
    {
        "id": "CVE-2021-0001", "cvss_v3": 7.5, "epss": 0.4,
        "description": "A flaw in SIMATIC S7-1200 firmware.",
        "refs": [{"url": "https://cert-portal.siemens.com/x"}],
        "known_exploited": False, "cwe_ids": ["CWE-306"],
        "cpe_affected": [
            {"vendor": "siemens", "product": "simatic_s7-1200_firmware", "version": "*"},
        ],
    },
    {
        "id": "CVE-2022-0002", "cvss_v3": 5.0, "epss": 0.9,
        "description": "A Siemens-wide issue listed in KEV.",
        "refs": [], "known_exploited": True, "cwe_ids": [],
        "cpe_affected": [{"vendor": "siemens", "product": "-", "version": "*"}],
    },
    {
        "id": "CVE-2023-0003", "cvss_v3": 9.8, "epss": 0.1,
        "description": "A Rockwell Logix issue (different vendor).",
        "refs": [], "known_exploited": False, "cwe_ids": [],
        "cpe_affected": [
            {"vendor": "rockwell_automation", "product": "controllogix", "version": "*"},
        ],
    },
]


async def _fetch_all(_tokens):
    return list(CVES)


@pytest.mark.asyncio
async def test_vendor_plus_product_match_is_cve_match():
    findings = await cvematch.match_devices([_siemens_plc()], _fetch_all)
    ids = {f["rule_id"] for f in findings}
    # vendor+product -> CVE-2021-0001; vendor+KEV -> CVE-2022-0002
    assert "CVE-2021-0001" in ids
    assert "CVE-2023-0003" not in ids  # different vendor, never matched

    f = next(f for f in findings if f["rule_id"] == "CVE-2021-0001")
    assert f["rule_source"] == "cve_match"
    assert f["severity"] == "high"        # cvss 7.5
    assert f["asset_kind"] == "ot_device"
    assert f["evidence"]["matched_cpe"]["product_hit"] is True
    assert f["cvss"] == 7.5


@pytest.mark.asyncio
async def test_kev_vendor_only_match_is_surfaced_as_critical():
    findings = await cvematch.match_devices([_siemens_plc()], _fetch_all)
    kev = next(f for f in findings if f["rule_id"] == "CVE-2022-0002")
    assert kev["severity"] == "critical"   # KEV bump
    assert kev["metadata"]["kev"] is True


@pytest.mark.asyncio
async def test_no_vendor_match_yields_nothing():
    findings = await cvematch.match_devices([_hp_printer()], _fetch_all)
    assert findings == []


def test_match_one_direct():
    matched, conf, ev = cvematch.match_one(_siemens_plc(), CVES[0])
    assert matched is True
    assert conf == 85
    assert ev["device_vendor"] == "Siemens"
