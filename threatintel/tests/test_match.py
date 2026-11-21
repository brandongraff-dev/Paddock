"""Matching tests: pure match logic + an end-to-end run over FakeDB."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import match


# --------------------------------------------------------------------------- #
# severity
# --------------------------------------------------------------------------- #

def test_severity_c2_label_is_critical():
    assert match.severity_for(["c2", "malicious-activity"], []) == "critical"


def test_severity_malware_present_is_critical():
    assert match.severity_for([], ["Emotet"]) == "critical"


def test_severity_default_is_high():
    assert match.severity_for(["suspicious"], []) == "high"
    assert match.severity_for([], []) == "high"


# --------------------------------------------------------------------------- #
# indicator <-> asset (pure)
# --------------------------------------------------------------------------- #

def test_ipv4_exact_equality():
    ind = {"type": "ipv4", "value": "203.0.113.10"}
    assert match.indicator_asset_match(ind, {"kind": "ipv4", "value": "203.0.113.10"}) == "203.0.113.10"
    assert match.indicator_asset_match(ind, {"kind": "ipv4", "value": "203.0.113.11"}) is None


def test_ipv6_equality_case_insensitive():
    ind = {"type": "ipv6", "value": "2001:DB8::1"}
    assert match.indicator_asset_match(ind, {"kind": "ipv6", "value": "2001:db8::1"})


def test_domain_suffix_matches_subdomain():
    ind = {"type": "domain", "value": "evil.com"}
    assert match.indicator_asset_match(ind, {"kind": "domain", "value": "evil.com"}) == "evil.com"
    assert match.indicator_asset_match(ind, {"kind": "subdomain", "value": "login.evil.com"}) == "login.evil.com"
    # not a suffix match
    assert match.indicator_asset_match(ind, {"kind": "subdomain", "value": "evil.com.safe.net"}) is None
    assert match.indicator_asset_match(ind, {"kind": "subdomain", "value": "notevil.com"}) is None


def test_cidr_contains_asset_ip():
    ind = {"type": "cidr", "value": "192.0.2.0/24"}
    assert match.indicator_asset_match(ind, {"kind": "ipv4", "value": "192.0.2.55"}) == "192.0.2.55"
    assert match.indicator_asset_match(ind, {"kind": "ipv4", "value": "192.0.3.1"}) is None


def test_url_host_matches_endpoint_and_domain():
    ind = {"type": "url", "value": "http://bad.example/x"}
    assert match.indicator_asset_match(ind, {"kind": "endpoint", "value": "http://bad.example/other"})
    assert match.indicator_asset_match(ind, {"kind": "domain", "value": "bad.example"})


def test_endpoint_host_matches_ip_indicator():
    ind = {"type": "ipv4", "value": "203.0.113.10"}
    assert match.indicator_asset_match(ind, {"kind": "endpoint", "value": "http://203.0.113.10:8080/a"})


def test_url_helper_parses_hosts():
    assert match.url_host("http://a.b.com:8443/x?y=1") == "a.b.com"
    assert match.url_host("a.b.com/x") == "a.b.com"
    assert match.url_host("") is None


# --------------------------------------------------------------------------- #
# findings evidence (pure)
# --------------------------------------------------------------------------- #

def test_evidence_iocs_extracts_hashes_urls_emails():
    ev = {
        "nested": {"sha256": "a" * 64, "md5": "b" * 32},
        "url": "http://bad.example/drop",
        "note": "contact attacker@phish.example for decryptor",
    }
    iocs = match.evidence_iocs(ev)
    assert ("a" * 64) in iocs["hashes"]
    assert ("b" * 32) in iocs["hashes"]
    assert "http://bad.example/drop" in iocs["urls"]
    assert "attacker@phish.example" in iocs["emails"]


def test_indicator_finding_match_hash_and_url():
    iocs = {"hashes": {"a" * 64}, "urls": {"http://bad.example/drop"}, "emails": set()}
    assert match.indicator_finding_match({"type": "file_sha256", "value": "A" * 64}, iocs) == "A" * 64
    assert match.indicator_finding_match({"type": "url", "value": "http://bad.example/drop"}, iocs)
    assert match.indicator_finding_match({"type": "file_md5", "value": "c" * 32}, iocs) is None


# --------------------------------------------------------------------------- #
# end-to-end over FakeDB + FakeOrchestrator
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_run_match_writes_matches_and_emits_findings(fake_db, fake_orch):
    # assets the owner owns
    a_ip = fake_db.seed_asset("ipv4", "203.0.113.10")
    a_sub = fake_db.seed_asset("subdomain", "login.evil.com")
    fake_db.seed_asset("ipv4", "10.0.0.1")  # unrelated, must not match
    # a finding whose evidence embeds a known-bad hash
    a_host = fake_db.seed_asset("domain", "clean.example")
    f_id = fake_db.seed_finding(a_host, {"artifact_sha256": "a" * 64})

    await fake_db.seed_indicator(type="ipv4", value="203.0.113.10",
                                 labels=["malicious-activity"], malware=[], threat_actor="APT-X")
    await fake_db.seed_indicator(type="domain", value="evil.com",
                                 labels=["c2"], malware=["Emotet"])
    await fake_db.seed_indicator(type="file_sha256", value="a" * 64, labels=[], malware=[])

    res = await match.run_match(fake_db, fake_orch)

    assert res["matches"] == 3
    assert res["findings_emitted"] == 3

    subjects = {(m["subject_type"], m["subject_id"]) for m in fake_db.matches}
    assert ("asset", a_ip) in subjects
    assert ("asset", a_sub) in subjects
    assert ("finding", f_id) in subjects

    # severities: ip (malicious-activity) -> high; domain (c2/malware) -> critical
    sev = {m["subject_id"]: m["severity"] for m in fake_db.matches}
    assert sev[a_ip] == "high"
    assert sev[a_sub] == "critical"

    # finding_id threaded back into the match rows
    assert all(m["finding_id"] for m in fake_db.matches)
    # every emitted finding is a threat_intel finding titled as specified
    assert all(f["rule_source"] == "threat_intel" for f in fake_orch.posted_findings)
    assert all(f["title"].startswith("Asset matches threat indicator") for f in fake_orch.posted_findings)


@pytest.mark.asyncio
async def test_run_match_is_idempotent(fake_db, fake_orch):
    fake_db.seed_asset("ipv4", "203.0.113.10")
    await fake_db.seed_indicator(type="ipv4", value="203.0.113.10")
    first = await match.run_match(fake_db, fake_orch)
    second = await match.run_match(fake_db, fake_orch)
    assert first["matches"] == 1
    assert second["matches"] == 0  # already present, no new rows
    assert len(fake_db.matches) == 1


@pytest.mark.asyncio
async def test_run_match_skips_expired_indicators(fake_db, fake_orch):
    fake_db.seed_asset("ipv4", "203.0.113.10")
    await fake_db.seed_indicator(
        type="ipv4", value="203.0.113.10",
        valid_until=datetime.now(timezone.utc) - timedelta(days=1),
    )
    res = await match.run_match(fake_db, fake_orch)
    assert res["matches"] == 0
