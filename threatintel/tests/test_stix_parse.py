"""Pure STIX 2.1 parsing tests (no network, no DB)."""
from __future__ import annotations

from app import stix
from tests.conftest import load_fixture


# --------------------------------------------------------------------------- #
# Pattern parsing
# --------------------------------------------------------------------------- #

def test_parse_pattern_ipv4():
    assert stix.parse_pattern("[ipv4-addr:value = '203.0.113.10']") == [
        ("ipv4", "203.0.113.10")
    ]


def test_parse_pattern_ipv6():
    out = stix.parse_pattern("[ipv6-addr:value = '2001:db8::1']")
    assert out == [("ipv6", "2001:db8::1")]


def test_parse_pattern_cidr_detected_from_ip_object():
    assert stix.parse_pattern("[ipv4-addr:value = '192.0.2.0/24']") == [
        ("cidr", "192.0.2.0/24")
    ]


def test_parse_pattern_domain_lowercased():
    assert stix.parse_pattern("[domain-name:value = 'Evil-C2.Example']") == [
        ("domain", "evil-c2.example")
    ]


def test_parse_pattern_url_preserved():
    assert stix.parse_pattern("[url:value = 'http://bad.example/payload.bin']") == [
        ("url", "http://bad.example/payload.bin")
    ]


def test_parse_pattern_sha256_and_md5():
    sha = "a" * 64
    md5 = "b" * 32
    assert stix.parse_pattern(f"[file:hashes.'SHA-256' = '{sha}']") == [
        ("file_sha256", sha)
    ]
    assert stix.parse_pattern(f"[file:hashes.MD5 = '{md5}']") == [
        ("file_md5", md5)
    ]


def test_parse_pattern_email():
    assert stix.parse_pattern("[email-addr:value = 'Bad@Phish.Example']") == [
        ("email", "bad@phish.example")
    ]


def test_parse_pattern_compound_or():
    out = stix.parse_pattern(
        "[ipv4-addr:value = '198.51.100.5' OR domain-name:value = 'multi.example']"
    )
    assert ("ipv4", "198.51.100.5") in out
    assert ("domain", "multi.example") in out
    assert len(out) == 2


def test_parse_pattern_unsupported_object_dropped():
    assert stix.parse_pattern("[network-traffic:dst_ref.value = 'x']") == []


def test_parse_pattern_malformed_is_safe():
    for bad in ["", "not a pattern", "[", "[domain-name:value = ]", None]:
        assert stix.parse_pattern(bad) == []  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Bundle parsing (fixture)
# --------------------------------------------------------------------------- #

def test_parse_bundle_extracts_all_supported_iocs():
    bundle = load_fixture("stix_bundle.json")
    records = stix.parse_bundle(bundle, source="unit")
    by_type: dict[str, list[str]] = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r["value"])

    assert "203.0.113.10" in by_type["ipv4"]
    assert "evil-c2.example" in by_type["domain"]
    assert "multi.example" in by_type["domain"]
    assert "198.51.100.5" in by_type["ipv4"]
    assert "192.0.2.0/24" in by_type["cidr"]
    assert "http://bad.example/payload.bin" in by_type["url"]
    assert ("a" * 64) in by_type["file_sha256"]
    assert "attacker@phish.example" in by_type["email"]


def test_parse_bundle_attaches_malware_and_actor_via_relationships():
    bundle = load_fixture("stix_bundle.json")
    records = stix.parse_bundle(bundle)
    by_value = {r["value"]: r for r in records}

    # domain indicator -> Emotet (relationship 'indicates' malware)
    assert by_value["evil-c2.example"]["malware"] == ["Emotet"]
    assert "c2" in by_value["evil-c2.example"]["labels"]
    # ipv4 indicator -> APT-X (relationship 'indicates' threat-actor)
    assert by_value["203.0.113.10"]["threat_actor"] == "APT-X"
    assert by_value["203.0.113.10"]["confidence"] == 90


def test_parse_bundle_skips_malformed_objects():
    bundle = load_fixture("stix_bundle.json")
    records = stix.parse_bundle(bundle)
    # the no-pattern indicator and junk object contribute nothing
    assert all(r["value"] for r in records)
    assert all(r["type"] in stix.VALID_TYPES for r in records)


def test_parse_bundle_accepts_json_string():
    import json
    bundle = load_fixture("stix_bundle.json")
    records = stix.parse_bundle(json.dumps(bundle))
    assert len(records) >= 8


def test_parse_bundle_garbage_input_is_empty():
    assert stix.parse_bundle("not json") == []
    assert stix.parse_bundle(None) == []
    assert stix.parse_bundle({"type": "bundle"}) == []
    assert stix.parse_bundle({"objects": "nope"}) == []


def test_compound_indicator_drops_stix_id_to_avoid_unique_collision():
    # a compound pattern yields 2 records; they must not share one stix_id
    bundle = load_fixture("stix_bundle.json")
    records = stix.parse_bundle(bundle)
    compound = [r for r in records if r["value"] in ("198.51.100.5", "multi.example")]
    assert len(compound) == 2
    assert all(r["stix_id"] is None for r in compound)
