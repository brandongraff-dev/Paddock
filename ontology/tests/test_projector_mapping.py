"""Pure projection mapping tests (no DB): row -> object, edge -> link."""
from __future__ import annotations

import uuid

from app import types as T


def _aid() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# asset -> object
# --------------------------------------------------------------------------- #

def test_subdomain_asset_becomes_host():
    aid = _aid()
    obj = T.asset_to_object({
        "id": aid, "kind": "subdomain", "value": "api.example.com",
        "canonical": "api.example.com", "confidence": 90, "source": "dns",
        "metadata": {"env": "prod"}, "classification": "confidential",
    })
    assert obj is not None
    assert obj["object_type"] == "Host"
    assert obj["title"] == "api.example.com"
    assert obj["backing_table"] == "assets"
    assert obj["backing_id"] == aid
    assert obj["classification"] == "confidential"
    assert obj["properties"]["env"] == "prod"
    assert obj["properties"]["kind"] == "subdomain"


def test_ip_and_domain_also_host():
    for kind in ("ipv4", "ipv6", "domain"):
        obj = T.asset_to_object({
            "id": _aid(), "kind": kind, "value": "x", "canonical": "x",
            "confidence": 100, "source": "s", "metadata": {},
            "classification": "internal",
        })
        assert obj["object_type"] == "Host"


def test_port_and_service_become_service():
    for kind in ("port", "service"):
        obj = T.asset_to_object({
            "id": _aid(), "kind": kind, "value": "tcp/443", "canonical": "tcp/443",
            "confidence": 100, "source": "scan", "metadata": {"port": "443", "protocol": "tcp"},
            "classification": "internal",
        })
        assert obj["object_type"] == "Service"


def test_technology_secret_cert_repository_mapping():
    cases = {
        "technology": "Technology",
        "secret_candidate": "Secret",
        "certificate": "Certificate",
        "repository": "Repository",
    }
    for kind, otype in cases.items():
        obj = T.asset_to_object({
            "id": _aid(), "kind": kind, "value": "v", "canonical": "v",
            "confidence": 100, "source": "s", "metadata": {}, "classification": "internal",
        })
        assert obj is not None and obj["object_type"] == otype


def test_unmapped_asset_kind_returns_none():
    for kind in ("org", "endpoint", "cloud_account", "cloud_resource"):
        obj = T.asset_to_object({
            "id": _aid(), "kind": kind, "value": "v", "canonical": "v",
            "confidence": 100, "source": "s", "metadata": {}, "classification": "internal",
        })
        assert obj is None


def test_missing_classification_defaults_internal():
    obj = T.asset_to_object({
        "id": _aid(), "kind": "domain", "value": "v", "canonical": "v",
        "confidence": 100, "source": "s", "metadata": {}, "classification": None,
    })
    assert obj["classification"] == "internal"


# --------------------------------------------------------------------------- #
# finding / package / ticket / attackpath -> object
# --------------------------------------------------------------------------- #

def test_finding_becomes_vulnerability():
    fid = _aid()
    obj = T.finding_to_object({
        "id": fid, "rule_id": "CVE-2021-1", "rule_source": "cve_match",
        "severity": "high", "status": "open", "title": "RCE in widget",
        "cvss": 9.8, "epss": 0.4, "classification": "restricted",
    })
    assert obj["object_type"] == "Vulnerability"
    assert obj["title"] == "RCE in widget"
    assert obj["backing_table"] == "findings"
    assert obj["backing_id"] == fid
    assert obj["classification"] == "restricted"
    assert obj["properties"]["cvss"] == 9.8
    assert obj["properties"]["severity"] == "high"


def test_package_object_title_is_name_at_version():
    obj = T.package_to_object({
        "id": _aid(), "project_id": _aid(), "ecosystem": "npm",
        "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0",
        "direct": True, "depth": 0,
    })
    assert obj["object_type"] == "Package"
    assert obj["title"] == "left-pad@1.0.0"
    assert obj["properties"]["ecosystem"] == "npm"


def test_ticket_and_team_objects():
    t = T.ticket_to_object({
        "id": _aid(), "finding_id": _aid(), "title": "Fix RCE", "status": "open",
        "severity": "high", "system": "internal", "owner_team": "platform",
        "sla_due": None, "breached": False,
    })
    assert t["object_type"] == "Ticket"
    assert t["properties"]["owner_team"] == "platform"

    team = T.team_to_object("platform")
    assert team["object_type"] == "Team"
    assert team["backing_table"] == "team"
    assert team["backing_id"] == "platform"
    assert team["title"] == "platform"


def test_attackpath_object():
    obj = T.attackpath_to_object({
        "id": _aid(), "source_asset_id": _aid(), "target_asset_id": _aid(),
        "hops": [], "length": 3, "severity": "critical",
        "exploitability": 72.5, "kev_on_path": True, "title": "edge->crown",
    })
    assert obj["object_type"] == "AttackPath"
    assert obj["properties"]["exploitability"] == 72.5
    assert obj["properties"]["kev_on_path"] is True


# --------------------------------------------------------------------------- #
# edge -> link classification
# --------------------------------------------------------------------------- #

def test_resolves_to_edge_host_to_host():
    assert T.classify_edge("Host", "Host", "resolves_to") == ("RESOLVES_TO", None)


def test_host_host_contains_is_not_a_link():
    # domain contains subdomain: both Host, but not a resolve -> skipped.
    assert T.classify_edge("Host", "Host", "contains") is None


def test_host_service_edge_becomes_runs_oriented_host_first():
    # stored as port(Service) hosts ipv4(Host): from_type says Host leads.
    assert T.classify_edge("Service", "Host", "hosts") == ("RUNS", "Host")
    assert T.classify_edge("Host", "Service", "runs") == ("RUNS", "Host")


def test_certificate_host_edge_becomes_secures():
    assert T.classify_edge("Certificate", "Host", "issued_for") == ("SECURES", "Certificate")


def test_repository_secret_edge_becomes_contains():
    assert T.classify_edge("Repository", "Secret", "contains") == ("CONTAINS", "Repository")


def test_unknown_or_none_endpoints_skip():
    assert T.classify_edge(None, "Host", "resolves_to") is None
    assert T.classify_edge("Technology", "Service", "has_version") is None
