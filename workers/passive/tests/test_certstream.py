"""Pure-function tests for the CertStream parser."""
from __future__ import annotations

from app.modules.cert_transparency import (
    _cert_assets_from_message,
    _match_domains,
)


def test_match_domains_normalizes_and_filters() -> None:
    pairs = _match_domains(
        ["*.api.example.com", "www.example.com", "EXAMPLE.com", "evil.net"],
        ["example.com"],
    )
    names = {p[0] for p in pairs}
    assert "api.example.com" in names
    assert "www.example.com" in names
    assert "example.com" in names
    assert "evil.net" not in names


def test_cert_assets_from_message_builds_edges_and_assets() -> None:
    msg = {
        "message_type": "certificate_update",
        "data": {
            "cert_index": 9999,
            "leaf_cert": {
                "all_domains": ["api.example.com", "*.example.com"],
                "serial_number": "0a0b",
                "issuer": {"CN": "Let's Encrypt R3"},
                "not_before": 1700000000,
                "not_after":  1710000000,
            }
        }
    }
    assets, edges = _cert_assets_from_message(msg, ["example.com"])
    kinds = [a["kind"] for a in assets]
    assert kinds.count("certificate") == 1
    assert kinds.count("subdomain") == 2  # api. + bare example.com
    assert any(e["kind"] == "contains" for e in edges)
    assert any(e["kind"] == "issued_for" for e in edges)


def test_cert_assets_from_message_ignores_non_cert() -> None:
    assets, edges = _cert_assets_from_message({"message_type": "heartbeat"},
                                              ["example.com"])
    assert assets == [] and edges == []


def test_cert_assets_from_message_ignores_out_of_scope() -> None:
    msg = {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {
            "all_domains": ["foo.evil.net"], "serial_number": "01",
        }}
    }
    assets, _ = _cert_assets_from_message(msg, ["example.com"])
    assert assets == []
