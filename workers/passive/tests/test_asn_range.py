"""Tests for the ASN range module."""
from __future__ import annotations

from aioresponses import aioresponses

from app.modules import asn_range
from app.modules.asn_range import _parse_asn_or_ip, _build_result
from .conftest import load_fixture


def test_parse_asn_or_ip() -> None:
    assert _parse_asn_or_ip("AS12345") == ("asn", "12345")
    assert _parse_asn_or_ip("as 12345") == ("asn", "12345")
    assert _parse_asn_or_ip("12345") == ("asn", "12345")
    assert _parse_asn_or_ip("1.2.3.4") == ("ip", "1.2.3.4")
    assert _parse_asn_or_ip("notarealthing") == ("invalid", None)


def test_build_result_has_cidr_metadata() -> None:
    prefixes = [
        {"prefix": "203.0.113.0/24", "name": "n", "description": "d", "country_code": "US"},
        {"prefix": "2001:db8::/32", "name": "nv6", "description": "dv6"},
    ]
    r = _build_result(prefixes, "12345")
    ipv4 = [a for a in r.assets if a["kind"] == "ipv4"]
    ipv6 = [a for a in r.assets if a["kind"] == "ipv6"]
    assert len(ipv4) == 1 and ipv4[0]["metadata"]["cidr"] is True
    assert len(ipv6) == 1 and ipv6[0]["metadata"]["cidr"] is True
    assert ipv4[0]["metadata"]["asn"] == 12345


async def test_asn_range_from_asn(ctx) -> None:
    body = load_fixture("bgpview_asn_prefixes.json")
    with aioresponses() as m:
        m.get("https://api.bgpview.io/asn/12345/prefixes", payload=body)
        r = await asn_range.run("AS12345", ctx)
    values = {a["value"] for a in r.assets}
    assert "203.0.113.0/24" in values
    assert "198.51.100.0/24" in values
    assert "2001:db8::/32" in values
