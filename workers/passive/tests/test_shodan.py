"""Tests for the Shodan + InternetDB module."""
from __future__ import annotations

from aioresponses import aioresponses

from app.modules import shodan_lookup
from app.modules.shodan_lookup import _expand, _merge_host
from .conftest import load_fixture


def test_expand_ip_and_cidr() -> None:
    assert _expand("203.0.113.5") == ["203.0.113.5"]
    expanded = _expand("203.0.113.0/30")
    # /30 has 2 usable hosts
    assert len(expanded) == 2
    assert _expand("not-an-ip") == []


def test_merge_host_combines_ports_from_shodan_data() -> None:
    base = {"ip": "1.2.3.4", "ports": [80], "cpes": [], "hostnames": [], "tags": []}
    enriched = {"data": [
        {"port": 443, "product": "nginx", "version": "1.18.0",
         "transport": "tcp", "cpe": ["cpe:/a:nginx:nginx:1.18.0"]},
    ]}
    merged = _merge_host(base, enriched)
    assert 80 in merged["ports"]
    assert 443 in merged["ports"]
    assert merged["services"][0]["product"] == "nginx"


async def test_internetdb_emits_port_service_tech(ctx) -> None:
    body = load_fixture("internetdb_example.json")
    ip = body["ip"]
    with aioresponses() as m:
        m.get(f"https://internetdb.shodan.io/{ip}", payload=body)
        r = await shodan_lookup.run(ip, ctx)

    kinds = {a["kind"] for a in r.assets}
    assert "ipv4" in kinds
    assert "port" in kinds
    assert "technology" in kinds  # from cpes[]
    assert any(a["kind"] == "port" and a["value"].endswith(":443") for a in r.assets)
    assert any(e["kind"] == "hosts" for e in r.edges)


async def test_internetdb_404_is_silent(ctx) -> None:
    with aioresponses() as m:
        m.get("https://internetdb.shodan.io/192.0.2.99", status=404)
        r = await shodan_lookup.run("192.0.2.99", ctx)
    assert r.assets == []
