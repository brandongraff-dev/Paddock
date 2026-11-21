"""Shodan lookup — passive host intel.

InternetDB ( https://internetdb.shodan.io/{ip} ) is free and keyless. For
each in-scope IP we retrieve:
  {ip, ports: [int], hostnames: [str], cpes: [str], tags: [str], vulns: [str]}

If SHODAN_API_KEY is set we additionally pull the real host endpoint
( https://api.shodan.io/shodan/host/{ip} ) for richer service banners.

We emit:
  - `port` assets for each open port (value = "<ip>:<port>")
  - `service` assets for each detected service (value = "<ip>:<port>/<name>")
  - `technology` assets per CPE
  - edges: port -(hosts)-> ipv4, service -(runs)-> port, technology -(has_version)-> service

Target input can be a bare IP or a CIDR. CIDRs expand client-side.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


INTERNETDB_SOURCE = "internetdb"
SHODAN_SOURCE = "shodan"
MAX_CIDR_HOSTS = 1024


def _expand(target: str) -> list[str]:
    """Return a list of IP strings; accepts an IP, CIDR, or comma list."""
    out: list[str] = []
    for piece in target.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            net = ipaddress.ip_network(piece, strict=False)
        except ValueError:
            continue
        hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
        if len(hosts) > MAX_CIDR_HOSTS:
            logger.warning("shodan target CIDR too large; truncating {} -> {}",
                           len(hosts), MAX_CIDR_HOSTS)
            hosts = hosts[:MAX_CIDR_HOSTS]
        out.extend(str(h) for h in hosts)
    return out


async def _internetdb(ctx: ModuleContext, ip: str) -> dict[str, Any] | None:
    url = f"https://internetdb.shodan.io/{ip}"
    status, body = await ctx.get_json(url, source=INTERNETDB_SOURCE)
    if status == 404 or not isinstance(body, dict):
        return None
    if status >= 400:
        return None
    return body


async def _shodan_host(ctx: ModuleContext, ip: str, api_key: str) -> dict[str, Any] | None:
    url = f"https://api.shodan.io/shodan/host/{ip}"
    status, body = await ctx.get_json(
        url, source=SHODAN_SOURCE, params={"key": api_key},
    )
    if status >= 400 or not isinstance(body, dict):
        return None
    return body


def _merge_host(primary: dict[str, Any], enriched: dict[str, Any] | None) -> dict[str, Any]:
    if not enriched:
        return primary
    out = dict(primary)
    # merge port list
    ports = set(primary.get("ports", []) or [])
    for s in enriched.get("data", []) or []:
        p = s.get("port")
        if p:
            ports.add(p)
    out["ports"] = sorted(ports)
    # richer service metadata
    out["services"] = [
        {
            "port": s.get("port"),
            "transport": s.get("transport"),
            "product": s.get("product"),
            "version": s.get("version"),
            "cpe": s.get("cpe") or [],
        }
        for s in enriched.get("data", []) or []
    ]
    return out


def _result_for_ip(ip: str, host: dict[str, Any]) -> ModuleResult:
    r = ModuleResult(module="shodan_lookup")
    r.assets.append({"kind": "ipv4", "value": ip, "source": "shodan", "metadata": {
        "hostnames": host.get("hostnames", []),
        "tags": host.get("tags", []),
        "cpes": host.get("cpes", []),
        "vulns": host.get("vulns", []),
    }})
    for port in host.get("ports", []) or []:
        port_value = f"{ip}:{port}"
        r.assets.append({
            "kind": "port",
            "value": port_value,
            "source": "shodan",
            "metadata": {"ip": ip, "port": int(port)},
        })
        r.edges.append({
            "src_kind": "port", "src_value": port_value,
            "dst_kind": "ipv4", "dst_value": ip,
            "kind": "hosts",
        })
    for svc in host.get("services", []) or []:
        p = svc.get("port")
        if not p:
            continue
        name = svc.get("product") or "unknown"
        svc_value = f"{ip}:{p}/{name}"
        r.assets.append({
            "kind": "service",
            "value": svc_value,
            "source": "shodan",
            "metadata": {
                "ip": ip, "port": p,
                "product": svc.get("product"),
                "version": svc.get("version"),
                "transport": svc.get("transport"),
            },
        })
        r.edges.append({
            "src_kind": "service", "src_value": svc_value,
            "dst_kind": "port", "dst_value": f"{ip}:{p}",
            "kind": "runs",
        })
        for cpe in svc.get("cpe") or []:
            r.assets.append({
                "kind": "technology",
                "value": cpe,
                "source": "shodan",
                "metadata": {"cpe": cpe},
            })
            r.edges.append({
                "src_kind": "technology", "src_value": cpe,
                "dst_kind": "service", "dst_value": svc_value,
                "kind": "has_version",
            })
    for cpe in host.get("cpes", []) or []:
        r.assets.append({
            "kind": "technology",
            "value": cpe,
            "source": "shodan",
            "metadata": {"cpe": cpe, "ip": ip},
        })
    return r


async def run(target: str, ctx: ModuleContext) -> ModuleResult:
    ips = _expand(target)
    if not ips:
        return ModuleResult(module="shodan_lookup",
                            errors=[f"no IPs in target {target!r}"])

    combined = ModuleResult(module="shodan_lookup")
    api_key = ctx.settings.shodan_api_key
    for ip in ips:
        base = await _internetdb(ctx, ip)
        if base is None:
            continue
        enriched = await _shodan_host(ctx, ip, api_key) if api_key else None
        host = _merge_host(base, enriched)
        per = _result_for_ip(ip, host)
        combined.assets.extend(per.assets)
        combined.edges.extend(per.edges)
        combined.source_calls += 1 + (1 if api_key else 0)
    return combined


__all__ = ["run", "_expand", "_merge_host", "_result_for_ip"]
