"""ASN → announced prefix expansion.

Given either an ASN (e.g. "AS12345" or "12345") or a single IP, query
BGPView to learn which prefixes that AS announces. We also fall back to
RIPE stat's announced-prefixes endpoint.

For every prefix returned we emit an `ipv4` asset with metadata
`{cidr: true, asn: <int>}` — this is the "a whole range belongs to us"
pattern used by the asset graph.

The orchestrator's scope_check is still the gate: a prefix is only
upserted if it matches an active `ipv4_cidr` or `asn` scope entry. The
module doesn't try to resolve ownership itself.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


BGPVIEW_SOURCE = "bgpview"
RIPE_SOURCE = "ripe"


def _parse_asn_or_ip(target: str) -> tuple[str, str | None]:
    """Return ("asn", N) or ("ip", ip) or ("invalid", None)."""
    t = target.strip()
    m = re.fullmatch(r"(?i)as\s*(\d+)", t)
    if m:
        return "asn", m.group(1)
    if t.isdigit():
        return "asn", t
    try:
        ipaddress.ip_address(t)
        return "ip", t
    except ValueError:
        return "invalid", None


async def _bgpview_asn_prefixes(ctx: ModuleContext, asn: str) -> list[dict[str, Any]]:
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    status, body = await ctx.get_json(url, source=BGPVIEW_SOURCE)
    if status >= 400 or not isinstance(body, dict):
        return []
    data = body.get("data") or {}
    return list(data.get("ipv4_prefixes", []) or []) + list(data.get("ipv6_prefixes", []) or [])


async def _bgpview_ip_asn(ctx: ModuleContext, ip: str) -> str | None:
    url = f"https://api.bgpview.io/ip/{ip}"
    status, body = await ctx.get_json(url, source=BGPVIEW_SOURCE)
    if status >= 400 or not isinstance(body, dict):
        return None
    prefixes = body.get("data", {}).get("prefixes", []) or []
    for p in prefixes:
        asn_info = p.get("asn") or {}
        if asn_info.get("asn"):
            return str(asn_info["asn"])
    return None


async def _ripe_asn_prefixes(ctx: ModuleContext, asn: str) -> list[dict[str, Any]]:
    url = "https://stat.ripe.net/data/announced-prefixes/data.json"
    status, body = await ctx.get_json(url, source=RIPE_SOURCE, params={"resource": f"AS{asn}"})
    if status >= 400 or not isinstance(body, dict):
        return []
    data = body.get("data", {}) or {}
    return [{"prefix": p.get("prefix")} for p in (data.get("prefixes") or [])]


def _build_result(prefixes: list[dict[str, Any]], asn: str | None) -> ModuleResult:
    r = ModuleResult(module="asn_range")
    seen: set[str] = set()
    for p in prefixes:
        cidr = p.get("prefix")
        if not cidr or cidr in seen:
            continue
        seen.add(cidr)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        kind = "ipv4" if isinstance(net, ipaddress.IPv4Network) else "ipv6"
        r.assets.append({
            "kind": kind,
            "value": str(net),
            "source": "asn_range",
            "metadata": {
                "cidr": True,
                "asn": int(asn) if asn and asn.isdigit() else None,
                "name": p.get("name"),
                "description": p.get("description"),
                "country_code": p.get("country_code"),
            },
        })
    return r


async def run(target: str, ctx: ModuleContext) -> ModuleResult:
    kind, val = _parse_asn_or_ip(target)
    if kind == "invalid" or not val:
        return ModuleResult(module="asn_range",
                            errors=[f"not an ASN or IP: {target!r}"])

    if kind == "ip":
        asn = await _bgpview_ip_asn(ctx, val)
        if asn is None:
            logger.info("asn_range: could not derive ASN for ip")
            return ModuleResult(module="asn_range")
    else:
        asn = val

    prefixes = await _bgpview_asn_prefixes(ctx, asn)
    source_calls = 1 if kind == "asn" else 2
    if not prefixes:
        prefixes = await _ripe_asn_prefixes(ctx, asn)
        source_calls += 1

    r = _build_result(prefixes, asn)
    r.source_calls = source_calls
    return r
