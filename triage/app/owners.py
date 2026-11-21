"""Owner resolution: map an asset to the team that owns it.

Pure, side-effect-free matching against the ``asset_owners`` rule table. Rules
are evaluated by ``priority`` ASC (lower wins) and the FIRST enabled rule whose
present match keys ALL hold is returned — a deterministic first-match-wins.

A rule's ``match`` is an AND of its present keys; an absent (or empty/falsy)
key is a wildcard, so an empty ``{}`` match is a catch-all. Recognised keys:

  * ``kinds``        — asset.kind ∈ list
  * ``value_regex``  — ``re.search`` hits asset.value
  * ``cidr``         — the asset's IP ∈ the CIDR (ipv4/ipv6 by value; port /
                       resolved-subdomain etc. by ``metadata.ip``)
  * ``metadata_env`` — asset.metadata.env == value
  * ``tag``          — value ∈ asset.metadata.tags

Any other key in ``match`` (e.g. a carried ``system``) is ignored for matching.

This module reads nothing and sends nothing — it is a pure function of its
arguments, which is why its tests need neither a database nor the network.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Optional

log = logging.getLogger("triage.owners")

# The keys of ``match`` that participate in matching. Anything else (a carried
# ``system``, a human ``note``, …) is ignored here.
MATCH_KEYS = ("kinds", "value_regex", "cidr", "metadata_env", "tag")


def _asset_ip(asset: dict[str, Any]) -> Optional[str]:
    """Best-effort single IP for an asset, for CIDR matching.

    ipv4/ipv6 assets carry the IP as their value; ports, services and
    resolved subdomains carry it in ``metadata`` (``ip`` / ``resolved_ip`` /
    ``address``, or the first of an ``ips`` / ``addresses`` list).
    """
    kind = asset.get("kind")
    value = asset.get("value") or ""
    if kind in ("ipv4", "ipv6"):
        return value
    meta = asset.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    for key in ("ip", "resolved_ip", "address"):
        v = meta.get(key)
        if isinstance(v, str) and v:
            return v
    for key in ("ips", "addresses"):
        seq = meta.get(key)
        if isinstance(seq, (list, tuple)) and seq and isinstance(seq[0], str):
            return seq[0]
    return None


def _match_cidr(cidr: str, asset: dict[str, Any]) -> bool:
    ip = _asset_ip(asset)
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


def owner_matches(match: dict[str, Any], asset: dict[str, Any]) -> bool:
    """True if ``asset`` satisfies every present (truthy) recognised predicate.

    Unrecognised keys are ignored, so a ``match`` may carry extra metadata
    (such as the rule's ``system``) without affecting the decision.
    """
    kinds = match.get("kinds")
    if kinds and asset.get("kind") not in kinds:
        return False

    value_regex = match.get("value_regex")
    if value_regex:
        try:
            if not re.search(value_regex, asset.get("value") or ""):
                return False
        except re.error:  # a broken regex never matches
            return False

    cidr = match.get("cidr")
    if cidr and not _match_cidr(cidr, asset):
        return False

    meta = asset.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}

    metadata_env = match.get("metadata_env")
    if metadata_env and meta.get("env") != metadata_env:
        return False

    tag = match.get("tag")
    if tag:
        tags = meta.get("tags")
        if not isinstance(tags, (list, tuple)) or tag not in tags:
            return False

    return True


def resolve_owner(
    asset: dict[str, Any],
    rules: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """First enabled rule (priority ASC) that matches ``asset``.

    Returns ``{"team", "contact", "system"}`` (``contact``/``system`` may be
    ``None``) or ``None`` when nothing matches. ``system`` is carried on the
    rule (or inside its ``match`` blob) and defaults to ``None`` here; the
    ticket layer turns a missing/``None`` system into ``'internal'``.
    """
    ordered = sorted(
        rules,
        key=lambda r: (r.get("priority", 100), str(r.get("id") or "")),
    )
    for rule in ordered:
        if not rule.get("enabled", True):
            continue
        match = rule.get("match") or {}
        if not isinstance(match, dict):
            match = {}
        if owner_matches(match, asset):
            system = rule.get("system")
            if system is None:
                system = match.get("system")
            return {
                "team": rule.get("team"),
                "contact": rule.get("contact"),
                "system": system,
            }
    return None
