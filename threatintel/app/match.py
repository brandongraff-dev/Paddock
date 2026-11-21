"""Defensive matching: owner's assets/findings <-> threat indicators.

For every indicator we ask "is any of MY surface this known-bad value, or does
it touch this known threat infrastructure?". We match against:

  * assets (read-only):
      - ipv4 / ipv6 indicator == asset value (exact)
      - cidr indicator contains an ipv4/ipv6 asset (network containment)
      - domain indicator == a domain asset, OR is a suffix of a subdomain
        asset ("evil.com" matches "login.evil.com")
      - url indicator: its host matches a domain/subdomain/ip asset, or an
        endpoint asset's host
      - endpoint (URL) asset: its host matches an ip/domain/url indicator
  * findings evidence (read-only): file hashes and URLs embedded in a
    finding's evidence JSON.

A match writes a ``ti_matches`` row and emits a ``threat_intel`` finding on
the affected asset via the orchestrator. Severity: c2 / malware -> critical,
otherwise high. Everything here is READ-ONLY over the owner's own data; no
indicator value is ever contacted.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from .stix import (
    IOC_CIDR, IOC_DOMAIN, IOC_EMAIL, IOC_IPV4, IOC_IPV6, IOC_MD5, IOC_SHA256,
    IOC_URL,
)

log = logging.getLogger(__name__)

# Labels / malware that escalate a match to critical.
_CRITICAL_LABELS = {
    "c2", "c&c", "command-and-control", "command-control",
    "malware", "malware-activity", "malicious-activity-c2",
    "botnet", "ransomware", "trojan", "backdoor", "apt",
}

_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

ASSET_KINDS = ("ipv4", "ipv6", "domain", "subdomain", "endpoint")


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #

def severity_for(
    labels: Iterable[str] | None,
    malware: Iterable[str] | None,
    confidence: int | None = None,
) -> str:
    """c2 / malware -> critical, else high (the floor for a known-bad hit)."""
    if malware:
        return "critical"
    labs = {str(l).strip().lower() for l in (labels or [])}
    if labs & _CRITICAL_LABELS:
        return "critical"
    # A low-confidence hit with no malicious label stays high (it is still the
    # owner's surface appearing on a threat feed) -- we never drop below high.
    return "high"


# --------------------------------------------------------------------------- #
# Host / value helpers (pure)
# --------------------------------------------------------------------------- #

def url_host(value: str) -> str | None:
    """Host of a URL or a bare host[:port]/path string, lowercased."""
    if not value:
        return None
    v = value.strip()
    try:
        if "://" in v:
            host = urlsplit(v).hostname
        else:
            # bare authority or host/path
            host = urlsplit("//" + v).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _as_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _as_net(value: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _domain_suffix_match(indicator_domain: str, host: str) -> bool:
    """True if ``host`` equals the indicator domain or is a subdomain of it."""
    d = indicator_domain.lower().strip(".")
    h = host.lower().strip(".")
    return bool(d) and (h == d or h.endswith("." + d))


# --------------------------------------------------------------------------- #
# Indicator <-> asset (pure)
# --------------------------------------------------------------------------- #

def indicator_asset_match(indicator: dict[str, Any], asset: dict[str, Any]) -> str | None:
    """Return the matched value if this indicator matches this asset, else None.

    ``indicator`` needs {type, value}; ``asset`` needs {kind, value}.
    """
    itype = indicator.get("type")
    ivalue = (indicator.get("value") or "").strip()
    akind = asset.get("kind")
    avalue = (asset.get("value") or "").strip()
    if not ivalue or not avalue:
        return None

    # --- IP equality ---
    if itype in (IOC_IPV4, IOC_IPV6):
        if akind in ("ipv4", "ipv6") and avalue.lower() == ivalue.lower():
            return avalue
        if akind == "endpoint":
            h = url_host(avalue)
            if h and h == ivalue.lower():
                return avalue
        return None

    # --- CIDR containment ---
    if itype == IOC_CIDR:
        net = _as_net(ivalue)
        if net is None:
            return None
        if akind in ("ipv4", "ipv6"):
            ip = _as_ip(avalue)
            if ip is not None and ip.version == net.version and ip in net:
                return avalue
        if akind == "endpoint":
            ip = _as_ip(url_host(avalue) or "")
            if ip is not None and ip.version == net.version and ip in net:
                return avalue
        return None

    # --- Domain (== or suffix-of subdomain) ---
    if itype == IOC_DOMAIN:
        if akind == "domain" and avalue.lower() == ivalue.lower():
            return avalue
        if akind == "subdomain" and _domain_suffix_match(ivalue, avalue):
            return avalue
        if akind == "endpoint":
            h = url_host(avalue)
            if h and _domain_suffix_match(ivalue, h):
                return avalue
        return None

    # --- URL (exact or host match) ---
    if itype == IOC_URL:
        ihost = url_host(ivalue)
        if akind == "endpoint":
            if avalue == ivalue:
                return avalue
            ahost = url_host(avalue)
            if ihost and ahost and ihost == ahost:
                return avalue
        if ihost and akind in ("domain", "subdomain") and avalue.lower() == ihost:
            return avalue
        if ihost and akind in ("ipv4", "ipv6") and avalue.lower() == ihost:
            return avalue
        return None

    return None


# --------------------------------------------------------------------------- #
# Findings evidence (pure)
# --------------------------------------------------------------------------- #

def _walk_strings(node: Any) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _walk_strings(v)


def evidence_iocs(evidence: Any) -> dict[str, set[str]]:
    """Extract candidate IOCs embedded in a finding's evidence JSON."""
    hashes: set[str] = set()
    urls: set[str] = set()
    emails: set[str] = set()
    for s in _walk_strings(evidence):
        for m in _HASH_RE.findall(s):
            hashes.add(m.lower())
        for m in _URL_RE.findall(s):
            urls.add(m.strip().rstrip(".,);"))
        for m in _EMAIL_RE.findall(s):
            emails.add(m.lower())
    return {"hashes": hashes, "urls": urls, "emails": emails}


def indicator_finding_match(indicator: dict[str, Any], iocs: dict[str, set[str]]) -> str | None:
    """Return the matched value if this indicator appears in a finding's evidence."""
    itype = indicator.get("type")
    ivalue = (indicator.get("value") or "").strip()
    if not ivalue:
        return None
    low = ivalue.lower()
    if itype in (IOC_SHA256, IOC_MD5):
        return ivalue if low in iocs.get("hashes", set()) else None
    if itype == IOC_URL:
        if ivalue in iocs.get("urls", set()):
            return ivalue
        ihost = url_host(ivalue)
        for u in iocs.get("urls", set()):
            if ihost and url_host(u) == ihost:
                return u
        return None
    if itype == IOC_DOMAIN:
        for u in iocs.get("urls", set()):
            h = url_host(u)
            if h and _domain_suffix_match(ivalue, h):
                return u
        return None
    if itype == IOC_EMAIL:
        return ivalue if low in iocs.get("emails", set()) else None
    return None


# --------------------------------------------------------------------------- #
# Finding payload
# --------------------------------------------------------------------------- #

def _label_phrase(indicator: dict[str, Any]) -> str:
    malware = indicator.get("malware") or []
    if malware:
        return ", ".join(malware[:3])
    labels = indicator.get("labels") or []
    if labels:
        return ", ".join(labels[:3])
    actor = indicator.get("threat_actor")
    if actor:
        return str(actor)
    return "malicious indicator"


def rule_id_for(indicator: dict[str, Any]) -> str:
    """Stable rule id so (asset, indicator) de-dupes on the findings side too."""
    iid = indicator.get("id")
    if iid:
        return f"ti:{iid}"
    return f"ti:{indicator.get('type')}:{indicator.get('value')}"


def build_finding(
    *,
    indicator: dict[str, Any],
    asset_id: str,
    matched_value: str,
    severity: str,
    subject_type: str,
) -> dict[str, Any]:
    """POST /v1/findings/bulk-shaped dict for one asset<->indicator match."""
    label = _label_phrase(indicator)
    ivalue = indicator.get("value")
    itype = indicator.get("type")
    actor = indicator.get("threat_actor")
    malware = indicator.get("malware") or []
    labels = indicator.get("labels") or []

    impact_bits = [
        f"An asset in your inventory ({matched_value}) matches a known-bad "
        f"threat indicator ({itype} {ivalue})."
    ]
    if malware:
        impact_bits.append("Associated malware: " + ", ".join(malware) + ".")
    if actor:
        impact_bits.append(f"Attributed threat actor: {actor}.")
    if labels:
        impact_bits.append("Feed labels: " + ", ".join(labels) + ".")
    impact_bits.append(
        "This means part of your attack surface is, or resolves to / touches, "
        "infrastructure a threat-intel feed flags as malicious."
    )

    return {
        "asset_id": asset_id,
        "rule_id": rule_id_for(indicator),
        "rule_source": "threat_intel",
        "severity": severity,
        "title": f"Asset matches threat indicator ({label})",
        "description": (
            f"The {subject_type} value {matched_value} matches threat indicator "
            f"{itype}:{ivalue}"
            + (f" ({label})" if label else "")
            + "."
        ),
        "impact": " ".join(impact_bits),
        "remediation": (
            "Investigate the asset for compromise or unauthorized change. "
            "Confirm whether this surface should exist and whether it has "
            "communicated with the flagged infrastructure. If confirmed "
            "malicious, isolate the asset, rotate exposed credentials, and open "
            "an incident. If this is a false positive (shared hosting, expired "
            "indicator), mark the finding accordingly."
        ),
        "evidence": {
            "matcher": "threat_intel",
            "indicator_type": itype,
            "indicator_value": ivalue,
            "matched_value": matched_value,
            "subject_type": subject_type,
            "labels": labels,
            "malware": malware,
            "threat_actor": actor,
            "confidence": indicator.get("confidence"),
            "stix_id": indicator.get("stix_id"),
            "source_feed": indicator.get("feed_name") or indicator.get("source"),
        },
        "references": [r for r in (indicator.get("references") or []) if isinstance(r, str)],
        "metadata": {
            "indicator_id": str(indicator.get("id")) if indicator.get("id") else None,
            "confidence": indicator.get("confidence"),
        },
    }


def _expired(indicator: dict[str, Any], now: datetime) -> bool:
    vu = indicator.get("valid_until")
    if isinstance(vu, datetime):
        if vu.tzinfo is None:
            vu = vu.replace(tzinfo=timezone.utc)
        return vu < now
    return False


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

async def run_match(
    db: Any,
    orch: Any,
    *,
    scan_limit: int = 50000,
    include_expired: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-run matching over all indicators and the owner's assets + findings.

    Returns a summary dict: {indicators, assets, findings_scanned, matches,
    findings_emitted}.
    """
    now = now or datetime.now(timezone.utc)
    indicators = await db.list_indicators(limit=scan_limit)
    assets = await db.list_match_assets(kinds=list(ASSET_KINDS), limit=scan_limit)
    findings = await db.list_findings_with_evidence(limit=scan_limit)

    # Pre-compute evidence IOCs once per finding.
    finding_iocs: list[tuple[dict[str, Any], dict[str, set[str]]]] = [
        (f, evidence_iocs(f.get("evidence"))) for f in findings
    ]

    # (asset_id, rule_id) -> pending match row, plus the finding payload.
    pending: list[dict[str, Any]] = []
    findings_payload: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str]] = set()

    def _queue_finding(indicator, asset_id, matched_value, severity, subject_type):
        key = (str(asset_id), rule_id_for(indicator))
        if key in seen_finding_keys:
            return
        seen_finding_keys.add(key)
        findings_payload.append(build_finding(
            indicator=indicator, asset_id=asset_id, matched_value=matched_value,
            severity=severity, subject_type=subject_type,
        ))

    for ind in indicators:
        if not include_expired and _expired(ind, now):
            continue
        sev = severity_for(ind.get("labels"), ind.get("malware"), ind.get("confidence"))
        # assets
        for asset in assets:
            mv = indicator_asset_match(ind, asset)
            if mv is None:
                continue
            pending.append({
                "indicator_id": ind["id"],
                "subject_type": "asset",
                "subject_id": asset["id"],
                "asset_id": asset["id"],
                "matched_value": mv,
                "severity": sev,
                "rule_id": rule_id_for(ind),
            })
            _queue_finding(ind, asset["id"], mv, sev, "asset")
        # findings evidence
        for finding, iocs in finding_iocs:
            mv = indicator_finding_match(ind, iocs)
            if mv is None:
                continue
            asset_id = finding.get("asset_id")
            pending.append({
                "indicator_id": ind["id"],
                "subject_type": "finding",
                "subject_id": finding["id"],
                "asset_id": asset_id,
                "matched_value": mv,
                "severity": sev,
                "rule_id": rule_id_for(ind),
            })
            if asset_id:
                _queue_finding(ind, asset_id, mv, sev, "finding")

    # Emit findings first so we can thread finding_id back into ti_matches.
    finding_id_by_key: dict[tuple[str, str], str] = {}
    if findings_payload:
        resp = await orch.bulk_findings(findings_payload)
        for item in (resp or {}).get("items", []) or []:
            aid = item.get("asset_id")
            rid = item.get("rule_id")
            fid = item.get("id")
            if aid and rid and fid:
                finding_id_by_key[(str(aid), rid)] = str(fid)

    matches_written = 0
    for row in pending:
        fid = finding_id_by_key.get((str(row.get("asset_id")), row["rule_id"]))
        inserted = await db.upsert_match(
            indicator_id=row["indicator_id"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            matched_value=row["matched_value"],
            severity=row["severity"],
            finding_id=fid,
        )
        if inserted:
            matches_written += 1

    summary = {
        "indicators": len(indicators),
        "assets": len(assets),
        "findings_scanned": len(findings),
        "matches": matches_written,
        "findings_emitted": len(findings_payload),
    }
    log.info("match: pass complete %s", summary)
    return summary
