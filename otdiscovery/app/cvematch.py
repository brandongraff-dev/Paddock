"""Match a discovered device against the shared CVE feed (cves table + KEV).

We reuse the orchestrator/intel CVE model: each ``cves`` row carries a flattened
``cpe_affected`` list of ``{vendor, product, version, ...}`` specs (see
intel/app/sources/nvd.py). A device fingerprinted to a vendor/model is matched
by comparing its vendor + product tokens against those specs. ICS/OT equipment
frequently carries ICS-CERT / KEV-listed CVEs, so a KEV hit on a vendor match
is surfaced even without a precise product token.

The candidate CVEs are supplied by an injected fetcher so the matcher is pure
and unit-testable without a database; the live service backs it with a Postgres
query against ``cves``.
"""
from __future__ import annotations

import re
from typing import Any, Awaitable, Callable, Iterable

from .fingerprint.device import Device

# an async fetcher: given a set of normalized vendor tokens, return cve rows
CveFetcher = Callable[[set[str]], Awaitable[list[dict[str, Any]]]]

_WORD_RE = re.compile(r"[a-z0-9]+")


def _norm(text: str | None) -> str:
    return (text or "").strip().lower()


def _tokens(text: str | None) -> set[str]:
    return {t for t in _WORD_RE.findall(_norm(text)) if len(t) >= 2}


def severity_for(cvss_v3: float | None, kev: bool) -> str:
    """CVSS v3 base -> severity, with a KEV bump (mirrors intel finding_writer)."""
    if kev:
        return "critical"
    if cvss_v3 is None:
        return "low"
    try:
        v = float(cvss_v3)
    except (TypeError, ValueError):
        return "low"
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    return "low"


def vendor_tokens(device: Device) -> set[str]:
    """Vendor words to search the CVE feed with (drops generic filler)."""
    toks = _tokens(device.vendor)
    # drop corporate filler that would over-match
    toks -= {"automation", "electric", "technologies", "technology", "inc",
             "corp", "corporation", "ltd", "co", "gmbh", "communications",
             "systems", "controls", "digital", "the"}
    return toks


def product_tokens(device: Device) -> set[str]:
    toks = _tokens(device.model) | _tokens(device.type)
    toks -= {"device", "controller", "unknown"}
    return toks


def _ref_urls(refs: Iterable[Any] | None) -> list[str]:
    out: list[str] = []
    for r in refs or []:
        if isinstance(r, str):
            out.append(r)
        elif isinstance(r, dict) and r.get("url"):
            out.append(str(r["url"]))
    return out[:20]


def _cpe_vendor_product(cve: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for e in cve.get("cpe_affected") or []:
        if not isinstance(e, dict):
            continue
        out.append((_norm(e.get("vendor")), _norm(e.get("product"))))
    return out


def match_one(device: Device, cve: dict[str, Any]) -> tuple[bool, int, dict[str, Any]]:
    """Return (matched, confidence, evidence) for a device<->cve pair."""
    dev_vendors = vendor_tokens(device)
    dev_products = product_tokens(device)
    if not dev_vendors:
        return False, 0, {}

    kev = bool(cve.get("known_exploited"))
    best_conf = 0
    matched_spec: dict[str, Any] | None = None

    for cpe_vendor, cpe_product in _cpe_vendor_product(cve):
        cpe_vendor_toks = _tokens(cpe_vendor)
        if not (dev_vendors & cpe_vendor_toks):
            continue
        # vendor matches; now gauge product specificity
        product_hit = False
        if dev_products and cpe_product:
            cpe_product_toks = _tokens(cpe_product)
            if dev_products & cpe_product_toks:
                product_hit = True
            elif any(pt in cpe_product for pt in dev_products if len(pt) >= 3):
                product_hit = True

        if product_hit:
            conf = 85
        elif kev:
            # KEV + vendor match on ICS gear: worth surfacing, lower confidence
            conf = 55
        else:
            # vendor-only, non-KEV: too weak, skip (avoid vendor-wide noise)
            continue

        if conf > best_conf:
            best_conf = conf
            matched_spec = {"cpe_vendor": cpe_vendor, "cpe_product": cpe_product,
                            "product_hit": product_hit}

    if matched_spec is None:
        return False, 0, {}
    evidence = {
        "matcher": "cpe_vendor_product",
        "match_confidence": best_conf,
        "matched_cpe": matched_spec,
        "device_vendor": device.vendor,
        "device_model": device.model,
        "device_type": device.type,
        "kev": kev,
        "passive": True,
    }
    return True, best_conf, evidence


def build_finding(device: Device, cve: dict[str, Any], confidence: int,
                  evidence: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve["id"]
    kev = bool(cve.get("known_exploited"))
    cvss = cve.get("cvss_v3")
    severity = severity_for(cvss, kev)
    asset_value = device.asset_value()
    label = device.vendor or device.type or "device"
    desc = cve.get("description") or f"{cve_id} affects {label} equipment."
    impact_bits = []
    if cvss is not None:
        impact_bits.append(f"CVSS v3 {cvss}.")
    if kev:
        impact_bits.append("Listed in CISA KEV (active in-the-wild exploitation).")
    impact_bits.append(
        "Matched passively from the device's fingerprinted vendor/model against "
        "the CVE feed's affected-product list; no probe was sent to confirm."
    )
    return {
        "asset_value": asset_value,
        "asset_kind": "ot_device" if device.role == "ot" else "iot_device",
        "rule_id": cve_id,
        "rule_source": "cve_match",
        "severity": severity,
        "title": f"{cve_id} may affect {label} {device.model or device.type} ({asset_value})",
        "description": desc,
        "impact": " ".join(impact_bits),
        "remediation": (
            "Confirm the exact firmware/model against the vendor advisory, then "
            "apply the vendor's fixed release or mitigation. For OT, schedule the "
            "update in a maintenance window and keep the device off any IT/public "
            "path until patched. See the advisories in `references`."
            + (" CISA KEV: treat as highest priority." if kev else "")
        ),
        "evidence": evidence,
        "cvss": cvss,
        "epss": cve.get("epss"),
        "references": _ref_urls(cve.get("refs")),
        "metadata": {"source": "otdiscovery", "confidence": confidence,
                     "device_id": device.key, "kev": kev,
                     "cwe_ids": cve.get("cwe_ids") or []},
    }


async def match_devices(
    devices: list[Device], fetch: CveFetcher
) -> list[dict[str, Any]]:
    """Produce cve_match findings for the device inventory, de-duplicated."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for dev in devices:
        if not dev.is_device:
            continue
        v_toks = vendor_tokens(dev)
        if not v_toks:
            continue
        candidates = await fetch(v_toks)
        for cve in candidates:
            matched, conf, evidence = match_one(dev, cve)
            if not matched:
                continue
            key = (dev.asset_value(), cve["id"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(build_finding(dev, cve, conf, evidence))
    return findings
