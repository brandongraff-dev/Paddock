"""Build the ``cve_match`` finding payload that gets posted to the orchestrator.

Severity is derived from the CVSS v3 base score, with a KEV bump:
- KEV OR cvss >= 9.0       => critical
- cvss >= 7.0              => high
- cvss >= 4.0              => medium
- cvss <  4.0              => low
- cvss unknown & !KEV      => low (soft default)
"""
from __future__ import annotations

from typing import Any, Iterable


def severity_for(cvss_v3: float | None, kev: bool) -> str:
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


def _ref_urls(refs: Iterable[Any] | None) -> list[str]:
    out: list[str] = []
    if not refs:
        return out
    for r in refs:
        if isinstance(r, str):
            out.append(r)
        elif isinstance(r, dict) and r.get("url"):
            out.append(r["url"])
    return out


def _impact(cve: dict[str, Any]) -> str:
    bits: list[str] = []
    cvss = cve.get("cvss_v3")
    if cvss is not None:
        bits.append(f"CVSS v3 base score {cvss}.")
    vec = cve.get("cvss_v3_vector")
    if vec:
        bits.append(f"Vector: {vec}.")
    if cve.get("known_exploited"):
        bits.append(
            "Listed in CISA KEV: active in-the-wild exploitation has been observed."
        )
    epss = cve.get("epss")
    if epss is not None:
        try:
            bits.append(
                f"EPSS exploitation likelihood: {float(epss):.3f}"
                + (f" (percentile {float(cve.get('epss_percentile') or 0):.3f})"
                   if cve.get("epss_percentile") is not None else "")
            )
        except (TypeError, ValueError):
            pass
    cwe_ids = cve.get("cwe_ids") or []
    if cwe_ids:
        bits.append("Weakness class: " + ", ".join(cwe_ids[:5]) + ".")
    if not bits:
        return (
            "Software matching this CVE's affected-product list is deployed on an "
            "asset in scope."
        )
    return " ".join(bits)


def _remediation(cve: dict[str, Any]) -> str:
    # Deliberately generic — this service does not emit exploit guidance,
    # payloads, or step-by-step offensive instructions. The owner is pointed
    # at the authoritative vendor/NVD references.
    msg = (
        "Upgrade the affected software to a fixed release listed by the vendor. "
        "If no fix is yet available, apply vendor-recommended mitigations and "
        "restrict exposure (network segmentation, authentication) in the interim. "
        "See the vendor advisory and NVD entry linked in `references`."
    )
    if cve.get("known_exploited"):
        msg = (
            "CISA KEV directs federal civilian agencies to remediate by the "
            "catalog's due date; for others, treat as highest priority. "
        ) + msg
    return msg


def build_finding(
    *,
    cve: dict[str, Any],
    asset: dict[str, Any],
    confidence: int,
) -> dict[str, Any]:
    """Return a POST /v1/findings/bulk-shaped dict for one asset<->cve match."""
    cve_id = cve["id"]
    severity = severity_for(cve.get("cvss_v3"), bool(cve.get("known_exploited")))
    description = cve.get("description") or f"{cve_id} affects deployed software."
    title = f"{cve_id} affects {asset.get('value') or asset.get('id')}"

    evidence = {
        "matcher": "cpe",
        "match_confidence": int(confidence),
        "asset_metadata": {
            k: asset.get("metadata", {}).get(k)
            for k in ("cpe", "vendor", "product", "version")
            if asset.get("metadata", {}).get(k) is not None
        },
        "cve_cvss_v3_vector": cve.get("cvss_v3_vector"),
        "kev": bool(cve.get("known_exploited")),
    }

    return {
        "asset_id": asset.get("id"),
        "rule_id": cve_id,
        "rule_source": "cve_match",
        "severity": severity,
        "title": title,
        "description": description,
        "impact": _impact(cve),
        "remediation": _remediation(cve),
        "evidence": evidence,
        "cvss": cve.get("cvss_v3"),
        "epss": cve.get("epss"),
        "references": _ref_urls(cve.get("refs")),
        "metadata": {
            "confidence": int(confidence),
            "cwe_ids": cve.get("cwe_ids") or [],
        },
    }
