"""CPE 2.3 matching.

Given a CVE record (its parsed ``cpe_affected`` list) and an asset of
kind ``technology`` whose metadata carries either a raw CPE string or
vendor/product/version fields, decide whether and how strongly the two
match. Confidence tiers:

- 100: exact CPE string match (vendor, product, version all equal)
-  85: vendor + product match AND asset version falls inside the CVE's
       declared version range
-  60: vendor + product match and NO version info to narrow with
-  40: product-name heuristic only (vendor missing on the asset)
-   0: no match

The CVE `cpe_affected` entries are produced by ``sources/nvd._cpe_affected``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from . import version as version_matcher

CPE_WILDCARDS = {"*", "-", ""}


@dataclass
class AssetTech:
    """The subset of a `technology` asset metadata we need to match on."""
    vendor: str | None
    product: str | None
    version: str | None
    raw_cpe: str | None = None


def parse_cpe(criteria: str) -> dict[str, str] | None:
    """Parse ``cpe:2.3:part:vendor:product:version:...`` into a dict."""
    if not criteria:
        return None
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    keys = ["part", "vendor", "product", "version", "update", "edition",
            "language", "sw_edition", "target_sw", "target_hw", "other"]
    out = {k: (parts[i + 2] if i + 2 < len(parts) else "*") for i, k in enumerate(keys)}
    return out


def _is_wild(s: str | None) -> bool:
    return s is None or s in CPE_WILDCARDS


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def asset_from_metadata(meta: dict[str, Any] | None) -> AssetTech | None:
    """Build an AssetTech from an asset's metadata payload.

    The asset contract is loose — try a raw CPE first, then the explicit
    vendor/product/version triple. Return None if we can't identify a product.
    """
    if not isinstance(meta, dict):
        return None
    cpe_str = meta.get("cpe") or meta.get("cpe23")
    vendor = meta.get("vendor")
    product = meta.get("product") or meta.get("name")
    version = meta.get("version")

    if isinstance(cpe_str, str) and cpe_str:
        parsed = parse_cpe(cpe_str)
        if parsed:
            vendor = vendor or parsed.get("vendor")
            product = product or parsed.get("product")
            version = version or parsed.get("version")
            return AssetTech(
                vendor=_norm(vendor) or None,
                product=_norm(product) or None,
                version=version if version and version != "*" else None,
                raw_cpe=cpe_str,
            )
    if product:
        return AssetTech(
            vendor=_norm(vendor) or None,
            product=_norm(product),
            version=version if version else None,
            raw_cpe=None,
        )
    return None


def _entry_matches_asset(entry: dict[str, Any], asset: AssetTech) -> int:
    """Confidence tier for one CVE cpe_affected entry against one asset."""
    if not isinstance(entry, dict):
        return 0
    if entry.get("vulnerable") is False:
        return 0

    e_vendor = _norm(entry.get("vendor"))
    e_product = _norm(entry.get("product"))
    e_version = entry.get("version") or ""

    if not e_product:
        return 0

    # Exact raw CPE match (asset carries full cpe string).
    if asset.raw_cpe:
        parsed = parse_cpe(asset.raw_cpe)
        if parsed and _norm(parsed.get("vendor")) == e_vendor \
                and _norm(parsed.get("product")) == e_product \
                and _norm(parsed.get("version")) == _norm(e_version) \
                and e_version not in CPE_WILDCARDS:
            return 100

    vendor_ok = bool(e_vendor) and asset.vendor == e_vendor
    product_ok = asset.product == e_product

    if not product_ok:
        return 0

    # Full vendor+product+version in range
    if vendor_ok:
        has_range = any(k in entry for k in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        ))
        if asset.version:
            # Exact version in CVE entry
            if e_version and e_version not in CPE_WILDCARDS and not has_range:
                r = version_matcher.compare(asset.version, e_version)
                if r == 0:
                    return 100
                # explicit non-matching version
                return 0
            # Range check
            if has_range:
                if version_matcher.in_range(
                    asset.version,
                    start_including=entry.get("versionStartIncluding"),
                    start_excluding=entry.get("versionStartExcluding"),
                    end_including=entry.get("versionEndIncluding"),
                    end_excluding=entry.get("versionEndExcluding"),
                ):
                    return 85
                return 0
            # vendor+product match, CVE version is wildcard -> 85 (within scope)
            if e_version in CPE_WILDCARDS:
                return 85
        # Asset has no version: vendor+product match only.
        return 60

    # Product matches but vendor missing or mismatched: heuristic.
    return 40


def best_match(
    cve_cpe_affected: Iterable[dict[str, Any]], asset_meta: dict[str, Any] | None
) -> int:
    """Return the max confidence (0-100) across all CVE cpe entries for an asset."""
    asset = asset_from_metadata(asset_meta)
    if asset is None:
        return 0
    best = 0
    for entry in cve_cpe_affected or []:
        score = _entry_matches_asset(entry, asset)
        if score > best:
            best = score
        if best == 100:
            break
    return best
