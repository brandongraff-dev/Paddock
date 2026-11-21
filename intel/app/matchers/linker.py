"""Asset -> candidate CVEs linker.

The main linker:
- lists `technology` assets (paged via the orchestrator)
- for each, extracts vendor/product from metadata
- pulls candidate CVEs whose cpe_affected includes that vendor+product
- runs the CPE matcher, writes `cve_matches` rows
- for confidence >= threshold, bulk-posts `cve_match` findings

It is driven by two triggers:
  1. Batch loop (every LINKER_INTERVAL_MIN minutes), via ``run_all``.
  2. Event-driven: when a `technology` asset is added, ``match_one_asset``
     is called directly (see app/main.py).
  3. NVD-driven: when a CVE is added/updated, ``reverse_match_cve`` is
     called to scan asset candidates for just that CVE.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from .cpe import asset_from_metadata, best_match
from ..enrich.finding_writer import build_finding

log = logging.getLogger(__name__)

MATCHER_NAME = "cpe"


async def _candidate_cves(db: Any, vendor: str | None, product: str) -> list[dict[str, Any]]:
    # If we have a vendor, narrow by (vendor, product). If not, probe product-only.
    rows = []
    if vendor:
        rows = await db.candidate_cves_for(vendor, product)
    if not rows and product:
        # Vendor-less probe: fall back to any vendor with this product name.
        # candidate_cves_for requires a vendor, so we do a looser second-shot
        # using a synthetic wildcard-vendor path. In practice this is rare, so
        # it's acceptable to return fewer results; a product-only hit ends up
        # at confidence 40 in the matcher.
        rows = await db.candidate_cves_for("", product)
    return rows


async def match_one_asset(
    db: Any,
    orch: Any,
    asset: dict[str, Any],
    *,
    min_finding_confidence: int = 60,
) -> dict[str, Any]:
    """Match one asset against all candidate CVEs; emit matches + findings."""
    meta = asset.get("metadata") or {}
    tech = asset_from_metadata(meta)
    if tech is None or not tech.product:
        return {"asset_id": asset.get("id"), "candidates": 0, "matches": 0}

    asset_id = asset.get("id")
    if not asset_id:
        return {"asset_id": None, "candidates": 0, "matches": 0}

    cves = await _candidate_cves(db, tech.vendor, tech.product)

    findings: list[dict[str, Any]] = []
    matches_written = 0

    for cve in cves:
        confidence = best_match(cve.get("cpe_affected") or [], meta)
        if confidence <= 0:
            continue
        inserted = await db.upsert_match(
            cve_id=cve["id"],
            asset_id=asset_id,
            confidence=confidence,
            matcher=MATCHER_NAME,
        )
        if inserted:
            matches_written += 1
        if confidence >= min_finding_confidence:
            findings.append(build_finding(cve=cve, asset=asset, confidence=confidence))

    if findings:
        await orch.bulk_findings(findings)

    return {
        "asset_id": asset_id,
        "candidates": len(cves),
        "matches": matches_written,
        "findings": len(findings),
    }


async def reverse_match_cve(
    db: Any,
    orch: Any,
    cve: dict[str, Any],
    *,
    min_finding_confidence: int = 60,
) -> dict[str, Any]:
    """Given a freshly-ingested CVE, scan assets for matches.

    We pull candidate assets via the orchestrator for each (vendor,
    product) tuple referenced in the CVE's cpe_affected, then run
    ``match_one_asset`` on each. This is the "CVE arrived -> who do we
    need to alert?" pass.
    """
    pairs: set[tuple[str, str]] = set()
    for e in cve.get("cpe_affected") or []:
        v = (e.get("vendor") or "").lower().strip()
        p = (e.get("product") or "").lower().strip()
        if p:
            pairs.add((v, p))

    assets_checked = 0
    total_findings = 0
    total_matches = 0

    for vendor, product in pairs:
        # The orchestrator doesn't expose a fine filter; we rely on the full
        # tech-asset enumeration and let match_one_asset drop non-matches.
        # For scale we'd push a vendor/product query onto the orchestrator.
        async for asset in orch.iter_technology_assets():
            meta = asset.get("metadata") or {}
            tech = asset_from_metadata(meta)
            if tech is None:
                continue
            if tech.product != product:
                continue
            if vendor and tech.vendor and tech.vendor != vendor:
                continue
            res = await match_one_asset(
                db, orch, asset, min_finding_confidence=min_finding_confidence
            )
            assets_checked += 1
            total_matches += res.get("matches", 0)
            total_findings += res.get("findings", 0)
    return {
        "cve_id": cve.get("id"),
        "assets_checked": assets_checked,
        "matches": total_matches,
        "findings": total_findings,
    }


async def run_all(
    db: Any,
    orch: Any,
    *,
    min_finding_confidence: int = 60,
) -> dict[str, Any]:
    """Batch pass: walk all `technology` assets, match each."""
    total = {"assets": 0, "candidates": 0, "matches": 0, "findings": 0}
    async for asset in orch.iter_technology_assets():
        total["assets"] += 1
        res = await match_one_asset(
            db, orch, asset, min_finding_confidence=min_finding_confidence
        )
        total["candidates"] += res.get("candidates", 0)
        total["matches"] += res.get("matches", 0)
        total["findings"] += res.get("findings", 0)
    log.info("linker: full pass %s", total)
    return total
