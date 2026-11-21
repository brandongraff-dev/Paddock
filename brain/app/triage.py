"""Finding-cluster triage.

Clustering is pure and deterministic: open findings are grouped by
(asset_value, severity-family, rule family). For each cluster we produce a
{label, summary, remediation, severity, finding_ids} record.

If the LLM is enabled we ask it (batched) for a tight label/impact/
remediation per cluster and write the clusters with engine='llm'. If the
call fails, or no key is present, we fall back to deterministic template
summaries with engine='template'. Either way the clusters are persisted to
`finding_clusters`.
"""
from __future__ import annotations

import logging
from typing import Any

from .db import Database
from .llm import LLM

log = logging.getLogger("brain.triage")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Map a raw severity to a coarser "family" used as part of the cluster key.
_SEVERITY_FAMILY = {
    "critical": "severe",
    "high": "severe",
    "medium": "moderate",
    "low": "low",
    "info": "low",
}

# Human-readable blurbs per rule family, used by the template engine.
_RULE_FAMILY_BLURB = {
    "nuclei": ("Active exposure checks flagged issues",
               "Review the matched templates and remediate or restrict the exposed service."),
    "cve_match": ("Known CVEs match software on this asset",
                  "Patch or upgrade the affected software to a fixed version."),
    "cve": ("Known CVEs match software on this asset",
            "Patch or upgrade the affected software to a fixed version."),
    "secret_scan": ("Leaked secrets detected",
                    "Rotate the exposed credentials and remove them from the source."),
    "tls_check": ("TLS configuration weaknesses",
                  "Update the TLS configuration to current secure defaults."),
    "tls_grade": ("TLS configuration weaknesses",
                  "Update the TLS configuration to current secure defaults."),
    "header_check": ("Missing or weak security headers",
                     "Add the recommended security response headers."),
    "exposed_file": ("Sensitive files exposed",
                     "Remove or restrict access to the exposed files."),
    "policy": ("Policy violations",
               "Bring the asset into compliance with the stated policy."),
    "chain": ("Correlated multi-step risk",
              "Break the chain by remediating any one of the linked findings."),
    "takeover": ("Potential subdomain/resource takeover",
                 "Reclaim or remove the dangling DNS/resource reference."),
    "sca": ("Vulnerable dependencies in the software bill of materials",
            "Upgrade the affected dependencies to fixed versions."),
}


def _family(sev: str | None) -> str:
    return _SEVERITY_FAMILY.get((sev or "info").lower(), "low")


def _max_severity(sevs: list[str]) -> str:
    best = "info"
    for s in sevs:
        if _SEVERITY_RANK.get((s or "info").lower(), 0) > _SEVERITY_RANK.get(best, 0):
            best = (s or "info").lower()
    return best


def build_clusters(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings into clusters. Pure — no DB, no LLM."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for f in findings:
        asset = f.get("asset_value") or "(unknown asset)"
        rule_family = (f.get("rule_source") or "other").lower()
        key = (asset, _family(f.get("severity")), rule_family)
        g = groups.get(key)
        if g is None:
            g = {
                "asset_value": asset,
                "severity_family": key[1],
                "rule_source": rule_family,
                "finding_ids": [],
                "severities": [],
                "examples": [],
            }
            groups[key] = g
        g["finding_ids"].append(str(f.get("id")))
        g["severities"].append((f.get("severity") or "info").lower())
        if len(g["examples"]) < 5:
            g["examples"].append({
                "rule_id": f.get("rule_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
            })

    clusters: list[dict[str, Any]] = []
    for g in groups.values():
        clusters.append({
            "asset_value": g["asset_value"],
            "rule_source": g["rule_source"],
            "severity": _max_severity(g["severities"]),
            "finding_ids": g["finding_ids"],
            "examples": g["examples"],
        })
    # Deterministic order: most severe, then largest, then asset name.
    clusters.sort(
        key=lambda c: (
            -_SEVERITY_RANK.get(c["severity"], 0),
            -len(c["finding_ids"]),
            c["asset_value"],
        )
    )
    return clusters


def template_summaries(clusters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic label/summary/remediation for each cluster."""
    out = []
    for c in clusters:
        rule = c["rule_source"]
        blurb, remediation = _RULE_FAMILY_BLURB.get(
            rule, ("Findings detected", "Review and remediate the listed findings.")
        )
        n = len(c["finding_ids"])
        label = f"{rule} / {c['severity']} on {c['asset_value']}"
        summary = (
            f"{blurb} on {c['asset_value']} "
            f"({n} open {c['severity']} finding{'s' if n != 1 else ''} "
            f"from the {rule} family)."
        )
        out.append({
            "label": label,
            "summary": summary,
            "remediation": remediation,
            "severity": c["severity"],
            "finding_ids": c["finding_ids"],
            "metadata": {
                "asset_value": c["asset_value"],
                "rule_source": rule,
                "count": n,
            },
        })
    return out


def _apply_llm(
    clusters: list[dict[str, Any]], llm_out: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Merge the LLM's label/summary/remediation back onto the clusters,
    keeping our deterministic severity + finding_ids."""
    out = []
    for c, got in zip(clusters, llm_out):
        n = len(c["finding_ids"])
        out.append({
            "label": got.get("label") or f"{c['rule_source']} on {c['asset_value']}",
            "summary": got.get("summary") or "",
            "remediation": got.get("remediation") or "",
            "severity": c["severity"],
            "finding_ids": c["finding_ids"],
            "metadata": {
                "asset_value": c["asset_value"],
                "rule_source": c["rule_source"],
                "count": n,
            },
        })
    return out


async def run_triage(db: Database, llm: LLM) -> dict[str, Any]:
    """Pull open findings, cluster, summarize (LLM or template), persist."""
    findings = await db.open_findings()
    clusters = build_clusters(findings)

    engine = "template"
    records = template_summaries(clusters)

    if clusters and llm.is_enabled():
        llm_out = await llm.summarize_clusters(clusters)
        if llm_out is not None:
            engine = "llm"
            records = _apply_llm(clusters, llm_out)

    written = await db.replace_clusters(records, engine)
    log.info("triage: %d findings -> %d clusters (engine=%s)",
             len(findings), written, engine)
    return {
        "findings": len(findings),
        "clusters": written,
        "engine": engine,
    }
