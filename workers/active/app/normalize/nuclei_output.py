"""Normalize nuclei JSONL output into our findings schema.

Nuclei prints one JSON object per match. The shape has changed a bit over
versions; we read the fields that are stable across 2.x and 3.x.
"""
from __future__ import annotations

import json
from typing import Iterable

_SEVERITY_MAP = {
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def normalize_hits(
    lines: Iterable[str],
    *,
    in_scope_hosts: set[str] | None = None,
) -> list[dict]:
    """Parse nuclei JSONL lines into finding dicts.

    If ``in_scope_hosts`` is provided, drop any hit whose host is not in that
    set (nuclei may follow a redirect we did not anticipate).
    """
    findings: list[dict] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        matched_url = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
        host = _host_from(matched_url)
        if in_scope_hosts is not None and host and host not in in_scope_hosts:
            continue

        template_id = obj.get("template-id") or obj.get("templateID") or "unknown"
        severity = _SEVERITY_MAP.get(
            str(info.get("severity", "info")).lower(), "info"
        )
        refs = info.get("reference") or info.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cvss = classification.get("cvss-score") or classification.get("cvss_score")
        try:
            cvss_num = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_num = None

        findings.append({
            "target_host": host,
            "target_url": matched_url,
            "rule_id": template_id,
            "rule_source": "nuclei",
            "severity": severity,
            "title": info.get("name") or template_id,
            "description": (info.get("description") or "").strip(),
            "impact": info.get("impact"),
            "remediation": info.get("remediation"),
            "evidence": {
                "matched_at": matched_url,
                "matcher_name": obj.get("matcher-name") or obj.get("matcher_name"),
                "extracted_results": obj.get("extracted-results") or obj.get("extracted_results"),
                "curl_command": obj.get("curl-command"),
                "type": obj.get("type"),
                "cve_ids": cve_ids,
            },
            "cvss": cvss_num,
            "references": list(refs),
            "metadata": {
                "tags": info.get("tags") or [],
                "author": info.get("author"),
                "classification": classification,
            },
        })
    return findings


def _host_from(url_or_host: str) -> str:
    from urllib.parse import urlsplit

    if "://" in url_or_host:
        return (urlsplit(url_or_host).hostname or "").lower()
    return url_or_host.split("/", 1)[0].split(":", 1)[0].lower()
