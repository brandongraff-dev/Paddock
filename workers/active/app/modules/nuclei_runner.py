"""nuclei subprocess with the safe-template filters this service enforces.

Defaults (not configurable to anything looser):

* ``-rate-limit 50``
* ``-rate-limit-minute 500``
* ``-exclude-tags intrusive,fuzz,dos,miscellaneous``
* ``-exclude-severity unknown``
* ``-timeout 10 -retries 1``

The severity+tags from the job config can narrow the surface further, never widen.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from app.config import settings
from app.normalize.nuclei_output import normalize_hits
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeDenied, ScopeGuard, normalize_target
from app.util import runner
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_ALLOWED_TAGS = {
    "exposure", "misconfig", "cve", "default-login", "takeover",
    "tech", "panel", "config", "backup", "ssrf", "xss", "lfi",
    "sqli", "rce", "xxe", "oob",
}


async def run_nuclei(
    url: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    severity: str = "low,medium,high,critical",
    tags: str = "exposure,misconfig,cve",
    scan_id: str | None = None,
) -> dict[str, Any]:
    await scope.allow(url)
    host = _host_of(url)
    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []

    sev = _filter_csv(severity, _ALLOWED_SEVERITIES, default="low,medium,high,critical")
    tgs = _filter_csv(tags, _ALLOWED_TAGS, default="exposure,misconfig,cve")

    args = [
        "-u", url,
        "-severity", sev,
        "-tags", tgs,
        "-exclude-tags", settings.nuclei_exclude_tags,
        "-exclude-severity", "unknown",
        "-rate-limit", str(settings.nuclei_rate_limit),
        "-rate-limit-minute", str(settings.nuclei_rate_limit_minute),
        "-timeout", "10",
        "-retries", "1",
        "-jsonl",
        "-silent",
        "-stats-interval", "0",
        "-disable-update-check",
        "-H", f"User-Agent: {settings.user_agent}",
    ]

    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            result = await runner.run("nuclei", args, timeout=settings.subprocess_timeout_sec)
    except runner.ToolUnavailable:
        findings.append({
            "target_host": host,
            "target_canonical": normalize_target(url),
            "target_kind": "endpoint",
            "rule_id": "tool-unavailable-nuclei",
            "rule_source": "policy",
            "severity": "info",
            "title": "nuclei not installed on this worker",
            "description": "Scan skipped; binary missing.",
            "evidence": {"tool": "nuclei"},
        })
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {}}
    except runner.ToolTimeout as e:
        log.warning("nuclei.timeout", error=str(e))
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"error": "timeout"}}
    except runner.ToolFailed as e:
        # nuclei can return non-zero with no hits in some versions.
        log.info("nuclei.nonzero", returncode=e.returncode, stderr=e.stderr[:200])
        result = None

    duration_ms = int((time.monotonic() - t0) * 1000) if result else None
    if result is None:
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"hits": 0}}

    await orchestrator.outbound_log(new_outbound_row(
        target=url, tool="nuclei",
        request_summary=" ".join(args),
        duration_ms=duration_ms, scope_matched=True,
    ))

    # Build an "in-scope hosts" filter so nuclei's redirect-followed rows
    # cannot smuggle out-of-scope results in.
    in_scope: set[str] = set()
    # Pre-seed with the target's host.
    in_scope.add(host)
    for hit in normalize_hits(result.lines):
        h = hit.get("target_host") or ""
        if h and h not in in_scope:
            try:
                await scope.allow(h)
                in_scope.add(h)
            except ScopeDenied:
                log.warning("nuclei.drop_out_of_scope", host=h)
                continue
        findings.append(_to_finding(hit))

    return {"assets": assets, "edges": edges, "findings": findings, "summary": {"hits": len(findings)}}


def _filter_csv(csv: str, allowed: set[str], *, default: str) -> str:
    kept = [v.strip().lower() for v in csv.split(",") if v.strip().lower() in allowed]
    if not kept:
        kept = default.split(",")
    return ",".join(kept)


def _to_finding(hit: dict) -> dict:
    return {
        "target_host": hit["target_host"],
        "target_canonical": normalize_target(hit["target_url"]),
        "target_kind": "endpoint",
        "rule_id": hit["rule_id"],
        "rule_source": "nuclei",
        "severity": hit["severity"],
        "title": hit["title"],
        "description": hit["description"],
        "impact": hit.get("impact"),
        "remediation": hit.get("remediation"),
        "evidence": hit["evidence"],
        "cvss": hit.get("cvss"),
        "references": hit.get("references", []),
        "metadata": hit.get("metadata", {}),
    }
