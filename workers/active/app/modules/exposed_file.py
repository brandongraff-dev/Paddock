"""Exposed-file sweep.

Polite single GETs to a short list of well-known sensitive paths. Only flags
a finding when the status is 200 *and* the body matches a format marker we
expect for that path (so a SPA that returns 200 for everything does not
drown the operator in false positives).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
import structlog

from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeGuard, normalize_target
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _Target:
    path: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    rule_id: str
    pattern: re.Pattern | None  # body must match this if provided
    description: str


# Each entry's severity is the severity we attach when the match is positive.
PATHS: list[_Target] = [
    _Target("/.git/HEAD", "high", "exposed-git-head",
            re.compile(rb"^ref: refs/heads/\S+", re.M),
            "A .git directory is accessible — source tree may be reconstructable."),
    _Target("/.env", "critical", "exposed-env",
            re.compile(rb"(?i)^(?:[A-Z0-9_]{2,}=|APP_|DATABASE_|AWS_|SECRET_|TOKEN=)", re.M),
            "An environment file is publicly accessible — likely contains secrets."),
    _Target("/.env.local", "critical", "exposed-env-local",
            re.compile(rb"(?i)^(?:[A-Z0-9_]{2,}=)", re.M),
            "A local environment file is publicly accessible."),
    _Target("/.aws/credentials", "critical", "exposed-aws-credentials",
            re.compile(rb"\[default\]|aws_access_key_id\s*="),
            "AWS credentials file is publicly accessible."),
    _Target("/config.php.bak", "high", "exposed-config-backup",
            re.compile(rb"(?i)<\?php|define\s*\("),
            "A PHP config backup is publicly accessible."),
    _Target("/backup.zip", "high", "exposed-backup-archive", None,
            "A backup archive is publicly accessible."),
    _Target("/database.sql", "critical", "exposed-database-dump",
            re.compile(rb"(?i)^-- MySQL|CREATE TABLE|DROP TABLE", re.M),
            "A database dump is publicly accessible."),
    _Target("/.DS_Store", "low", "exposed-ds-store",
            re.compile(rb"^Bud1"),
            "macOS .DS_Store exposes directory listing."),
    _Target("/robots.txt", "info", "robots-txt-present",
            re.compile(rb"(?i)user-agent:"),
            "robots.txt is served — informational."),
    _Target("/sitemap.xml", "info", "sitemap-present",
            re.compile(rb"(?i)<urlset|<sitemapindex"),
            "sitemap.xml is served — informational."),
    _Target("/server-status", "medium", "exposed-apache-server-status",
            re.compile(rb"(?i)Apache Server Status|Current Time:"),
            "Apache mod_status exposes operational details."),
    _Target("/.well-known/security.txt", "info", "security-txt-present",
            re.compile(rb"(?i)^Contact:", re.M),
            "security.txt is published — informational (good hygiene)."),
]

_MAX_SNIFF_BYTES = 8192


async def scan(
    base_url: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Probe each exposed path under ``base_url``. Returns findings ready
    for bulk upsert.
    """
    await scope.allow(base_url)
    host = _host_of(base_url)
    findings: list[dict] = []
    client = scope.build_client()

    try:
        for entry in PATHS:
            url = urljoin(base_url if base_url.endswith("/") else base_url + "/", entry.path.lstrip("/"))
            try:
                async with politeness.acquire(host):
                    t0 = time.monotonic()
                    resp = await client.get(url)
                politeness.record_response(host, resp.status_code, resp.headers.get("retry-after"))
                duration_ms = int((time.monotonic() - t0) * 1000)
                body_head = resp.content[:_MAX_SNIFF_BYTES]
                await orchestrator.outbound_log(new_outbound_row(
                    target=url, tool="exposed_file", method="GET",
                    response_code=resp.status_code, scope_matched=True,
                    duration_ms=duration_ms, bytes_in=len(resp.content),
                ))
            except Exception as e:
                await orchestrator.outbound_log(new_outbound_row(
                    target=url, tool="exposed_file", method="GET",
                    error=str(e), scope_matched=True,
                ))
                log.info("exposed_file.error", url=url, error=str(e))
                continue

            # 200 with the right content pattern → finding. 2xx/3xx otherwise
            # without the pattern → nothing: avoids SPA-wildcard FPs.
            if resp.status_code == 200 and (entry.pattern is None or entry.pattern.search(body_head)):
                findings.append({
                    "target_host": host,
                    "target_canonical": normalize_target(url),
                    "target_kind": "endpoint",
                    "rule_id": entry.rule_id,
                    "rule_source": "exposed_file",
                    "severity": entry.severity,
                    "title": f"Sensitive file exposed: {entry.path}",
                    "description": entry.description,
                    "evidence": {
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type"),
                        "body_head_sha_prefix": body_head[:64].hex(),
                        "bytes": len(resp.content),
                    },
                    "remediation": "Remove the file or block the path at the web server / CDN.",
                })
    finally:
        await client.aclose()

    return {"assets": [], "edges": [], "findings": findings, "summary": {"findings_count": len(findings)}}
