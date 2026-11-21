"""In-scope crawler backed by katana.

Reads katana's JSON lines, drops anything that falls out of scope, scans
JS bodies for common secret patterns and emits ``secret_candidate`` assets.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog

from app import USER_AGENT
from app.config import settings
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeDenied, ScopeGuard, normalize_target
from app.util import runner
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


# Conservative secret patterns. False positives are expensive at this layer
# (they end up in the asset graph), so we require relatively specific markers.
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws-access-key-id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("aws-secret-access-key", re.compile(r"\baws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "critical"),
    ("slack-webhook", re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}\b"), "high"),
    ("stripe-live-key", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "critical"),
    ("stripe-test-key", re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"), "medium"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "medium"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("private-key-header", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) PRIVATE KEY-----"), "critical"),
]


async def crawl(
    url: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    depth: int = 2,
    respect_robots: bool = True,
    scan_id: str | None = None,
) -> dict[str, Any]:
    await scope.allow(url)
    host = _host_of(url)
    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []

    if not respect_robots:
        log.warning("crawler.robots.override", url=url,
                    note="respect_robots=false for this scan — override logged")

    # Pre-check: fetch robots.txt courtesy of the limiter's cache.
    allowed = await politeness.robots_allows(url, respect=respect_robots)
    if not allowed:
        log.info("crawler.robots_disallow", url=url)
        return {"assets": assets, "edges": edges, "findings": findings,
                "summary": {"skipped": "robots_disallow"}}

    args = [
        "-u", url,
        "-d", str(depth),
        "-silent",
        "-jc", "-jsl",
        "-json",
        "-c", "10",
        "-rl", "20",
        "-ef", "woff,woff2,ttf,png,jpg,jpeg,gif,svg,ico,mp4",
    ]
    # NOTE: katana has -mdc for "match disallowed by robots". We let our own
    # pre-check gate things; katana itself will discover links we then filter.

    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            result = await runner.run("katana", args, timeout=settings.subprocess_timeout_sec)
    except runner.ToolUnavailable:
        findings.append({
            "target_host": host,
            "target_canonical": normalize_target(url),
            "target_kind": "endpoint",
            "rule_id": "tool-unavailable-katana",
            "rule_source": "policy",
            "severity": "info",
            "title": "katana not installed on this worker",
            "description": "Crawler skipped; binary missing.",
            "evidence": {"tool": "katana"},
        })
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {}}
    except (runner.ToolTimeout, runner.ToolFailed) as e:
        log.warning("katana.error", error=str(e))
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"error": str(e)}}

    duration_ms = int((time.monotonic() - t0) * 1000)
    await orchestrator.outbound_log(new_outbound_row(
        target=url, tool="katana", request_summary=" ".join(args),
        duration_ms=duration_ms, scope_matched=True,
    ))

    endpoints_seen: set[str] = set()
    js_urls: list[str] = []

    for line in result.lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        link = obj.get("request", {}).get("endpoint") or obj.get("endpoint") or obj.get("url")
        if not link:
            continue
        # Drop anything that falls out of scope.
        try:
            await scope.allow(link)
        except ScopeDenied:
            log.info("katana.drop_out_of_scope", url=link)
            continue
        if link in endpoints_seen:
            continue
        endpoints_seen.add(link)
        # Per-URL canonical form so different paths on the same host are
        # distinct endpoints in the asset graph.
        canonical = f"{normalize_target(link)}{urlsplit(link).path or '/'}"
        assets.append({
            "kind": "endpoint",
            "value": link,
            "canonical": canonical,
            "source": "crawler",
            "metadata": {"depth": obj.get("depth"), "discovered_by": "katana", "scan_id": scan_id},
        })
        if _is_js_url(link):
            js_urls.append(link)

    # Secret sweep on JS files. One short-timeout GET per unique JS URL,
    # throttled through the same politeness limiter.
    if js_urls:
        client = scope.build_client()
        try:
            for jurl in js_urls[:200]:  # bound: do not crawl a CDN forever
                try:
                    async with politeness.acquire(_host_of(jurl)):
                        resp = await client.get(jurl)
                    politeness.record_response(_host_of(jurl), resp.status_code,
                                               resp.headers.get("retry-after"))
                except Exception as e:
                    log.debug("crawler.js_fetch_failed", url=jurl, error=str(e))
                    continue
                await orchestrator.outbound_log(new_outbound_row(
                    target=jurl, tool="crawler", method="GET",
                    response_code=resp.status_code, scope_matched=True,
                    bytes_in=len(resp.content),
                ))
                body_text = resp.text[:300_000]
                for name, rx, severity in _SECRET_PATTERNS:
                    for m in rx.finditer(body_text):
                        snippet = _redact(body_text, m)
                        assets.append({
                            "kind": "secret_candidate",
                            "value": f"{name}:{_fingerprint(m.group(0))}",
                            "canonical": f"{name}:{_fingerprint(m.group(0))}",
                            "source": "crawler",
                            "confidence": 60,
                            "metadata": {
                                "pattern": name,
                                "found_in": jurl,
                            },
                        })
                        findings.append({
                            "target_host": _host_of(jurl),
                            "target_canonical": normalize_target(jurl),
                            "target_kind": "endpoint",
                            "rule_id": f"secret-{name}",
                            "rule_source": "secret_scan",
                            "severity": severity,
                            "title": f"Possible {name} in a served JavaScript file",
                            "description": f"Pattern {name!r} matched in a crawled JS bundle.",
                            "evidence": {"url": jurl, "snippet": snippet, "pattern": name},
                            "remediation": "Rotate the credential immediately and move it out of frontend bundles.",
                        })
        finally:
            await client.aclose()

    return {
        "assets": assets,
        "edges": edges,
        "findings": findings,
        "summary": {
            "endpoints": len(endpoints_seen),
            "js_scanned": len(js_urls),
            "findings_count": len(findings),
        },
    }


def _is_js_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs") or ".js?" in url.lower()


def _redact(body: str, m: re.Match) -> str:
    start = max(0, m.start() - 40)
    end = min(len(body), m.end() + 40)
    snippet = body[start:end]
    # Keep first/last 4 chars of the secret so analysts can confirm match
    # against a vault entry without the raw value flowing through the graph.
    raw = m.group(0)
    if len(raw) > 10:
        redacted = raw[:4] + "***" + raw[-4:]
    else:
        redacted = "***"
    return snippet.replace(raw, redacted)


def _fingerprint(raw: str) -> str:
    import hashlib

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
