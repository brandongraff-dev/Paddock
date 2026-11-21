"""HTTP liveness + fingerprint probe.

Issues a GET (then a cheap HEAD + OPTIONS if the GET succeeded) and captures:

* status + redirect chain + final URL
* response headers, content type, server banner
* first 1 MiB body SHA-256 + response title
* technology fingerprints via normalize.tech_detect

Returns a dict of ``{assets, edges, findings}`` ready for bulk upsert.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any

import httpx
import structlog

from app import USER_AGENT
from app.config import settings
from app.normalize import tech_detect
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeGuard, normalize_target
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)

_MAX_BODY = 1 * 1024 * 1024  # 1 MiB
_TITLE_RX = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


async def probe(
    target: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Probe a single URL. Returns ``{assets, edges, findings, summary}``."""
    await scope.allow(target)
    host = _host_of(target)
    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []

    client = scope.build_client()
    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            try:
                resp = await client.get(target)
            except Exception as e:
                await orchestrator.outbound_log(new_outbound_row(
                    target=target, tool="http_probe", method="GET",
                    error=str(e), scope_matched=True, started_at=time.time(),
                ))
                log.warning("http_probe.error", target=target, error=str(e))
                raise

            politeness.record_response(host, resp.status_code, resp.headers.get("retry-after"))
            duration_ms = int((time.monotonic() - t0) * 1000)
            body = resp.content[:_MAX_BODY]
            body_sha = hashlib.sha256(body).hexdigest()

        await orchestrator.outbound_log(new_outbound_row(
            target=str(resp.url), tool="http_probe", method="GET",
            response_code=resp.status_code, scope_matched=True,
            duration_ms=duration_ms, bytes_in=len(body),
        ))

        title = _extract_title(body)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        redirect_chain = [str(h.url) for h in resp.history] + [str(resp.url)]

        endpoint_canonical = normalize_target(str(resp.url))
        endpoint_metadata = {
            "status": resp.status_code,
            "final_url": str(resp.url),
            "redirect_chain": redirect_chain,
            "content_type": headers.get("content-type"),
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "title": title,
            "body_sha256": body_sha,
            "body_bytes": len(body),
            "headers": headers,
            "scan_id": scan_id,
        }
        endpoint_asset = {
            "kind": "endpoint",
            "value": str(resp.url),
            "canonical": endpoint_canonical,
            "source": "http_probe",
            "metadata": endpoint_metadata,
        }
        assets.append(endpoint_asset)

        hits = tech_detect.detect(headers=headers, body=body)
        for h in hits:
            assets.append({
                "kind": "technology",
                "value": h.name + (f"@{h.version}" if h.version else ""),
                "canonical": h.name.lower() + (f"@{h.version}" if h.version else ""),
                "source": "http_probe",
                "confidence": h.confidence,
                "metadata": {"version": h.version, "detected_via": h.source},
            })
            edges.append({
                "src_kind": "endpoint",
                "src_canonical": endpoint_canonical,
                "dst_kind": "technology",
                "dst_canonical": h.name.lower() + (f"@{h.version}" if h.version else ""),
                "kind": "runs",
            })

        # Follow up with cheap HEAD/OPTIONS when the GET succeeded. They enrich
        # the endpoint record (allowed methods, caching) without re-pulling body.
        if 200 <= resp.status_code < 400:
            try:
                async with politeness.acquire(host):
                    opt = await client.request("OPTIONS", str(resp.url))
                endpoint_metadata["allow_methods"] = opt.headers.get("allow")
                await orchestrator.outbound_log(new_outbound_row(
                    target=str(resp.url), tool="http_probe", method="OPTIONS",
                    response_code=opt.status_code, scope_matched=True,
                ))
            except Exception as e:
                log.debug("http_probe.options_failed", error=str(e))
            try:
                async with politeness.acquire(host):
                    head = await client.head(str(resp.url))
                endpoint_metadata["head_status"] = head.status_code
                await orchestrator.outbound_log(new_outbound_row(
                    target=str(resp.url), tool="http_probe", method="HEAD",
                    response_code=head.status_code, scope_matched=True,
                ))
            except Exception as e:
                log.debug("http_probe.head_failed", error=str(e))

        # Security-header findings are produced by header_check — call it here
        # so a lone http_probe job still yields them.
        from app.modules.header_check import analyze_headers

        findings.extend(analyze_headers(
            final_url=str(resp.url),
            headers=headers,
            status_code=resp.status_code,
        ))
    finally:
        await client.aclose()

    return {
        "assets": assets,
        "edges": edges,
        "findings": findings,
        "summary": {
            "status": resp.status_code,
            "final_url": str(resp.url),
            "tech_count": len([a for a in assets if a["kind"] == "technology"]),
            "findings_count": len(findings),
        },
    }


def _extract_title(body: bytes) -> str | None:
    m = _TITLE_RX.search(body)
    if not m:
        return None
    try:
        return m.group(1).decode("utf-8", errors="replace").strip()[:300]
    except Exception:  # pragma: no cover
        return None
