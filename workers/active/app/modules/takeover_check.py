"""Subdomain-takeover detection.

Detection-only. For a subdomain asset we:

1. Resolve its CNAME chain (dnspython, async).
2. If the final CNAME target lands on a known third-party provider (S3, GitHub
   Pages, Heroku, Azure, Fastly, ...), politely GET the subdomain over HTTPS
   with the defensive scanner UA.
3. Match the provider's "unclaimed"/"dangling" fingerprint (body substring
   and/or HTTP status). A match means the DNS record points at a resource that
   no longer exists and could be re-registered by someone else.

On a match we raise a ``takeover`` finding describing how to reclaim or remove
the dangling record. We never register, claim, or otherwise take over the
resource — the whole point is to warn the owner before an attacker does.

Fingerprints live in ``app/data/takeover_fingerprints.json`` (sourced from the
community can-i-take-over-xyz project; see that file's ``_source``).

Scope is checked before any DNS lookup and again before the HTTP probe; an
out-of-scope subdomain is dropped (``ScopeDenied``) without a packet sent.
"""
from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeGuard, normalize_target
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)

_FINGERPRINTS_PATH = Path(__file__).resolve().parent.parent / "data" / "takeover_fingerprints.json"
_MAX_CNAME_DEPTH = 10
_MAX_SNIFF_BYTES = 64 * 1024


@lru_cache(maxsize=1)
def _load_fingerprints() -> dict[str, dict]:
    """Load (and cache) the service -> fingerprint map."""
    with _FINGERPRINTS_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("services", {})


async def _resolve_cname_chain(host: str) -> list[str]:
    """Follow CNAME records for ``host`` and return the chain of targets.

    Returns an ordered list of CNAME targets (without trailing dots); empty if
    the name has no CNAME. Resolution errors are swallowed — we return whatever
    chain we managed to follow. This is a module-level function so tests can
    monkeypatch it without touching the network.
    """
    import dns.asyncresolver
    import dns.resolver

    chain: list[str] = []
    name = host.rstrip(".")
    resolver = dns.asyncresolver.Resolver()
    seen: set[str] = set()
    for _ in range(_MAX_CNAME_DEPTH):
        if name.lower() in seen:
            break
        seen.add(name.lower())
        try:
            answer = await resolver.resolve(name, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            break
        except Exception as e:  # pragma: no cover - defensive
            log.info("takeover.cname_resolve_error", host=name, error=str(e))
            break
        targets = [r.target.to_text().rstrip(".") for r in answer]
        if not targets:
            break
        target = targets[0]
        chain.append(target)
        name = target
    return chain


def _match_service(cname_target: str, fingerprints: dict[str, dict]) -> str | None:
    """Return the service name whose CNAME suffixes match ``cname_target``."""
    target = cname_target.lower().rstrip(".")
    for service, spec in fingerprints.items():
        for suffix in spec.get("cname_suffixes", []):
            suf = suffix.lower().lstrip(".")
            if target == suf or target.endswith("." + suf):
                return service
    return None


def _fingerprint_match(spec: dict, status: int, body_text: str) -> bool:
    """Does the HTTP response match this service's 'unclaimed' signature?

    ``fingerprint_text`` (case-insensitive body substring) is the authoritative
    signal when present. Only when a service has no stable body marker do we
    fall back to matching ``http_status`` alone.
    """
    fp = (spec.get("fingerprint_text") or "").strip()
    want_status = spec.get("http_status")
    if fp:
        return fp.lower() in body_text.lower()
    if want_status is not None:
        return status == want_status
    return False


def _is_sensitive(asset_metadata: dict | None) -> bool:
    if not asset_metadata:
        return False
    env = str(asset_metadata.get("env") or "").lower()
    if env == "prod" or env == "production":
        return True
    sensitive = asset_metadata.get("sensitive")
    return sensitive is True or str(sensitive).lower() == "true"


async def check(
    subdomain: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
    asset_metadata: dict | None = None,
) -> dict[str, Any]:
    """Check a single subdomain for a dangling-CNAME takeover.

    Returns ``{assets, edges, findings, summary}``. Scope is enforced before
    the DNS lookup and again before the HTTP probe.
    """
    host = _host_of(subdomain)
    findings: list[dict] = []

    # Scope-gate before any DNS traffic. ScopeDenied propagates so the
    # dispatcher records the drop.
    await scope.allow(host)

    fingerprints = _load_fingerprints()
    chain = await _resolve_cname_chain(host)
    if not chain:
        return {"assets": [], "edges": [], "findings": findings,
                "summary": {"cname_chain": [], "matched_service": None}}

    cname_target = chain[-1]
    service = _match_service(cname_target, fingerprints)
    if service is None:
        return {"assets": [], "edges": [], "findings": findings,
                "summary": {"cname_chain": chain, "cname_target": cname_target,
                            "matched_service": None}}

    spec = fingerprints[service]

    # A third-party CNAME alone is normal. Confirm the dangling state by
    # fetching the subdomain over HTTPS (scope re-checked by the client hook)
    # and matching the provider's unclaimed fingerprint.
    url = f"https://{host}/"
    await scope.allow(url)
    client = scope.build_client()
    status = 0
    body_text = ""
    fetch_error: str | None = None
    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            try:
                resp = await client.get(url)
            except Exception as e:
                fetch_error = str(e)
                await orchestrator.outbound_log(new_outbound_row(
                    target=url, tool="takeover_check", method="GET",
                    error=fetch_error, scope_matched=True,
                ))
                log.info("takeover.fetch_error", url=url, error=fetch_error)
            else:
                politeness.record_response(host, resp.status_code, resp.headers.get("retry-after"))
                duration_ms = int((time.monotonic() - t0) * 1000)
                status = resp.status_code
                body_text = resp.content[:_MAX_SNIFF_BYTES].decode("utf-8", errors="replace")
                await orchestrator.outbound_log(new_outbound_row(
                    target=url, tool="takeover_check", method="GET",
                    response_code=status, scope_matched=True,
                    duration_ms=duration_ms, bytes_in=len(resp.content),
                ))
    finally:
        await client.aclose()

    matched = fetch_error is None and _fingerprint_match(spec, status, body_text)
    summary = {
        "cname_chain": chain,
        "cname_target": cname_target,
        "matched_service": service,
        "http_status": status,
        "takeover": matched,
    }
    if not matched:
        return {"assets": [], "edges": [], "findings": findings, "summary": summary}

    critical = _is_sensitive(asset_metadata)
    severity = "critical" if critical else "high"
    matched_fp = (spec.get("fingerprint_text") or "").strip() or f"http_status={spec.get('http_status')}"
    findings.append({
        "target_host": host,
        "target_canonical": normalize_target(host),
        "target_kind": "subdomain",
        "rule_id": "subdomain-takeover",
        "rule_source": "takeover",
        "severity": severity,
        "title": f"Dangling DNS — possible subdomain takeover ({service})",
        "description": (
            f"{host} has a CNAME pointing at {cname_target} ({service}), but that "
            f"resource returns {service}'s unclaimed-endpoint response. The backing "
            f"resource no longer exists, so an attacker who registers it on "
            f"{service} would serve content under {host} — enabling phishing, "
            f"cookie/session theft and brand abuse."
        ),
        "remediation": (
            f"Reclaim the resource on {service} if it should still exist, or delete "
            f"the dangling DNS record for {host}. Do not leave the CNAME pointing at "
            f"an unowned third-party resource."
        ),
        "evidence": {
            "cname_chain": chain,
            "cname_target": cname_target,
            "service": service,
            "matched_fingerprint": matched_fp,
            "http_status": status,
        },
    })
    log.info("takeover.detected", host=host, service=service, severity=severity)
    return {"assets": [], "edges": [], "findings": findings, "summary": summary}
