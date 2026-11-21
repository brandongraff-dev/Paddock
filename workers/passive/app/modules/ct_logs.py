"""Certificate Transparency log enumeration.

Primary source: crt.sh JSON API
  https://crt.sh/?q=%25.{domain}&output=json

Optional fallback: Censys CT API (requires CENSYS_API_ID / CENSYS_API_SECRET).

For every unique certificate row we:
  - split the `name_value` field on newlines (crt.sh packs SANs there)
  - lowercase, strip wildcards, dedupe
  - keep only names that end in `.{domain}` or equal `{domain}`
  - emit `subdomain` assets, `certificate` assets, and the edges
"""
from __future__ import annotations

import base64
from typing import Any

from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


CRTSH_SOURCE = "crtsh"
CENSYS_SOURCE = "censys"


def _normalize_name(raw: str) -> str:
    n = raw.strip().lower()
    if n.startswith("*."):
        n = n[2:]
    # strip trailing dot; also protect against embedded whitespace
    n = n.rstrip(".").strip()
    return n


def _extract_names(name_value: str, apex: str) -> set[str]:
    """Parse crt.sh name_value and filter to the apex scope."""
    out: set[str] = set()
    for piece in (name_value or "").split("\n"):
        n = _normalize_name(piece)
        if not n:
            continue
        if n == apex or n.endswith("." + apex):
            out.add(n)
    return out


def _parse_crtsh_rows(rows: list[dict[str, Any]], apex: str) -> tuple[set[str], list[dict[str, Any]]]:
    """Return (subdomain_set, certificate_asset_list) from raw crt.sh rows."""
    subdomains: set[str] = set()
    certs: list[dict[str, Any]] = []
    seen_certs: set[str] = set()
    for row in rows or []:
        names = _extract_names(row.get("name_value", ""), apex)
        subdomains.update(names)

        # Deduplicate certificates by (serial_number, issuer_name) — crt.sh
        # repeats rows per SAN. A missing serial falls back to id.
        cert_key = f"{row.get('serial_number','')}:{row.get('issuer_name','')}"
        if cert_key in seen_certs:
            continue
        seen_certs.add(cert_key)

        certs.append({
            "serial_number": row.get("serial_number"),
            "issuer_name": row.get("issuer_name"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "entry_timestamp": row.get("entry_timestamp"),
            "common_name": row.get("common_name"),
            "names": sorted(names),
        })
    return subdomains, certs


async def _fetch_crtsh(ctx: ModuleContext, domain: str) -> list[dict[str, Any]]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, body = await ctx.get_json(url, source=CRTSH_SOURCE)
    if status >= 400 or not isinstance(body, list):
        logger.warning("crt.sh returned status={} for domain", status)
        return []
    return body


async def _fetch_censys(ctx: ModuleContext, domain: str) -> list[dict[str, Any]]:
    """Fallback CT search via Censys. Returns [] if no credentials."""
    s = ctx.settings
    if not (s.censys_api_id and s.censys_api_secret):
        return []
    userpass = f"{s.censys_api_id}:{s.censys_api_secret}".encode()
    token = base64.b64encode(userpass).decode()
    url = "https://search.censys.io/api/v2/certificates/search"
    params = {"q": f"names: {domain}", "per_page": 100}
    status, body = await ctx.get_json(
        url, source=CENSYS_SOURCE,
        headers={"Authorization": f"Basic {token}"},
        params=params,
    )
    if status >= 400 or not isinstance(body, dict):
        return []
    hits = body.get("result", {}).get("hits", []) or []
    # Normalize to a crt.sh-ish shape so we can share the parser.
    rows: list[dict[str, Any]] = []
    for h in hits:
        names = h.get("names") or []
        parsed = h.get("parsed") or {}
        rows.append({
            "name_value": "\n".join(names),
            "serial_number": parsed.get("serial_number"),
            "issuer_name": (parsed.get("issuer") or {}).get("common_name"),
            "not_before": parsed.get("validity", {}).get("start"),
            "not_after": parsed.get("validity", {}).get("end"),
            "common_name": (parsed.get("subject") or {}).get("common_name"),
        })
    return rows


def _build_result(
    domain: str,
    subdomains: set[str],
    certs: list[dict[str, Any]],
    *,
    source: str,
) -> ModuleResult:
    r = ModuleResult(module="ct_logs")
    # domain asset (so edges have a target)
    r.assets.append({
        "kind": "domain",
        "value": domain,
        "source": source,
        "metadata": {},
    })
    for sub in sorted(subdomains):
        r.assets.append({
            "kind": "subdomain",
            "value": sub,
            "source": source,
            "metadata": {"apex": domain},
        })
        r.edges.append({
            "src_kind": "subdomain", "src_value": sub,
            "dst_kind": "domain", "dst_value": domain,
            "kind": "contains",
        })
    for c in certs:
        cert_id = c.get("serial_number") or c.get("common_name") or c.get("issuer_name")
        if not cert_id:
            continue
        r.assets.append({
            "kind": "certificate",
            "value": str(cert_id),
            "source": source,
            "metadata": {
                "issuer": c.get("issuer_name"),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "common_name": c.get("common_name"),
                "names": c.get("names", []),
            },
        })
        # Edge: certificate issued_for subdomain/domain for each name
        for n in c.get("names", []) or []:
            if n == domain:
                r.edges.append({
                    "src_kind": "certificate", "src_value": str(cert_id),
                    "dst_kind": "domain", "dst_value": domain,
                    "kind": "issued_for",
                })
            else:
                r.edges.append({
                    "src_kind": "certificate", "src_value": str(cert_id),
                    "dst_kind": "subdomain", "dst_value": n,
                    "kind": "issued_for",
                })
    return r


async def run(domain: str, ctx: ModuleContext) -> ModuleResult:
    domain = domain.strip().lower().rstrip(".")
    rows = await _fetch_crtsh(ctx, domain)
    if not rows:
        rows = await _fetch_censys(ctx, domain)
        source = "censys"
    else:
        source = "crtsh"

    subs, certs = _parse_crtsh_rows(rows, domain)
    result = _build_result(domain, subs, certs, source=source)
    result.source_calls = 1 if rows else 0
    return result
