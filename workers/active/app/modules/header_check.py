"""Security-headers analyzer.

Pure Python: given response headers and the final URL it returns findings for
missing or weak security headers. The severity table is deliberately small
and conservative — "high" is reserved for cases where the absence meaningfully
changes attack surface on a real HTML response.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.scope_guard import normalize_target


# Each row: (rule_id, title, severity, impact, remediation)
_HEADER_RULES = {
    "missing_hsts": (
        "missing-strict-transport-security",
        "Strict-Transport-Security header missing",
        "medium",
        "Clients may be downgraded to HTTP, enabling SSL-strip style attacks.",
        "Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    "weak_hsts": (
        "weak-strict-transport-security",
        "Strict-Transport-Security max-age too low",
        "low",
        "Short max-age defeats the purpose of HSTS caching.",
        "Set max-age to at least 15552000 (180 days).",
    ),
    "missing_csp": (
        "missing-content-security-policy",
        "Content-Security-Policy missing",
        "medium",
        "No in-depth defense against XSS / data exfiltration via script injection.",
        "Add a strict CSP; start with report-only and ratchet up.",
    ),
    "weak_csp": (
        "weak-content-security-policy",
        "Content-Security-Policy allows unsafe-inline or '*'",
        "low",
        "Permissive CSP provides little real protection against XSS.",
        "Tighten CSP: drop unsafe-inline, enumerate origins.",
    ),
    "missing_xcto": (
        "missing-x-content-type-options",
        "X-Content-Type-Options missing",
        "low",
        "Browsers may MIME-sniff responses, enabling type-confusion attacks.",
        "Add `X-Content-Type-Options: nosniff`.",
    ),
    "missing_xfo_or_frame_ancestors": (
        "missing-frame-protection",
        "No X-Frame-Options and no CSP frame-ancestors directive",
        "medium",
        "Page can be framed by a third party — clickjacking surface.",
        "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    ),
    "missing_referrer_policy": (
        "missing-referrer-policy",
        "Referrer-Policy missing",
        "info",
        "Full referrer URLs may leak to third parties.",
        "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    "missing_permissions_policy": (
        "missing-permissions-policy",
        "Permissions-Policy missing",
        "info",
        "No explicit control over browser feature access.",
        "Add a Permissions-Policy denying unused features.",
    ),
    "cookie_missing_secure": (
        "cookie-missing-secure",
        "Set-Cookie missing Secure attribute",
        "medium",
        "Cookie can be sent over plaintext HTTP, exposing session tokens.",
        "Add the Secure attribute on every cookie set over HTTPS.",
    ),
    "cookie_missing_httponly": (
        "cookie-missing-httponly",
        "Set-Cookie missing HttpOnly attribute",
        "medium",
        "Cookie value is reachable from JavaScript (XSS → session theft).",
        "Add HttpOnly on session cookies.",
    ),
    "cookie_missing_samesite": (
        "cookie-missing-samesite",
        "Set-Cookie missing SameSite attribute",
        "low",
        "Cross-site requests may send the cookie (CSRF surface).",
        "Add `SameSite=Lax` (or `Strict`).",
    ),
}


def analyze_headers(
    *,
    final_url: str,
    headers: dict[str, str],
    status_code: int,
) -> list[dict[str, Any]]:
    """Return a list of finding dicts (with ``target_host`` set)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    parsed = urlsplit(final_url)
    is_https = parsed.scheme == "https"
    host = (parsed.hostname or "").lower()
    canonical = normalize_target(final_url)
    out: list[dict[str, Any]] = []

    def emit(key: str, *, evidence: dict | None = None) -> None:
        rule_id, title, severity, impact, remediation = _HEADER_RULES[key]
        out.append({
            "target_host": host,
            "target_canonical": canonical,
            "target_kind": "endpoint",
            "rule_id": rule_id,
            "rule_source": "header_check",
            "severity": severity,
            "title": title,
            "description": impact,
            "impact": impact,
            "remediation": remediation,
            "evidence": {"url": final_url, "status": status_code, **(evidence or {})},
        })

    # Only meaningful on 2xx/3xx HTML-ish responses, but we check anyway at info
    # level so the operator sees the gap even on redirects.
    hsts = h.get("strict-transport-security")
    if is_https:
        if not hsts:
            emit("missing_hsts")
        else:
            max_age = _extract_max_age(hsts)
            if max_age is not None and max_age < 15552000:
                emit("weak_hsts", evidence={"max_age": max_age})

    csp = h.get("content-security-policy") or h.get("content-security-policy-report-only")
    if not csp:
        emit("missing_csp")
    else:
        low = csp.lower()
        if "unsafe-inline" in low or "'unsafe-inline'" in low or " * " in f" {low} " or low.strip().endswith("*"):
            emit("weak_csp", evidence={"csp": csp[:300]})

    if "x-content-type-options" not in h:
        emit("missing_xcto")

    xfo = h.get("x-frame-options")
    frame_ancestors = _csp_has(csp or "", "frame-ancestors")
    if not xfo and not frame_ancestors:
        emit("missing_xfo_or_frame_ancestors")

    if "referrer-policy" not in h:
        emit("missing_referrer_policy")

    if "permissions-policy" not in h:
        emit("missing_permissions_policy")

    # Cookies: evaluate every Set-Cookie header value.
    cookies = _split_cookies(h.get("set-cookie", ""))
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        if is_https and "secure" not in low:
            emit("cookie_missing_secure", evidence={"cookie": name})
        if "httponly" not in low:
            emit("cookie_missing_httponly", evidence={"cookie": name})
        if "samesite" not in low:
            emit("cookie_missing_samesite", evidence={"cookie": name})

    return out


def _extract_max_age(hsts_value: str) -> int | None:
    for part in hsts_value.split(";"):
        p = part.strip()
        if p.lower().startswith("max-age="):
            try:
                return int(p.split("=", 1)[1])
            except (ValueError, IndexError):
                return None
    return None


def _csp_has(csp: str, directive: str) -> bool:
    for part in csp.split(";"):
        if part.strip().lower().startswith(directive.lower()):
            return True
    return False


def _split_cookies(raw: str) -> list[str]:
    if not raw:
        return []
    # httpx's Set-Cookie join uses ", " but a cookie value can also contain
    # commas in the Expires attribute. Split on a conservative heuristic:
    # look for ", " followed by what looks like a new cookie name.
    import re
    parts = re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", raw)
    return [p for p in parts if "=" in p]
