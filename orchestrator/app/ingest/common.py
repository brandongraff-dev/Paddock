"""Shared types and sanitizers for the universal ingest parsers.

Everything that arrives here is hostile input from a third-party tool, so:
text is control-character-stripped and length-capped, severities are mapped
onto Paddock's five levels, file paths are made relative and traversal-free,
URLs lose their credentials, and a malformed record never raises -- it is
counted and reported (``ParseResult.errors``).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_ERRORS = 50

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)


class IngestError(ValueError):
    """The payload is unusable as a whole (maps to HTTP 4xx)."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


@dataclass
class IFinding:
    asset_kind: str
    asset_value: str
    rule_id: str
    rule_source: str
    severity: str
    title: str
    description: str = ""
    remediation: Optional[str] = None
    impact: Optional[str] = None
    cvss: Optional[float] = None
    references: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    format: str
    tool: str = ""
    findings: list[IFinding] = field(default_factory=list)
    # SBOM-shaped output (same shape as app.standards.parse_sbom) or None
    sbom: Optional[dict[str, Any]] = None
    # components seen alongside findings (Trivy/Grype), stored under project_hint
    components: list[dict[str, Any]] = field(default_factory=list)
    component_vulns: list[dict[str, Any]] = field(default_factory=list)
    project_hint: Optional[str] = None
    errors: list[dict[str, str]] = field(default_factory=list)
    skipped: int = 0

    def error(self, where: str, message: str) -> None:
        self.skipped += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"where": clean(where, 120), "message": clean(message, 300)})


def clean(value: Any, limit: int = 2000) -> str:
    """Printable, bounded string (never raises)."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = _CTRL_RE.sub("", s).replace("\r\n", "\n").strip()
    return s[:limit]


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


_SEV_WORDS = {
    "critical": "critical", "crit": "critical", "fatal": "critical", "blocker": "critical",
    "high": "high", "error": "high", "important": "high", "major": "high", "severe": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low", "note": "low", "negligible": "low",
    "info": "info", "informational": "info", "information": "info", "none": "info",
    "unknown": "info", "unspecified": "info", "trivial": "info", "style": "info", "ignored": "info",
}


def norm_severity(value: Any, default: str = "medium") -> str:
    """Map a tool's severity word or number (0-5 ordinal, 0-10 CVSS) onto Paddock's levels."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        if value > 5:
            return cvss_severity(float(value))
        return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical"}.get(
            int(value), default)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _SEV_WORDS:
            return _SEV_WORDS[v]
        try:
            return norm_severity(float(v), default)
        except ValueError:
            return default
    return default


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def to_cvss(v: Any) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return round(f, 1) if 0 <= f <= 10 else None


def cves_in(*texts: Any) -> list[str]:
    found: list[str] = []
    for t in texts:
        for s in (t if isinstance(t, list) else [t]):
            if isinstance(s, str):
                for m in _CVE_RE.findall(s):
                    m = m.upper()
                    if m not in found:
                        found.append(m)
    return found


def clean_refs(refs: Any, limit: int = 20) -> list[str]:
    out: list[str] = []
    for r in as_list(refs):
        if isinstance(r, dict):
            r = r.get("url") or r.get("href")
        if isinstance(r, str):
            r = clean(r, 500)
            if r.startswith(("http://", "https://")) and r not in out:
                out.append(r)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
# paths & hosts
# --------------------------------------------------------------------------- #

def safe_path(p: Any) -> str:
    """A repository-relative path with no traversal, drive, scheme or NUL.

    ``file:///etc/passwd`` -> ``etc/passwd``; ``../../x`` -> ``x``; ``C:\\a\\b`` -> ``a/b``.
    Used for display and identity only -- the server never opens these paths.
    """
    s = clean(p, 1024).replace("\\", "/")
    if s.lower().startswith("file:"):
        s = s[5:]
    s = re.sub(r"^[A-Za-z]:", "", s)
    parts = [x for x in s.split("/") if x not in ("", ".", "..")]
    return "/".join(parts)[:512]


def strip_url_credentials(u: str) -> str:
    try:
        parts = urlsplit(u)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return ""
    if not parts.scheme or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    return f"{parts.scheme.lower()}://{netloc}{parts.path or ''}"[:512]


def host_asset(value: Any) -> Optional[tuple[str, str]]:
    """Classify a host / IP / URL into (asset_kind, value), or None."""
    s = clean(value, 600)
    if not s or " " in s:
        return None
    if "://" in s:
        url = strip_url_credentials(s)
        return ("endpoint", url) if url else None
    h = s.strip("[]").lower()
    if h.count(":") == 1 and h.rsplit(":", 1)[1].isdigit():       # host:port
        h = h.rsplit(":", 1)[0]
    try:
        ip = ipaddress.ip_address(h)
        return ("ipv6" if ip.version == 6 else "ipv4", str(ip))
    except ValueError:
        pass
    h = h.rstrip(".")
    if _HOST_RE.match(h):
        return ("subdomain" if h.count(".") >= 2 else "domain", h)
    return None


def slug(value: Any, limit: int = 120) -> str:
    return re.sub(r"[^A-Za-z0-9._:@/+-]+", "_", clean(value, limit)).strip("_") or "unknown"
