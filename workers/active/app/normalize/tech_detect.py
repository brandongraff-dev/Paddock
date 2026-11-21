"""Tiny wappalyzer-flavored tech detector.

Not a full wappalyzer fingerprint database — just a well-maintained short list
that covers the most common signals: server banners, Set-Cookie flavors,
common response-header patterns, and a few body markers. Returns a list of
``(name, version|None, confidence 0..100)`` tuples.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TechHit:
    name: str
    version: str | None
    confidence: int
    source: str  # "header", "cookie", "body"


# Precompiled signatures. Keep this list conservative; false positives at
# this layer get re-emitted downstream and create noise in the asset graph.
_HEADER_SIGS: list[tuple[str, re.Pattern, str, int]] = [
    ("nginx", re.compile(r"^nginx(?:/([\d.]+))?", re.I), "server", 95),
    ("apache", re.compile(r"^apache(?:/([\d.]+))?", re.I), "server", 95),
    ("caddy", re.compile(r"^caddy", re.I), "server", 95),
    ("cloudflare", re.compile(r"cloudflare", re.I), "server", 90),
    ("microsoft-iis", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.I), "server", 95),
    ("gunicorn", re.compile(r"gunicorn(?:/([\d.]+))?", re.I), "server", 95),
    ("uvicorn", re.compile(r"uvicorn(?:/([\d.]+))?", re.I), "server", 95),
    ("vercel", re.compile(r"vercel", re.I), "server", 90),
    ("express", re.compile(r"express", re.I), "x-powered-by", 85),
    ("php", re.compile(r"PHP/([\d.]+)", re.I), "x-powered-by", 95),
    ("asp.net", re.compile(r"asp\.net", re.I), "x-powered-by", 90),
    ("wordpress", re.compile(r"wordpress", re.I), "x-powered-by", 75),
    ("cloudfront", re.compile(r"cloudfront", re.I), "via", 90),
]

_COOKIE_SIGS: list[tuple[str, re.Pattern, int]] = [
    ("django", re.compile(r"(?:^|; )(csrftoken|sessionid)="), 70),
    ("flask", re.compile(r"(?:^|; )session="), 50),
    ("express", re.compile(r"(?:^|; )connect\.sid="), 80),
    ("laravel", re.compile(r"(?:^|; )laravel_session=|XSRF-TOKEN="), 80),
    ("wordpress", re.compile(r"(?:^|; )wordpress_|wp-settings-"), 90),
    ("rails", re.compile(r"(?:^|; )_session_id="), 60),
    ("tomcat", re.compile(r"(?:^|; )JSESSIONID="), 60),
]

_BODY_SIGS: list[tuple[str, re.Pattern, int]] = [
    ("wordpress", re.compile(rb"(?i)<meta name=\"generator\" content=\"WordPress ([\d.]+)"), 90),
    ("drupal", re.compile(rb"(?i)<meta name=\"generator\" content=\"Drupal ([\d.]+)"), 90),
    ("joomla", re.compile(rb"(?i)<meta name=\"generator\" content=\"Joomla"), 90),
    ("next.js", re.compile(rb"__NEXT_DATA__"), 85),
    ("react", re.compile(rb"(?i)data-reactroot|__REACT_DEVTOOLS"), 70),
    ("angular", re.compile(rb"(?i)ng-version=\"([\d.]+)\""), 90),
    ("vue", re.compile(rb"(?i)__VUE__|data-v-"), 65),
]


def detect(
    *,
    headers: dict[str, str] | None,
    body: bytes | None,
) -> list[TechHit]:
    """Return a de-duplicated list of tech hits."""
    hits: dict[str, TechHit] = {}

    def add(h: TechHit) -> None:
        prev = hits.get(h.name)
        if prev is None or h.confidence > prev.confidence:
            hits[h.name] = h

    # Normalize headers to lowercase keys.
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}

    for name, rx, header_name, conf in _HEADER_SIGS:
        val = hdrs.get(header_name, "")
        if not val:
            continue
        m = rx.search(val)
        if m:
            version = m.group(1) if m.groups() else None
            add(TechHit(name=name, version=version, confidence=conf, source="header"))

    # cookies
    cookie = hdrs.get("set-cookie", "")
    for name, rx, conf in _COOKIE_SIGS:
        if rx.search(cookie):
            add(TechHit(name=name, version=None, confidence=conf, source="cookie"))

    if body:
        for name, rx, conf in _BODY_SIGS:
            m = rx.search(body[:200_000])  # bound body scan
            if m:
                version = None
                try:
                    if m.groups():
                        version = m.group(1).decode("utf-8", errors="replace")
                except IndexError:  # pragma: no cover
                    version = None
                add(TechHit(name=name, version=version, confidence=conf, source="body"))

    return sorted(hits.values(), key=lambda h: h.name)
