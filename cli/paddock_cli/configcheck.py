"""Web-server configuration checks (CLI-local, nginx-style ``.conf`` files).

The Paddock engines have no repo-level IaC scanner, but the remediation
generators already know how to flip two insecure nginx settings
(``ssl_protocols`` and the HSTS header). These checks detect exactly the cases
those generators can fix, so every finding here comes with a ready-made patch.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

_WEAK_TLS = re.compile(r"\b(SSLv2|SSLv3|TLSv1(?:\.0)?|TLSv1\.1)\b(?!\.\d)")
_SSL_PROTOCOLS = re.compile(r"^\s*ssl_protocols\s+([^;]+);", re.I)
_LISTEN_SSL = re.compile(r"^\s*listen\s+[^;]*\bssl\b", re.I)
_SERVER_OPEN = re.compile(r"^\s*server\s*\{?\s*$|\bserver\s*\{")


@dataclass
class ConfigHit:
    rule: str            # 'nginx-weak-tls' | 'nginx-no-hsts'
    severity: str
    file: str
    line: int
    message: str
    why: str
    fix_class: str       # remediation generator class: config_fix | security_header
    fix_header: str | None = None


def looks_like_nginx(rel: str, text: str) -> bool:
    base = os.path.basename(rel).lower()
    if not (base.endswith(".conf") or base in ("nginx.conf", "default")):
        return False
    return bool(re.search(r"^\s*(server|http|events)\s*\{", text, re.M)
                or "ssl_protocols" in text)


def _first_server_has_ssl(text: str) -> bool:
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if _SERVER_OPEN.search(ln)), None)
    if start is None:
        return False
    nxt = next((i for i in range(start + 1, len(lines)) if _SERVER_OPEN.search(lines[i])),
               len(lines))
    return any(_LISTEN_SSL.match(ln) for ln in lines[start:nxt])


def check_nginx(rel: str, text: str) -> list[ConfigHit]:
    if not looks_like_nginx(rel, text):
        return []
    hits: list[ConfigHit] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _SSL_PROTOCOLS.match(line)
        if m and _WEAK_TLS.search(m.group(1)):
            hits.append(ConfigHit(
                "nginx-weak-tls", "medium", rel, i,
                f"ssl_protocols allows deprecated protocols ({m.group(1).strip()})",
                "TLS 1.0 and 1.1 have known downgrade and cipher weaknesses and are rejected by "
                "PCI DSS and every current browser. Pin to TLS 1.2 and 1.3.",
                "config_fix"))
    if not re.search(r"strict-transport-security", text, re.I) and _first_server_has_ssl(text):
        ln = next((i for i, x in enumerate(text.splitlines(), 1) if _LISTEN_SSL.match(x)), 1)
        hits.append(ConfigHit(
            "nginx-no-hsts", "low", rel, ln,
            "HTTPS server does not send a Strict-Transport-Security header",
            "Without HSTS a first visit over plain HTTP can be downgraded or intercepted. "
            "The header tells browsers to use HTTPS only.",
            "security_header", "strict-transport-security"))
    return hits
