"""Domain validation for the public passive features.

A public, unauthenticated endpoint takes a domain from the internet, so the
validator is strict and boring. It accepts ONLY a registrable public domain
(``example.com``, ``bücher.de``, ``example.co.uk``) and returns its canonical
lower-case ASCII (punycode) form. It rejects, with a stable machine code:

* IP literals in every spelling (dotted, decimal, hex, octal, IPv6, bracketed)
* internal / reserved names (``localhost``, ``*.local``, ``*.internal``, bare
  labels such as ``intranet``, ``*.arpa`` ...)
* public suffixes themselves (``com``, ``co.uk``) and sub-domains
  (``www.example.com`` -> ask for ``example.com``)
* URLs, ports, paths, user-info, wildcards, whitespace / control characters
* malformed IDN / punycode, over-long names (>253 octets, label >63)

The list of multi-label suffixes is a deliberately small embedded subset of
the Public Suffix List: it only needs to be right for the common cases, and a
wrong guess can only make a passive DNS/CT lookup cover a slightly different
(still public) name.
"""
from __future__ import annotations

import ipaddress
import re

import idna

MAX_RAW = 300          # refuse to even IDNA-process anything longer
MAX_NAME = 253
MAX_LABEL = 63


class DomainError(ValueError):
    """The input is not an acceptable public domain. ``code`` is stable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Top-level labels that can only ever mean "not on the public internet".
INTERNAL_TLDS = frozenset({
    "localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
    "corp", "private", "test", "invalid", "example", "onion", "arpa", "alt",
    "domain", "workgroup", "host", "router", "gateway", "dhcp", "wpad",
    "mshome", "belkin", "lab", "svc", "cluster", "kubernetes", "consul",
    "ts", "sys", "zone",
})

# Multi-label public suffixes (ICANN section) + popular private-suffix hosts
# where each customer owns exactly one label below the suffix.
MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
    "co.za", "org.za", "net.za", "gov.za",
    "com.mx", "org.mx", "gob.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.uy",
    "com.tr", "org.tr", "gov.tr", "com.sg", "edu.sg", "com.hk", "org.hk",
    "com.tw", "org.tw", "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id",
    "com.my", "com.ph", "com.pk", "com.ng", "com.eg", "com.ua", "com.pl", "net.pl",
    "co.th", "in.th", "com.vn", "com.sa", "com.qa", "co.ke", "com.gh", "co.tz",
    "co.at", "or.at", "co.hu", "com.gr", "com.pt", "com.ro", "com.ru", "org.ru",
    # private-section suffixes that are shared hosting platforms
    "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net", "blogspot.com",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "cloudfront.net",
    "amazonaws.com", "appspot.com", "firebaseapp.com", "web.app", "onrender.com",
    "fly.dev", "wordpress.com", "myshopify.com", "s3.amazonaws.com", "cloudapp.net",
    "trafficmanager.net", "azureedge.net", "ngrok.io", "repl.co", "glitch.me",
})

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BAD_CHARS = re.compile(r"[\s\x00-\x1f\x7f/\\@:?#*\[\]()<>,;'\"`|{}%^&=+~!$]")


def _looks_like_ip(s: str) -> bool:
    """True for any spelling an inet_aton / URL parser would treat as an IP."""
    t = s.strip("[]")
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        pass
    labels = t.split(".")
    # 127.1, 0x7f.1, 017700000001, 2130706433, 1.2.3.4.5 ...
    def numberish(x: str) -> bool:
        return bool(re.fullmatch(r"(0[xX][0-9a-fA-F]*|[0-9]+)", x))
    return all(numberish(x) for x in labels if x != "") and any(labels)


def _suffix_len(labels: list[str]) -> int:
    for n in range(min(3, len(labels)), 1, -1):  # try 3, then 2 labels
        if ".".join(labels[-n:]) in MULTI_SUFFIXES:
            return n
    return 1


def validate_public_domain(raw: object) -> str:
    """Return the canonical ASCII registrable domain or raise :class:`DomainError`."""
    if not isinstance(raw, str):
        raise DomainError("invalid", "domain must be a string")
    s = raw.strip()
    if not s:
        raise DomainError("empty", "enter a domain such as example.com")
    if len(s) > MAX_RAW:
        raise DomainError("too_long", "domain name is too long")
    if s.endswith("."):
        s = s[:-1]
    if _looks_like_ip(s):
        raise DomainError("ip_literal", "IP addresses are not accepted; enter a domain name")
    if _BAD_CHARS.search(s):
        raise DomainError(
            "invalid_chars",
            "enter just the domain (example.com), without a scheme, path, port or wildcard",
        )
    if s.startswith(".") or ".." in s or s.endswith("."):
        raise DomainError("invalid", "malformed domain name")
    if _looks_like_ip(s):
        raise DomainError("ip_literal", "IP addresses are not accepted; enter a domain name")

    try:
        ascii_name = idna.encode(s, uts46=True, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        raise DomainError("invalid_idn", "that is not a valid (internationalised) domain name") from None
    ascii_name = ascii_name.lower()

    # An all-ASCII input that already contains punycode must round-trip.
    for lab in ascii_name.split("."):
        if lab.startswith("xn--"):
            try:
                idna.decode(lab)
            except (idna.IDNAError, UnicodeError):
                raise DomainError("invalid_idn", "malformed punycode label") from None

    if len(ascii_name) > MAX_NAME:
        raise DomainError("too_long", "domain name is too long")
    labels = ascii_name.split(".")
    if any(len(lab) > MAX_LABEL or not _LABEL_RE.match(lab) for lab in labels):
        raise DomainError("invalid", "malformed domain name")
    if len(labels) < 2:
        raise DomainError("internal_name", "single-label names are not public domains")

    tld = labels[-1]
    if _looks_like_ip(ascii_name) or tld.isdigit():
        raise DomainError("ip_literal", "IP addresses are not accepted; enter a domain name")
    if tld in INTERNAL_TLDS or ascii_name.endswith(".home.arpa"):
        raise DomainError("internal_name", "internal or reserved names are not public domains")
    if len(tld) < 2 or not (tld.isalpha() or tld.startswith("xn--")):
        raise DomainError("invalid", "unrecognised top-level domain")

    n_suffix = _suffix_len(labels)
    if len(labels) <= n_suffix:
        raise DomainError("public_suffix", "that is a public suffix, not a registrable domain")
    if len(labels) > n_suffix + 1:
        reg = ".".join(labels[-(n_suffix + 1):])
        raise DomainError("not_registrable", f"enter the registrable domain ({reg}), not a sub-domain")
    return ascii_name


def registrable_of(name: str) -> str | None:
    """Best-effort registrable domain of an already-lowercased host name."""
    labels = name.strip(".").lower().split(".")
    if len(labels) < 2:
        return None
    n = _suffix_len(labels)
    if len(labels) <= n:
        return None
    return ".".join(labels[-(n + 1):])


def mask_host(host: str, domain: str) -> str:
    """``admin.example.com`` -> ``a***.example.com``: shape without the name."""
    if host == domain:
        return host
    if host.endswith("." + domain):
        left = host[: -(len(domain) + 1)]
        first = left.split(".")[0]
        return f"{first[:1]}***.{domain}" if first else f"***.{domain}"
    return "***"
