"""The passive assessment engine.

Inputs are two *narrow, injectable* clients so tests (and any future caching
layer) never need a network:

* a :class:`Resolver` -- DNS answers from a recursive resolver
* a :class:`CTClient` -- certificate-transparency rows for a domain

and nothing else. The engine never opens a connection to an address it learns
about: no HTTP, no TLS handshake, no port probe. Every finding is derived from
a DNS answer or a CT row, and anything that can only be confirmed by probing
(e.g. a subdomain takeover) is reported as ``confidence: "possible"``.

Output: an :class:`Assessment` carrying the full internal finding list plus
the grade; :func:`public_summary` / :func:`teaser` project the public-safe
view (no raw host lists, no IPs).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .config import GrowthSettings, growth_settings
from .domains import mask_host, registrable_of

logger = logging.getLogger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_DEDUCT = {"info": 0, "low": 2, "medium": 6, "high": 12, "critical": 25}
# One rule can only ever cost so much, however many hosts it fires on.
_RULE_CAP = {"info": 0, "low": 6, "medium": 12, "high": 24, "critical": 25}

DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1", "cm", "zendesk1",
    "sendgrid", "mailjet", "amazonses", "protonmail", "scph0",
)

SENSITIVE_LABELS = frozenset({
    "admin", "vpn", "jenkins", "grafana", "kibana", "phpmyadmin", "gitlab", "git",
    "sonar", "sonarqube", "vault", "internal", "intranet", "staging", "stage", "uat",
    "dev", "test", "qa", "backup", "db", "sql", "mysql", "postgres", "ssh", "rdp",
    "citrix", "owa", "jira", "confluence", "nexus", "artifactory", "prometheus",
    "elastic", "redis", "mongo", "rancher", "argocd", "k8s", "kube", "bastion",
})

# CNAME-target suffixes of services whose dangling records are classic
# takeover vectors. DNS-only: we never fetch the page to confirm.
TAKEOVER_SERVICES: tuple[tuple[str, str], ...] = (
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.net", "Azure Cloud Services"),
    ("cloudapp.azure.com", "Azure"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("azureedge.net", "Azure CDN"),
    ("s3.amazonaws.com", "AWS S3"),
    ("s3-website", "AWS S3 website"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("cloudfront.net", "AWS CloudFront"),
    ("fastly.net", "Fastly"),
    ("readme.io", "Readme"),
    ("zendesk.com", "Zendesk"),
    ("myshopify.com", "Shopify"),
    ("surge.sh", "Surge"),
    ("bitbucket.io", "Bitbucket"),
    ("wordpress.com", "WordPress.com"),
    ("ghost.io", "Ghost"),
    ("pantheonsite.io", "Pantheon"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("statuspage.io", "Statuspage"),
    ("helpjuice.com", "Helpjuice"),
    ("helpscoutdocs.com", "Help Scout"),
    ("unbouncepages.com", "Unbounce"),
    ("cargocollective.com", "Cargo"),
    ("uservoice.com", "UserVoice"),
    ("feedpress.me", "FeedPress"),
    ("webflow.io", "Webflow"),
    ("vercel.app", "Vercel"),
    ("fly.dev", "Fly.io"),
    ("pages.dev", "Cloudflare Pages"),
)

# MX / NS suffix -> provider label (inferred, informational).
_MAIL_PROVIDERS = (
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"), ("protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"), ("mimecast.com", "Mimecast"),
    ("zoho.com", "Zoho Mail"), ("protonmail.ch", "Proton Mail"),
    ("messagelabs.com", "Broadcom Email Security"), ("mailgun.org", "Mailgun"),
)


# --------------------------------------------------------------------------- #
# Client protocols
# --------------------------------------------------------------------------- #

@dataclass
class DnsResult:
    status: str = "ok"            # ok | nxdomain | nodata | error
    records: list[str] = field(default_factory=list)


class Resolver(Protocol):
    async def resolve(self, name: str, rtype: str) -> DnsResult: ...


class CTClient(Protocol):
    async def fetch(self, domain: str) -> list[dict[str, Any]]:
        """crt.sh-shaped rows: name_value, serial_number, issuer_name,
        not_before, not_after, common_name[, key_type, key_bits, sig_alg]."""


class CTError(RuntimeError):
    pass


class DomainNotFound(RuntimeError):
    """The apex has no NS / A / MX records at all."""


# --------------------------------------------------------------------------- #
# Real clients (never used in tests)
# --------------------------------------------------------------------------- #

class DnsPythonResolver:
    """Recursive-resolver client built on dnspython. Queries are plain DNS
    lookups through the configured resolver."""

    def __init__(self, settings: GrowthSettings | None = None) -> None:
        import dns.asyncresolver

        self._s = settings or growth_settings
        r = dns.asyncresolver.Resolver(configure=True)
        r.lifetime = self._s.dns_timeout_sec
        r.timeout = self._s.dns_timeout_sec
        ns = [x.strip() for x in self._s.dns_nameservers.split(",") if x.strip()]
        if ns:
            r.nameservers = ns
        self._r = r

    async def resolve(self, name: str, rtype: str) -> DnsResult:
        import dns.exception
        import dns.resolver

        try:
            ans = await self._r.resolve(name, rtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            return DnsResult("nxdomain")
        except dns.resolver.NoAnswer:
            return DnsResult("nodata")
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return DnsResult("error")
        except Exception:  # noqa: BLE001
            return DnsResult("error")
        out: list[str] = []
        for rd in ans:
            if rtype == "TXT":
                out.append(b"".join(rd.strings).decode("utf-8", "replace"))
            else:
                out.append(rd.to_text().rstrip(".") if rtype in ("CNAME", "NS") else rd.to_text())
        if rtype == "MX":
            out = [re.sub(r"\.$", "", x) for x in out]
        return DnsResult("ok", out)


class CrtShClient:
    """Certificate-transparency rows from crt.sh (a public log aggregator)."""

    MAX_BYTES = 25 * 1024 * 1024

    def __init__(self, settings: GrowthSettings | None = None, transport: Any = None) -> None:
        self._s = settings or growth_settings
        self._transport = transport

    async def fetch(self, domain: str) -> list[dict[str, Any]]:
        import json

        import httpx

        url = self._s.ct_url
        try:
            async with httpx.AsyncClient(
                timeout=self._s.ct_timeout_sec,
                headers={"User-Agent": "paddock-passive-check/1 (+certificate transparency lookup)"},
                transport=self._transport,
                follow_redirects=False,
            ) as c:
                async with c.stream("GET", url, params={"q": f"%.{domain}", "output": "json"}) as r:
                    if r.status_code != 200:
                        raise CTError(f"ct source returned {r.status_code}")
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > self.MAX_BYTES:
                            raise CTError("ct response too large")
        except httpx.HTTPError as exc:
            raise CTError(f"ct source unreachable: {type(exc).__name__}") from exc
        try:
            rows = json.loads(bytes(buf) or b"[]")
        except ValueError as exc:
            raise CTError("ct source returned invalid json") from exc
        if not isinstance(rows, list):
            raise CTError("ct source returned an unexpected shape")
        return [r for r in rows if isinstance(r, dict)]


def default_clients() -> tuple[Resolver, CTClient]:
    return DnsPythonResolver(), CrtShClient()


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #

@dataclass
class Assessment:
    domain: str
    assessed_at: datetime
    grade: str
    score: int
    reasons: list[str]
    findings: list[dict[str, Any]]
    stats: dict[str, Any]
    checks: list[dict[str, str]]

    def full(self) -> dict[str, Any]:
        """Everything, INCLUDING hosts. Internal / owner-only."""
        return {
            "domain": self.domain,
            "assessed_at": self.assessed_at.isoformat(),
            "grade": self.grade,
            "score": self.score,
            "reasons": self.reasons,
            "findings": self.findings,
            "stats": self.stats,
            "checks": self.checks,
        }


def _fid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]  # noqa: S324 -- id, not security


def _finding(
    rule: str,
    category: str,
    severity: str,
    title: str,
    detail: str,
    fix: str,
    *,
    host: str | None = None,
    key: str = "",
    confidence: str = "confirmed",
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": _fid(rule, host or "", key),
        "rule": rule,
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "fix": fix,
        "host": host,
        "confidence": confidence,
        "data": data or {},
    }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_ts(v: Any) -> datetime | None:
    if not v:
        return None
    s = str(v).strip().replace(" ", "T")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _norm_name(n: str) -> str:
    return n.strip().lower().rstrip(".")


def _in_domain(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _covers(cert_name: str, host: str) -> bool:
    if cert_name == host:
        return True
    if cert_name.startswith("*."):
        base = cert_name[2:]
        return host.endswith("." + base) and host.count(".") == base.count(".") + 1
    return False


def _ip_class(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "bad"
    if a.is_loopback or a.is_unspecified:
        return "loopback"
    if a.is_private or a.is_link_local or a.is_reserved or getattr(a, "is_site_local", False):
        return "private"
    return "public"


def _takeover_service(target: str) -> str | None:
    t = target.lower().rstrip(".")
    for suffix, service in TAKEOVER_SERVICES:
        if t.endswith("." + suffix) or t == suffix or (suffix == "s3-website" and "s3-website" in t):
            return service
    return None


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #

class _Q:
    """A budgeted, concurrency-limited, memoised DNS front."""

    def __init__(self, resolver: Resolver, concurrency: int, budget: int = 1500) -> None:
        self._r = resolver
        self._sem = asyncio.Semaphore(concurrency)
        self._memo: dict[tuple[str, str], DnsResult] = {}
        self.budget = budget
        self.queries = 0

    async def __call__(self, name: str, rtype: str) -> DnsResult:
        key = (name, rtype)
        if key in self._memo:
            return self._memo[key]
        if self.queries >= self.budget:
            return DnsResult("error")
        self.queries += 1
        async with self._sem:
            try:
                res = await self._r.resolve(name, rtype)
            except Exception:  # noqa: BLE001 -- a broken resolver must not kill the run
                res = DnsResult("error")
        self._memo[key] = res
        return res


async def assess(
    domain: str,
    *,
    resolver: Resolver,
    ct: CTClient,
    now: datetime | None = None,
    settings: GrowthSettings | None = None,
) -> Assessment:
    s = settings or growth_settings
    now = now or datetime.now(timezone.utc)
    q = _Q(resolver, s.dns_concurrency)
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    stats: dict[str, Any] = {}

    # ---- apex DNS --------------------------------------------------------
    ns, a, aaaa, mx, txt, caa, ds = await asyncio.gather(
        q(domain, "NS"), q(domain, "A"), q(domain, "AAAA"), q(domain, "MX"),
        q(domain, "TXT"), q(domain, "CAA"), q(domain, "DS"),
    )
    if ns.status == "nxdomain" and a.status == "nxdomain":
        raise DomainNotFound(domain)
    has_mx = mx.status == "ok" and any(not re.match(r"^0\s+\.?$", m) for m in mx.records)
    stats["nameservers"] = len(ns.records)
    stats["mail_exchangers"] = len(mx.records) if has_mx else 0
    stats["dnssec"] = ds.status == "ok"

    # ---- CT --------------------------------------------------------------
    ct_ok = True
    rows: list[dict[str, Any]] = []
    try:
        rows = await ct.fetch(domain)
    except Exception as exc:  # noqa: BLE001
        ct_ok = False
        logger.info("growth_ct_unavailable", extra={"reason": type(exc).__name__})
    stats["ct_available"] = ct_ok

    certs = _parse_certs(rows, domain)
    names: set[str] = set()
    for c in certs:
        names.update(c["names"])
    wildcard_names = {n for n in names if n.startswith("*.")}
    hosts_all = sorted({n for n in names if not n.startswith("*.")} | {domain})
    hosts_all = [h for h in hosts_all if h != domain]
    stats["subdomains_ct"] = len(hosts_all)
    hosts = hosts_all[: s.max_hosts]
    stats["subdomains_checked"] = len(hosts)

    # ---- per-host DNS ----------------------------------------------------
    host_info = await _resolve_hosts(q, hosts, domain)
    live = {h for h, i in host_info.items() if i["ips_public"]}
    stats["live_hosts"] = len(live) + (1 if a.status == "ok" else 0)
    stats["cnames"] = sum(1 for i in host_info.values() if i["chain"])

    findings += _dns_findings(domain, ns, a, mx, has_mx, caa, host_info, q)
    findings += await _ns_mx_findings(domain, ns, mx, has_mx, q)
    findings += await _takeover_findings(domain, host_info, q)
    ef, email_state = await _email_findings(domain, has_mx, txt, mx, q)
    findings += ef
    stats["email"] = email_state
    findings += _cert_findings(domain, certs, hosts, live | {domain}, wildcard_names, now, s)
    stats["certificates"] = len({c["serial"] for c in certs})
    stats["certificates_valid"] = sum(1 for c in certs if c["not_before"] <= now < c["not_after"])
    stats["wildcard_certificates"] = sum(
        1 for c in certs if c["not_before"] <= now < c["not_after"] and any(n.startswith("*.") for n in c["names"])
    )
    stats["issuers"] = len({c["issuer"] for c in certs if c["not_before"] <= now < c["not_after"]})
    stats["inferred_services"] = _inferred(mx, ns)
    stats["dns_queries"] = q.queries

    findings.sort(key=lambda f: (-_SEV_RANK[f["severity"]], f["rule"], f["host"] or ""))
    score, grade, reasons = grade_findings(findings)
    checks = _checks(findings, stats, ct_ok)
    return Assessment(domain, now, grade, score, reasons, findings, stats, checks)


# ---- DNS host resolution ---------------------------------------------------

async def _resolve_hosts(q: _Q, hosts: list[str], domain: str) -> dict[str, dict[str, Any]]:
    async def one(h: str) -> tuple[str, dict[str, Any]]:
        chain: list[str] = []
        cur = h
        last_status = "ok"
        for _ in range(8):
            r = await q(cur, "CNAME")
            if r.status == "ok" and r.records:
                nxt = _norm_name(r.records[0])
                chain.append(nxt)
                cur = nxt
                continue
            break
        aa = await q(cur, "A")
        last_status = aa.status
        ips = list(aa.records) if aa.status == "ok" else []
        if aa.status == "nodata":
            a6 = await q(cur, "AAAA")
            if a6.status == "ok":
                ips = list(a6.records)
                last_status = "ok"
        classes = [_ip_class(i) for i in ips]
        return h, {
            "chain": chain,
            "final": cur,
            "status": last_status,
            "ips": ips,
            "ips_public": [i for i, c in zip(ips, classes) if c == "public"],
            "ips_private": [i for i, c in zip(ips, classes) if c == "private"],
        }

    out = await asyncio.gather(*(one(h) for h in hosts))
    return dict(out)


def _dns_findings(domain, ns, a, mx, has_mx, caa, host_info, q) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if ns.status == "ok" and len(ns.records) < 2:
        out.append(_finding(
            "single_nameserver", "dns", "low", "Only one nameserver is published",
            "The domain delegates to a single nameserver, so one outage takes the whole domain offline.",
            "Publish at least two nameservers on independent networks.",
        ))
    if caa.status in ("nodata", "nxdomain"):
        out.append(_finding(
            "no_caa", "certificates", "low", "No CAA record restricts who may issue certificates",
            "Without a CAA record any public certificate authority may issue for the domain.",
            "Publish CAA records naming only the authorities you use.",
        ))
    priv = sorted(h for h, i in host_info.items() if i["ips_private"])
    if priv:
        out.append(_finding(
            "private_ip_in_public_dns", "dns", "low",
            f"{len(priv)} public host name(s) resolve to private addresses",
            "Public DNS reveals internal address ranges (RFC 1918 / link-local).",
            "Move internal records to a split-horizon / private zone.",
            key=",".join(priv), data={"count": len(priv), "hosts": priv[:20]},
        ))
    sens = sorted(
        h for h, i in host_info.items()
        if i["ips_public"] and (set(h[: -(len(domain) + 1)].split(".")) & SENSITIVE_LABELS)
    )
    if sens:
        out.append(_finding(
            "sensitive_hostnames", "exposure", "low",
            f"{len(sens)} publicly resolvable host name(s) look administrative or non-production",
            "Names such as admin, vpn, staging or jenkins in public DNS and CT logs invite targeted attention.",
            "Confirm each is intended to be internet-facing, restrict access, or drop the public record.",
            key=",".join(sens), data={"count": len(sens), "hosts": sens[:20]},
        ))
    return out


async def _ns_mx_findings(domain, ns, mx, has_mx, q: _Q) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    async def dead(name: str) -> bool:
        r = await q(name, "A")
        if r.status == "nxdomain":
            return True
        return False

    if ns.status == "ok":
        targets = [t for t in ns.records[:8] if not _in_domain(_norm_name(t), domain)]
        dead_ns = [t for t, d in zip(targets, await asyncio.gather(*(dead(_norm_name(t)) for t in targets))) if d]
        for t in dead_ns:
            out.append(_finding(
                "dangling_ns", "dangling_dns", "high",
                "A delegated nameserver does not resolve",
                "The domain delegates to a nameserver host that no longer exists. If its parent domain can be "
                "registered by someone else, they could answer for your zone.",
                "Remove the stale NS record or re-point it to a live nameserver you control.",
                host=_norm_name(t), confidence="possible",
            ))
    if has_mx:
        mx_hosts = []
        for rec in mx.records[:5]:
            parts = rec.split()
            if len(parts) == 2 and parts[1] not in (".", ""):
                mx_hosts.append(_norm_name(parts[1]))
        res = await asyncio.gather(*(dead(h) for h in mx_hosts))
        for h, d in zip(mx_hosts, res):
            if d:
                out.append(_finding(
                    "mx_unresolvable", "email", "medium", "A mail exchanger does not resolve",
                    "An MX record points at a host that does not exist, so mail to that route bounces and the "
                    "name may be claimable.",
                    "Remove or correct the MX record.", host=h,
                ))
    return out


async def _takeover_findings(domain, host_info, q: _Q) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for host, i in sorted(host_info.items()):
        if not i["chain"] or i["status"] != "nxdomain":
            continue
        target = i["final"]
        service = _takeover_service(target) or next((x for x in map(_takeover_service, i["chain"]) if x), None)
        reg = registrable_of(target)
        expired = False
        if reg and not _in_domain(reg, domain) and reg != domain:
            r = await q(reg, "NS")
            expired = r.status == "nxdomain"
        if service:
            out.append(_finding(
                "dangling_cname_takeover", "dangling_dns", "high",
                f"Possible subdomain takeover via {service}",
                f"This host is a CNAME to {service} whose target no longer exists. If the {service} resource "
                "can be re-claimed by anyone, they could serve content on your hostname. Reported from DNS "
                "only; the service was not contacted.",
                f"Delete the dangling CNAME, or re-create the {service} resource that it points at.",
                host=host, confidence="possible", data={"service": service},
            ))
        elif expired:
            out.append(_finding(
                "dangling_cname_expired_domain", "dangling_dns", "high",
                "CNAME points to a domain that appears unregistered",
                "The CNAME target's registrable domain has no nameservers, which usually means it expired. "
                "Anyone who registers it would control this hostname.",
                "Delete the CNAME, or re-register the target.",
                host=host, confidence="possible",
            ))
        else:
            out.append(_finding(
                "dangling_cname", "dangling_dns", "medium",
                "CNAME points to a name that does not exist",
                "The record targets a host that returns NXDOMAIN. It is harmless today, but becomes a takeover "
                "risk if the target name can ever be claimed.",
                "Delete the stale CNAME.", host=host, confidence="possible",
            ))
    return out


# ---- email authentication --------------------------------------------------

def _tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


async def _spf_lookups(q: _Q, domain: str, depth: int, seen: set[str], budget: list[int]) -> int:
    """DNS-lookup-causing mechanisms in the SPF tree (RFC 7208 §4.6.4)."""
    if depth > 6 or domain in seen or budget[0] <= 0:
        return 0
    seen.add(domain)
    budget[0] -= 1
    r = await q(domain, "TXT")
    rec = next((t for t in r.records if t.lower().startswith("v=spf1")), None)
    if not rec:
        return 0
    n = 0
    for term in rec.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            n += 1 + await _spf_lookups(q, t[8:], depth + 1, seen, budget)
        elif t.startswith("redirect="):
            n += 1 + await _spf_lookups(q, t[9:], depth + 1, seen, budget)
        elif re.match(r"^(a|mx|ptr|exists)([:/]|$)", t):
            n += 1
    return n


async def _email_findings(domain, has_mx, txt, mx, q: _Q) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    out: list[dict[str, Any]] = []
    state: dict[str, Any] = {"spf": "missing", "dmarc": "missing", "dkim": False, "mta_sts": False, "tls_rpt": False}

    # SPF
    spf = [t for t in txt.records if t.lower().startswith("v=spf1")] if txt.status == "ok" else []
    if len(spf) > 1:
        out.append(_finding(
            "spf_multiple", "email", "medium", "More than one SPF record is published",
            "Receivers treat multiple SPF records as a permanent error, so SPF fails for every message.",
            "Merge the records into a single v=spf1 record.",
        ))
    if not spf:
        out.append(_finding(
            "spf_missing", "email", "medium" if has_mx else "low",
            "No SPF record" if has_mx else "No SPF record (null SPF recommended)",
            "Without SPF anyone can send mail claiming to be this domain and receivers cannot tell."
            if has_mx else "A domain that sends no mail should publish 'v=spf1 -all' to stop spoofing.",
            "Publish an SPF record listing your senders and ending in -all." if has_mx
            else "Publish v=spf1 -all.",
        ))
    else:
        rec = spf[0].lower()
        allm = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", rec)
        redirect = "redirect=" in rec
        if allm:
            qual = allm.group(1) or "+"
            state["spf"] = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass_all"}[qual]
            if qual == "+":
                out.append(_finding(
                    "spf_allow_all", "email", "high", "SPF allows any server to send as this domain",
                    "The record ends in +all, which authorises the entire internet.",
                    "Replace +all with -all (or ~all while you finish an inventory).",
                ))
            elif qual == "?":
                out.append(_finding(
                    "spf_neutral", "email", "medium", "SPF ends in ?all and enforces nothing",
                    "A neutral result tells receivers not to judge spoofed mail.",
                    "Move to ~all and then -all.",
                ))
        elif redirect:
            state["spf"] = "redirect"
        else:
            state["spf"] = "no_all"
            out.append(_finding(
                "spf_no_all", "email", "medium", "SPF record has no 'all' terminator",
                "Without a closing all-mechanism the policy is incomplete and unenforced.",
                "End the record with -all or ~all.",
            ))
        if "ptr" in rec.split() or " ptr:" in rec or " +ptr" in rec:
            out.append(_finding(
                "spf_ptr", "email", "low", "SPF uses the deprecated ptr mechanism",
                "RFC 7208 discourages ptr: it is slow and unreliable.", "Replace ptr with ip4/ip6/include.",
            ))
        lookups = await _spf_lookups(q, domain, 0, set(), [20])
        state["spf_lookups"] = lookups
        if lookups > 10:
            out.append(_finding(
                "spf_too_many_lookups", "email", "medium",
                f"SPF needs {lookups} DNS lookups (limit is 10)",
                "More than ten lookups is a permanent SPF error, so legitimate mail can be rejected.",
                "Flatten includes or drop unused senders.", data={"lookups": lookups},
            ))

    # DMARC
    dm = await q(f"_dmarc.{domain}", "TXT")
    recs = [t for t in dm.records if t.lower().startswith("v=dmarc1")] if dm.status == "ok" else []
    if not recs:
        out.append(_finding(
            "dmarc_missing", "email", "high" if has_mx else "low", "No DMARC policy",
            "DMARC tells receivers what to do with mail that fails SPF/DKIM. Without it, spoofed mail from this "
            "domain is delivered.", "Publish _dmarc with p=none and rua reporting, then move to quarantine/reject.",
        ))
    else:
        t = _tags(recs[0])
        pol = t.get("p", "none").lower()
        state["dmarc"] = pol
        if pol == "none":
            out.append(_finding(
                "dmarc_none", "email", "medium", "DMARC is monitor-only (p=none)",
                "Spoofed mail is reported but still delivered.", "Move to p=quarantine, then p=reject.",
            ))
        elif t.get("pct") and t["pct"].isdigit() and int(t["pct"]) < 100:
            out.append(_finding(
                "dmarc_partial", "email", "low", f"DMARC applies to only {t['pct']}% of mail",
                "The policy is enforced for a fraction of messages.", "Raise pct to 100.",
            ))
        if "rua" not in t:
            out.append(_finding(
                "dmarc_no_reports", "email", "low", "DMARC has no aggregate-report address",
                "Without rua= you will not see who is sending as your domain.", "Add rua=mailto:...",
            ))

    # DKIM (selectors are not enumerable; check the common ones)
    found = 0
    weak = 0
    res = await asyncio.gather(*(q(f"{sel}._domainkey.{domain}", "TXT") for sel in DKIM_SELECTORS))
    for r in res:
        for t in r.records if r.status == "ok" else []:
            tags = _tags(t)
            if "p" in tags and tags["p"]:
                found += 1
                bits = _rsa_bits(tags["p"])
                if bits is not None and bits < 2048:
                    weak += 1
    state["dkim"] = found > 0
    state["dkim_selectors_found"] = found
    if weak:
        out.append(_finding(
            "dkim_weak_key", "email", "medium", f"{weak} DKIM key(s) shorter than 2048 bits",
            "1024-bit DKIM keys are considered weak.", "Rotate to 2048-bit RSA (or Ed25519).",
        ))
    if has_mx and found == 0:
        out.append(_finding(
            "dkim_not_found", "email", "info", "No DKIM key found at common selector names",
            "Selectors cannot be listed from DNS, so this only means none of the common names exist. "
            "It is not proof that DKIM is absent.", "Verify DKIM signing for each sending service.",
        ))

    # MTA-STS / TLS-RPT
    sts = await q(f"_mta-sts.{domain}", "TXT")
    rpt = await q(f"_smtp._tls.{domain}", "TXT")
    state["mta_sts"] = sts.status == "ok" and any("v=stsv1" in t.lower() for t in sts.records)
    state["tls_rpt"] = rpt.status == "ok" and any("v=tlsrptv1" in t.lower() for t in rpt.records)
    if has_mx and not state["mta_sts"]:
        out.append(_finding(
            "mta_sts_missing", "email", "low", "MTA-STS is not published",
            "Without MTA-STS, mail between servers can be downgraded to plaintext by an on-path attacker.",
            "Publish _mta-sts TXT and a policy file, and add TLS-RPT reporting.",
        ))
    return out, state


def _rsa_bits(p_b64: str) -> int | None:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        key = load_der_public_key(base64.b64decode(p_b64 + "=" * (-len(p_b64) % 4)))
        return key.key_size if isinstance(key, rsa.RSAPublicKey) else None
    except Exception:  # noqa: BLE001
        return None


# ---- certificates ----------------------------------------------------------

def _parse_certs(rows: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        nb, na = parse_ts(r.get("not_before")), parse_ts(r.get("not_after"))
        if not nb or not na:
            continue
        names = {
            _norm_name(x) for x in str(r.get("name_value") or "").split("\n")
            if x.strip() and _in_domain(_norm_name(x).removeprefix("*."), domain)
        }
        if not names:
            continue
        serial = str(r.get("serial_number") or r.get("id") or "")
        issuer = str(r.get("issuer_name") or "")
        key = (serial, issuer)
        if key in out:
            out[key]["names"] |= names
            continue
        out[key] = {
            "serial": serial, "issuer": issuer, "names": names, "not_before": nb, "not_after": na,
            "key_type": str(r.get("key_type") or "").upper(), "key_bits": r.get("key_bits"),
            "sig_alg": str(r.get("sig_alg") or "").lower(),
        }
    return list(out.values())


def _cert_findings(domain, certs, hosts, live, wildcard_names, now, s) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    # best (latest) not_after covering each live host
    best: dict[str, tuple[datetime, dict[str, Any]]] = {}
    for h in live:
        cands = [c for c in certs if any(_covers(n, h) for n in c["names"]) and c["not_before"] <= now]
        if cands:
            c = max(cands, key=lambda c: c["not_after"])
            best[h] = (c["not_after"], c)
    by_cert: dict[str, list[str]] = {}
    for h, (na, c) in best.items():
        left = na - now
        if left <= timedelta(days=s.expiry_warn_days):
            by_cert.setdefault(c["serial"], []).append(h)
    seen_c = {c["serial"]: c for _, c in best.values()}
    for serial, hs in sorted(by_cert.items()):
        c = seen_c[serial]
        left = c["not_after"] - now
        days = int(left.total_seconds() // 86400)
        if left.total_seconds() <= 0:
            sev, title, rule = "high", "A certificate for a live host has expired", "cert_expired"
        elif left <= timedelta(days=s.expiry_critical_days):
            sev, title, rule = "high", f"A certificate expires in {max(days, 0)} day(s)", "cert_expiring"
        else:
            sev, title, rule = "medium", f"A certificate expires in {days} days", "cert_expiring"
        out.append(_finding(
            rule, "certificates", sev, title,
            f"The newest logged certificate covering {len(hs)} live host(s) "
            f"{'expired' if left.total_seconds() <= 0 else 'expires'} on {c['not_after'].date().isoformat()} "
            "and no replacement has been logged.",
            "Renew the certificate and check that automated renewal is working.",
            host=sorted(hs)[0], key=serial,
            data={"hosts": sorted(hs)[:20], "count": len(hs), "days_left": days,
                  "not_after": c["not_after"].isoformat()},
        ))
    # weak keys / signatures (only when the CT source supplied them)
    for c in certs:
        if not (c["not_before"] <= now < c["not_after"]):
            continue
        bits = c["key_bits"]
        weak_key = c["key_type"].startswith("RSA") and isinstance(bits, int) and bits < 2048
        weak_sig = bool(re.search(r"sha1|md5|md2", c["sig_alg"]))
        if weak_key or weak_sig:
            out.append(_finding(
                "cert_weak_crypto", "certificates", "high", "A valid certificate uses weak cryptography",
                "The logged certificate "
                + (f"has a {bits}-bit RSA key" if weak_key else f"is signed with {c['sig_alg']}")
                + ".", "Re-issue with RSA-2048+ or ECDSA P-256 and a SHA-2 signature.",
                host=sorted(c["names"])[0], key=c["serial"],
            ))
    valid = [c for c in certs if c["not_before"] <= now < c["not_after"]]
    wild = [c for c in valid if any(n.startswith("*.") for n in c["names"])]
    if len(wild) >= 3:
        out.append(_finding(
            "wildcard_sprawl", "certificates", "medium" if len(wild) >= 8 else "low",
            f"{len(wild)} wildcard certificates are valid at once",
            "Many live wildcard certificates mean the private keys are spread across many systems, and one "
            "leak exposes every sub-domain.", "Consolidate wildcards or move to per-host certificates.",
            data={"count": len(wild)},
        ))
    issuers = {c["issuer"] for c in valid}
    if len(issuers) >= 4:
        out.append(_finding(
            "issuer_sprawl", "certificates", "low", f"Certificates come from {len(issuers)} different issuers",
            "A wide spread of certificate authorities is hard to govern and defeats CAA.",
            "Standardise on one or two issuers and publish CAA.", data={"count": len(issuers)},
        ))
    return out


def _inferred(mx: DnsResult, ns: DnsResult) -> list[str]:
    inferred: set[str] = set()
    for rec in (mx.records if mx.status == "ok" else []):
        host = rec.split()[-1].lower().rstrip(".")
        for suf, label in _MAIL_PROVIDERS:
            if host.endswith(suf):
                inferred.add(f"Mail: {label}")
    return sorted(inferred)


# --------------------------------------------------------------------------- #
# Grading
# --------------------------------------------------------------------------- #

def grade_for(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def grade_findings(findings: list[dict[str, Any]]) -> tuple[int, str, list[str]]:
    per_rule: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        per_rule[f["rule"]] = min(_RULE_CAP[sev], per_rule.get(f["rule"], 0) + _DEDUCT[sev])
    score = max(0, 100 - sum(per_rule.values()))
    grade = grade_for(score)
    sevs = [f["severity"] for f in findings]
    if "critical" in sevs and grade in ("A", "B", "C"):
        grade = "D"
    elif "high" in sevs and grade == "A":
        grade = "B"
    ranked = sorted(
        (f for f in findings if _DEDUCT[f["severity"]] > 0),
        key=lambda f: (-_SEV_RANK[f["severity"]], f["title"]),
    )
    reasons: list[str] = []
    seen: set[str] = set()
    for f in ranked:
        if f["rule"] in seen:
            continue
        seen.add(f["rule"])
        reasons.append(f"{f['title']} ({f['severity']})")
        if len(reasons) == 5:
            break
    if not reasons:
        reasons = ["No issues found in public DNS and certificate-transparency data."]
    return score, grade, reasons


def _checks(findings, stats, ct_ok) -> list[dict[str, str]]:
    by_cat: dict[str, int] = {}
    worst: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        worst[f["category"]] = max(worst.get(f["category"], 0), _SEV_RANK[f["severity"]])

    def st(cat: str) -> str:
        w = worst.get(cat)
        if w is None or w == 0:
            return "pass"
        return "fail" if w >= _SEV_RANK["high"] else "warn"

    checks = [
        {"key": "email", "label": "Email authentication (SPF, DKIM, DMARC, MTA-STS)", "status": st("email")},
        {"key": "dangling_dns", "label": "Dangling DNS records", "status": st("dangling_dns")},
        {"key": "certificates", "label": "Certificate hygiene", "status": st("certificates")
         if ct_ok else "unknown"},
        {"key": "dns", "label": "DNS configuration", "status": st("dns")},
        {"key": "exposure", "label": "Exposed host names", "status": st("exposure")},
    ]
    return checks


# --------------------------------------------------------------------------- #
# Public projections
# --------------------------------------------------------------------------- #

def public_summary(a: Assessment | dict[str, Any]) -> dict[str, Any]:
    """Aggregates only: counts, grade, reasons, scorecard. No host names, IPs."""
    d = a.full() if isinstance(a, Assessment) else a
    findings = d["findings"]
    sev = {s: 0 for s in SEVERITIES}
    cat: dict[str, int] = {}
    for f in findings:
        sev[f["severity"]] += 1
        cat[f["category"]] = cat.get(f["category"], 0) + 1
    st = d["stats"]
    email = st.get("email", {})
    return {
        "grade": d["grade"],
        "score": d["score"],
        "reasons": d["reasons"],
        "findings_total": len(findings),
        "by_severity": sev,
        "by_category": cat,
        "checks": d["checks"],
        "stats": {
            "subdomains": st.get("subdomains_ct", 0),
            "live_hosts": st.get("live_hosts", 0),
            "certificates_valid": st.get("certificates_valid", 0),
            "wildcard_certificates": st.get("wildcard_certificates", 0),
            "issuers": st.get("issuers", 0),
            "nameservers": st.get("nameservers", 0),
            "dnssec": bool(st.get("dnssec")),
            "ct_available": bool(st.get("ct_available", True)),
        },
        "email": {
            "spf": email.get("spf", "missing"),
            "dmarc": email.get("dmarc", "missing"),
            "dkim_found": bool(email.get("dkim")),
            "mta_sts": bool(email.get("mta_sts")),
        },
        "assessed_at": d["assessed_at"],
    }


def teaser(a: Assessment | dict[str, Any], limit: int = 3) -> dict[str, Any]:
    """The top findings with host names masked and no remediation detail."""
    d = a.full() if isinstance(a, Assessment) else a
    ranked = sorted(d["findings"], key=lambda f: (-_SEV_RANK[f["severity"]], f["rule"]))
    ranked = [f for f in ranked if f["severity"] != "info"]
    shown = []
    for f in ranked[:limit]:
        shown.append({
            "severity": f["severity"],
            "category": f["category"],
            "title": _scrub(f["title"]),
            "confidence": f["confidence"],
            "host": mask_host(f["host"], d["domain"]) if f.get("host") else None,
        })
    return {"shown": shown, "hidden": max(0, len(ranked) - len(shown))}


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![\w:])", re.I)


def _scrub(text: str) -> str:
    return _IP_RE.sub("[redacted]", text)
