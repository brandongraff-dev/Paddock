"""DNS enumeration.

Strategy:
1) Try subfinder (projectdiscovery) as a subprocess if the binary exists.
   `subfinder -silent -d {domain} -json` emits one JSON object per line
   with at least {"host": "..."}.
2) If subfinder is missing OR returns nothing, fall back to a built-in
   wordlist-based brute force over DNS. We resolve each `w.domain` with
   dnspython's async resolver and keep ones that answer.

For every discovered FQDN we also resolve A / AAAA and emit edges:
   subdomain -(resolves_to)-> ipv4 / ipv6

DNS resolution to a *public* resolver is explicitly allowed by the rules:
"If you need to resolve DNS, that IS a packet to a resolver (public DNS),
which is allowed — but never a direct HTTP(S) probe to a scope target."
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Iterable

import dns.asyncresolver
import dns.exception
import dns.resolver
from loguru import logger

from ..context import ModuleContext
from . import ModuleResult


SUBFINDER_BIN = "subfinder"
DNS_SOURCE = "dns"

# Short, high-signal wordlist — keep it under 100 words so the fallback
# path doesn't itself become a load bomb when subfinder is missing.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
    "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
    "info", "apps", "download", "remote", "db", "forums", "store", "relay",
    "files", "newsletter", "app", "live", "owa", "en", "start", "sms", "office",
    "exchange", "ipv4",
)


async def _run_subfinder(domain: str, timeout_s: float = 90.0) -> list[str]:
    """Run subfinder as a subprocess; returns a list of hostnames or []."""
    if shutil.which(SUBFINDER_BIN) is None:
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            SUBFINDER_BIN, "-silent", "-d", domain, "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as e:
        logger.warning("subfinder failed to launch: {}", e)
        return []
    try:
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        with suppress_all():
            proc.kill()
            await proc.wait()
        return []

    hosts: list[str] = []
    for line in (stdout or b"").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            # some versions emit plain hostnames with -silent
            hosts.append(line.decode("utf-8", errors="ignore").strip().lower())
            continue
        h = rec.get("host") or rec.get("input") or rec.get("domain")
        if h:
            hosts.append(str(h).strip().lower())
    return [h for h in hosts if h.endswith(domain)]


class suppress_all:
    def __enter__(self): return self
    def __exit__(self, *_a): return True


async def _resolve_one(name: str, limiter) -> tuple[str, list[str], list[str]]:
    """Return (name, a_records, aaaa_records)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    a: list[str] = []
    aaaa: list[str] = []
    for rtype, dest in (("A", a), ("AAAA", aaaa)):
        await limiter.acquire(DNS_SOURCE)
        try:
            ans = await resolver.resolve(name, rtype)
            for r in ans:
                dest.append(r.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as e:  # noqa: BLE001
            logger.debug("dns resolve error name={} type={} err={}", name, rtype, e)
            continue
    return name, a, aaaa


async def _wordlist_bruteforce(
    domain: str, wordlist: Iterable[str], limiter, concurrency: int = 20
) -> list[str]:
    sem = asyncio.Semaphore(concurrency)
    found: list[str] = []

    async def probe(w: str) -> None:
        name = f"{w}.{domain}"
        async with sem:
            _, a, aaaa = await _resolve_one(name, limiter)
        if a or aaaa:
            found.append(name)

    await asyncio.gather(*(probe(w) for w in wordlist))
    return found


async def run(domain: str, ctx: ModuleContext) -> ModuleResult:
    domain = domain.strip().lower().rstrip(".")
    result = ModuleResult(module="dns_enum")

    discovered = set(await _run_subfinder(domain))
    if not discovered:
        discovered.update(
            await _wordlist_bruteforce(domain, DEFAULT_WORDLIST, ctx.rate_limiter)
        )

    # Resolve every discovered subdomain (even ones subfinder found, so we
    # get the IP edges).
    sem = asyncio.Semaphore(20)

    async def resolve(name: str):
        async with sem:
            return await _resolve_one(name, ctx.rate_limiter)

    resolutions = await asyncio.gather(*(resolve(n) for n in discovered))

    # Emit domain + each subdomain + its IPs and edges
    result.assets.append({
        "kind": "domain", "value": domain,
        "source": "dns_enum", "metadata": {},
    })
    seen_ips: set[tuple[str, str]] = set()
    for name, a, aaaa in resolutions:
        result.assets.append({
            "kind": "subdomain", "value": name,
            "source": "dns_enum",
            "metadata": {"apex": domain, "a": a, "aaaa": aaaa},
        })
        result.edges.append({
            "src_kind": "subdomain", "src_value": name,
            "dst_kind": "domain", "dst_value": domain,
            "kind": "contains",
        })
        for ip in a:
            if ("ipv4", ip) not in seen_ips:
                result.assets.append({
                    "kind": "ipv4", "value": ip,
                    "source": "dns_enum", "metadata": {},
                })
                seen_ips.add(("ipv4", ip))
            result.edges.append({
                "src_kind": "subdomain", "src_value": name,
                "dst_kind": "ipv4", "dst_value": ip,
                "kind": "resolves_to",
            })
        for ip in aaaa:
            if ("ipv6", ip) not in seen_ips:
                result.assets.append({
                    "kind": "ipv6", "value": ip,
                    "source": "dns_enum", "metadata": {},
                })
                seen_ips.add(("ipv6", ip))
            result.edges.append({
                "src_kind": "subdomain", "src_value": name,
                "dst_kind": "ipv6", "dst_value": ip,
                "kind": "resolves_to",
            })
    result.source_calls = len(discovered)
    return result
