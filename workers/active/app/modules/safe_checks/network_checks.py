"""DNS / TCP safe checks.

subdomain_takeover   the dangling-CNAME fingerprint is still present (reuses
                     the takeover module's fingerprints and matcher)
open_port            the port still accepts a TCP connection (and, when the
                     service volunteers one, still shows a banner)

The TCP check connects and READS ONLY: it never sends a byte, so it cannot
trigger a command, login attempt or protocol handler.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.modules import takeover_check as takeover_mod

from .base import (
    CONNECT_TIMEOUT_SEC,
    CheckEnv,
    CheckResult,
    FindingCtx,
    SafeFetcher,
    confirmed,
    excerpt,
    inconclusive,
    not_reproducible,
)

# --------------------------------------------------------------------------- #
# subdomain takeover
# --------------------------------------------------------------------------- #


async def strict_cname_chain(host: str) -> tuple[list[str], str | None]:
    """CNAME chain for ``host``, and an error string when resolution was NOT
    definitive. (The detector's own resolver swallows timeouts, which would turn
    a flaky resolver into a false "fixed"; here only NoAnswer/NXDOMAIN end a chain.)
    """
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    chain: list[str] = []
    name = host.rstrip(".")
    seen: set[str] = set()
    for _ in range(takeover_mod._MAX_CNAME_DEPTH):
        if name.lower() in seen:
            break
        seen.add(name.lower())
        try:
            answer = await resolver.resolve(name, "CNAME")
        except dns.resolver.NoAnswer:
            break
        except dns.resolver.NXDOMAIN:
            if not chain:
                return [], "nxdomain"
            break  # a CNAME to a name that no longer exists still ends the chain
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            return chain, f"dns resolution failed: {type(e).__name__}"
        except Exception as e:  # noqa: BLE001
            return chain, f"dns resolution failed: {type(e).__name__}"
        targets = [r.target.to_text().rstrip(".") for r in answer]
        if not targets:
            break
        chain.append(targets[0])
        name = targets[0]
    return chain, None


def _match_takeover(f: FindingCtx) -> bool:
    return f.rule_source == "takeover" and f.rule_id == "subdomain-takeover" and bool(f.host)


async def _run_takeover(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "subdomain_takeover"
    host = f.host
    await env.scope.allow(host)
    lookup = env.cname_lookup or strict_cname_chain
    chain, err = await lookup(host)
    if err == "nxdomain":
        return not_reproducible(cid, f"{host} no longer resolves (NXDOMAIN)", host=host, cname_chain=[])
    if err:
        return inconclusive(cid, err, host=host, cname_chain=chain)
    if not chain:
        return not_reproducible(cid, f"{host} has no CNAME record any more", host=host, cname_chain=[])
    fingerprints = takeover_mod._load_fingerprints()
    target = chain[-1]
    service = takeover_mod._match_service(target, fingerprints)
    if service is None:
        return not_reproducible(cid, f"{host} now points at {target}, not a takeover-prone provider",
                                host=host, cname_chain=chain)
    url = f"https://{host}/"
    r = await SafeFetcher(env, cid).get(url, max_bytes=takeover_mod._MAX_SNIFF_BYTES)
    if r.error:
        return inconclusive(cid, f"could not fetch {url}: {r.error}", host=host, cname_chain=chain,
                            service=service)
    spec = fingerprints[service]
    ev = {"host": host, "cname_chain": chain, "service": service, "http_status": r.status}
    if takeover_mod._fingerprint_match(spec, r.status, r.text()):
        fp = (spec.get("fingerprint_text") or "").strip() or f"http_status={spec.get('http_status')}"
        return confirmed(cid, f"{host} still shows {service}'s unclaimed-resource response", **ev,
                         matched_fingerprint=fp)
    return not_reproducible(cid, f"{service} no longer answers with its unclaimed-resource fingerprint",
                            **ev)


# --------------------------------------------------------------------------- #
# open port / service banner
# --------------------------------------------------------------------------- #

_PORT_RULE = re.compile(
    r"(?i)^(exposed|open|risky|public)[-_](port|service|ssh|rdp|telnet|ftp|smb|vnc|redis|mongo(db)?|"
    r"mysql|postgres(ql)?|mssql|elasticsearch|memcached|docker|kubelet|etcd|ldap|rpc|snmp|database)")
_PORT_IN_RULE = re.compile(r"(?i)(?:port[-_]?|[-_])(\d{2,5})(?:$|[-_])")
_NAME_PORTS = {"ssh": 22, "rdp": 3389, "telnet": 23, "ftp": 21, "smb": 445, "vnc": 5900,
               "redis": 6379, "mongo": 27017, "mongodb": 27017, "mysql": 3306, "postgres": 5432,
               "postgresql": 5432, "mssql": 1433, "elasticsearch": 9200, "memcached": 11211,
               "docker": 2375, "etcd": 2379, "ldap": 389, "snmp": 161}
_MAX_BANNER = 256


def _port_for(f: FindingCtx) -> int | None:
    p = f.evidence.get("port")
    if isinstance(p, int) or (isinstance(p, str) and p.isdigit()):
        return int(p)
    m = _PORT_IN_RULE.search(f.rule_id)
    if m and 0 < int(m.group(1)) < 65536:
        return int(m.group(1))
    for name, port in _NAME_PORTS.items():
        if re.search(rf"(?i)[-_]{name}(?:$|[-_])", f.rule_id):
            return port
    return None


def _match_port(f: FindingCtx) -> bool:
    return bool(_PORT_RULE.search(f.rule_id)) and bool(f.host) and _port_for(f) is not None \
        and f.rule_source != "chain"


async def tcp_banner(host: str, port: int, timeout: float = CONNECT_TIMEOUT_SEC) -> dict[str, Any]:
    """Connect, wait briefly for a server-first banner, close. Sends nothing."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return {"state": "filtered", "error": "timeout"}
    except ConnectionRefusedError:
        return {"state": "closed", "error": "refused"}
    except OSError as e:
        return {"state": "error", "error": f"{type(e).__name__}: {str(e)[:100]}"}
    banner = b""
    try:
        banner = await asyncio.wait_for(r.read(_MAX_BANNER), 1.5)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 2)
        except Exception:  # noqa: BLE001
            pass
    return {"state": "open", "banner": banner}


async def _run_port(f: FindingCtx, env: CheckEnv) -> CheckResult:
    cid = "open_port"
    host, port = f.host, _port_for(f)
    assert port
    await env.scope.allow(f"{host}:{port}")
    res = await (env.tcp_banner or tcp_banner)(host, port)
    await env.audit(target=f"{host}:{port}", tool="safe_check:open_port", method="tcp_connect",
                    scope_matched=True, bytes_in=len(res.get("banner") or b""), error=res.get("error"))
    ev = {"host": host, "port": port, "state": res["state"]}
    if res["state"] == "open":
        banner = res.get("banner") or b""
        return confirmed(cid, f"{host}:{port} still accepts TCP connections", **ev,
                         banner=excerpt(banner, 120) if banner else None)
    if res["state"] == "closed":
        return not_reproducible(cid, f"{host}:{port} refuses connections", **ev)
    if res["state"] == "filtered":
        # Dropped packets: firewalled (a real fix) or just slow/blocked from here.
        # Not distinguishable from one vantage point, so never a proof of a fix.
        return inconclusive(cid, f"{host}:{port} did not answer (filtered or unreachable)", **ev)
    return inconclusive(cid, f"could not probe {host}:{port}: {res.get('error')}", **ev)


NETWORK_CHECKS = [
    ("subdomain_takeover", "Subdomain takeover", "CNAME lookup + GET / and match provider fingerprint.",
     _match_takeover, _run_takeover, ("DNS", "GET")),
    ("open_port", "Open port / service banner", "TCP connect and passive banner read (nothing sent).",
     _match_port, _run_port, ("TCP connect",)),
]
