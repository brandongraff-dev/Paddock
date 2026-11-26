# SPDX-License-Identifier: Apache-2.0
"""The resolver interface, quorum rules and resolver specs (spec/05 section 6.3).

``Resolver.resolve_txt(qname, timeout) -> DnsAnswer``. A resolver never raises: failure is a status.
All configured resolvers that answer definitively (``ok``, ``nxdomain``, ``nodata``) must agree, and at least
``min_resolvers`` must answer. Disagreement is unverifiable and is never resolved by picking the answer that matches.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence

STATUSES = ("ok", "nxdomain", "nodata", "servfail", "timeout", "error")
_DEFINITIVE = ("ok", "nxdomain", "nodata")


class DnsAnswer(NamedTuple):
    status: str
    txt: List[str]
    ad: Optional[bool]           # True/False: the resolver's AD flag over an authenticated channel; None: it cannot say
    source: str
    ttl: Optional[int] = None
    truncated: bool = False


def error_answer(source: str, status: str = "error") -> DnsAnswer:
    return DnsAnswer(status, [], None, source)


class Quorum(NamedTuple):
    error: Optional[str]         # dns.lookup_failed | dns.insufficient_resolvers | dns.resolvers_disagree | None
    status: Optional[str]        # "ok" (records) | "none" (every answering resolver says there are none)
    records: List[str]
    answered: int
    ad: str                      # ad_asserted | not_asserted | unknown
    sources: List[str]
    ttl: Optional[int]


def _signature(a: DnsAnswer):
    if a.status == "ok":
        return ("ok", tuple(sorted(a.txt)))
    return ("none",)


def quorum(answers: Sequence[DnsAnswer], min_resolvers: int) -> Quorum:
    done = [a for a in answers if a.status in _DEFINITIVE]
    sources = [a.source for a in done]
    if not done:
        return Quorum("dns.lookup_failed", None, [], 0, "unknown", sources, None)
    if len(done) < max(1, min_resolvers):
        return Quorum("dns.insufficient_resolvers", None, [], len(done), "unknown", sources, None)
    sigs = set(_signature(a) for a in done)
    if len(sigs) != 1:
        return Quorum("dns.resolvers_disagree", None, [], len(done), "unknown", sources, None)
    flags = [a.ad for a in done]
    ad = "not_asserted" if any(f is False for f in flags) else ("unknown" if any(f is None for f in flags) else "ad_asserted")
    ttls = [a.ttl for a in done if a.ttl is not None]
    sig = sigs.pop()
    if sig[0] == "ok":
        return Quorum(None, "ok", list(sig[1]), len(done), ad, sources, min(ttls) if ttls else None)
    return Quorum(None, "none", [], len(done), ad, sources, min(ttls) if ttls else None)


class FakeResolver(object):
    """An injectable resolver: ``answers`` maps a (case-insensitive) name to a DnsAnswer; an absent name is NXDOMAIN."""

    network = False

    def __init__(self, answers: Dict[str, DnsAnswer], name: str = "fake") -> None:
        self.name = name
        self._answers = dict((k.lower().rstrip("."), v) for k, v in answers.items())

    def resolve_txt(self, qname: str, timeout: float) -> DnsAnswer:
        a = self._answers.get(qname.lower().rstrip("."))
        if a is None:
            return DnsAnswer("nxdomain", [], None, self.name)
        return a


class ResolverSet(object):
    """The configured resolvers plus the quorum threshold (default 2 for the default DoH set, else 1)."""

    def __init__(self, resolvers: Iterable[Any], min_resolvers: Optional[int] = None) -> None:
        self.resolvers = list(resolvers)
        if not self.resolvers:
            raise ValueError("at least one resolver is required")
        from . import doh
        self.is_default = [getattr(r, "name", None) for r in self.resolvers] == [r.name for r in doh.default_resolvers()]
        if min_resolvers is None:
            min_resolvers = 2 if self.is_default else 1
        if not isinstance(min_resolvers, int) or isinstance(min_resolvers, bool) or min_resolvers < 1:
            raise ValueError("min_resolvers must be a positive integer")
        self.min_resolvers = min_resolvers

    def lookup(self, qname: str, timeout: float = 5.0) -> Quorum:
        answers = []
        for r in self.resolvers:
            try:
                a = r.resolve_txt(qname, timeout)
                if not isinstance(a, DnsAnswer) or a.status not in STATUSES:
                    raise TypeError("a resolver returned something other than a DnsAnswer")
            except Exception:
                a = error_answer(str(getattr(r, "name", "resolver")))
            answers.append(a)
        return quorum(answers, self.min_resolvers)


def parse_specs(specs: Sequence[str]) -> List[Any]:
    """``doh:<url>``, ``udp:<ip>[:port]``, ``system`` and ``file:<path>`` as resolver objects (ValueError otherwise)."""
    from . import doh, filefix, udp
    out = []
    for spec in specs:
        if not isinstance(spec, str) or not spec:
            raise ValueError("empty resolver spec")
        if spec == "system":
            out.append(udp.SystemResolver())
        elif spec.startswith("doh:") and len(spec) > 4:
            out.append(doh.DohResolver(spec[4:]))
        elif spec.startswith("udp:") and len(spec) > 4:
            out.append(udp.UdpResolver(*_host_port(spec[4:])))
        elif spec.startswith("file:") and len(spec) > 5:
            out.append(filefix.FileResolver(spec[5:]))
        else:
            raise ValueError("unknown resolver spec %r (doh:<url>, udp:<ip>[:port], system, file:<path>)" % spec[:40])
    return out


def _host_port(text: str):
    host, port = text, 53
    if text.startswith("["):                                   # [v6]:port
        end = text.find("]")
        if end < 0:
            raise ValueError("bad IPv6 literal")
        host, rest = text[1:end], text[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValueError("bad port")
            port = _port(rest[1:])
    elif text.count(":") == 1:
        host, p = text.split(":")
        port = _port(p)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("udp: needs an IP address") from None
    return host, port


def _port(p: str) -> int:
    if not p.isdigit() or not 1 <= int(p) <= 65535:
        raise ValueError("bad port")
    return int(p)


def offline_safe(resolvers: Iterable[Any]) -> List[Any]:
    """The resolvers that need no network (``file:`` and fakes): all that an ``--offline`` run may use."""
    return [r for r in resolvers if getattr(r, "network", True) is False]
