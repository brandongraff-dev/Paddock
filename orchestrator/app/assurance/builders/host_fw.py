"""``host_fw`` builder: what a managed host's own firewall lets in, from its signed posture.

Source ``host_fw``, mode ``replace``. It turns the latest VERIFIED ``agent_posture`` of every live v2
agent (docs/ASSURANCE_P2.md section 7.1, agent/PAYLOAD.md) into

* **nodes**   ``agent:<uuid>`` (kind ``host``), or the cloud instance ``asset:<uuid>`` when the agent is
              corroborated as that instance or an admin PAIRED it with that instance (docs/ASSURANCE_P2_1.md
              section 4: a pairing changes identity only, never trust). Never ``ip:`` for a managed host.
* **edges**   per non-loopback listener x source atom, by walking every input-hook base chain of the
              canonical firewall model with first-match semantics. Basis ``configured``, never ``observed``.
              Confidence 100 for a rule path that ALLOWS in an exact model, 60 for everything else.
* **coverage** direction ``in``, tier ``configured``, only when ALL of the conditions in ``_coverage_gate``
              hold.
* **facts**   the host's collector entries for the library registry (``sshd``, ``firewall``,
              ``listeners``, ``patch``) plus an informational ``host_agent`` summary.

The soundness rule (the product claims "no counterexample under this evidence"): every uncertainty either
WIDENS reachability (more edges, ``maybe`` edges at confidence 60) or REMOVES coverage and facts. A signed
posture is a claim by the host, not a fact about it: its facts have tier ``configured``, and the external
scan can contradict it (``agent_closed_scan_open``), which withdraws coverage and marks every fact of the
host in conflict.

Why edges matter only where coverage is granted. A node with no inbound coverage already has "possible
unknown edges" from every source that is blind outbound, so a missing or too narrow edge on such a node
cannot produce a false HOLDS. On a node WITH coverage the edge set must be exhaustive: so for a covered
host the walk covers every address family, protocol class (tcp, udp, icmp, anything else) and source
block, the internet AND the internal address space (a world-open rule admits the guest laptop too, which
the loader's cidr expansion turns into edges from every node), and it refuses coverage whenever it had to
fall back (too many source atoms, walk budget, edge cap).

What is NOT modelled (stated, never silently treated as closed):
* loopback-bound listeners (reachable only with ``route_localnet`` tricks);
* sockets in other network namespaces, DNAT-only ports: any NAT rewriting makes the model approximate, so
  every listener (and with NAT every port) is reachable from every source at confidence 60 and the host
  gets no coverage;
* raw/packet sockets, kernel services without a listener row, IP protocols other than tcp/udp/icmp (they
  are probed as one representative protocol number, which is enough for the default-deny/accept-all
  distinction a covered host needs);
* source addresses outside the unicast universe (0/8, 127/8, multicast, 240/4), which cannot be remote
  sources.

``load`` is read-only SQL on a tenant-bound connection (tenancy comes from the pool, never from the
SQL) and RE-VERIFIES every stored signature against the agent's key. ``build`` is pure: no DB, clock,
network or randomness; ``now`` is a parameter; the output is sorted and byte-stable.
"""
from __future__ import annotations

import asyncio
import bisect
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import re
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .. import refs
from ..types import BuildOutput, CoverageOut, EdgeOut, FactOut, NodeOut
from . import _ipmap

logger = logging.getLogger(__name__)

SOURCE = "host_fw"

#: how old a posture may be and still count (the runner passes ``agent_posture_max_age``).
DEFAULT_POSTURE_MAX_AGE = dt.timedelta(hours=6)
DEFAULT_EXTERNAL_MAX_AGE = dt.timedelta(hours=168)    # how long an external scan observation is kept (settings)
#: edges from the last good posture of a silent/stale agent are kept this long (over-approximation).
DEFAULT_SILENT_EDGE_TTL = dt.timedelta(days=7)
FUTURE_SKEW = dt.timedelta(minutes=5)
#: a scan observation counts against a posture when it is newer than ``collected_at - CONFLICT_SLACK``.
CONFLICT_SLACK = dt.timedelta(minutes=5)

MAX_ATOMS = 4096              # source atoms per family (fwmodel's own cap)
WALK_BUDGET = 250_000         # firewall walks per agent per build
WALK_STEP_CAP = 100_000       # states visited per single walk
# A walk costs up to one rule evaluation per rule, so the NUMBER of walks says little about the work: a signed
# posture of 2000 distinct-CIDR rules and 2000 listeners (about 700 KB, schema-valid) is billions of evaluations
# (hours of CPU in a worker thread that a timeout cannot stop). The work is therefore bounded in rule
# evaluations: per agent, and for the whole build. Past either bound the host is WIDENED (every listener from
# every source at confidence 60, no coverage), the same sound fallback as every other cap here.
STEP_BUDGET = 8_000_000       # rule evaluations one agent may cost in one build (about 4 s; a typical host needs 0.2 M)
BUILD_STEP_BUDGET = 100_000_000  # ... and all agents together (agents past it widen at once, in id order)
MAX_BLOCKS = 32               # CIDR blocks one listener may name before the sources are widened
MAX_EDGES_PER_AGENT = 4000
MAX_CONFLICTS = 20
MAX_LISTENERS = 2000
MAX_DEPTH = 8                 # jump/goto depth (the model's own bound)
CONF_ALLOW = 100
CONF_MAYBE = 60

IIF_EXTERNAL = "<external>"   # "some non-loopback interface, name unknown" (same token as fwmodel)
_PORT_PROTOS = frozenset(("dccp", "sctp", "tcp", "udp", "udplite"))
_KNOWN_M = frozenset(("iif", "oif", "src", "dst", "proto", "sport", "dport", "ct", "icmp", "dtype"))
#: a protocol number nothing special-cases: "any other IP protocol" for the covered-host probe.
_OTHER_PROTO = "p253"
# The canonical tokens of a rule's ``m`` (agent/paddock_agent/collectors/fwmodel.py). The agent always writes these;
# a token outside them (version skew, a bug, a lying host) is NOT "a rule that does not match": the rule is marked
# unknown and explored both ways, so a rule can never silently disappear (review finding hostfw-8).
_PROTO_NAMES = frozenset(("tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "udplite", "gre", "esp", "ah", "igmp",
                          "ipip", "ipv6"))
_PROTO_NUMBERS = frozenset((1, 2, 4, 6, 17, 33, 41, 47, 50, 51, 58, 132, 136))   # have a name: 'pNNN' is not their spelling
# The names the agent forwards unchanged when its own table (fwmodel._PROTO_NAMES) does not know them: ``iptables -p
# vrrp`` reads ``vrrp``, ``-p 112`` reads ``p112``. They are the lower-case names (and aliases) of /etc/protocols
# (netbase), each a protocol NUMBER; here they are folded onto ONE token per protocol, so ``vrrp`` and ``p112`` are the
# same protocol in a walk (a drop of one applies to the other), and an honest rule for another IP protocol stays exact
# instead of widening every listener (review finding Z-5). A name that is NOT in this table (a typo, 'TCP', 'all',
# 'ipv6-icmp' which the agent itself writes ``icmpv6``) is still unknown and widens (hostfw-8).
_ETC_PROTOCOLS = {
    "ggp": 3, "ipencap": 4, "ip-encap": 4, "st": 5, "egp": 8, "igp": 9, "pup": 12, "hmp": 20, "xns-idp": 22, "rdp": 27,
    "iso-tp4": 29, "xtp": 36, "ddp": 37, "idpr-cmtp": 38, "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45, "rsvp": 46,
    "ipsec-esp": 50, "ipsec-ah": 51, "skip": 57, "ipv6-nonxt": 59, "ipv6-opts": 60, "rspf": 73, "cphb": 73, "vmtp": 81,
    "eigrp": 88, "ospf": 89, "ospfigp": 89, "etherip": 97, "encap": 98, "pim": 103, "ipcomp": 108, "vrrp": 112,
    "l2tp": 115, "isis": 124, "fc": 133, "mobility-header": 135, "mpls-in-ip": 137, "manet": 138, "hip": 139,
    "shim6": 140, "wesp": 141, "rohc": 142, "ethernet": 143,
}
_NAME_OF_NUMBER = {1: "icmp", 2: "igmp", 4: "ipip", 6: "tcp", 17: "udp", 33: "dccp", 41: "ipv6", 47: "gre", 50: "esp",
                   51: "ah", 58: "icmpv6", 132: "sctp", 136: "udplite"}
_CT_STATES = frozenset(("established", "invalid", "new", "related", "untracked"))
_DTYPES = frozenset(("anycast", "broadcast", "local", "multicast", "unicast"))
_PNNN = re.compile(r"p(0|[1-9][0-9]{0,2})")
_IFNAME = re.compile(r"[\x21-\x7e]{1,15}")            # printable, no space; the kernel's limit is 15 characters


def _proto_token(tok: Any) -> Optional[str]:
    """The one token a protocol is walked by (``tcp``, ``udp``, ... for the agent's own names, ``pNNN`` for every other
    number), or ``None`` for a token that is not a protocol spelling the agent writes (the rule is then unknown)."""
    if not isinstance(tok, str):
        return None
    if tok in _PROTO_NAMES:
        return tok
    m = _PNNN.fullmatch(tok)
    if m is not None:
        n = int(tok[1:])
        return tok if n <= 255 and n not in _PROTO_NUMBERS else None
    n = _ETC_PROTOCOLS.get(tok)
    if n is not None:
        return _NAME_OF_NUMBER.get(n) or f"p{n}"
    return None


def _canonical_proto(tok: Any) -> bool:
    return _proto_token(tok) is not None


def _canonical_ifname(tok: Any) -> bool:
    return isinstance(tok, str) and _IFNAME.fullmatch(tok) is not None and "*" not in tok and "/" not in tok
_NAT_FEATURES = frozenset(("nat_rewrite", "ipvs", "notrack"))
_UNIVERSE = {4: (1 << 24, (224 << 24) - 1), 6: (1, (0xFF00 << 112) - 1)}
_WORLD = {4: refs.cidr_ref("0.0.0.0/0"), 6: refs.cidr_ref("::/0")}


def _blocks(items: Iterable[str]) -> list[tuple[int, int]]:
    out = []
    for c in items:
        n = ipaddress.ip_network(c)
        out.append((int(n.network_address), int(n.broadcast_address)))
    return out


#: "P" = the internal address space (RFC1918, CGNAT, link-local, ULA): sources that are inside, not the
#: internet. "X" = never a remote source (loopback). Everything else in the universe is "G", global.
_BLOCKS = {
    4: {"P": _blocks(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"]),
        "X": _blocks(["127.0.0.0/8"])},
    6: {"P": _blocks(["fc00::/7", "fe80::/10"]), "X": _blocks(["::1/128"])},
}

_INSTANCE_RESOURCE_KIND = "cloud_instance"
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------- #
# small helpers (pure)
# --------------------------------------------------------------------------- #

def _aware(t: dt.datetime) -> dt.datetime:
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return _aware(t).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(v: Any, limit: int = 64) -> str:
    """Printable ASCII only, bounded: agent-supplied text never goes into a ref, label or finding raw."""
    if not isinstance(v, str):
        return ""
    return re.sub(r"[^\x20-\x7e]", "?", v)[:limit]


def _is_int(v: Any) -> bool:
    return type(v) is int


def _merge(ivs: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(ivs):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def _in_ivs(ivs: list[tuple[int, int]], x: int) -> bool:
    i = bisect.bisect_right(ivs, (x, 1 << 130)) - 1
    return i >= 0 and ivs[i][0] <= x <= ivs[i][1]


def _cidr_ivs(items: Any, fam: int) -> Optional[list[tuple[int, int]]]:
    """Merged intervals of a CIDR list for one family; ``None`` for anything unreadable (=> unknown)."""
    if not isinstance(items, list) or not items or len(items) > 4096:
        return None
    out = []
    for c in items:
        if not isinstance(c, str) or len(c) > 64:
            return None
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            return None
        if n.version != fam:
            return None
        out.append((int(n.network_address), int(n.broadcast_address)))
    return _merge(out)


def _ranges(items: Any) -> Optional[list[tuple[int, int]]]:
    """``[[lo, hi], ...]`` port ranges, validated; ``None`` when unreadable (=> unknown)."""
    if not isinstance(items, list) or not items or len(items) > 4096:
        return None
    out = []
    for it in items:
        if (not isinstance(it, (list, tuple)) or len(it) != 2 or not _is_int(it[0]) or not _is_int(it[1])
                or not 0 <= it[0] <= it[1] <= 65535):
            return None
        out.append((it[0], it[1]))
    return _merge(out)


def _addr_int(text: Any, fam: int) -> Optional[int]:
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return int(ip) if ip.version == fam else None


def _cidrs_of(fam: int, lo: int, hi: int) -> list[str]:
    mk = ipaddress.IPv4Address if fam == 4 else ipaddress.IPv6Address
    return [str(n) for n in ipaddress.summarize_address_range(mk(lo), mk(hi))]


# --------------------------------------------------------------------------- #
# the packet walk: first-match semantics over every input base chain
# --------------------------------------------------------------------------- #

class _Rule:
    """One compiled rule. ``unknown`` marks a condition we could not read: it is explored both ways."""
    __slots__ = ("v", "opaque", "unknown", "iif", "oif", "src", "dst", "proto", "sport", "dport", "ct",
                 "icmp", "dtype", "has_dst")

    def __init__(self, rule: Any, fam: int) -> None:
        self.unknown = False
        self.iif = self.oif = self.proto = None
        self.src = self.dst = self.sport = self.dport = self.ct = self.icmp = self.dtype = None
        self.has_dst = False
        if not isinstance(rule, dict):
            self.v, self.opaque, self.unknown = "opaque", True, True
            return
        v = rule.get("v")
        self.v = v if isinstance(v, str) else "opaque"
        # ANY opaque_reason (even an action-only one) is an unmodelled condition: explored both ways.
        # That can only ever widen the verdict.
        self.opaque = bool(rule.get("opaque_reason"))
        m = rule.get("m")
        if not isinstance(m, dict):
            self.unknown = True
            return
        for k in m:
            if k not in _KNOWN_M:
                self.unknown = True
        self.has_dst = "dst" in m
        for key in ("iif", "oif", "proto"):
            if key in m:
                tok = _proto_token(m[key]) if key == "proto" else (m[key] if _canonical_ifname(m[key]) else None)
                if tok is not None:
                    setattr(self, key, tok)
                else:
                    self.unknown = True        # the condition is NOT applied (it would decide "no match"), the rule is "maybe"
        for key in ("src", "dst"):
            if key in m:
                ivs = _cidr_ivs(m[key], fam)
                if ivs is None:
                    self.unknown = True
                setattr(self, key, ivs)
        for key in ("sport", "dport"):
            if key in m:
                ivs = _ranges(m[key])
                if ivs is None:
                    self.unknown = True
                setattr(self, key, ivs)
        for key, canon in (("ct", _CT_STATES), ("dtype", _DTYPES)):
            if key in m:
                if (isinstance(m[key], list) and m[key] and all(isinstance(x, str) for x in m[key])
                        and set(m[key]) <= canon):
                    setattr(self, key, frozenset(m[key]))
                else:
                    self.unknown = True
        if "icmp" in m:
            if isinstance(m["icmp"], list) and m["icmp"] and all(_is_int(x) and 0 <= x <= 255 for x in m["icmp"]):
                self.icmp = frozenset(m["icmp"])
            else:
                self.unknown = True


def _match(r: _Rule, pkt: Mapping[str, Any]) -> Optional[bool]:
    """Does the rule match the packet? ``True``, ``False`` or ``None`` (cannot tell: explored both ways).

    A key absent from ``pkt`` is unknown. A condition the rule carries but we could not read, or an
    opaque extra condition, can turn True into None, never False into anything else.
    """
    res: Optional[bool] = True
    proto = pkt.get("proto")
    if r.proto is not None:
        if proto is None:
            res = None
        elif r.proto != proto:
            return False
    for key, rng in (("sport", r.sport), ("dport", r.dport)):
        if rng is not None:
            if proto is not None and proto not in _PORT_PROTOS:
                return False
            val = pkt.get(key)
            if val is None:
                res = None
            elif not any(lo <= val <= hi for lo, hi in rng):
                return False
    if r.icmp is not None:
        if proto is not None and proto not in ("icmp", "icmpv6"):
            return False
        val = pkt.get("icmp")
        if val is None:
            res = None
        elif val not in r.icmp:
            return False
    if r.ct is not None:
        val = pkt.get("ct")
        if val is None:
            res = None
        elif val not in r.ct:
            return False
    if r.iif is not None:
        val = pkt.get("iif")
        if val is None:
            res = None
        elif val == IIF_EXTERNAL:
            if r.iif == "lo":
                return False
            res = None
        elif val != r.iif:
            return False
    if r.oif is not None:
        val = pkt.get("oif")
        if val is None:
            res = None
        elif val != r.oif:
            return False
    if r.dtype is not None:
        val = pkt.get("dtype")
        if val is None:
            res = None
        elif val not in r.dtype:
            return False
    for key, ivs in (("src", r.src), ("dst", r.dst)):
        if ivs is not None:
            val = pkt.get(key)
            if val is None:
                res = None
            elif not _in_ivs(ivs, val):
                return False
    if res is True and (r.opaque or r.unknown):
        return None
    return res


_BOTH = frozenset(("accept", "drop"))
_RANK = {"deny": 0, "maybe": 1, "allow": 2}


class _BudgetExceeded(Exception):
    """The rule-evaluation budget of this agent (or of the build) is spent."""


class _Walker:
    """The input base chains of one address family, compiled, with the verdict walk."""

    def __init__(self, family: Mapping[str, Any], fam: int) -> None:
        self.fam = fam
        self.chains: dict[str, tuple[Optional[str], list[_Rule]]] = {}
        self.bases: list[str] = []
        self.src_ranges: list[tuple[int, int]] = []
        self.dport_points: set[int] = set()
        self.uses_dst = False
        self.other_protos: set[str] = set()      # protocols rules name that are not tcp/udp/icmp
        self.walks = 0
        self.steps = 0                            # rule evaluations done so far (all agents sharing this ruleset)
        self.limit: Optional[int] = None          # raise _BudgetExceeded once ``steps`` passes this
        self.vcache: dict[tuple, list[str]] = {}  # verdict arrays, shared by every host with this ruleset
        self.scache: dict[tuple, list] = {}       # source lists derived from them
        self.truncated = False
        self._atoms: Any = False
        for c in family.get("chains") or []:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str):
                continue
            rules = [_Rule(x, fam) for x in (c.get("rules") or [])]
            policy = c.get("policy") if isinstance(c.get("policy"), str) else None
            self.chains[c["name"]] = (policy, rules)
            if c.get("base") is True:
                self.bases.append(c["name"])
            for r in rules:
                if r.src:
                    self.src_ranges.extend(r.src)
                for lo, hi in r.dport or ():
                    self.dport_points.add(lo)
                    self.dport_points.add(hi + 1)
                if r.has_dst or r.unknown:
                    self.uses_dst = True
                if r.proto is not None and r.proto not in ("tcp", "udp", "icmp", "icmpv6"):
                    self.other_protos.add(r.proto)
        self.bases.sort()
        self._pts = sorted(self.dport_points | {1, 65536})
        self._pts = [p for p in self._pts if 1 <= p <= 65536]

    # -- ports ------------------------------------------------------------------------------------ #
    def port_class(self, port: int) -> int:
        return bisect.bisect_right(self._pts, port)

    def port_ranges(self) -> list[tuple[int, int]]:
        return [(a, b - 1) for a, b in zip(self._pts, self._pts[1:]) if a <= b - 1]

    # -- atoms ------------------------------------------------------------------------------------ #
    def atoms(self) -> Optional[list["_Atom"]]:
        if self._atoms is False:
            self._atoms = _make_atoms(self.fam, self.src_ranges)   # NOT merged: every rule's edges are boundaries
        return self._atoms

    # -- the walk --------------------------------------------------------------------------------- #
    def _outcomes(self, base: str, pkt: Mapping[str, Any]) -> frozenset:
        """The set of final outcomes (``accept`` / ``drop``) of one base chain for ``pkt``.

        Straight-line execution inside a chain; only an undecidable rule (``None``) forks, and only the
        fork is memoised. ``goto`` keeps the caller's return address, ``jump`` pushes one.
        """
        policy = self.chains[base][0]
        end = "drop" if policy == "drop" else "accept"
        start = (base, 0, ())
        seen = {start}
        work = [start]
        outs: set[str] = set()
        steps = 0
        chains = self.chains
        while work:
            name, i, stack = work.pop()
            while True:
                steps += 1
                if steps > WALK_STEP_CAP:
                    self.truncated = True
                    self.steps += steps
                    return _BOTH
                ch = chains.get(name)
                if ch is None:
                    outs |= _BOTH
                    break
                rules = ch[1]
                if i >= len(rules):                       # fell off the end: back to the caller, or the policy
                    if stack:
                        (name, i), stack = stack[-1], stack[:-1]
                        continue
                    outs.add(end)
                    break
                r = rules[i]
                res = _match(r, pkt)
                if res is False:
                    i += 1
                    continue
                if res is None:                           # may not match: the fall-through branch is also real
                    st = (name, i + 1, stack)
                    if st not in seen:
                        seen.add(st)
                        work.append(st)
                v = r.v
                if v == "accept":
                    outs.add("accept")
                    break
                if v in ("drop", "reject"):
                    outs.add("drop")
                    break
                if v == "return":
                    if stack:
                        (name, i), stack = stack[-1], stack[:-1]
                        continue
                    outs.add(end)
                    break
                if v.startswith("jump:"):
                    tgt = v[5:]
                    if tgt not in chains or len(stack) >= MAX_DEPTH:
                        outs |= _BOTH
                        i += 1                            # and it may also have fallen through
                        if res is True:
                            continue
                        break
                    stack = stack + ((name, i + 1),)
                    name, i = tgt, 0
                    continue
                if v.startswith("goto:"):
                    tgt = v[5:]
                    if tgt not in chains:
                        outs |= _BOTH
                        break
                    name, i = tgt, 0
                    continue
                outs |= _BOTH                             # opaque / unknown action: anything, or fall through
                i += 1
                if res is True:
                    continue
                break
        self.steps += steps
        return frozenset(outs)

    def verdict(self, pkt: Mapping[str, Any]) -> str:
        """``allow`` only if EVERY base chain can only accept, ``deny`` only if some base chain can only
        drop, else ``maybe``. No base chain at all means nothing filters: ``allow``."""
        self.walks += 1
        if not self.bases:
            return "allow"
        accept_possible, drop_possible = True, False
        for b in self.bases:
            outs = self._outcomes(b, pkt)
            if self.limit is not None and self.steps > self.limit:
                raise _BudgetExceeded()
            if "accept" not in outs:
                accept_possible = False
            if "drop" in outs:
                drop_possible = True
        if not accept_possible:
            return "deny"
        return "maybe" if drop_possible else "allow"


@dataclass(frozen=True)
class _Atom:
    lo: int
    hi: int
    klass: str          # "G" global, "P" internal
    rep: int            # a representative address (every rule CIDR is constant over the atom)


def _make_atoms(fam: int, src_ranges: list[tuple[int, int]]) -> Optional[list[_Atom]]:
    """Partition the unicast source universe by every rule CIDR and by the internal-space boundaries, so
    each atom is entirely internal or entirely global. ``None`` when there would be too many atoms."""
    ulo, uhi = _UNIVERSE[fam]
    blocks = _BLOCKS[fam]
    points = {ulo, uhi + 1}
    for lo, hi in blocks["P"] + blocks["X"] + src_ranges:
        for p in (lo, hi + 1):
            if ulo < p <= uhi:
                points.add(p)
    pts = sorted(points)
    if len(pts) - 1 > MAX_ATOMS:
        return None
    out = []
    for a, b in zip(pts, pts[1:]):
        if any(lo <= a <= hi for lo, hi in blocks["X"]):
            continue
        klass = "P" if any(lo <= a <= hi for lo, hi in blocks["P"]) else "G"
        out.append(_Atom(a, b - 1, klass, a))
    return out


# --------------------------------------------------------------------------- #
# sections: firewall, listeners
# --------------------------------------------------------------------------- #

@dataclass
class _Fw:
    state: str = "missing"            # ok | unavailable | error | missing
    exact: bool = False
    reasons: list = field(default_factory=list)
    ipv6: Optional[bool] = None
    walkers: dict = field(default_factory=dict)
    nat_like: bool = False
    engine: str = ""
    #: the build-wide pool of rule evaluations (a one-element list shared by every agent of one ``build``); set by
    #: ``_agent_out`` before it walks this firewall. ``None`` = only the per-agent ``STEP_BUDGET`` applies.
    budget: Optional[list] = None

    def truncated(self) -> bool:
        return any(w.truncated for w in self.walkers.values())


def _parse_fw(sec: Any) -> _Fw:
    fw = _Fw()
    if not isinstance(sec, dict):
        fw.reasons.append("section_missing")
        return fw
    s = sec.get("s")
    if s != "ok":
        fw.state = "unavailable" if s == "unavailable" else "error"
        fw.reasons.append("section_" + (_text(sec.get("reason"), 40) or str(s)))
        return fw
    fw.state = "ok"
    v = sec.get("v")
    if not isinstance(v, dict):
        fw.reasons.append("bad_model")
        return fw
    reasons = fw.reasons
    if sec.get("conf") != "exact":
        reasons.append("section_conf_approximate")
    if sec.get("partial") is not False:
        reasons.append("section_partial")
    if v.get("v") != 1:
        reasons.append("model_version")
    flat = v.get("flat_view")
    conf = flat.get("confidence") if isinstance(flat, dict) else None
    if conf != "exact":
        reasons.append("model_confidence_" + (conf if isinstance(conf, str) and conf.isalpha() else "missing"))
    feats = v.get("opaque_features")
    plane = v.get("dataplane")
    if not isinstance(feats, list) or not isinstance(plane, list):
        reasons.append("bad_model")
        feats, plane = [], []
    if feats:
        reasons.append("opaque_features")
    if plane:
        reasons.append("dataplane")
    fw.nat_like = bool(plane) or any(f in _NAT_FEATURES for f in feats)
    backend = v.get("backend")
    fw.engine = backend if backend in ("nft", "legacy", "mixed", "none") else ""
    v6 = v.get("ipv6_enabled")
    if not isinstance(v6, bool):
        reasons.append("ipv6_unknown")
    else:
        fw.ipv6 = v6
    fams = v.get("families")
    if not isinstance(fams, dict):
        reasons.append("bad_model")
        fams = {}
    need = (4,) + ((6,) if fw.ipv6 else ())
    for fam in need:
        f = fams.get(f"ip{fam}")
        if not isinstance(f, dict) or f.get("read") is not True or not isinstance(f.get("chains"), list):
            reasons.append(f"family_unread_ip{fam}")
            continue
        fw.walkers[fam] = _Walker(f, fam)
    fw.exact = not reasons
    return fw


@dataclass(frozen=True)
class _Listener:
    proto: str
    port: int
    ip: str
    bind_class: str
    fams: tuple
    dst: Optional[int]
    forced: bool            # published through a container: never claimed as certain
    comm: str


@dataclass
class _Lst:
    state: str = "missing"            # ok | unavailable | error | missing
    complete: bool = False
    listeners: list = field(default_factory=list)
    count: int = 0
    bad_rows: int = 0
    loopback: int = 0
    bindv6only: Optional[int] = None
    v6_needed_when_disabled: bool = False


def _parse_listeners(sec: Any, ipv6_enabled: Optional[bool]) -> _Lst:
    lst = _Lst()
    if not isinstance(sec, dict):
        return lst
    s = sec.get("s")
    if s != "ok":
        lst.state = "unavailable" if s == "unavailable" else "error"
        return lst
    lst.state = "ok"
    v = sec.get("v")
    rows = v.get("listeners") if isinstance(v, dict) else None
    if not isinstance(rows, list):
        lst.bad_rows = 1
        return lst
    bv6 = v.get("bindv6only")
    lst.bindv6only = bv6 if bv6 in (0, 1) else None
    seen: set = set()
    for r in rows[:MAX_LISTENERS + 1]:
        if not isinstance(r, dict):
            lst.bad_rows += 1
            continue
        proto, port, ip, bc = r.get("proto"), r.get("port"), r.get("ip"), r.get("bind_class")
        if (proto not in ("tcp", "udp") or not _is_int(port) or not 1 <= port <= 65535
                or not isinstance(ip, str) or bc not in ("wildcard4", "wildcard6", "loopback", "specific")):
            lst.bad_rows += 1
            continue
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6 and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
        except ValueError:
            addr = None
        if bc == "loopback" and addr is not None and addr.is_loopback:
            lst.loopback += 1               # a socket the agent calls loopback AND whose address is loopback
            continue
        if bc == "loopback":
            bc = "specific" if addr is not None else "wildcard6"   # the two disagree: reachable until proven not
        dst: Optional[int] = None
        if bc == "wildcard4":
            fams: tuple = (4,)
        elif bc == "wildcard6":
            fams = (6,) if lst.bindv6only == 1 else (4, 6)
        elif addr is not None:
            fams = (addr.version,)
            dst = int(addr)
        else:
            fams = (4, 6)                           # a specific bind we cannot read: any family
        if 6 in fams and ipv6_enabled is False:
            if bc == "specific":
                lst.v6_needed_when_disabled = True  # contradiction with the claim: no exact reading
            else:
                fams = tuple(f for f in fams if f != 6)
        key = (proto, port, ip)
        if key in seen:
            continue
        seen.add(key)
        comm = _text(r.get("comm"), 16)
        forced = comm == "docker-proxy" or isinstance(r.get("container"), str)
        lst.listeners.append(_Listener(proto, port, ip, bc, fams, dst, forced, comm))
    lst.listeners.sort(key=lambda x: (x.port, x.proto, x.ip))
    count = v.get("count")
    lst.count = count if _is_int(count) else -1
    # ``dropped`` (rows the agent cut past its own cap) contradicts a complete table whatever else the section says
    lst.complete = (sec.get("conf") == "exact" and sec.get("partial") is False and lst.bad_rows == 0
                    and v.get("dropped") is None and lst.count == len(rows) and len(rows) <= MAX_LISTENERS)
    return lst


# --------------------------------------------------------------------------- #
# the reachability of one host
# --------------------------------------------------------------------------- #

@dataclass
class _EdgeAcc:
    conf: int = 0
    flags: set = field(default_factory=set)
    tags: set = field(default_factory=set)


class _Reach:
    """The edge set of one host, by (src_ref, proto, lo, hi) -> confidence/flags/listener tags."""

    def __init__(self) -> None:
        self.edges: dict[tuple[str, str, int, int], _EdgeAcc] = {}
        self.flags: set[str] = set()
        self.fallback = False

    def add(self, src: str, proto: str, lo: int, hi: int, conf: int, flags: Iterable[str],
            tag: str = "") -> None:
        e = self.edges.setdefault((src, proto, lo, hi), _EdgeAcc())
        e.conf = max(e.conf, conf)              # a derivation that really allows beats a maybe
        e.flags.update(flags)
        if tag:
            e.tags.add(tag)


def _group_cidrs(fam: int, atoms: list[_Atom], idxs: list[int]) -> list[tuple[list[str], list[int]]]:
    """Group allowed atom indexes into contiguous runs, as (cidr blocks, indexes in the run)."""
    runs: list[list[int]] = []
    for i in idxs:
        if runs and atoms[runs[-1][-1]].hi + 1 == atoms[i].lo:
            runs[-1].append(i)
        else:
            runs.append([i])
    return [(_cidrs_of(fam, atoms[r[0]].lo, atoms[r[-1]].hi), r) for r in runs]


def _sources(fam: int, atoms: list[_Atom], verd: list[str], exact: bool, addressable: Optional[bool],
             forced: bool) -> list[tuple[str, int, frozenset]]:
    """Source refs (with confidence and assumption flags) of the atoms whose verdict is not ``deny``.

    * every global address allowed: ``internet`` (unless the node is known not to be addressable) AND the
      world cidr, because the loader's cidr expansion is what makes the estate's own nodes (a server
      with a public address, a laptop at 10.x) sources; the world cidr is confidence 100 only when the
      internal space is allowed too;
    * otherwise the exact CIDR blocks of the allowed atoms (global and internal);
    * more than ``MAX_BLOCKS`` blocks widen to ``internet`` plus the world cidr at 60.

    A verdict ``maybe`` (or a forced one) is confidence 60.
    """
    out: dict[str, list] = {}

    def put(ref: str, conf: int, flags: Iterable[str]) -> None:
        cur = out.setdefault(ref, [0, set()])
        cur[0] = max(cur[0], conf)
        cur[1].update(flags)

    def conf_of(idxs: Iterable[int]) -> int:
        ok = exact and not forced and all(verd[i] == "allow" for i in idxs)
        return CONF_ALLOW if ok else CONF_MAYBE

    every = {k: [i for i, a in enumerate(atoms) if a.klass == k] for k in ("G", "P")}
    allowed = {k: [i for i in v if verd[i] != "deny"] for k, v in every.items()}
    g_full = bool(every["G"]) and len(allowed["G"]) == len(every["G"])
    p_full = len(allowed["P"]) == len(every["P"])
    shown = ["assumed_public"] if addressable is None else []

    def blocks_of(idxs: list[int]) -> list[tuple[list[str], list[int]]]:
        return _group_cidrs(fam, atoms, idxs)

    if g_full:
        if addressable is not False:
            put(refs.INTERNET, conf_of(allowed["G"]), shown)
        put(_WORLD[fam], conf_of(allowed["G"] + allowed["P"]) if p_full else CONF_MAYBE,
            () if p_full else ("internal_sources_widened",))
        return [(ref, v[0], frozenset(v[1])) for ref, v in sorted(out.items())]
    runs = blocks_of(sorted(allowed["G"] + allowed["P"]))
    if sum(len(cidrs) for cidrs, _ in runs) > MAX_BLOCKS:
        if addressable is not False:
            put(refs.INTERNET, CONF_MAYBE, ["sources_widened"] + shown)
        put(_WORLD[fam], CONF_MAYBE, ["sources_widened"])
        return [(ref, v[0], frozenset(v[1])) for ref, v in sorted(out.items())]
    for cidrs, run in runs:
        c = conf_of(run)
        for net in cidrs:
            put(refs.cidr_ref(net), c, ())
    return [(ref, v[0], frozenset(v[1])) for ref, v in sorted(out.items())]


def _all_sources(fam: int, addressable: Optional[bool], flags: Iterable[str]) -> list[tuple[str, int, frozenset]]:
    """Every source: the internet (or, for a known non-addressable node, only the world cidr) and the
    world cidr, all at confidence 60."""
    fl = frozenset(flags)
    out = [(_WORLD[fam], CONF_MAYBE, fl)]
    if addressable is not False:
        out.append((refs.INTERNET, CONF_MAYBE, fl | ({"assumed_public"} if addressable is None else set())))
    return sorted(out)


def _pkt(src: int, proto: str, port: Optional[int], dst: Optional[int], dtype: Optional[str]) -> dict:
    pkt: dict[str, Any] = {"src": src, "proto": proto, "ct": "new", "iif": IIF_EXTERNAL}
    if port is not None:
        pkt["dport"] = port
    if dst is not None:
        pkt["dst"] = dst
    if dtype is not None:
        pkt["dtype"] = dtype
    return pkt


def _verdicts(w: _Walker, atoms: list[_Atom], proto: str, port: Optional[int], dst: Optional[int],
              dtype: Optional[str]) -> list[str]:
    return [w.verdict(_pkt(a.rep, proto, port, dst, dtype)) for a in atoms]


def _widen_all(fw: _Fw, lst: _Lst, addressable: Optional[bool], reach: _Reach, why: str) -> None:
    """The not-exact reading: every listener from every source at confidence 60, plus ICMP; with NAT
    rewriting (or an unreadable listener table) every tcp/udp port."""
    fams = [4] + ([6] if fw.ipv6 is not False or lst.v6_needed_when_disabled else [])
    reach.flags.add(why)
    base_flags = {why}
    all_ports = fw.nat_like or lst.state != "ok" or not lst.complete
    if fw.nat_like:
        base_flags.add("nat_rewrite")
    if lst.state != "ok" or not lst.complete:
        base_flags.add("listeners_unknown")
    for fam in fams:
        srcs = _all_sources(fam, addressable, base_flags)
        for ref, conf, fl in srcs:
            reach.add(ref, "icmp", 0, 0, conf, fl)
            if all_ports:
                reach.add(ref, "tcp", 1, 65535, conf, fl)
                reach.add(ref, "udp", 1, 65535, conf, fl)
        if not all_ports:
            for L in lst.listeners:
                if fam in L.fams:
                    for ref, conf, fl in srcs:
                        reach.add(ref, L.proto, L.port, L.port, conf,
                                  fl | ({"container_published"} if L.forced else set()), f"{L.proto}/{L.port}")


class _Limited:
    """Context manager: every walker of ``fw`` raises :class:`_BudgetExceeded` once this agent has spent its
    share of rule evaluations (``STEP_BUDGET``, and what is left of ``budget``, the whole build's pool)."""

    def __init__(self, fw: "_Fw") -> None:
        self.fw, self.budget = fw, fw.budget
        self.marks: list[tuple[_Walker, int]] = []

    def __enter__(self) -> "_Limited":
        allowance = STEP_BUDGET if self.budget is None else max(0, min(STEP_BUDGET, self.budget[0]))
        for w in self.fw.walkers.values():
            self.marks.append((w, w.steps))
            w.limit = w.steps + allowance
        return self

    def __exit__(self, *exc: Any) -> None:
        used = 0
        for w, start in self.marks:
            used += w.steps - start
            w.limit = None
        if self.budget is not None:
            self.budget[0] -= used


def compute_reach(fw: _Fw, lst: _Lst, addressable: Optional[bool]) -> _Reach:
    """Every edge one host's firewall and listeners allow, within the rule-evaluation budget (see
    ``STEP_BUDGET``): a host that would cost more is widened exactly like one with too many sources."""
    with _Limited(fw):
        try:
            return _compute_reach(fw, lst, addressable)
        except _BudgetExceeded:
            pass
    reach = _Reach()
    _widen_all(fw, lst, addressable, reach, "walk_budget_exceeded")
    reach.fallback = True
    return _finish(reach, fw)


def _compute_reach(fw: _Fw, lst: _Lst, addressable: Optional[bool]) -> _Reach:
    """Every edge one host's firewall and listeners allow. See the module docstring for the rules."""
    reach = _Reach()
    if not fw.exact:
        _widen_all(fw, lst, addressable, reach,
                   "firewall_unreadable" if fw.state != "ok" else "firewall_approximate")
        return _finish(reach, fw)
    if lst.v6_needed_when_disabled:
        _widen_all(fw, lst, addressable, reach, "ipv6_claim_contradicted")
        reach.fallback = True
        return _finish(reach, fw)
    fams = [4] + ([6] if fw.ipv6 else [])
    spent = [0]

    def fall_back(why: str) -> _Reach:
        reach.edges.clear()
        _widen_all(fw, lst, addressable, reach, why)
        reach.fallback = True
        return _finish(reach, fw)

    def verdicts(w: _Walker, atoms: list[_Atom], key: tuple, proto: str, port: Optional[int],
                 dst: Optional[int], dtype: Optional[str]) -> Optional[list[str]]:
        v = w.vcache.get(key)
        if v is None:
            if spent[0] + len(atoms) > WALK_BUDGET:
                return None
            spent[0] += len(atoms)
            v = w.vcache[key] = _verdicts(w, atoms, proto, port, dst, dtype)
        return v

    def sources(w: _Walker, fam: int, atoms: list[_Atom], key: tuple, verd: list[str], forced: bool) -> list:
        k = (key, forced, addressable)
        srcs = w.scache.get(k)
        if srcs is None:
            srcs = w.scache[k] = _sources(fam, atoms, verd, True, addressable, forced)
        return srcs

    for fam in fams:
        w = fw.walkers[fam]
        atoms = w.atoms()
        if atoms is None:
            return fall_back("too_many_sources")
        # -- listeners (or every port, when the table is unusable) ---------------------------------- #
        if lst.state == "ok" and lst.complete:
            for L in lst.listeners:
                if fam not in L.fams:
                    continue
                dtype = None if (L.proto == "udp" and L.dst is None) else "local"
                dst = L.dst if w.uses_dst else None
                key = ("L", L.proto, w.port_class(L.port), dst, dtype)
                verd = verdicts(w, atoms, key, L.proto, L.port, dst, dtype)
                if verd is None:
                    return fall_back("walk_budget_exceeded")
                for ref, conf, fl in sources(w, fam, atoms, key, verd, L.forced):
                    reach.add(ref, L.proto, L.port, L.port, conf,
                              fl | ({"container_published"} if L.forced else set()), f"{L.proto}/{L.port}")
        else:
            for proto in ("tcp", "udp"):
                dtype = None if proto == "udp" else "local"
                runs: list[tuple[int, int, tuple]] = []
                for lo, hi in w.port_ranges():
                    key = ("S", proto, lo, dtype)
                    verd = verdicts(w, atoms, key, proto, lo, None, dtype)
                    if verd is None:
                        return fall_back("walk_budget_exceeded")
                    sig = tuple(sources(w, fam, atoms, key, verd, False))
                    if runs and runs[-1][1] + 1 == lo and runs[-1][2] == sig:
                        runs[-1] = (runs[-1][0], hi, sig)
                    else:
                        runs.append((lo, hi, sig))
                for lo, hi, sig in runs:
                    for ref, conf, fl in sig:
                        reach.add(ref, proto, lo, hi, conf, fl | {"listeners_unknown"})
        # -- ICMP, and every other IP protocol: one probe per protocol a rule names plus a protocol number
        #    nothing special-cases (the default-deny / accept-all distinction). Any allowed probe makes an
        #    ``any`` edge (the library's "all traffic" proto, ports 1-65535). ------------------------------ #
        ikey = ("I", "icmp" if fam == 4 else "icmpv6")
        icmp = verdicts(w, atoms, ikey, ikey[1], None, None, "local")
        if icmp is None:
            return fall_back("walk_budget_exceeded")
        for ref, conf, fl in sources(w, fam, atoms, ikey, icmp, False):
            reach.add(ref, "icmp", 0, 0, conf, fl)
        best = ["deny"] * len(atoms)
        for proto in [_OTHER_PROTO] + sorted(w.other_protos):
            v = verdicts(w, atoms, ("O", proto), proto, None, None, "local")
            if v is None:
                return fall_back("walk_budget_exceeded")
            for i, x in enumerate(v):
                if _RANK[x] > _RANK[best[i]]:
                    best[i] = x
        okey = ("A", tuple(sorted(w.other_protos)))
        for ref, conf, fl in sources(w, fam, atoms, okey, best, False):
            reach.add(ref, "any", 1, 65535, conf, fl | {"other_ip_protocols"})
    if fw.truncated():
        return fall_back("walk_step_cap")
    return _finish(reach, fw)


def _finish(reach: _Reach, fw: _Fw) -> _Reach:
    if len(reach.edges) > MAX_EDGES_PER_AGENT:
        reach.edges.clear()
        reach.fallback = True
        tmp = _Fw(ipv6=fw.ipv6, nat_like=True)
        _widen_all(tmp, _Lst(), None, reach, "edge_cap")
    return reach


# --------------------------------------------------------------------------- #
# facts: compact, signed, tier configured
# --------------------------------------------------------------------------- #

# ``daemon`` (the RUNNING sshd) and ``truncated`` (config keys the collector cut) go through UNCHANGED: the library
# accepts a config claim only on the daemon block's positive evidence and reads a cut list as unknown.
_SSHD_KEYS = ("installed", "source", "version", "binary", "socket_activated", "config", "probes", "match",
              "daemon", "truncated")
#: listener rows a fact carries (the rest of a big table is counted, never stored: the library reads
#: ``count != len(listeners)`` as an incomplete table, so no claim of absence can rest on it)
MAX_FACT_LISTENERS = 200


def _clip(value: Any, depth: int = 0) -> Any:
    """A bounded, float-free copy of agent data (the store's caps are 12 levels, 2048 chars, 5000 items)."""
    if depth > 10:
        raise ValueError("too deep")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise ValueError("float")
    if isinstance(value, str):
        return _text(value, 1000) if len(value) > 1000 else re.sub(r"[\x00-\x1f\x7f]", "?", value)
    if isinstance(value, list):
        if len(value) > 4000:
            raise ValueError("too long")
        return [_clip(v, depth + 1) for v in value]
    if isinstance(value, dict):
        if len(value) > 500:
            raise ValueError("too wide")
        return {str(k)[:80]: _clip(v, depth + 1) for k, v in value.items()}
    raise ValueError("type")


def _compact_sshd(v: Mapping[str, Any]) -> dict[str, Any]:
    out = {k: v[k] for k in _SSHD_KEYS if k in v}
    files = v.get("files")
    out["files_count"] = len(files) if isinstance(files, list) else 0
    return _clip(out)


def _compact_firewall(v: Mapping[str, Any]) -> dict[str, Any]:
    fams = {}
    for name, f in (v.get("families") or {}).items():
        if isinstance(f, dict):
            fams[name] = {"read": f.get("read"), "effective_default": f.get("effective_default")}
    flat = v.get("flat_view") if isinstance(v.get("flat_view"), dict) else {}
    out = {
        "v": v.get("v"), "backend": v.get("backend"), "ipv6_enabled": v.get("ipv6_enabled"),
        "families": fams,
        "flat_view": {"default_input_policy": flat.get("default_input_policy"),
                      "confidence": flat.get("confidence")},
        "confidence_reasons": v.get("confidence_reasons") or [],
        "opaque_features": v.get("opaque_features") or [], "dataplane": v.get("dataplane") or [],
        "other_hooks": v.get("other_hooks") or [], "rule_count": v.get("rule_count"),
        "frontends": v.get("frontends") or [],
    }
    return _clip(out)


def _norm_ip(ip: Any) -> Any:
    """The canonical text of an address (a long, odd spelling cannot bloat a fact row); anything that does not
    parse is kept, clipped, so the library still sees what the host said."""
    if not isinstance(ip, str):
        return ip
    try:
        return ipaddress.ip_address(ip.strip()).compressed
    except ValueError:
        return ip[:64]


def _exe_name(exe: Any) -> Any:
    """The executable's BASENAME: all the library reads of it is the name (is it an SSH server?), and the
    directories of a host's binaries are not something a fact needs to carry."""
    return exe.rsplit("/", 1)[-1] if isinstance(exe, str) else exe


def _listener_order(r: Mapping[str, Any]) -> tuple:
    port = r.get("port")
    return (r.get("bind_class") == "loopback", port if _is_int(port) else 1 << 20, str(r.get("proto")),
            str(r.get("ip")))


def _compact_listeners(v: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    for r in v.get("listeners") or []:
        if isinstance(r, dict):
            rows.append({"proto": r.get("proto"), "ip": _norm_ip(r.get("ip")), "port": r.get("port"),
                         "bind_class": r.get("bind_class"), "comm": r.get("comm"), "exe": _exe_name(r.get("exe"))})
    seen = len(rows)
    omitted = max(0, seen - MAX_FACT_LISTENERS)
    if omitted:       # reachable rows first; ``count`` keeps the true total, so the table reads as incomplete
        rows = sorted(rows, key=_listener_order)[:MAX_FACT_LISTENERS]
    reported, dropped = v.get("count"), v.get("dropped")
    count = reported
    cut = (omitted > 0) or (dropped is not None)
    if cut:
        # The library calls a table complete when ``count == len(rows)``. The agent's number is its own word, so when
        # this fact is NOT the whole table (the builder capped it, or the agent cut rows itself) the count can never
        # be below what we know exists: rows seen here plus rows the agent says it dropped. A lying or buggy ``count``
        # equal to the capped length therefore still reads as incomplete (review finding Z-6); the agent's own
        # number stays visible as ``reported_count`` so a consumer can say "N of M".
        if dropped is None or (_is_int(dropped) and dropped >= 0):
            known = seen + (dropped or 0)
        else:
            known = seen + 1       # "I cut rows" in an unusable number: at least one more exists, never complete
        count = max(reported, known) if _is_int(reported) else known
    out = {"count": count, "listeners": rows, "ipv6": v.get("ipv6"),
           "bindv6only": v.get("bindv6only"), "attribution": v.get("attribution")}
    if cut and reported != count:
        out["reported_count"] = reported
    if dropped is not None:      # the agent's own cut: the table is a sample (absent unless > 0)
        out["dropped"] = dropped
    if omitted:
        out["omitted"] = omitted
        out["capped"] = MAX_FACT_LISTENERS
    return _clip(out)


def _compact_patch(v: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in ("os", "manifest", "pending", "auto_update", "kernel", "reboot"):
        b = v.get(name)
        if not isinstance(b, dict):
            continue
        b = dict(b)
        b.pop("packages", None)          # the full package list never goes into a fact
        b.pop("security_pkgs", None)
        b.pop("pkgs", None)
        b.pop("installed", None) if name == "kernel" else None
        out[name] = b
    return _clip(out)


_COMPACT = {"sshd": _compact_sshd, "firewall": _compact_firewall, "listeners": _compact_listeners,
            "patch": _compact_patch}


def _entry(name: str, sec: Any, base: dict[str, Any], conflict: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """One collector's fact entry, or ``None`` if the posture carries no such section."""
    if not isinstance(sec, dict):
        return None
    s = sec.get("s")
    e = dict(base)
    if s == "ok" and isinstance(sec.get("v"), dict):
        try:
            data = _COMPACT[name](sec["v"])
            e.update(status="ok", conf="exact" if sec.get("conf") == "exact" else "approximate",
                     partial=sec.get("partial") is not False, data=data)
        except (ValueError, TypeError, KeyError, AttributeError):
            e.update(status="error", reason="builder_parse", conf="approximate", partial=True, data={})
    elif s == "unavailable":
        e.update(status="unavailable", reason=_text(sec.get("reason"), 60) or "unavailable",
                 conf="approximate", partial=True, data={})
    else:
        e.update(status="error", reason=_text(sec.get("reason"), 60) or "error",
                 conf="approximate", partial=True, data={})
    if conflict:
        e["conflict"] = [dict(c) for c in conflict]
    return e


# --------------------------------------------------------------------------- #
# identity (E3): corroborated cloud instance, else the agent itself
# --------------------------------------------------------------------------- #

@dataclass
class _Ident:
    agent_id: str
    ref: str
    basis: str                       # claimed | corroborated | paired
    note: str
    claimed: list                    # sorted claimed bind addresses (a CLAIM: never a placement)
    node_ips: list                   # addresses the node is KNOWN by: the instance's own when corroborated or paired, else none
    addressable: Optional[bool]
    observed: list = field(default_factory=list)   # the server-observed peer when it is a usable address hint
    conflict: str = ""               # ``paired_peer_mismatch`` when a paired host's direct private peer is not the asset's


def _claimed_ips(identity: Any) -> list[str]:
    return _ipmap.claimed_ips(identity)


DEFAULT_PAIRING_ASSET_MAX_AGE = dt.timedelta(hours=72)     # ``settings.assurance_pairing_asset_max_age_h``


def _pairing_rows(pairings: Iterable[Mapping[str, Any]]) -> tuple[dict[str, _ipmap.PairingRow], set[str]]:
    """``agent id -> its active pairing row`` and the agents with MORE than one (impossible: ``uq_pairing_active_agent``;
    if the table was tampered with those agents are inert, never guessed)."""
    out: dict[str, _ipmap.PairingRow] = {}
    dup: set[str] = set()
    for rec in pairings or ():
        row = _ipmap.pairing_row(rec) if isinstance(rec, Mapping) else None
        if row is None:
            continue
        if row.agent_id in out:
            dup.add(row.agent_id)
        else:
            out[row.agent_id] = row
    return out, dup


def _resolve_identities(agents: list[Mapping[str, Any]], amap: _ipmap.IpMap,
                        pairings: Iterable[Mapping[str, Any]] = (), now: Optional[dt.datetime] = None,
                        pairing_max_age: Optional[dt.timedelta] = None) -> dict[str, _Ident]:
    """Decide every agent's node with the SAME functions the ingest uses (:func:`_ipmap.pairing_decision` first, then
    :func:`_ipmap.corroborate`, review findings hostfw-2, hostfw-5, wire-5): the graph must not depend on a column a
    bug could have set, and the column must not disagree with the graph. A cloud instance absorbs an agent ONLY when
    an admin paired them (docs/ASSURANCE_P2_1.md section 4) or its claimed addresses are a subset of that one
    instance's private addresses, the server saw it connect from one of those private addresses, no other enrolled agent
    presents the same peer address and no other agent that passed the same checks claims the instance (the second path
    is OFF, :data:`_ipmap.PRIVATE_PEER_IS_PROOF`). Two agents on one cloud node merge NEITHER; a claim that never passed
    cannot demote anyone.

    A PAIRED agent is the asset: ``node_ips`` are the ASSET's addresses and never what the host claims (a host cannot
    place itself by lying, review finding hostfw-1). An INERT pairing (the asset is missing, stale or not a VM) falls
    back to ``agent:<uuid>``/``claimed`` with the note ``pairing_inert:<why>``: never silently dropped.

    ``node_ips`` is what the node is KNOWN by. An uncorroborated agent is known by NOTHING (review finding
    hostfw-1): the addresses it claims are the host's own signed words, so they must not decide its zone or
    which CIDR rules include it; the graph loader treats a node without addresses as possibly anywhere (D6).
    They stay visible as ``claimed``. ``observed`` is the server-observed peer address when it is private and
    not shared with another agent: independent of the host's claims, the one hint a zone may rest on."""
    claims = [_ipmap.claim_of(str(a["id"]), a.get("identity")) for a in agents]
    decided = _ipmap.corroborate(claims, amap)
    peers: dict[str, int] = {}
    for c in claims:
        if c.peer:
            peers[c.peer] = peers.get(c.peer, 0) + 1
    prows, dup = _pairing_rows(pairings)
    if prows and now is None:
        raise ValueError("pairings need the build clock")
    max_age = pairing_max_age if isinstance(pairing_max_age, dt.timedelta) and pairing_max_age > dt.timedelta(0) \
        else DEFAULT_PAIRING_ASSET_MAX_AGE
    out: dict[str, _Ident] = {}
    for c in claims:
        aid = c.agent_id
        d = decided[aid]
        row = prows.get(aid)
        if aid in dup:
            d = _ipmap.Decision(None, "pairing_inert:pairing_ambiguous")
        elif row is not None:
            assert now is not None
            d = _ipmap.pairing_decision(c, row, now, max_age, bool(c.peer) and peers.get(c.peer, 0) > 1)
        if d.ref is not None and d.basis == _ipmap.PAIRED:
            assert row is not None
            ips = sorted(row.asset_ips)
            out[aid] = _Ident(aid, d.ref, _ipmap.PAIRED, "", list(c.ips), ips,
                              True if any(_ipmap.is_public_ip(ip) for ip in ips) else None, [], d.conflict)
            continue
        if d.ref is not None:
            ref, basis, note = d.ref, "corroborated", ""
            node_ips = sorted(set(c.ips) | set(amap.ips_of(ref)))
        else:
            ref, basis, note = refs.agent_ref(aid), "claimed", d.note
            node_ips = []
        public = any(_ipmap.is_public_ip(ip) for ip in (set(c.ips) | set(amap.ips_of(ref))
                                                         if basis == "corroborated" else c.ips))
        usable_peer = (basis == "claimed" and c.direct and c.peer is not None and not _ipmap.is_public_ip(c.peer)
                       and peers.get(c.peer, 0) == 1 and ipaddress.ip_address(c.peer).is_private
                       and not ipaddress.ip_address(c.peer).is_loopback)
        out[aid] = _Ident(aid, ref, basis, note, list(c.ips), node_ips, True if public else None,
                          [c.peer] if usable_peer else [])
    return out


# --------------------------------------------------------------------------- #
# conflicts with the external scan
# --------------------------------------------------------------------------- #

def _scan_conflicts(fw: _Fw, lst: _Lst, ident: _Ident, scans: Mapping[str, list[Mapping[str, Any]]],
                    collected_at: dt.datetime, cover: Optional[Mapping[str, list[Mapping[str, Any]]]] = None
                    ) -> list[dict[str, Any]]:
    """See :func:`_scan_conflicts_unbounded`. When the check itself is too expensive to finish, the host
    carries a conflict marker (no coverage, every fact unusable): it cannot be shown NOT to contradict the scan."""
    with _Limited(fw):
        try:
            return _scan_conflicts_unbounded(fw, lst, ident, scans, collected_at, cover or {})
        except _BudgetExceeded:
            return [{"kind": "agent_scan_check_budget_exceeded", "proto": "any", "port": 0,
                     "scan_seen_at": _iso(collected_at)}]


def _scan_conflicts_unbounded(fw: _Fw, lst: _Lst, ident: _Ident,
                              scans: Mapping[str, list[Mapping[str, Any]]],
                              collected_at: dt.datetime,
                              cover: Mapping[str, list[Mapping[str, Any]]]) -> list[dict[str, Any]]:
    """Ports the external scan saw open on this node (an observation still inside the external window) that the
    agent models as closed. Only a host whose firewall and listener table are exact can claim "closed", so only such
    a host can contradict a scan. A conflict is evidence the host's signature carries a falsehood.

    The conflict is STICKY (review finding hostfw-3): while the observation is in the graph, a newer posture that
    repeats "closed" does not clear it (a persistent liar would otherwise read HOLDS between two scans). It is
    cleared only by positive evidence: a later completed FULL scan of this node (it finished after the posture was
    collected) that started after the last observation of the port and so did not see it open again. The scanner is
    TCP only; it never clears a UDP observation."""
    if not fw.exact or not lst.complete:
        return []
    mine = {ident.ref, refs.agent_ref(ident.agent_id)} | {f"ip:{ip}" for ip in (*ident.node_ips, *ident.claimed)}
    last: dict[tuple[str, int], dt.datetime] = {}
    matched = [e for dst in sorted(mine) for e in scans.get(dst, ())]
    for e in matched:
        seen = e.get("last_seen")
        if not isinstance(seen, dt.datetime):
            continue
        seen = _aware(seen)
        proto = e.get("proto")
        lo, hi = e.get("port_lo"), e.get("port_hi")
        if proto not in ("tcp", "udp", "any") or not _is_int(lo) or not _is_int(hi) or lo > hi:
            continue
        protos = ("tcp", "udp") if proto == "any" else (proto,)
        span = range(max(lo, 1), min(hi, 65535) + 1)
        if len(span) > 256:
            span = range(0)          # a scan edge that wide is not a port observation; cannot be judged
        for p in protos:
            for port in span:
                if (p, port) not in last or seen > last[(p, port)]:
                    last[(p, port)] = seen
    later = [c for dst in sorted(mine) for c in cover.get(dst, ())]
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for (p, port) in sorted(last):
        seen = last[(p, port)]
        if p == "tcp" and any(c["finished_at"] > collected_at and c["started_at"] > seen for c in later):
            continue                 # a later full scan did not see it again: positive evidence, the claim stands
        if _agent_closed(fw, lst, p, port):
            out[(p, port)] = {"kind": "agent_closed_scan_open", "proto": p, "port": port,
                              "scan_seen_at": _iso(seen)}
            if len(out) >= MAX_CONFLICTS:
                break
    return [out[k] for k in sorted(out)]


def _agent_closed(fw: _Fw, lst: _Lst, proto: str, port: int) -> bool:
    """Does the (exact) model say NO global address can reach ``proto/port``?"""
    here = [L for L in lst.listeners if L.proto == proto and L.port == port]
    if not here:
        return True                                  # nothing listens (and the table is complete)
    for L in here:
        for fam in L.fams:
            w = fw.walkers.get(fam)
            atoms = w.atoms() if w is not None else None
            if w is None or atoms is None:
                return False
            dtype = None if (proto == "udp" and L.dst is None) else "local"
            for a in atoms:
                if a.klass != "G":
                    continue
                if w.verdict(_pkt(a.rep, proto, port, L.dst if w.uses_dst else None, dtype)) != "deny":
                    return False
    return True


# --------------------------------------------------------------------------- #
# acknowledged scan conflicts (docs/ASSURANCE_P2_1.md 4.6, D30)
# --------------------------------------------------------------------------- #

#: the only conflict an operator can acknowledge; ``agent_scan_check_budget_exceeded`` and ``paired_peer_mismatch`` never.
ACKABLE_KIND = "agent_closed_scan_open"
#: no acknowledgement outlives this, whatever a row says (the API caps it too; this is defence in depth).
MAX_ACK_LIFETIME = dt.timedelta(hours=720)


def _parse_time(v: Any) -> Optional[dt.datetime]:
    if isinstance(v, dt.datetime):
        return _aware(v)
    if isinstance(v, str):
        try:
            return _aware(dt.datetime.fromisoformat(v.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _whole_second(t: dt.datetime) -> dt.datetime:
    return t.replace(microsecond=0)


def _apply_acks(conflicts: list[dict[str, Any]], acks: Iterable[Mapping[str, Any]],
                now: dt.datetime) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``(open, acknowledged)``. A conflict is acknowledged iff an ACTIVE ack of this agent exists with the same kind,
    proto and port, ``expires_at > now`` (and a lifetime of at most 720 h) and the conflict's ``scan_seen_at`` is NOT
    after the ack's ``through_seen_at``: an acknowledgement binds the observation the operator looked at, so a LATER
    observation is not covered and the conflict is re-raised with its new time. Only ``agent_closed_scan_open`` can be
    acknowledged. Times compare at whole seconds (a conflict record prints whole seconds). Anything unreadable is NOT
    an ack. Pure; the newest covering ack (then the lowest id) is the one disclosed."""
    now = _aware(now)
    usable: list[tuple[dt.datetime, str, Mapping[str, Any], dt.datetime]] = []
    for a in acks or ():
        if not isinstance(a, Mapping) or a.get("kind") != ACKABLE_KIND:
            continue
        through, expires, acked_at = _parse_time(a.get("through_seen_at")), _parse_time(a.get("expires_at")), \
            _parse_time(a.get("acked_at"))
        if through is None or expires is None or expires <= now:
            continue
        if acked_at is None or expires - acked_at > MAX_ACK_LIFETIME:
            continue
        usable.append((_whole_second(through), str(a.get("id")), a, expires))
    usable.sort(key=lambda t: (-t[0].timestamp(), t[1]))
    open_: list[dict[str, Any]] = []
    acked: list[dict[str, Any]] = []
    for c in conflicts:
        seen = _parse_time(c.get("scan_seen_at"))
        hit = None
        if c.get("kind") == ACKABLE_KIND and seen is not None:
            for through, _id, a, expires in usable:
                if a.get("proto") == c.get("proto") and a.get("port") == c.get("port") \
                        and _whole_second(seen) <= through:
                    hit = (a, expires)
                    break
        if hit is None:
            open_.append(c)
            continue
        a, expires = hit
        acked.append({"kind": c["kind"], "proto": c["proto"], "port": c["port"], "scan_seen_at": c["scan_seen_at"],
                      "ack_id": str(a.get("id")), "acked_by": _text(a.get("acked_by"), 64), "expires_at": _iso(expires)})
    acked.sort(key=lambda r: (r["proto"], r["port"]))
    return open_, acked


# --------------------------------------------------------------------------- #
# inputs
# --------------------------------------------------------------------------- #

@dataclass
class HostFwRows:
    """Everything ``build`` needs, as plain data (JSON columns decoded, signatures already re-verified).

    ``agents``    live v2 agents: ``id, hostname, status, legacy, revoked_at, last_seen, silent_after_s,
                  node_ref, identity (dict with ips / peer_ip), last_posture_at, agent_version``.
    ``postures``  agent id -> the NEWEST stored posture: ``key_id, seq, collected_at, received_at, signed
                  (the DB flag), key_status, verified (the loader re-checked the signature and the digests),
                  problem, payload_sha256, sections`` (the signed ``sections``, package list stripped).
    ``assets``    identity rows for ``_ipmap`` (cloud resources and devices; agent rows are ignored here).
    ``scan_edges`` ``external_scan`` edges ``internet -> node`` already persisted by external_exposure.
    ``scan_cover`` full-port external scans of a node, completed: ``node_ref, started_at, finished_at`` (the
                  positive evidence that can clear a ``agent_closed_scan_open`` conflict).
    ``pairings``  active operator pairings of an agent with a cloud instance (docs/ASSURANCE_P2_1.md 4.5).
    ``acks``      active acknowledgements of a scan conflict (4.6).
    ``tombstones`` revoked or legacy agents that still have an OPEN invariant finding: ``id, hostname, status,
                  legacy, revoked_at, node_ref``. The host stays in the graph as an UNKNOWN tombstone.
    """
    agents: list[dict[str, Any]] = field(default_factory=list)
    postures: dict[str, dict[str, Any]] = field(default_factory=dict)
    assets: list[dict[str, Any]] = field(default_factory=list)
    scan_edges: list[dict[str, Any]] = field(default_factory=list)
    tombstones: list[dict[str, Any]] = field(default_factory=list)
    scan_cover: list[dict[str, Any]] = field(default_factory=list)
    #: ACTIVE operator pairings joined with their asset (``PAIRINGS_SQL``): ``pairing_id, agent_id, asset_id, a_id, kind,
    #: last_seen, md``. ``a_id`` is None when the asset row is gone (the pairing is then inert).
    pairings: list[dict[str, Any]] = field(default_factory=list)
    #: ACTIVE scan-conflict acknowledgements (``ACKS_SQL``): ``id, agent_id, kind, proto, port, through_seen_at,
    #: expires_at, acked_by, acked_at``.
    acks: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #

@dataclass
class _Out:
    node: Optional[NodeOut] = None
    fact: Optional[FactOut] = None
    edges: list = field(default_factory=list)
    coverage: Optional[CoverageOut] = None
    state: str = ""
    conflicts: int = 0
    blocked: list = field(default_factory=list)


def _clamp_secs(v: Any, lo: int, hi: int, default: int) -> int:
    return v if _is_int(v) and lo <= v <= hi else default


def _posture_problem(p: Mapping[str, Any]) -> str:
    if p.get("signed") is not True:
        return "unsigned"
    if p.get("key_status") != "active":
        return "key_not_active"
    if p.get("verified") is not True:
        return str(p.get("problem") or "unverified")[:40]
    if not isinstance(p.get("sections"), dict):
        return "unreadable"
    return ""


#: Walk results kept ACROSS builds (review finding hostfw-9): hosts with the same firewall and listener table (config
#: management makes that the rule) share one walk, and a rebuild triggered by ANOTHER host's change does not repeat
#: the 4 s walk of a large ruleset. Keyed by the digest of the firewall and listener sections and the
#: address-ability flag, which together fully decide the result; only a COMPLETE walk is kept (a widened
#: fallback depends on the budget left in that build). Bounded, thread-safe, read-only once stored.
_REACH_CACHE: "OrderedDict[str, _Reach]" = OrderedDict()
_REACH_CACHE_MAX = 256
_REACH_LOCK = threading.Lock()


def _reach_key(fw_sec: Any, lst_sec: Any, addressable: Optional[bool]) -> Optional[str]:
    try:
        h = hashlib.sha256()
        for part in (fw_sec, lst_sec):
            h.update(json.dumps(part, sort_keys=True, separators=(",", ":"), default=str).encode())
            h.update(b"\x00")
        h.update(repr(addressable).encode())
        return h.hexdigest()
    except (TypeError, ValueError):
        return None


def _reach_cached(key: Optional[str]) -> Optional["_Reach"]:
    if key is None:
        return None
    with _REACH_LOCK:
        hit = _REACH_CACHE.get(key)
        if hit is not None:
            _REACH_CACHE.move_to_end(key)
        return hit


def _reach_remember(key: Optional[str], reach: "_Reach") -> None:
    if key is None or reach.fallback:
        return
    with _REACH_LOCK:
        _REACH_CACHE[key] = reach
        _REACH_CACHE.move_to_end(key)
        while len(_REACH_CACHE) > _REACH_CACHE_MAX:
            _REACH_CACHE.popitem(last=False)


def _fw_for(sec: Any, cache: dict[str, _Fw]) -> _Fw:
    """The parsed firewall of a section; hosts with an identical section (config management makes that the
    rule) share one parse and its verdict caches."""
    try:
        key = hashlib.sha256(json.dumps(sec, sort_keys=True, separators=(",", ":"),
                                        default=str).encode()).hexdigest()
    except (TypeError, ValueError):
        return _parse_fw(sec)
    fw = cache.get(key)
    if fw is None:
        fw = cache[key] = _parse_fw(sec)
    return fw


def _agent_out(a: Mapping[str, Any], ident: _Ident, p: Optional[Mapping[str, Any]], now: dt.datetime,
               max_age: dt.timedelta, edge_ttl: dt.timedelta,
               scans: Mapping[str, list[Mapping[str, Any]]], fw_cache: dict[str, _Fw],
               budget: Optional[list[int]] = None,
               cover: Optional[Mapping[str, list[Mapping[str, Any]]]] = None,
               acks: Iterable[Mapping[str, Any]] = ()) -> _Out:
    out = _Out()
    aid = ident.agent_id
    hostname = _text(a.get("hostname"), 64) or aid[:8]
    own_ref = refs.agent_ref(aid)
    if ident.ref == own_ref:
        out.node = NodeOut(ref=own_ref, kind="host", label=hostname,
                           attrs=_node_attrs(ident))
    last_seen = a.get("last_seen")
    silent_after = _clamp_secs(a.get("silent_after_s"), 30, 86400, 300)
    silent = (not isinstance(last_seen, dt.datetime) or _aware(last_seen) > now + FUTURE_SKEW
              or (now - _aware(last_seen)).total_seconds() > silent_after)
    row_at = now
    state = "no_posture"
    problem = ""
    observed = now
    posture_ts = None
    if p is not None:
        problem = _posture_problem(p)
        collected, received = p.get("collected_at"), p.get("received_at")
        if not isinstance(collected, dt.datetime) or not isinstance(received, dt.datetime):
            problem = problem or "unreadable"
        else:
            observed = min(_aware(collected), _aware(received), now)
            row_at = observed
            lp = a.get("last_posture_at")
            lp = _aware(lp) if isinstance(lp, dt.datetime) else _aware(received)
            posture_ts = min(max(_aware(received), lp), now)
            stale = (now - observed > max_age or lp > now + FUTURE_SKEW or now - lp > max_age)
            if problem:
                state = "untrusted"
            elif silent:
                state = "silent"
            elif stale:
                state = "stale"
            else:
                state = "fresh"
    out.state = state
    entries: dict[str, dict[str, Any]] = {}
    reason = {"no_posture": "no_posture", "untrusted": "untrusted_posture", "silent": "silent",
              "stale": "stale_posture"}.get(state)
    base_meta = {"signed": False, "key_id": "", "seq": 0, "evidence_ref": ""}

    if state in ("fresh", "silent", "stale") and p is not None and posture_ts is not None \
            and now - posture_ts <= edge_ttl:
        sections = p["sections"]
        fw = _fw_for(sections.get("firewall"), fw_cache)
        lst = _parse_listeners(sections.get("listeners"), fw.ipv6)
        fw.budget = budget
        rkey = _reach_key(sections.get("firewall"), sections.get("listeners"), ident.addressable)
        reach = _reach_cached(rkey)
        if reach is None:
            try:
                reach = compute_reach(fw, lst, ident.addressable)
                _reach_remember(rkey, reach)
            except Exception:  # noqa: BLE001 -- an unforeseen shape widens, never narrows
                logger.exception("host_fw_reach_failed")
                reach = _Reach()
                reach.fallback = True
                _widen_all(_Fw(), _Lst(), ident.addressable, reach, "reach_failed")
        out.edges = _edge_outs(reach, ident, p, observed, fw, lst, state)
        if state == "fresh":
            conflicts, acked = _apply_acks(_scan_conflicts(fw, lst, ident, scans, _aware(p["collected_at"]), cover),
                                           acks, now)
            if ident.conflict == _ipmap.PEER_MISMATCH:
                # the peer address contradicts the pairing: no coverage, every fact in conflict, never acknowledgeable
                conflicts.append({"kind": _ipmap.PEER_MISMATCH, "proto": "any", "port": 0,
                                  "scan_seen_at": _iso(observed)})
            out.conflicts = len(conflicts)
            meta = {"signed": True, "key_id": _text(p.get("key_id"), 64), "seq": p.get("seq") if _is_int(p.get("seq")) else 0,
                    "evidence_ref": f"agent_posture:{aid}:{_text(p.get('key_id'), 64)}:{p.get('seq') if _is_int(p.get('seq')) else 0}"}
            for name in ("sshd", "firewall", "listeners", "patch"):
                e = _entry(name, sections.get(name), meta, conflicts)
                if e is not None:
                    entries[name] = e
            blocked = _coverage_gate(fw, lst, conflicts, reach)
            out.blocked = blocked
            if not blocked:
                out.coverage = CoverageOut(
                    node_ref=ident.ref, direction="in", tier="configured", observed_at=observed, source=SOURCE,
                    detail={"agent": aid, "key_id": _text(p.get("key_id"), 64), "seq": meta["seq"],
                            "listeners": len(lst.listeners), "families": sorted(fw.walkers),
                            **({"acknowledged_conflicts": len(acked)} if acked else {})})
            entries["host_agent"] = _summary_entry(a, ident, p, fw, lst, conflicts, blocked, meta, observed,
                                                   hostname, silent_after, acked)
    if "host_agent" not in entries:
        entries["host_agent"] = dict(base_meta, status="unavailable", reason=reason or "unavailable",
                                     conf="approximate", partial=True,
                                     data={"agent_id": aid, "identity_basis": ident.basis,
                                           **({"identity_note": ident.note} if ident.note else {})})
    out.fact = FactOut(node_ref=ident.ref, source=SOURCE, tier="configured", observed_at=row_at,
                       facts=entries)
    return out


def _node_attrs(ident: _Ident) -> dict[str, Any]:
    """Attributes of an ``agent:<uuid>`` node. ``ips`` stays EMPTY (the loader reads it as "address unknown", so the
    node is inside every CIDR expansion and no zone comes from it); what the host claims is ``claimed_ips`` and the
    server-observed private peer address, when usable, is ``observed_ips``. The loader places a host from the observed
    peer only when the host's claim resolves to the same zone (both are only evidence, review finding Z2-2)."""
    attrs: dict[str, Any] = {"ips": [], "agent_id": ident.agent_id, "identity_basis": ident.basis}
    if ident.claimed:
        attrs["claimed_ips"] = list(ident.claimed)
    if ident.observed:
        attrs["observed_ips"] = list(ident.observed)
    return attrs


def _failed_out(a: Mapping[str, Any], ident: _Ident) -> _Out:
    """What a host we could not process looks like: in scope, with no evidence, no edges, no coverage."""
    out = _Out(state="untrusted")
    own = refs.agent_ref(ident.agent_id)
    if ident.ref == own:
        out.node = NodeOut(ref=own, kind="host", label=_text(a.get("hostname"), 64) or ident.agent_id[:8],
                           attrs=_node_attrs(ident))
    out.fact = FactOut(node_ref=ident.ref, source=SOURCE, tier="configured", observed_at=_EPOCH,
                       facts={"host_agent": {"signed": False, "key_id": "", "seq": 0, "evidence_ref": "",
                                             "status": "unavailable", "reason": "builder_error",
                                             "conf": "approximate", "partial": True, "data": {}}})
    return out


def _coverage_gate(fw: _Fw, lst: _Lst, conflicts: list, reach: _Reach) -> list[str]:
    """Why this host gets NO inbound coverage (empty list = coverage). Signature, key, agent status,
    liveness and posture freshness were settled by the caller: only a ``fresh`` state gets here."""
    why: list[str] = []
    if not fw.exact:
        why.append("firewall_not_exact")
    if not lst.complete:
        why.append("listeners_incomplete")
    if conflicts:
        why.append("conflict")
    if reach.fallback:
        why.append("edge_fallback")
    return why


def _summary_entry(a: Mapping[str, Any], ident: _Ident, p: Mapping[str, Any], fw: _Fw, lst: _Lst,
                   conflicts: list, blocked: list, meta: dict, observed: dt.datetime, hostname: str,
                   silent_after: int, acked: Optional[list] = None) -> dict[str, Any]:
    sections = p["sections"]
    data: dict[str, Any] = {
        "agent_id": ident.agent_id, "hostname": hostname, "identity_basis": ident.basis,
        "key_id": meta["key_id"], "seq": meta["seq"], "payload_sha256": _text(p.get("payload_sha256"), 64),
        "collected_at": _iso(_aware(p["collected_at"])), "silent_after_s": silent_after,
        "firewall": {"engine": fw.engine, "exact": fw.exact, "reasons": sorted(set(fw.reasons))[:8]},
        "listeners": {"count": len(lst.listeners), "complete": lst.complete},
        "coverage": {"granted": not blocked, "blocked_by": sorted(blocked)},
        "conflicts": [dict(c) for c in conflicts],
    }
    if acked:       # disclosed, never silent (D30): P3 must count these like exceptions
        data["conflicts_acknowledged"] = [dict(r) for r in acked]
    if ident.note:
        data["identity_note"] = ident.note
    ver = a.get("agent_version")
    if isinstance(ver, str):
        data["agent_version"] = _text(ver, 32)
    ssh = sections.get("sshd")
    if isinstance(ssh, dict) and ssh.get("s") == "ok" and isinstance(ssh.get("v"), dict):
        cfg = ssh["v"].get("config") if isinstance(ssh["v"].get("config"), dict) else {}
        data["sshd"] = {"source": ssh["v"].get("source") if ssh["v"].get("source") in ("sshd_T", "text") else None,
                        **{k: cfg[k] for k in ("passwordauthentication", "permitrootlogin",
                                               "pubkeyauthentication", "permitemptypasswords", "maxauthtries")
                           if isinstance(cfg.get(k), (str, int)) and not isinstance(cfg.get(k), bool)}}
    patch = sections.get("patch")
    if isinstance(patch, dict) and patch.get("s") == "ok" and isinstance(patch.get("v"), dict):
        pend, reb = patch["v"].get("pending"), patch["v"].get("reboot")
        if isinstance(pend, dict) and pend.get("state") == "ok" and _is_int(pend.get("security")):
            data["pending_security"] = pend["security"]
        if isinstance(reb, dict) and reb.get("state") == "ok" and isinstance(reb.get("required"), bool):
            data["reboot_required"] = reb["required"]
    try:
        data = _clip(data)
    except ValueError:
        data = {"agent_id": ident.agent_id, "identity_basis": ident.basis}
    e = dict(meta)
    e.update(status="ok", conf="exact", partial=False, data=data)
    if conflicts:
        e["conflict"] = [dict(c) for c in conflicts]
    return e


def _edge_outs(reach: _Reach, ident: _Ident, p: Mapping[str, Any], observed: dt.datetime, fw: _Fw,
               lst: _Lst, state: str) -> list[EdgeOut]:
    fwstate = "exact" if fw.exact else ("unreadable" if fw.state != "ok" else "approximate")
    seq = p.get("seq") if _is_int(p.get("seq")) else 0
    out = []
    for (src, proto, lo, hi), e in sorted(reach.edges.items()):
        flags = set(e.flags) | set(reach.flags)
        if state != "fresh":
            flags.add("agent_silent" if state == "silent" else "posture_stale")
        out.append(EdgeOut(
            src_ref=src, dst_ref=ident.ref, proto=proto, port_lo=lo, port_hi=hi,  # type: ignore[arg-type]
            basis="configured", source=SOURCE, last_seen=observed, confidence=e.conf,
            evidence={"origin": SOURCE, "agent": ident.agent_id,
                      "verdict": "allow" if e.conf >= CONF_ALLOW else "maybe",
                      "firewall": fwstate, "listeners": sorted(e.tags)[:8],
                      "assumptions": sorted(flags), "posture_seq": seq,
                      "observed_at": _iso(observed)}))
    return out


def _tombstone_ref(t: Mapping[str, Any]) -> Optional[str]:
    """The node a revoked or legacy agent's open finding is about: the node it last had (``fleet_agents.node_ref``:
    its corroborated cloud instance, else itself)."""
    try:
        own = refs.agent_ref(t["id"])
    except (refs.RefError, KeyError, TypeError):
        return None
    ref = t.get("node_ref")
    if isinstance(ref, str) and ref and ref != refs.INTERNET and refs.is_valid_ref(ref):
        return ref
    return own


def _tombstones(rows: list[dict[str, Any]], facts: dict[str, FactOut], nodes: dict[str, NodeOut],
                notes: list[str]) -> int:
    """A host whose agent is revoked or legacy must not LEAVE the graph while a finding about it is open: a host
    that is in no list reads as "fixed" to a consumer that closes by absence. It stays as a node with one unsigned,
    unavailable ``host_agent`` fact whose ``agent_status`` the library reads as UNKNOWN (``agent_revoked``): nothing
    its old agent signed is relied on, there are no edges and no coverage. A live agent that decides the same node
    (an honest re-enrollment, a corroborated instance) wins: the tombstone is dropped."""
    done = 0
    for t in sorted((r for r in rows if isinstance(r, dict)), key=lambda r: str(r.get("id"))):
        ref = _tombstone_ref(t)
        if ref is None or ref in facts:
            continue
        revoked = t.get("status") == "revoked" or t.get("revoked_at") is not None
        status = "revoked" if revoked else "legacy"
        at = t.get("revoked_at")
        facts[ref] = FactOut(
            node_ref=ref, source=SOURCE, tier="configured", observed_at=_aware(at) if isinstance(at, dt.datetime) else _EPOCH,
            facts={"host_agent": {"signed": False, "key_id": "", "seq": 0, "evidence_ref": "",
                                  "status": "unavailable", "reason": f"agent_{status}", "conf": "approximate",
                                  "partial": True, "data": {"agent_id": str(t["id"]), "agent_status": status}}})
        own = refs.agent_ref(t["id"])
        if ref == own and own not in nodes:
            nodes[own] = NodeOut(ref=own, kind="host", label=_text(t.get("hostname"), 64) or str(t["id"])[:8],
                                 attrs={"ips": [], "agent_id": str(t["id"]), "identity_basis": "claimed"})
        done += 1
    return done


def build(rows: HostFwRows, now: dt.datetime, *, agent_posture_max_age: Optional[dt.timedelta] = None,
          silent_edge_ttl: Optional[dt.timedelta] = None, pairing_asset_max_age: Optional[dt.timedelta] = None,
          **_opts: Any) -> BuildOutput:
    """Pure: nodes, edges, coverage and facts of every live v2 agent. Same inputs, byte-identical output."""
    now = _aware(now)
    max_age = agent_posture_max_age if isinstance(agent_posture_max_age, dt.timedelta) \
        and agent_posture_max_age > dt.timedelta(0) else DEFAULT_POSTURE_MAX_AGE
    ttl = silent_edge_ttl if isinstance(silent_edge_ttl, dt.timedelta) and silent_edge_ttl > dt.timedelta(0) \
        else DEFAULT_SILENT_EDGE_TTL
    counters = {"revoked_or_legacy": 0, "untrusted": 0, "no_posture": 0, "silent": 0, "stale": 0,
                "fresh": 0, "bad_row": 0}
    live: list[Mapping[str, Any]] = []
    for a in rows.agents:
        try:
            refs.agent_ref(a["id"])
        except (refs.RefError, KeyError, TypeError):
            counters["bad_row"] += 1
            continue
        if (a.get("legacy") is not False or a.get("status") == "revoked"
                or a.get("revoked_at") is not None):
            counters["revoked_or_legacy"] += 1          # the loader excludes them; defence in depth
            continue
        live.append(a)
    live.sort(key=lambda a: str(a["id"]))
    amap = _ipmap.build_ip_map([r for r in rows.assets if r.get("kind") != _ipmap.AGENT_KIND])
    idents = _resolve_identities(live, amap, rows.pairings, now, pairing_asset_max_age)
    acks_by_agent: dict[str, list[Mapping[str, Any]]] = {}
    for k in rows.acks:
        if isinstance(k, dict) and k.get("agent_id") is not None:
            acks_by_agent.setdefault(str(k["agent_id"]), []).append(k)
    scans: dict[str, list[Mapping[str, Any]]] = {}
    for e in rows.scan_edges:
        if isinstance(e, dict) and isinstance(e.get("dst_ref"), str):
            scans.setdefault(e["dst_ref"], []).append(e)

    cover: dict[str, list[dict[str, Any]]] = {}
    for c in rows.scan_cover:
        if (isinstance(c, dict) and isinstance(c.get("node_ref"), str) and isinstance(c.get("started_at"), dt.datetime)
                and isinstance(c.get("finished_at"), dt.datetime)):
            cover.setdefault(c["node_ref"], []).append(
                {"started_at": _aware(c["started_at"]), "finished_at": _aware(c["finished_at"])})

    fw_cache: dict[str, _Fw] = {}
    budget = [BUILD_STEP_BUDGET]
    nodes: dict[str, NodeOut] = {}
    edges: list[EdgeOut] = []
    coverage: list[CoverageOut] = []
    facts: dict[str, FactOut] = {}
    conflicts_total = 0
    blocked: dict[str, int] = {}
    notes: list[str] = list(rows.notes)
    clashed = 0
    shared_peer = 0
    paired = inert = 0
    for a in live:
        aid = str(a["id"])
        ident = idents[aid]
        try:
            o = _agent_out(a, ident, rows.postures.get(aid), now, max_age, ttl, scans, fw_cache, budget, cover,
                           acks_by_agent.get(aid, ()))
        except Exception:  # noqa: BLE001 -- one host's surprise must not stop the others; it fails CLOSED
            logger.exception("host_fw_agent_failed", extra={"agent": aid})
            o = _failed_out(a, ident)
            notes.append("host_fw: 1 agent could not be processed and was left without edges, coverage or facts")
        counters[o.state] = counters.get(o.state, 0) + 1
        if ident.note == "ambiguous_cloud_node":
            clashed += 1
        elif ident.note == "shared_peer_address":
            shared_peer += 1
        if ident.basis == _ipmap.PAIRED:
            paired += 1
        elif ident.note.startswith("pairing_inert:"):
            inert += 1
        if o.node is not None:
            nodes[o.node.ref] = o.node
        edges.extend(o.edges)
        if o.coverage is not None:
            coverage.append(o.coverage)
        conflicts_total += o.conflicts
        for b in o.blocked:
            blocked[b] = blocked.get(b, 0) + 1
        assert o.fact is not None
        if o.fact.node_ref in facts:                    # cannot happen after the clash rule; fail closed
            notes.append(f"host_fw: two agents resolved to {o.fact.node_ref}; neither fact row kept")
            facts.pop(o.fact.node_ref)
            coverage = [c for c in coverage if c.node_ref != o.fact.node_ref]
            continue
        facts[o.fact.node_ref] = o.fact
    tombstoned = _tombstones(rows.tombstones, facts, nodes, notes)
    for e in edges:
        if e.src_ref == refs.INTERNET and refs.INTERNET not in nodes:
            nodes[refs.INTERNET] = NodeOut(ref=refs.INTERNET, kind="internet", label="internet")
        if e.src_ref.startswith("cidr:") and e.src_ref not in nodes:
            net = e.src_ref[len("cidr:"):]
            nodes[e.src_ref] = NodeOut(ref=e.src_ref, kind="cidr", label=net, attrs={"cidr": net})
    edges.sort(key=lambda e: (e.dst_ref, e.src_ref, e.proto, e.port_lo, e.port_hi))
    coverage.sort(key=lambda c: c.node_ref)
    notes.append(f"host_fw: {len(live)} live agent(s): " + ", ".join(
        f"{counters[k]} {k}" for k in ("fresh", "silent", "stale", "untrusted", "no_posture")))
    notes.append(f"host_fw: {len(edges)} edge(s), {len(coverage)} host(s) with inbound coverage, "
                 f"{conflicts_total} scan conflict(s)")
    if counters["revoked_or_legacy"]:
        notes.append(f"host_fw: {counters['revoked_or_legacy']} revoked or legacy agent(s) ignored")
    if tombstoned:
        notes.append(f"host_fw: {tombstoned} revoked or legacy agent(s) with an open finding kept as UNKNOWN "
                     f"tombstone(s)")
    if clashed:
        notes.append(f"host_fw: {clashed} agent(s) claim a cloud instance another agent also claims: "
                     f"not merged into it")
    if shared_peer:
        notes.append(f"host_fw: {shared_peer} agent(s) connect from an address another agent also connects from "
                     f"(NAT, proxy or shared egress): not merged into a cloud instance")
    if paired or inert:
        notes.append(f"host_fw: {paired} paired agent(s) (identity from the operator pairing), {inert} inert "
                     f"pairing(s) (the host is judged as agent:<uuid> until the asset is seen again)")
    for k, n in sorted(blocked.items()):
        notes.append(f"host_fw: {n} fresh agent(s) without coverage: {k}")
    notes.extend(f"host_fw: {line}" for line in amap.report())
    return BuildOutput(source=SOURCE, mode="replace", nodes=sorted(nodes.values(), key=lambda n: n.ref),
                       edges=edges, coverage=coverage, notes=notes,
                       facts=sorted(facts.values(), key=lambda f: f.node_ref))


# --------------------------------------------------------------------------- #
# load (SQL; read-only; tenancy from the connection)
# --------------------------------------------------------------------------- #

AGENTS_SQL = """
SELECT id, hostname, status, legacy, revoked_at, last_seen, silent_after_s, node_ref, identity,
       last_posture_at, agent_version
  FROM fleet_agents
 WHERE legacy = FALSE AND status <> 'revoked' AND revoked_at IS NULL
 ORDER BY id
"""

# Revoked or legacy agents that still have an OPEN invariant finding about their node: they stay in the graph
# as UNKNOWN tombstones (a finding never closes because its host left the graph). Without an open finding there
# is nothing to protect and the row is not read (a decommissioned instance must not stay in the graph for ever).
# Scope, decided (review finding hostfw-4, Z-7): a tombstone lives exactly while an OPEN or TRIAGED host-config finding
# names the host; a revoked host with no such finding leaves the graph (one node and one fact per decommissioned
# autoscaling instance would otherwise grow the graph without bound). Dropping the EXISTS clause keeps every revoked or
# legacy agent. A host an operator LABELS out of the selector (declared ``agent=false`` / ``server=false``) is an
# opt-out, not a tombstone: it is simply no longer selected, and its open finding stays open because only
# ``passing_targets`` close a finding. There is NO operator "clear" action in P2 (a route, an RBAC decision and a
# migration, P2.1): the finding is closed by the host passing again, or by an operator setting its status through the
# existing findings route (PATCH /findings/{id}).
TOMBSTONES_SQL = """
SELECT a.id, a.hostname, a.status, a.legacy, a.revoked_at, a.node_ref
  FROM fleet_agents a
 WHERE (a.legacy OR a.status = 'revoked' OR a.revoked_at IS NOT NULL)
   AND EXISTS (SELECT 1 FROM findings f
                WHERE f.rule_source = 'invariant' AND f.status IN ('open', 'triaged')
                  AND f.evidence->'witness'->'detail' ? 'clause'
                  AND f.evidence->>'target_ref' IN ('agent:' || a.id::text, a.node_ref))
 ORDER BY a.id
 LIMIT 5001
"""
MAX_TOMBSTONES = 5000

# Active operator pairings (docs/ASSURANCE_P2_1.md 4.5). The asset is LEFT JOINed so a deleted asset makes the pairing
# inert instead of erasing it; the SELECT list is shared with the ingest (``_ipmap.PAIRING_SELECT_SQL``) so the two
# cannot read different things. No tenant in the SQL: RLS on the connection.
PAIRINGS_SQL = _ipmap.PAIRING_SELECT_SQL + " ORDER BY p.agent_id"
MAX_PAIRINGS = 20000

# Active, unexpired acknowledgements of a scan conflict (4.6). ``acked_at`` lets the builder refuse a lifetime past 720 h.
ACKS_SQL = """
SELECT id, agent_id, kind, proto, port, through_seen_at, expires_at, acked_by, acked_at
  FROM fleet_conflict_acks
 WHERE status = 'active' AND expires_at > $1
 ORDER BY agent_id, proto, port, id
 LIMIT 20001
"""
MAX_ACKS = 20000

# The NEWEST stored posture of each agent with the state of the key that signed it and that key's bytes
# (so the signature can be checked again, here, instead of trusting the ``signed`` column).
POSTURE_SQL = """
SELECT DISTINCT ON (p.agent_id)
       p.agent_id, p.key_id, p.seq, p.collected_at, p.received_at, p.header, p.payload_raw,
       p.payload_sha256, p.signature, p.signed, k.status AS key_status, k.public_key
  FROM agent_posture p
  LEFT JOIN fleet_agent_keys k ON k.agent_id = p.agent_id AND k.key_id = p.key_id
 WHERE p.agent_id = ANY($1::uuid[])
 ORDER BY p.agent_id, p.received_at DESC, p.seq DESC
"""

# What the external scan has seen open, already resolved to nodes by external_exposure.
SCAN_EDGES_SQL = """
SELECT dst_ref, proto, port_lo, port_hi, confidence, last_seen, evidence->>'origin' AS origin
  FROM reach_edges
 WHERE source = 'external_scan' AND src_ref = 'internet' AND basis = 'observed' AND last_seen >= $1
 ORDER BY dst_ref, proto, port_lo, port_hi
"""

# The full-port external scans of a node: external_exposure asserts ``in`` coverage only for a node whose latest
# completed scan PROVED completeness; ``detail.scans`` names the scans. With the scans' start times this is the
# positive evidence that clears a conflict (a full scan that started after the last observation of a port and
# did not see it open again).
SCAN_COVER_SQL = """
SELECT node_ref, detail->'scans' AS scan_ids
  FROM reach_coverage
 WHERE source = 'external_scan' AND direction = 'in'
 ORDER BY node_ref
 LIMIT 20000
"""
SCANS_SQL = "SELECT id, started_at, finished_at FROM scans WHERE id = ANY($1::uuid[])"

_CHUNK = 25
_MAX_PAYLOAD = 4 * 1024 * 1024


def _json(v: Any, default: Any) -> Any:
    if isinstance(v, (str, bytes, bytearray)):
        try:
            return json.loads(v)
        except ValueError:
            return default
    return default if v is None else v


def _no_float(text: str) -> Any:
    raise ValueError("float in a signed payload")


def _verify_stored(row: Mapping[str, Any]) -> tuple[bool, str, Optional[dict[str, Any]]]:
    """Re-check one stored posture end to end: the digests, the header's own claims and the Ed25519
    signature under the agent's key. ``(verified, problem, parsed payload)``; never raises."""
    try:
        raw = bytes(row["payload_raw"] or b"")
        if not row["signed"]:
            return False, "unsigned", None
        if row["key_status"] != "active":
            return False, "key_not_active", None
        if not raw or len(raw) > _MAX_PAYLOAD:
            return False, "payload_size", None
        header = _json(row["header"], None)
        if not isinstance(header, dict):
            return False, "header_unreadable", None
        sha = hashlib.sha256(raw).hexdigest()
        if sha != row["payload_sha256"] or header.get("payload_sha256") != sha \
                or header.get("payload_len") != len(raw):
            return False, "payload_digest_mismatch", None
        if (header.get("agent_id") != str(row["agent_id"]) or header.get("kid") != row["key_id"]
                or header.get("seq") != row["seq"] or header.get("kind") != "posture"):
            return False, "header_mismatch", None
        pub = bytes(row["public_key"] or b"")
        sig = bytes(row["signature"] or b"")
        from ... import fleet_enroll, fleet_posture     # lazy: ``build`` and the types stay import-light
        if not fleet_enroll.verify_ed25519(pub, fleet_posture.signing_input(header), sig):
            return False, "bad_signature", None
        if fleet_enroll.key_id_for(pub) != row["key_id"]:
            return False, "key_id_mismatch", None
        payload = json.loads(raw.decode("utf-8"), parse_float=_no_float)
        if not isinstance(payload, dict) or not isinstance(payload.get("sections"), dict):
            return False, "payload_unreadable", None
        return True, "", payload
    except Exception:  # noqa: BLE001 -- anything unexpected is "not verified"
        logger.warning("host_fw_verify_failed", exc_info=True)
        return False, "verify_error", None


def _strip_heavy(payload: dict[str, Any]) -> dict[str, Any]:
    """The sections only, without the package list (up to hundreds of KB, never used here)."""
    secs = dict(payload.get("sections") or {})
    patch = secs.get("patch")
    if isinstance(patch, dict) and isinstance(patch.get("v"), dict):
        v = dict(patch["v"])
        man = v.get("manifest")
        if isinstance(man, dict):
            v["manifest"] = {k: x for k, x in man.items() if k != "packages"}
        secs["patch"] = {**patch, "v": v}
    return secs


async def _load_scan_cover(conn) -> list[dict[str, Any]]:
    """``[{node_ref, started_at, finished_at}]``: the EARLIEST start and finish over the scans that back each
    node's external coverage; a node with a scan row missing, unfinished or undated is not listed (no evidence)."""
    out: list[dict[str, Any]] = []
    cov = [dict(r) for r in await conn.fetch(SCAN_COVER_SQL)]
    want: set[uuid.UUID] = set()
    parsed: dict[str, list[uuid.UUID]] = {}
    for r in cov:
        ids = _json(r.get("scan_ids"), [])
        good: list[uuid.UUID] = []
        for x in ids if isinstance(ids, list) else []:
            try:
                good.append(uuid.UUID(str(x)))
            except ValueError:
                good = []
                break
        if good:
            parsed[r["node_ref"]] = good
            want.update(good)
    got: dict[uuid.UUID, Mapping[str, Any]] = {}
    ordered = sorted(want)
    for i in range(0, len(ordered), 500):
        for r in await conn.fetch(SCANS_SQL, ordered[i:i + 500]):
            got[r["id"]] = r
    for node, ids in sorted(parsed.items()):
        recs = [got.get(i) for i in ids]
        if any(r is None or not isinstance(r["started_at"], dt.datetime) or not isinstance(r["finished_at"], dt.datetime)
               for r in recs):
            continue
        out.append({"node_ref": node, "started_at": min(_aware(r["started_at"]) for r in recs),   # type: ignore[index]
                    "finished_at": min(_aware(r["finished_at"]) for r in recs)})                  # type: ignore[index]
    return out


def _identity_view(ident: Any) -> dict[str, Any]:
    """What the builder keeps of a stored identity. ``peer_proxied`` is False ONLY when the ingest wrote exactly
    ``false``: a missing or malformed flag (a row written before the flag existed) means the peer may be a forwarding
    hop, which never corroborates and never places a host (review finding Z-3)."""
    ident = ident if isinstance(ident, dict) else {}
    return {"ips": ident.get("ips") if isinstance(ident.get("ips"), list) else [],
            "peer_ip": ident.get("peer_ip") if isinstance(ident.get("peer_ip"), str) else None,
            "peer_proxied": ident.get("peer_proxied") is not False}


async def load(conn, now: dt.datetime, *, agent_posture_max_age: Optional[dt.timedelta] = None,
               **_opts: Any) -> HostFwRows:
    """Read the rows ``build`` needs. ``conn`` is tenant-bound; nothing here names a tenant."""
    now = _aware(now)
    max_age = agent_posture_max_age or DEFAULT_POSTURE_MAX_AGE
    rows = HostFwRows()
    agents = []
    for r in await conn.fetch(AGENTS_SQL):
        d = dict(r)
        d["id"] = str(d["id"])
        d["identity"] = _identity_view(_json(d.get("identity"), {}))
        agents.append(d)
    rows.agents = agents
    ids = [a["id"] for a in agents]
    unverified = 0
    for i in range(0, len(ids), _CHUNK):
        fetched = await conn.fetch(POSTURE_SQL, ids[i:i + _CHUNK])
        # json parsing, sha256 and the Ed25519 check of a (possibly hostile, multi-MiB) posture are CPU work: they
        # run in a worker thread, never on the event loop that also serves the API (review finding hostfw-9)
        checked = await asyncio.to_thread(lambda recs=fetched: [_verify_stored(r) for r in recs])
        for r, (ok, problem, payload) in zip(fetched, checked):
            if not ok:
                unverified += 1
            rows.postures[str(r["agent_id"])] = {
                "key_id": r["key_id"], "seq": r["seq"], "collected_at": r["collected_at"],
                "received_at": r["received_at"], "signed": bool(r["signed"]), "key_status": r["key_status"],
                "verified": ok, "problem": problem, "payload_sha256": r["payload_sha256"],
                "sections": _strip_heavy(payload) if payload is not None else {}}
    if unverified:
        rows.notes.append(f"{unverified} stored posture(s) failed verification and are not evidence")
    tombs = [dict(r) for r in await conn.fetch(TOMBSTONES_SQL)]
    if len(tombs) > MAX_TOMBSTONES:
        rows.notes.append(f"host_fw: more than {MAX_TOMBSTONES} revoked agents with open findings: the rest are not "
                          f"kept as tombstones (their findings still stay open)")
        tombs = tombs[:MAX_TOMBSTONES]
    for d in tombs:
        d["id"] = str(d["id"])
    rows.tombstones = tombs
    rows.assets = [dict(r) for r in await _ipmap.load_ip_rows(conn)]
    # pairings and acknowledgements: a table that cannot be read is NOT "no pairing": the agents then keep their
    # claimed identity (P2 behaviour, which only ever loses coverage) and a failed ack read leaves every conflict open
    try:
        pairs = [dict(r) for r in await conn.fetch(PAIRINGS_SQL)]
        for d in pairs:
            d["pairing_id"] = str(d["pairing_id"])
            d["agent_id"] = str(d["agent_id"])
            d["asset_id"] = str(d["asset_id"])
            d["a_id"] = str(d["a_id"]) if d.get("a_id") is not None else None
            d["md"] = _json(d.get("md"), {})
        rows.pairings = pairs[:MAX_PAIRINGS]
    except Exception:  # noqa: BLE001 -- asyncpg.PostgresError and friends: fail toward claimed identities
        logger.warning("host_fw_pairings_unreadable", exc_info=True)
        rows.notes.append("host_fw: the pairings could not be read: every agent is judged as agent:<uuid>")
    try:
        ack_rows = [dict(r) for r in await conn.fetch(ACKS_SQL, now)]
        for d in ack_rows:
            d["id"] = str(d["id"])
            d["agent_id"] = str(d["agent_id"])
        if len(ack_rows) > MAX_ACKS:
            rows.notes.append("host_fw: more acknowledgements than the builder reads: the rest are ignored")
        rows.acks = ack_rows[:MAX_ACKS]
    except Exception:  # noqa: BLE001
        logger.warning("host_fw_acks_unreadable", exc_info=True)
        rows.notes.append("host_fw: the conflict acknowledgements could not be read: every conflict stays open")
    # an observation counts for the whole EXTERNAL window (``max_age``, 168 h by default), exactly as long as
    # external_exposure keeps the edge in the graph: not for the posture window (review finding hostfw-3)
    ext = _opts.get("max_age")
    ext = ext if isinstance(ext, dt.timedelta) and ext > dt.timedelta(0) else DEFAULT_EXTERNAL_MAX_AGE
    rows.scan_edges = [dict(r) for r in await conn.fetch(SCAN_EDGES_SQL, now - ext)]
    rows.scan_cover = await _load_scan_cover(conn)
    return rows
