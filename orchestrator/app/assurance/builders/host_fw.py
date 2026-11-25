"""``host_fw`` builder: what a managed host's own firewall lets in, from its signed posture.

Source ``host_fw``, mode ``replace``. It turns the latest VERIFIED ``agent_posture`` of every live v2
agent (docs/ASSURANCE_P2.md section 7.1, agent/PAYLOAD.md) into

* **nodes**   ``agent:<uuid>`` (kind ``host``), or the cloud instance ``asset:<uuid>`` when the agent is
              corroborated as that instance. Never ``ip:`` for a managed host.
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

import bisect
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .. import refs
from ..types import BuildOutput, CoverageOut, EdgeOut, FactOut, NodeOut
from . import _ipmap

logger = logging.getLogger(__name__)

SOURCE = "host_fw"

#: how old a posture may be and still count (the runner passes ``agent_posture_max_age``).
DEFAULT_POSTURE_MAX_AGE = dt.timedelta(hours=6)
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
                if isinstance(m[key], str) and m[key]:
                    setattr(self, key, m[key])
                else:
                    self.unknown = True
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
        for key in ("ct", "dtype"):
            if key in m:
                if isinstance(m[key], list) and m[key] and all(isinstance(x, str) for x in m[key]):
                    setattr(self, key, frozenset(m[key]))
                else:
                    self.unknown = True
        if "icmp" in m:
            if isinstance(m["icmp"], list) and m["icmp"] and all(_is_int(x) for x in m["icmp"]):
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
    lst.complete = (sec.get("conf") == "exact" and sec.get("partial") is False and lst.bad_rows == 0
                    and lst.count == len(rows) and len(rows) <= MAX_LISTENERS)
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

_SSHD_KEYS = ("installed", "source", "version", "binary", "socket_activated", "config", "probes", "match")


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


def _compact_listeners(v: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    for r in v.get("listeners") or []:
        if isinstance(r, dict):
            rows.append({"proto": r.get("proto"), "ip": r.get("ip"), "port": r.get("port"),
                         "bind_class": r.get("bind_class"), "comm": r.get("comm")})
    return _clip({"count": v.get("count"), "listeners": rows, "ipv6": v.get("ipv6"),
                  "bindv6only": v.get("bindv6only"), "attribution": v.get("attribution")})


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
    basis: str                       # claimed | corroborated
    note: str
    claimed: list                    # sorted claimed bind addresses
    node_ips: list                   # every address the node is known by
    addressable: Optional[bool]


def _claimed_ips(identity: Any) -> list[str]:
    out: set[str] = set()
    raw = identity.get("ips") if isinstance(identity, dict) else None
    for v in raw if isinstance(raw, list) else []:
        n = _ipmap.norm_ip(v)
        if n is None:
            continue
        ip = ipaddress.ip_address(n)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            continue
        out.add(n)
        if len(out) >= 32:
            break
    return sorted(out)


def _resolve_identities(agents: list[Mapping[str, Any]], amap: _ipmap.IpMap) -> dict[str, _Ident]:
    """Decide every agent's node. A cloud instance absorbs an agent ONLY when all hold: its claimed
    bind addresses are a non-empty subset of that ONE instance's private addresses, the address the
    server saw the agent connect from (``identity.peer_ip``) is one of the instance's addresses, and no
    other live agent claims the instance (by the same candidate or by overlapping claimed addresses).
    Two agents on one cloud node merge NEITHER. This repeats the ingest's rule on purpose: the graph must
    not depend on a column a bug could have set."""
    cand: dict[str, str] = {}
    info: dict[str, dict[str, Any]] = {}
    for a in agents:
        aid = str(a["id"])
        ident = a.get("identity") if isinstance(a.get("identity"), dict) else {}
        claimed = _claimed_ips(ident)
        peer = _ipmap.norm_ip(ident.get("peer_ip")) if isinstance(ident.get("peer_ip"), str) else None
        info[aid] = {"claimed": claimed, "peer": peer, "note": ""}
        if not claimed:
            continue
        owners = {amap.unique.get(ip) for ip in claimed}
        if len(owners) != 1 or None in owners or any(amap.is_ambiguous(ip) for ip in claimed):
            if any(amap.is_ambiguous(ip) or amap.unique.get(ip) for ip in claimed):
                info[aid]["note"] = "ambiguous_cloud_node"
            continue
        ref = next(iter(owners))
        if amap.node_kind(ref) != _INSTANCE_RESOURCE_KIND:
            continue
        priv = {ip for ip in amap.ips_of(ref) if not _ipmap.is_public_ip(ip)}
        if not set(claimed) <= priv:
            continue
        if peer is None or peer not in set(amap.ips_of(ref)):
            info[aid]["note"] = "peer_address_not_instance"
            continue
        cand[aid] = ref
    # clashes: another live agent claims the same instance (same candidate, or overlapping addresses)
    out: dict[str, _Ident] = {}
    for a in agents:
        aid = str(a["id"])
        own = refs.agent_ref(aid)
        ref, basis, note = own, "claimed", info[aid]["note"]
        x = cand.get(aid)
        if x is not None:
            priv = {ip for ip in amap.ips_of(x) if not _ipmap.is_public_ip(ip)}
            clash = any(str(b["id"]) != aid and (cand.get(str(b["id"])) == x
                                                 or set(info[str(b["id"])]["claimed"]) & priv)
                        for b in agents)
            if clash:
                note = "ambiguous_cloud_node"
            else:
                ref, basis, note = x, "corroborated", ""
        node_ips = sorted(set(info[aid]["claimed"]) | (set(amap.ips_of(ref)) if basis == "corroborated" else set()))
        public = any(_ipmap.is_public_ip(ip) for ip in node_ips)
        out[aid] = _Ident(aid, ref, basis, note, info[aid]["claimed"], node_ips, True if public else None)
    return out


# --------------------------------------------------------------------------- #
# conflicts with the external scan
# --------------------------------------------------------------------------- #

def _scan_conflicts(fw: _Fw, lst: _Lst, ident: _Ident, scans: Mapping[str, list[Mapping[str, Any]]],
                    collected_at: dt.datetime) -> list[dict[str, Any]]:
    """See :func:`_scan_conflicts_unbounded`. When the check itself is too expensive to finish, the host
    carries a conflict marker (no coverage, every fact unusable): it cannot be shown NOT to contradict the scan."""
    with _Limited(fw):
        try:
            return _scan_conflicts_unbounded(fw, lst, ident, scans, collected_at)
        except _BudgetExceeded:
            return [{"kind": "agent_scan_check_budget_exceeded", "proto": "any", "port": 0,
                     "scan_seen_at": _iso(collected_at)}]


def _scan_conflicts_unbounded(fw: _Fw, lst: _Lst, ident: _Ident,
                              scans: Mapping[str, list[Mapping[str, Any]]],
                              collected_at: dt.datetime) -> list[dict[str, Any]]:
    """Ports the external scan saw open on this node, newer than the posture, that the agent models as
    closed. Only a host whose firewall and listener table are exact can claim "closed", so only such a
    host can contradict a scan. A conflict is evidence the host's signature carries a falsehood."""
    if not fw.exact or not lst.complete:
        return []
    mine = {ident.ref, refs.agent_ref(ident.agent_id)} | {f"ip:{ip}" for ip in ident.node_ips}
    out: dict[tuple[str, int], dict[str, Any]] = {}
    horizon = collected_at - CONFLICT_SLACK
    matched = [e for dst in sorted(mine) for e in scans.get(dst, ())]
    for e in sorted(matched, key=lambda r: (str(r.get("dst_ref")), str(r.get("proto")), r.get("port_lo") or 0)):
        seen = e.get("last_seen")
        if not isinstance(seen, dt.datetime):
            continue
        seen = _aware(seen)
        if seen <= horizon:
            continue
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
                if _agent_closed(fw, lst, p, port) and (p, port) not in out:
                    out[(p, port)] = {"kind": "agent_closed_scan_open", "proto": p, "port": port,
                                      "scan_seen_at": _iso(seen)}
                    if len(out) >= MAX_CONFLICTS:
                        return [out[k] for k in sorted(out)]
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
    """
    agents: list[dict[str, Any]] = field(default_factory=list)
    postures: dict[str, dict[str, Any]] = field(default_factory=dict)
    assets: list[dict[str, Any]] = field(default_factory=list)
    scan_edges: list[dict[str, Any]] = field(default_factory=list)
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
               budget: Optional[list[int]] = None) -> _Out:
    out = _Out()
    aid = ident.agent_id
    hostname = _text(a.get("hostname"), 64) or aid[:8]
    own_ref = refs.agent_ref(aid)
    if ident.ref == own_ref:
        out.node = NodeOut(ref=own_ref, kind="host", label=hostname,
                           attrs={"ips": ident.node_ips, "agent_id": aid, "identity_basis": ident.basis})
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
        try:
            reach = compute_reach(fw, lst, ident.addressable)
        except Exception:  # noqa: BLE001 -- an unforeseen shape widens, never narrows
            logger.exception("host_fw_reach_failed")
            reach = _Reach()
            reach.fallback = True
            _widen_all(_Fw(), _Lst(), ident.addressable, reach, "reach_failed")
        out.edges = _edge_outs(reach, ident, p, observed, fw, lst, state)
        if state == "fresh":
            conflicts = _scan_conflicts(fw, lst, ident, scans, _aware(p["collected_at"]))
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
                            "listeners": len(lst.listeners), "families": sorted(fw.walkers)})
            entries["host_agent"] = _summary_entry(a, ident, p, fw, lst, conflicts, blocked, meta, observed,
                                                   hostname, silent_after)
    if "host_agent" not in entries:
        entries["host_agent"] = dict(base_meta, status="unavailable", reason=reason or "unavailable",
                                     conf="approximate", partial=True,
                                     data={"agent_id": aid, "identity_basis": ident.basis,
                                           **({"identity_note": ident.note} if ident.note else {})})
    out.fact = FactOut(node_ref=ident.ref, source=SOURCE, tier="configured", observed_at=row_at,
                       facts=entries)
    return out


def _failed_out(a: Mapping[str, Any], ident: _Ident) -> _Out:
    """What a host we could not process looks like: in scope, with no evidence, no edges, no coverage."""
    out = _Out(state="untrusted")
    own = refs.agent_ref(ident.agent_id)
    if ident.ref == own:
        out.node = NodeOut(ref=own, kind="host", label=_text(a.get("hostname"), 64) or ident.agent_id[:8],
                           attrs={"ips": ident.node_ips, "agent_id": ident.agent_id})
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
                   silent_after: int) -> dict[str, Any]:
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


def build(rows: HostFwRows, now: dt.datetime, *, agent_posture_max_age: Optional[dt.timedelta] = None,
          silent_edge_ttl: Optional[dt.timedelta] = None, **_opts: Any) -> BuildOutput:
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
    idents = _resolve_identities(live, amap)
    scans: dict[str, list[Mapping[str, Any]]] = {}
    for e in rows.scan_edges:
        if isinstance(e, dict) and isinstance(e.get("dst_ref"), str):
            scans.setdefault(e["dst_ref"], []).append(e)

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
    for a in live:
        aid = str(a["id"])
        ident = idents[aid]
        try:
            o = _agent_out(a, ident, rows.postures.get(aid), now, max_age, ttl, scans, fw_cache, budget)
        except Exception:  # noqa: BLE001 -- one host's surprise must not stop the others; it fails CLOSED
            logger.exception("host_fw_agent_failed", extra={"agent": aid})
            o = _failed_out(a, ident)
            notes.append("host_fw: 1 agent could not be processed and was left without edges, coverage or facts")
        counters[o.state] = counters.get(o.state, 0) + 1
        if ident.note == "ambiguous_cloud_node":
            clashed += 1
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
    if clashed:
        notes.append(f"host_fw: {clashed} agent(s) claim a cloud instance another agent also claims: "
                     f"not merged into it")
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
        ident = _json(d.get("identity"), {})
        ident = ident if isinstance(ident, dict) else {}
        d["identity"] = {"ips": ident.get("ips") if isinstance(ident.get("ips"), list) else [],
                         "peer_ip": ident.get("peer_ip") if isinstance(ident.get("peer_ip"), str) else None}
        agents.append(d)
    rows.agents = agents
    ids = [a["id"] for a in agents]
    unverified = 0
    for i in range(0, len(ids), _CHUNK):
        for r in await conn.fetch(POSTURE_SQL, ids[i:i + _CHUNK]):
            ok, problem, payload = _verify_stored(r)
            if not ok:
                unverified += 1
            rows.postures[str(r["agent_id"])] = {
                "key_id": r["key_id"], "seq": r["seq"], "collected_at": r["collected_at"],
                "received_at": r["received_at"], "signed": bool(r["signed"]), "key_status": r["key_status"],
                "verified": ok, "problem": problem, "payload_sha256": r["payload_sha256"],
                "sections": _strip_heavy(payload) if payload is not None else {}}
    if unverified:
        rows.notes.append(f"{unverified} stored posture(s) failed verification and are not evidence")
    rows.assets = [dict(r) for r in await _ipmap.load_ip_rows(conn)]
    cutoff = now - max_age - 2 * CONFLICT_SLACK
    rows.scan_edges = [dict(r) for r in await conn.fetch(SCAN_EDGES_SQL, cutoff)]
    return rows
