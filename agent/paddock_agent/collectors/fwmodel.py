"""Canonical host-firewall model and the first-match packet walk (pure, stdlib only).

This module has no imports from the rest of the agent so the server-side ``host_fw``
builder can reuse it (``paddock_agent.collectors.fwmodel``). Python 3.8 syntax only.

Soundness stance (the product claims "no counterexample under this evidence"):

* The walk over-approximates acceptance. An unknown condition (an unmodelled matcher) is
  explored both ways, an unknown action may accept, drop or fall through, and an
  unresolved jump may do anything. A packet is reported ``deny`` only when *every*
  explored path drops it.
* ``effective_default`` answers "what happens to a packet that no conditional rule
  mentions". It is ``drop``/``reject`` only when (a) some input base chain reaches an
  unconditional drop/reject (or a drop policy) without an earlier unconditional accept,
  (b) at least one packet really falls through every conditional rule of that chain (the
  conditions do not cover the whole packet space), and (c) the chain's accept rules do not
  cover all new inbound TCP/UDP. Anything uncertain is ``unknown``, never ``drop``.
* ``confidence`` is ``exact`` only when nothing the walk relied on is opaque in a way that
  could accept, there is no NAT rewriting, nothing is unreadable and the dataplane is
  plain netfilter. Consumers must gate every HOLDS on ``confidence == "exact"``.

Canonical model::

    {"v": 1, "backend": "nft|legacy|mixed|none", "frontends": [...], "ipv6_enabled": bool,
     "families": {"ip4": F, "ip6": F}, "flat_view": {...}, "opaque_features": [...],
     "dataplane": [...], "other_hooks": [...], "rule_count": int}
    F = {"read": bool, "effective_default": "accept|drop|reject|unknown",
         "chains": [{"name", "hook", "prio", "policy", "base", "rules": [R]}]}
    R = {"m": M, "v": "accept|drop|reject|return|jump:<chain>|goto:<chain>|opaque",
         "opaque_reason"?: str}
    M = any of {iif, oif, src[], dst[], proto, sport[[lo,hi]], dport[[lo,hi]], ct[], icmp[],
        dtype[]}; an absent key means "no restriction"; ``m == {}`` is an unconditional rule.

``opaque_reason`` on a rule means: the rule has an unmodelled extra condition (it *may*
match packets inside ``m``). ``v == "opaque"`` means the action itself is unknown.
"""
import functools
import ipaddress
import re
import shlex

MODEL_V = 1
MAX_RULES = 2000
MAX_DEPTH = 8
MAX_EXPAND = 8
MAX_SET_ELEMS = 512
MAX_FLAT_RULES = 200
COVER_BUDGET = 60000
IIF_EXTERNAL = "<external>"
CT_STATES = ("established", "invalid", "new", "related", "untracked")
PORT_PROTOS = ("dccp", "sctp", "tcp", "udp", "udplite")
DTYPES = ("anycast", "broadcast", "local", "multicast", "unicast")
V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1
# Packets that can really reach an INPUT chain: unicast sources (not 0/8, multicast or
# reserved) and valid ports. The residual analysis only counts packets from this universe.
SRC_UNIVERSE = {4: (1 << 24, (224 << 24) - 1), 6: (1, (0xFF00 << 112) - 1)}
MULTICAST_RANGES = {4: (224 << 24, V4_MAX), 6: (0xFF00 << 112, V6_MAX)}

_PROTO_NAMES = {
    "icmp": "icmp", "1": "icmp", "tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp",
    "ipv6-icmp": "icmpv6", "icmpv6": "icmpv6", "58": "icmpv6", "sctp": "sctp", "132": "sctp",
    "dccp": "dccp", "33": "dccp", "udplite": "udplite", "136": "udplite", "gre": "gre",
    "47": "gre", "esp": "esp", "50": "esp", "ah": "ah", "51": "ah", "igmp": "igmp", "2": "igmp",
    "ipip": "ipip", "4": "ipip", "ipv6": "ipv6", "41": "ipv6",
}
_ICMP4 = {
    "echo-reply": 0, "destination-unreachable": 3, "source-quench": 4, "redirect": 5,
    "echo-request": 8, "ping": 8, "router-advertisement": 9, "router-solicitation": 10,
    "time-exceeded": 11, "parameter-problem": 12, "timestamp-request": 13,
    "timestamp-reply": 14, "info-request": 15, "info-reply": 16,
    "address-mask-request": 17, "address-mask-reply": 18,
}
_ICMP6 = {
    "destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3,
    "parameter-problem": 4, "echo-request": 128, "echo-reply": 129,
    "mld-listener-query": 130, "mld-listener-report": 131, "mld-listener-done": 132,
    "nd-router-solicit": 133, "nd-router-advert": 134, "nd-neighbor-solicit": 135,
    "nd-neighbor-advert": 136, "nd-redirect": 137, "mld2-listener-report": 143,
    "router-solicitation": 133, "router-advertisement": 134,
    "neighbour-solicitation": 135, "neighbour-advertisement": 136, "neighbor-solicitation": 135,
    "neighbor-advertisement": 136,
}
_PORT_NAMES = {"ssh": 22, "http": 80, "https": 443, "domain": 53, "smtp": 25, "ftp": 21,
               "telnet": 23, "ntp": 123, "imap": 143, "imaps": 993, "pop3": 110, "pop3s": 995,
               "mysql": 3306, "postgresql": 5432}
# statements that never change the verdict flow
_NOOP_STMTS = frozenset(["counter", "log", "mangle", "set", "comment", "nftrace", "meter",
                         "snat", "masquerade", "xt-noop", "reset"])
_NOOP_IPT_TARGETS = frozenset([
    "LOG", "ULOG", "NFLOG", "AUDIT", "MARK", "CONNMARK", "DSCP", "TOS", "TTL", "HL",
    "TCPMSS", "ECN", "CLASSIFY", "SECMARK", "CONNSECMARK", "TRACE", "MASQUERADE", "SNAT",
    "SAME", "NETMAP-NOOP", "TCPOPTSTRIP", "IDLETIMER", "LED", "RATEEST",
])
_NAT_REWRITE_TARGETS = frozenset(["DNAT", "REDIRECT", "TPROXY", "NETMAP"])
_DATAPLANE_PREFIXES = (("KUBE-", "k8s"), ("CILIUM_", "cilium"), ("cali-", "calico"),
                       ("FLANNEL", "flannel"), ("WEAVE", "weave"), ("CNI-", "cni"))
_BASIC_IPT_OPTS = frozenset(["-s", "--source", "--src", "-d", "--destination", "--dst",
                             "-i", "--in-interface", "-o", "--out-interface", "-p",
                             "--protocol", "-m", "--match", "-j", "--jump", "-g", "--goto",
                             "-f", "--fragment", "-c", "-A"])


class FwModelError(Exception):
    """Raised for structurally invalid input (the collector maps it to parse_error)."""


class FwTooLarge(Exception):
    """Raised when the modelled rule count exceeds ``MAX_RULES``."""


# --------------------------------------------------------------------- intervals
def _norm_iv(ivs):
    out = []
    for lo, hi in sorted(ivs):
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def _inter_iv(a, b):
    out = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def _compl_iv(a, top):
    out = []
    cur = 0
    for lo, hi in _norm_iv(a):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = hi + 1
    if cur <= top:
        out.append((cur, top))
    return out


def _in_iv(ivs, x):
    for lo, hi in ivs:
        if lo <= x <= hi:
            return True
    return False


@functools.lru_cache(maxsize=8192)
def _ip_int(text):
    try:
        return int(ipaddress.ip_address(text))
    except ValueError:
        return None


def _cidr_iv(text):
    net = ipaddress.ip_network(text, strict=False)
    return net.version, int(net.network_address), int(net.broadcast_address)


def _ivs_to_cidrs(ivs, fam):
    out = []
    mk = ipaddress.IPv4Address if fam == 4 else ipaddress.IPv6Address
    for lo, hi in ivs:
        for net in ipaddress.summarize_address_range(mk(lo), mk(hi)):
            out.append(str(net))
    return out


_CIDR_CACHE = {}


def _cidr_ivs(cidrs):
    key = tuple(cidrs)
    hit = _CIDR_CACHE.get(key)
    if hit is None:
        ivs = []
        for c in cidrs:
            _fam, lo, hi = _cidr_iv(c)
            ivs.append((lo, hi))
        hit = _norm_iv(ivs)
        if len(_CIDR_CACHE) > 4096:
            _CIDR_CACHE.clear()
        _CIDR_CACHE[key] = hit
    return hit


# ------------------------------------------------------------------ rule builder
class _Never(Exception):
    """The rule can never match (dropped from the model, which is exact)."""


class _RuleB(object):
    def __init__(self, fam=None):
        self.fam = fam
        self.src = None
        self.dst = None
        self.proto = None
        self.sport = None
        self.dport = None
        self.ct = None
        self.iif = None
        self.oif = None
        self.icmp = None
        self.dtype = None
        self.opaque = []

    def restrict_fam(self, fam):
        if self.fam is None:
            self.fam = fam
        elif self.fam != fam:
            raise _Never()

    def note(self, reason):
        if reason not in self.opaque:
            self.opaque.append(reason)

    def add_ivs(self, attr, ivs):
        cur = getattr(self, attr)
        new = _norm_iv(ivs) if cur is None else _inter_iv(cur, _norm_iv(ivs))
        if not new:
            raise _Never()
        setattr(self, attr, new)

    def add_set(self, attr, vals):
        cur = getattr(self, attr)
        new = frozenset(vals) if cur is None else cur & frozenset(vals)
        if not new:
            raise _Never()
        setattr(self, attr, new)

    def add_addr(self, attr, fam, ivs):
        self.restrict_fam(fam)
        self.add_ivs(attr, ivs)

    def finish(self):
        """Apply implicit constraints; return a list of canonical rule match dicts (expanded)."""
        if (self.sport is not None or self.dport is not None):
            allowed = frozenset(PORT_PROTOS)
            self.add_set("proto", allowed if self.proto is None else self.proto & allowed)
        if self.icmp is not None:
            if self.fam is None:
                raise FwModelError("icmp type without family")
            self.add_set("proto", ["icmp" if self.fam == 4 else "icmpv6"])
        if self.proto is not None:
            if self.proto == frozenset(["icmp"]):
                self.restrict_fam(4)
            elif self.proto == frozenset(["icmpv6"]):
                self.restrict_fam(6)
        top = V4_MAX if self.fam == 4 else V6_MAX
        for attr in ("src", "dst"):
            ivs = getattr(self, attr)
            if ivs is not None and ivs == [(0, top)]:
                setattr(self, attr, None)
        if self.ct is not None and self.ct == frozenset(CT_STATES):
            self.ct = None
        if self.dtype is not None and self.dtype == frozenset(DTYPES):
            self.dtype = None
        base = {}
        if self.src is not None:
            base["src"] = _ivs_to_cidrs(self.src, self.fam)
        if self.dst is not None:
            base["dst"] = _ivs_to_cidrs(self.dst, self.fam)
        if self.sport is not None:
            base["sport"] = [[lo, hi] for lo, hi in self.sport]
        if self.dport is not None:
            base["dport"] = [[lo, hi] for lo, hi in self.dport]
        if self.ct is not None:
            base["ct"] = sorted(self.ct)
        if self.icmp is not None:
            base["icmp"] = sorted(self.icmp)
        if self.dtype is not None:
            base["dtype"] = sorted(self.dtype)
        combos = [dict(base)]
        for attr, key in (("proto", "proto"), ("iif", "iif"), ("oif", "oif")):
            vals = getattr(self, attr)
            if vals is None:
                continue
            names = sorted(vals)
            if len(combos) * len(names) > MAX_EXPAND:
                self.note("big_" + key + "_set")
                continue
            combos = [dict(c, **{key: n}) for c in combos for n in names]
        return combos


# -------------------------------------------------------------- shared helpers
def _proto_token(tok):
    tok = str(tok).strip().lower()
    if tok in _PROTO_NAMES:
        return _PROTO_NAMES[tok]
    if tok.isdigit():
        return "p" + tok
    if re.match(r"^[a-z][a-z0-9-]{0,15}$", tok):
        return tok
    return None


def _port_value(tok):
    if isinstance(tok, bool):
        return None
    if isinstance(tok, int):
        return tok if 0 <= tok <= 65535 else None
    s = str(tok).strip().lower()
    if s.isdigit():
        n = int(s)
        return n if 0 <= n <= 65535 else None
    return _PORT_NAMES.get(s)


def _dataplane_of(name):
    for prefix, label in _DATAPLANE_PREFIXES:
        if name.startswith(prefix):
            return label
    return None


def _cond_opaque(rule):
    """True when the rule has an unmodelled *condition* (action-only opacity is ``act:``)."""
    reason = rule.get("opaque_reason")
    if not reason:
        return False
    return any(not part.startswith("act:") for part in reason.split(","))


def new_dump():
    return {"chains": {}, "nat_rewrite": False, "dataplane": set(), "features": set(),
            "other_hooks": set(), "problems": []}


def merge_dumps(dumps):
    out = new_dump()
    for d in dumps:
        for k, c in d["chains"].items():
            if k in out["chains"]:
                raise FwModelError("duplicate chain " + k)
            out["chains"][k] = c
        out["nat_rewrite"] = out["nat_rewrite"] or d["nat_rewrite"]
        for key in ("dataplane", "features", "other_hooks"):
            out[key] |= d[key]
        out["problems"].extend(d["problems"])
    return out


def _ckey(prefix, table, name):
    return "%s.%s.%s" % (prefix, table, name)


def _add_chain(dump, key, fams, hook, prio, policy, base):
    dump["chains"][key] = {"name": key, "fams": tuple(fams), "hook": hook, "prio": prio,
                           "policy": policy, "base": base, "rules": []}


# ======================================================================= nftables
def _nft_values(right, sets, tkey, out_kind):
    """Flatten an nft JSON right-hand side into ``[(kind, payload)]`` atoms.

    kinds: ``scalar`` (str/int), ``prefix`` (cidr str), ``range`` (lo, hi). Raises
    ``_OpaqueValue`` for dynamic/unresolvable sets.
    """
    atoms = []

    def walk(x, depth):
        if depth > 4:
            raise _OpaqueValue("nested_set")
        if isinstance(x, dict):
            if "prefix" in x:
                p = x["prefix"]
                atoms.append(("prefix", "%s/%s" % (p["addr"], p["len"])))
            elif "range" in x:
                lo, hi = x["range"]
                atoms.append(("range", (lo, hi)))
            elif "set" in x:
                for e in x["set"]:
                    walk(e, depth + 1)
            elif "elem" in x:
                el = x["elem"]
                if isinstance(el, dict) and any(k in el for k in ("timeout", "expires")):
                    raise _OpaqueValue("dynamic_set")
                walk(el.get("val") if isinstance(el, dict) else el, depth + 1)
            elif "concat" in x:
                raise _OpaqueValue("concat")
            else:
                raise _OpaqueValue("value_form")
        elif isinstance(x, list):
            for e in x:
                walk(e, depth + 1)
        elif isinstance(x, str) and x.startswith("@"):
            st = sets.get((tkey, x[1:]))
            if st is None:
                raise _OpaqueValue("unresolved_set")
            flags = st.get("flags") or []
            if "dynamic" in flags or "timeout" in flags or "timeout" in st or "map" in st:
                raise _OpaqueValue("dynamic_set")
            if isinstance(st.get("type"), list):
                raise _OpaqueValue("concat")
            for e in st.get("elem") or []:
                walk(e, depth + 1)
        elif isinstance(x, bool) or x is None:
            raise _OpaqueValue("value_form")
        else:
            atoms.append(("scalar", x))

    walk(right, 0)
    if len(atoms) > MAX_SET_ELEMS:
        raise _OpaqueValue("big_set")
    return atoms


class _OpaqueValue(Exception):
    pass


def _addr_ivs_from_atoms(atoms, fam):
    ivs = []
    for kind, p in atoms:
        if kind == "scalar":
            ip = ipaddress.ip_address(str(p))
            if ip.version != fam:
                raise _Never()
            ivs.append((int(ip), int(ip)))
        elif kind == "prefix":
            f, lo, hi = _cidr_iv(p)
            if f != fam:
                raise _Never()
            ivs.append((lo, hi))
        else:
            a, b = ipaddress.ip_address(str(p[0])), ipaddress.ip_address(str(p[1]))
            if a.version != fam or b.version != fam:
                raise _Never()
            ivs.append((int(a), int(b)))
    return ivs


def _port_ivs_from_atoms(atoms):
    ivs = []
    for kind, p in atoms:
        if kind == "scalar":
            n = _port_value(p)
            if n is None:
                raise _OpaqueValue("port_name")
            ivs.append((n, n))
        elif kind == "range":
            lo, hi = _port_value(p[0]), _port_value(p[1])
            if lo is None or hi is None:
                raise _OpaqueValue("port_name")
            ivs.append((lo, hi))
        else:
            raise _OpaqueValue("port_form")
    return ivs


def _nft_apply_match(b, mt, sets, tkey):
    op = mt.get("op", "==")
    left = mt.get("left")
    right = mt.get("right")
    if not isinstance(left, dict) or len(left) != 1:
        b.note("left_form")
        return
    (lk, lv), = left.items()
    positive = op in ("==", "in")
    negative = op == "!="
    ranged = op in ("<", "<=", ">", ">=")
    try:
        if lk == "meta":
            _nft_meta(b, lv.get("key"), op, right, sets, tkey, positive, negative)
        elif lk == "ct":
            _nft_ct(b, lv.get("key"), right, sets, tkey, positive, negative)
        elif lk == "payload":
            _nft_payload(b, lv, op, right, sets, tkey, positive, negative, ranged)
        else:
            b.note("match_" + clean_reason(lk))
    except _OpaqueValue as exc:
        b.note(str(exc))


def clean_reason(s):
    return re.sub(r"[^a-z0-9_]", "_", str(s).lower())[:24]


def _nft_meta(b, key, op, right, sets, tkey, positive, negative):
    if key in ("iif", "iifname", "oif", "oifname"):
        attr = "iif" if key.startswith("iif") else "oif"
        if not positive:
            b.note("negated_" + attr)
            return
        atoms = _nft_values(right, sets, tkey, "name")
        names = []
        for kind, p in atoms:
            if kind != "scalar" or not isinstance(p, str) or "*" in p:
                raise _OpaqueValue(attr + "_pattern")
            names.append(p)
        if not names:
            raise _Never()
        b.add_set(attr, names)
    elif key == "nfproto":
        atoms = _nft_values(right, sets, tkey, "name")
        fams = set()
        for kind, p in atoms:
            if str(p).lower() in ("ipv4", "2"):
                fams.add(4)
            elif str(p).lower() in ("ipv6", "10"):
                fams.add(6)
            else:
                raise _OpaqueValue("nfproto")
        if negative:
            fams = set([4, 6]) - fams
        if not fams:
            raise _Never()
        if len(fams) == 1:
            b.restrict_fam(fams.pop())
    elif key == "l4proto":
        if not positive:
            b.note("negated_proto")
            return
        atoms = _nft_values(right, sets, tkey, "name")
        names = []
        for kind, p in atoms:
            n = _proto_token(p)
            if kind != "scalar" or n is None:
                raise _OpaqueValue("proto_form")
            names.append(n)
        b.add_set("proto", names)
    elif key == "protocol":
        atoms = _nft_values(right, sets, tkey, "name")
        fams = set()
        for kind, p in atoms:
            if str(p).lower() in ("ip", "0x800", "2048"):
                fams.add(4)
            elif str(p).lower() in ("ip6", "0x86dd", "34525"):
                fams.add(6)
            else:
                raise _OpaqueValue("ethertype")
        if negative:
            raise _OpaqueValue("ethertype")
        if len(fams) == 1:
            b.restrict_fam(fams.pop())
    else:
        b.note("meta_" + clean_reason(key))


def _nft_ct(b, key, right, sets, tkey, positive, negative):
    if key == "state":
        atoms = _nft_values(right, sets, tkey, "name")
        states = set()
        for kind, p in atoms:
            s = str(p).lower()
            if kind != "scalar" or s not in CT_STATES:
                raise _OpaqueValue("ct_state_value")
            states.add(s)
        if negative:
            states = set(CT_STATES) - states
        elif not positive:
            raise _OpaqueValue("ct_state_op")
        if not states:
            raise _Never()
        b.add_set("ct", states)
    elif key == "status":
        atoms = _nft_values(right, sets, tkey, "name")
        if positive and all(kind == "scalar" and str(p).lower() == "dnat" for kind, p in atoms):
            b.note("ct_status_dnat")
        else:
            b.note("ct_status")
    else:
        b.note("ct_" + clean_reason(key))


_ADDR_FIELDS = {"saddr": "src", "daddr": "dst"}


def _nft_payload(b, pl, op, right, sets, tkey, positive, negative, ranged):
    proto = pl.get("protocol")
    field = pl.get("field")
    if proto in ("ip", "ip6") and field in _ADDR_FIELDS:
        fam = 4 if proto == "ip" else 6
        top = V4_MAX if fam == 4 else V6_MAX
        attr = _ADDR_FIELDS[field]
        if not (positive or negative):
            b.note("addr_op")
            return
        ivs = _addr_ivs_from_atoms(_nft_values(right, sets, tkey, "addr"), fam)
        ivs = _norm_iv(ivs)
        if negative:
            ivs = _compl_iv(ivs, top)
        if not ivs:
            raise _Never()
        b.add_addr(attr, fam, ivs)
    elif (proto, field) in (("ip", "protocol"), ("ip6", "nexthdr")):
        b.restrict_fam(4 if proto == "ip" else 6)
        if not positive:
            b.note("negated_proto")
            return
        names = []
        for kind, p in _nft_values(right, sets, tkey, "name"):
            n = _proto_token(p)
            if kind != "scalar" or n is None:
                raise _OpaqueValue("proto_form")
            names.append(n)
        b.add_set("proto", names)
    elif proto in PORT_PROTOS + ("th",) and field in ("sport", "dport"):
        if proto != "th":
            b.add_set("proto", [proto])
        attr = field
        if ranged:
            n = _port_value(right)
            if n is None:
                raise _OpaqueValue("port_form")
            ivs = {"<": [(0, n - 1)] if n > 0 else [], "<=": [(0, n)],
                   ">": [(n + 1, 65535)] if n < 65535 else [], ">=": [(n, 65535)]}[op]
        elif positive or negative:
            ivs = _norm_iv(_port_ivs_from_atoms(_nft_values(right, sets, tkey, "port")))
            if negative:
                ivs = _compl_iv(ivs, 65535)
        else:
            b.note("port_op")
            return
        if not ivs:
            raise _Never()
        b.add_ivs(attr, ivs)
    elif proto in ("icmp", "icmpv6") and field == "type":
        fam = 4 if proto == "icmp" else 6
        b.restrict_fam(fam)
        b.add_set("proto", [proto])
        table = _ICMP4 if fam == 4 else _ICMP6
        if not (positive or negative):
            b.note("icmp_op")
            return
        types = set()
        for kind, p in _nft_values(right, sets, tkey, "name"):
            if isinstance(p, int) and not isinstance(p, bool):
                types.add(p)
            elif str(p).lower() in table:
                types.add(table[str(p).lower()])
            else:
                raise _OpaqueValue("icmp_type_name")
        if negative:
            types = set(range(256)) - types
        if not types:
            raise _Never()
        b.add_set("icmp", types)
    else:
        if proto in PORT_PROTOS + ("icmp", "icmpv6"):
            b.add_set("proto", [proto])
        elif proto in ("ip", "ip6"):
            b.restrict_fam(4 if proto == "ip" else 6)
        b.note("payload_%s_%s" % (clean_reason(proto), clean_reason(field)))


def _nft_rule(expr, sets, tkey, prefix_table, rule_fam):
    """Parse one nft rule into ``(list of rule dicts, saw_nat_rewrite, features)``."""
    b = _RuleB(rule_fam)
    verdict = None
    action_opaque = None
    nat = False
    features = set()
    try:
        for e in expr:
            if not isinstance(e, dict) or len(e) != 1:
                b.note("expr_form")
                action_opaque = action_opaque or "act:expr_form"
                continue
            (k, val), = e.items()
            if k == "match":
                _nft_apply_match(b, val, sets, tkey)
            elif k in ("accept", "drop", "return"):
                verdict = k
            elif k == "reject":
                verdict = "reject"
            elif k in ("jump", "goto"):
                verdict = "%s:%s.%s" % (k, prefix_table, val.get("target"))
            elif k in _NOOP_STMTS:
                continue
            elif k in ("limit", "quota"):
                b.note(k)
            elif k in ("dnat", "redirect", "tproxy"):
                nat = True
                action_opaque = "act:" + k
            elif k == "notrack":
                features.add("notrack")
                action_opaque = "act:" + k
            elif k == "xt":
                name = str((val or {}).get("name", "")).upper()
                typ = (val or {}).get("type")
                if typ == "target" and name in _NOOP_IPT_TARGETS:
                    continue
                if typ == "target" and name in _NAT_REWRITE_TARGETS:
                    nat = True
                if typ == "target":
                    action_opaque = "act:xt_" + clean_reason(name)
                else:
                    b.note("xt_" + clean_reason(name))
            else:
                action_opaque = action_opaque or ("act:stmt_" + clean_reason(k))
        if verdict is None and action_opaque is None:
            return [], nat, features
        rule_combos = b.finish()
    except _Never:
        return [], nat, features
    out = []
    for m in rule_combos:
        r = {"m": m, "v": verdict if verdict is not None else "opaque"}
        reasons = list(b.opaque)
        if verdict is None:
            reasons.append(action_opaque)
        elif action_opaque is not None:
            reasons.append(action_opaque)
        if reasons:
            r["opaque_reason"] = ",".join(reasons[:3])
        if b.fam is not None:
            r["f"] = b.fam
        out.append(r)
    return out, nat, features


def normalise_nft(obj):
    """Normalise the parsed JSON of ``nft -j list ruleset`` into a chain dump."""
    if not isinstance(obj, dict) or not isinstance(obj.get("nftables"), list):
        raise FwModelError("not an nft json document")
    dump = new_dump()
    tables = {}
    sets = {}
    chains = []
    rules = []
    for ent in obj["nftables"]:
        if not isinstance(ent, dict) or len(ent) != 1:
            continue
        (k, v), = ent.items()
        if k == "table":
            tables[(v["family"], v["name"])] = v
        elif k in ("set", "map"):
            sets[((v["family"], v["table"]), v["name"])] = dict(v, **({"map": True} if k == "map" else {}))
        elif k == "chain":
            chains.append(v)
        elif k == "rule":
            rules.append(v)
    fam_map = {"inet": (4, 6), "ip": (4,), "ip6": (6,)}
    for c in chains:
        fam = c.get("family")
        label = _dataplane_of(str(c.get("name", "")))
        if label:
            dump["dataplane"].add(label)
        if fam not in fam_map:
            dump["other_hooks"].add(str(fam))
            continue
        key = _ckey(fam, c["table"], c["name"])
        hook = c.get("hook")
        if hook is None:
            _add_chain(dump, key, fam_map[fam], None, None, None, False)
        elif hook == "input" and c.get("type", "filter") == "filter":
            pol = c.get("policy", "accept")
            _add_chain(dump, key, fam_map[fam], "input", int(c.get("prio", 0)),
                       pol if pol in ("accept", "drop") else "accept", True)
        else:
            dump["other_hooks"].add(str(hook))
    # scan every rule (also in unmodelled chains) for NAT rewrites
    for r in rules:
        fam = r.get("family")
        if fam not in fam_map:
            continue
        key = _ckey(fam, r["table"], r["chain"])
        tkey = (fam, r["table"])
        rule_fam = {"ip": 4, "ip6": 6}.get(fam)
        parsed, nat, feats = _nft_rule(r.get("expr") or [], sets, tkey,
                                       "%s.%s" % (fam, r["table"]), rule_fam)
        dump["features"] |= feats
        if nat:
            dump["nat_rewrite"] = True
        ch = dump["chains"].get(key)
        if ch is None:
            continue
        ch["rules"].extend(parsed)
    return dump


def resolve_ct_status(dump):
    """Drop rules that need ``ct status dnat`` when nothing in the ruleset rewrites addresses.

    ``ct status dnat`` matches only connections that a DNAT/REDIRECT rule translated, so with no
    such rule (and no IPVS) it can never match; firewalld ships ``ct status dnat accept``
    in every ruleset. The assumption is recorded as the ``assumes_no_dnat_without_rule``
    feature. With any rewriting present the rule stays (opaque) and the model is approximate.
    """
    if dump["nat_rewrite"]:
        return
    for ch in dump["chains"].values():
        keep = []
        for r in ch["rules"]:
            if "ct_status_dnat" in r.get("opaque_reason", "").split(","):
                dump["features"].add("assumes_no_dnat_without_rule")
                continue
            keep.append(r)
        ch["rules"] = keep


# ==================================================================== iptables-save
def _ipt_addr_ivs(val, fam):
    ivs = []
    for part in val.split(","):
        part = part.strip()
        if not part:
            continue
        f, lo, hi = _cidr_iv(part)
        if f != fam:
            raise _Never()
        ivs.append((lo, hi))
    return ivs


def _ipt_ports(val):
    ivs = []
    for part in val.split(","):
        if ":" in part:
            a, _, c = part.partition(":")
            lo = _port_value(a) if a else 0
            hi = _port_value(c) if c else 65535
        else:
            lo = hi = _port_value(part)
        if lo is None or hi is None or lo > hi:
            raise _OpaqueValue("port_form")
        ivs.append((lo, hi))
    return ivs


def _ipt_icmp(val, fam):
    table = _ICMP4 if fam == 4 else _ICMP6
    head, _, code = val.partition("/")
    if head.isdigit():
        t = int(head)
        if t > 255:
            raise _OpaqueValue("icmp_type_name")
    elif head.lower() in table:
        t = table[head.lower()]
    else:
        raise _OpaqueValue("icmp_type_name")
    return t, bool(code)


def _ipt_rule(toks, fam, prefix, table_name):
    """Parse the option tokens of one ``-A`` line. Returns ``(rules, nat, features)``."""
    b = _RuleB(fam)
    nat = False
    features = set()
    target = None
    goto = False
    module = None
    neg = False
    action_opaque = None
    i = 0
    n = len(toks)

    def take_values(j):
        vals = []
        while j < n and not (toks[j].startswith("-") and len(toks[j]) > 1) and toks[j] != "!":
            vals.append(toks[j])
            j += 1
        return vals, j

    try:
        while i < n:
            t = toks[i]
            if t == "!":
                neg = True
                i += 1
                continue
            isneg, neg = neg, False
            if t in ("-s", "--source", "--src", "-d", "--destination", "--dst"):
                attr = "src" if t in ("-s", "--source", "--src") else "dst"
                top = V4_MAX if fam == 4 else V6_MAX
                ivs = _norm_iv(_ipt_addr_ivs(toks[i + 1], fam))
                if isneg:
                    ivs = _compl_iv(ivs, top)
                if not ivs:
                    raise _Never()
                b.add_ivs(attr, ivs)
                i += 2
            elif t in ("-i", "--in-interface", "-o", "--out-interface"):
                attr = "iif" if t in ("-i", "--in-interface") else "oif"
                name = toks[i + 1]
                if isneg:
                    b.note("negated_" + attr)
                elif "+" in name or "*" in name:
                    b.note(attr + "_pattern")
                else:
                    b.add_set(attr, [name])
                i += 2
            elif t in ("-p", "--protocol"):
                val = toks[i + 1]
                if val.lower() in ("all", "0"):
                    pass
                elif isneg:
                    b.note("negated_proto")
                else:
                    p = _proto_token(val)
                    if p is None:
                        b.note("proto_form")
                    else:
                        b.add_set("proto", [p])
                i += 2
            elif t in ("-m", "--match"):
                module = toks[i + 1].lower()
                if module not in ("tcp", "udp", "sctp", "dccp", "udplite", "multiport",
                                  "conntrack", "state", "icmp", "icmp6", "addrtype", "comment"):
                    b.note("m_" + clean_reason(module))
                if module in ("tcp", "udp", "sctp", "dccp", "udplite"):
                    b.add_set("proto", [module])
                i += 2
            elif t in ("-j", "--jump", "-g", "--goto"):
                target = toks[i + 1]
                goto = t in ("-g", "--goto")
                break
            elif t in ("-f", "--fragment"):
                b.note("fragment")
                i += 1
            elif t.startswith("--"):
                vals, j = take_values(i + 1)
                try:
                    _ipt_module_opt(b, module, t, vals, isneg, fam)
                except _OpaqueValue as exc:
                    b.note(str(exc))
                i = j
            else:
                i += 1
    except IndexError:
        raise FwModelError("truncated iptables rule")
    except ValueError:
        raise FwModelError("bad address in iptables rule")
    except _Never:
        return [], nat, features
    verdict = None
    if target is None:
        return [], nat, features
    up = target.upper()
    if up in ("ACCEPT", "DROP", "RETURN"):
        verdict = up.lower()
    elif up == "REJECT":
        verdict = "reject"
    elif up in _NAT_REWRITE_TARGETS:
        nat = True
        action_opaque = "act:target_" + up.lower()
    elif up in _NOOP_IPT_TARGETS:
        return [], nat, features
    elif up in ("CT", "NOTRACK"):
        features.add("notrack")
        action_opaque = "act:target_ct"
    elif up in ("NFQUEUE", "QUEUE", "SYNPROXY", "TEE", "CLUSTERIP", "TARPIT", "DELUDE"):
        action_opaque = "act:target_" + up.lower()
    elif re.match(r"^[A-Za-z0-9_.:-]{1,64}$", target):
        verdict = ("goto:" if goto else "jump:") + _ckey(prefix, table_name, target)
    else:
        action_opaque = "act:target_form"
    try:
        combos = b.finish()
    except _Never:
        return [], nat, features
    out = []
    for m in combos:
        r = {"m": m, "v": verdict if verdict is not None else "opaque"}
        reasons = list(b.opaque)
        if action_opaque:
            reasons.append(action_opaque)
        if reasons:
            r["opaque_reason"] = ",".join(reasons[:3])
        if b.fam is not None:
            r["f"] = b.fam
        out.append(r)
    return out, nat, features


def _ipt_module_opt(b, module, opt, vals, neg, fam):
    if opt in ("--sport", "--source-port", "--dport", "--destination-port",
               "--sports", "--source-ports", "--dports", "--destination-ports", "--ports"):
        if not vals:
            raise _OpaqueValue("port_form")
        ivs = _norm_iv(_ipt_ports(vals[0]))
        if neg:
            ivs = _compl_iv(ivs, 65535)
        if not ivs:
            raise _Never()
        if opt in ("--sport", "--source-port", "--sports", "--source-ports"):
            b.add_ivs("sport", ivs)
        elif opt == "--ports":
            b.note("multiport_ports")
        else:
            b.add_ivs("dport", ivs)
    elif opt in ("--ctstate", "--state") and module in ("conntrack", "state"):
        states = set()
        for s in vals[0].split(",") if vals else []:
            s = s.strip().lower()
            if s in CT_STATES:
                states.add(s)
            else:
                raise _OpaqueValue("ctstate_" + clean_reason(s))
        if neg:
            states = set(CT_STATES) - states
        if not states:
            raise _Never()
        b.add_set("ct", states)
    elif opt in ("--icmp-type", "--icmpv6-type") and module in ("icmp", "icmp6"):
        if neg or not vals:
            raise _OpaqueValue("icmp_type_neg")
        t, has_code = _ipt_icmp(vals[0], fam)
        b.add_set("icmp", [t])
        if has_code:
            b.note("icmp_code")
    elif opt == "--dst-type" and module == "addrtype":
        kinds = set()
        for s in vals[0].split(",") if vals else []:
            s = s.strip().lower()
            if s in DTYPES:
                kinds.add(s)
            else:
                raise _OpaqueValue("addrtype_" + clean_reason(s))
        if neg:
            kinds = set(DTYPES) - kinds
        if not kinds:
            raise _Never()
        b.add_set("dtype", kinds)
    elif module == "comment" and opt == "--comment":
        return
    elif module in ("tcp",) and opt in ("--tcp-flags", "--syn", "--tcp-option"):
        raise _OpaqueValue("tcp_flags")
    elif module in ("addrtype", "conntrack", "state", "icmp", "icmp6", "multiport"):
        raise _OpaqueValue("%s_%s" % (module, clean_reason(opt.lstrip("-"))))
    # options of other (already noted opaque) modules need no further handling


def parse_iptables_save(text, fam, prefix):
    """Normalise ``iptables-save`` / ``ip6tables-save`` text (legacy or nf_tables flavour)."""
    dump = new_dump()
    table = None
    nat_tables = ("nat", "mangle", "raw")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if line == "COMMIT":
            table = None
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if not parts:
                continue
            cname = parts[0]
            label = _dataplane_of(cname)
            if label:
                dump["dataplane"].add(label)
            if table == "filter":
                pol = parts[1].lower() if len(parts) > 1 else "-"
                if cname == "INPUT":
                    _add_chain(dump, _ckey(prefix, table, cname), (fam,), "input", 0,
                               pol if pol in ("accept", "drop") else "accept", True)
                elif cname in ("FORWARD", "OUTPUT"):
                    dump["other_hooks"].add(cname.lower())
                else:
                    _add_chain(dump, _ckey(prefix, table, cname), (fam,), None, None, None, False)
            continue
        if not line.startswith("-A "):
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            dump["problems"].append("unquoted_rule")
            if table == "filter":
                dump["features"].add("unparsed_rule")
            continue
        if len(toks) < 2:
            continue
        cname = toks[1]
        if table == "filter":
            key = _ckey(prefix, table, cname)
            rules, nat, feats = _ipt_rule(toks[2:], fam, prefix, table)
            dump["features"] |= feats
            if nat:
                dump["nat_rewrite"] = True
            ch = dump["chains"].get(key)
            if ch is not None:
                ch["rules"].extend(rules)
        elif table in nat_tables:
            rules, nat, feats = _ipt_rule(toks[2:], fam, prefix, table)
            dump["features"] |= feats
            if nat:
                dump["nat_rewrite"] = True
    return dump


# ============================================================== model construction
def _closure(chains, roots):
    keep = set()
    work = list(roots)
    while work:
        k = work.pop()
        if k in keep or k not in chains:
            continue
        keep.add(k)
        for r in chains[k]["rules"]:
            v = r["v"]
            if v.startswith("jump:") or v.startswith("goto:"):
                work.append(v.split(":", 1)[1])
    return keep


def _family_chains(dump, f):
    out = {}
    for key, c in dump["chains"].items():
        if f not in c["fams"]:
            continue
        rules = []
        for r in c["rules"]:
            if r.get("f") not in (None, f):
                continue
            rr = {"m": r["m"], "v": r["v"]}
            if "opaque_reason" in r:
                rr["opaque_reason"] = r["opaque_reason"]
            rules.append(rr)
        out[key] = {"name": key, "hook": c["hook"], "prio": c["prio"], "policy": c["policy"],
                    "base": c["base"], "rules": rules}
    roots = [k for k, c in out.items() if c["base"]]
    keep = _closure(out, roots)
    return dict((k, out[k]) for k in sorted(keep))


def _is_conditional(rule):
    return bool(rule["m"]) or _cond_opaque(rule)


def _policy_yield(policy):
    return "drop" if policy == "drop" else "accept"


def _residual_walk(chains, base):
    """Walk ``base`` treating every conditional rule as no-match.

    Returns ``(yield, encountered_conditional_rules)``; yield is accept|drop|reject|unknown.
    """
    policy = chains[base]["policy"]
    name, i, stack = base, 0, []
    seen = set()
    encountered = []
    steps = 0
    while True:
        steps += 1
        state = (name, i, tuple(stack))
        if state in seen or steps > 200000:
            return "unknown", encountered
        seen.add(state)
        ch = chains.get(name)
        if ch is None:
            return "unknown", encountered
        rules = ch["rules"]
        if i >= len(rules):
            if stack:
                name, i = stack.pop()
                continue
            return _policy_yield(policy), encountered
        r = rules[i]
        if _is_conditional(r):
            encountered.append((name, r))
            i += 1
            continue
        v = r["v"]
        if v in ("accept", "drop", "reject"):
            return v, encountered
        if v == "return":
            if stack:
                name, i = stack.pop()
                continue
            return _policy_yield(policy), encountered
        if v.startswith("jump:"):
            if len(stack) >= MAX_DEPTH:
                return "unknown", encountered
            stack.append((name, i + 1))
            name, i = v[5:], 0
            continue
        if v.startswith("goto:"):
            name, i = v[5:], 0
            continue
        return "unknown", encountered


# ---- universe-aware simplification and coverage ------------------------------------
def _simplify_rule(rule, fam):
    """Rewrite ``rule`` for the INPUT packet universe; ``None`` when it can never match there.

    Real inbound packets are unicast-to-this-host (``dtype`` local), come from a unicast source
    and carry ports 1..65535. A constraint every such packet satisfies is dropped, one that none
    satisfies kills the rule. ``dst`` is left alone: which addresses the host owns is unknown.
    """
    m = dict(rule["m"])
    if "dtype" in m:
        if "local" not in m["dtype"]:
            return None
        del m["dtype"]
    if "src" in m:
        uni = SRC_UNIVERSE[fam]
        ivs = _inter_iv(_cidr_ivs(m["src"]), [uni])
        if not ivs:
            return None
        if ivs == [uni]:
            del m["src"]
    if "dst" in m:
        lo, hi = MULTICAST_RANGES[fam]
        if all(a >= lo and b <= hi for a, b in _cidr_ivs(m["dst"])):
            return None
    for key in ("sport", "dport"):
        if key in m:
            ivs = _inter_iv([tuple(x) for x in m[key]], [(1, 65535)])
            if not ivs:
                return None
            if ivs == [(1, 65535)] and m.get("proto") in PORT_PROTOS:
                del m[key]
            else:
                m[key] = [list(x) for x in ivs]
    out = {"m": m, "v": rule["v"]}
    if "opaque_reason" in rule:
        out["opaque_reason"] = rule["opaque_reason"]
    return out


def _simplified(chains, fam):
    out = {}
    for k, c in chains.items():
        rules = []
        for r in c["rules"]:
            sr = _simplify_rule(r, fam)
            if sr is not None:
                rules.append(sr)
        out[k] = dict(c, rules=rules)
    return out


class _Cover(object):
    """Boxes over (proto, ct, iif, oif, dtype, dport, sport, icmp, src); ``dst`` is ignored
    (treated as matching everything), which only ever enlarges a box."""

    DIMS = ("proto", "ct", "iif", "oif", "dtype", "dport", "sport", "icmp", "src")

    def __init__(self, fam, rules):
        self.fam = fam
        self.maps = {"proto": {}, "iif": {}, "oif": {}, "dtype": {}}
        for p in PORT_PROTOS + ("icmp", "icmpv6"):
            self._id("proto", p)
        self._id("dtype", "local")
        self._id("iif", "lo")
        for r in rules:
            m = r["m"]
            if "proto" in m:
                self._id("proto", m["proto"])
            if "iif" in m:
                self._id("iif", m["iif"])
            if "oif" in m:
                self._id("oif", m["oif"])
        self.other = dict((k, len(v)) for k, v in self.maps.items())
        local = self.maps["dtype"]["local"]
        self.universe = {
            "proto": [(0, self.other["proto"])], "ct": [(0, len(CT_STATES) - 1)],
            "iif": [(0, self.other["iif"])], "oif": [(0, self.other["oif"])],
            "dtype": [(local, local)], "dport": [(1, 65535)], "sport": [(1, 65535)],
            "icmp": [(0, 255)], "src": [SRC_UNIVERSE[fam]],
        }

    def _id(self, kind, name):
        mp = self.maps[kind]
        if name not in mp:
            mp[name] = len(mp)
        return mp[name]

    def box(self, m):
        box = {}
        if "proto" in m:
            box["proto"] = [(self.maps["proto"][m["proto"]],) * 2]
        elif "dport" in m or "sport" in m:
            box["proto"] = _norm_iv([(self.maps["proto"][p],) * 2 for p in PORT_PROTOS])
        for key in ("iif", "oif"):
            if key in m:
                box[key] = [(self.maps[key][m[key]],) * 2]
        if "ct" in m:
            box["ct"] = _norm_iv([(CT_STATES.index(s),) * 2 for s in m["ct"]])
        for key in ("dport", "sport"):
            if key in m:
                box[key] = _norm_iv([tuple(x) for x in m[key]])
        if "icmp" in m:
            box["icmp"] = _norm_iv([(t, t) for t in m["icmp"]])
        if "src" in m:
            box["src"] = _cidr_ivs(m["src"])
        return box

    def covers(self, boxes, universe=None):
        """True: the union covers ``universe``; False: it does not; None: budget exhausted."""
        uni = dict(self.universe)
        if universe:
            uni.update(universe)
        self._budget = COVER_BUDGET
        return self._rec(0, uni, boxes)

    def _rec(self, di, uni, boxes):
        if not boxes:
            return False
        if di == len(self.DIMS):
            return True
        self._budget -= 1
        if self._budget < 0:
            return None
        dim = self.DIMS[di]
        cur = uni[dim]
        if all(dim not in b for b in boxes):
            return self._rec(di + 1, uni, boxes)
        points = set()
        for b in boxes:
            for lo, hi in b.get(dim, ()):
                points.add(lo)
                points.add(hi + 1)
        atoms = []
        for lo, hi in cur:
            pts = sorted(p for p in points if lo < p <= hi)
            start = lo
            for p in pts:
                atoms.append((start, p - 1))
                start = p
            atoms.append((start, hi))
        for lo, _hi in atoms:
            sub = [b for b in boxes if dim not in b or _in_iv(b[dim], lo)]
            res = self._rec(di + 1, uni, sub)
            if res is not True:
                return res
        return True


def _box_intersect(a, b):
    """Intersection of two boxes (``None`` when empty in some dimension)."""
    out = dict(a)
    for dim, ivs in b.items():
        cur = out.get(dim)
        new = ivs if cur is None else _inter_iv(cur, ivs)
        if not new:
            return None
        out[dim] = new
    return out


def _accept_boxes(chains, base, cover, limit=5000):
    """Boxes of every plain accept rule reachable from ``base``, each narrowed by the
    conditions of the jumps leading to it (order and shadowing are ignored: an over-approximation
    of what the chain can accept). ``None`` when there are too many."""
    out = []

    def walk(name, acc, trail):
        for r in chains[name]["rules"]:
            if len(out) > limit:
                return
            v = r["v"]
            if v == "accept" and not _cond_opaque(r):
                b = _box_intersect(acc, cover.box(r["m"]))
                if b is not None:
                    out.append(b)
            elif v.startswith(("jump:", "goto:")):
                tgt = v.split(":", 1)[1]
                if tgt in chains and tgt not in trail:
                    b = _box_intersect(acc, cover.box(r["m"]))
                    if b is not None:
                        walk(tgt, b, trail + (name,))

    walk(base, {}, ())
    return None if len(out) > limit else out


def _chain_effective(chains, base, fam):
    """Yield for one base chain after the residual, non-vacuity and accept-all checks."""
    y, enc = _residual_walk(chains, base)
    if y not in ("drop", "reject"):
        return y
    plain = [r for _n, r in enc if not _cond_opaque(r)]
    cover = _Cover(fam, [r for _n, r in enc])
    if cover.covers([cover.box(r["m"]) for r in plain]) is not False:
        return "unknown"
    closure = _closure(chains, [base])
    cover2 = _Cover(fam, [r for k in sorted(closure) for r in chains[k]["rules"]])
    abox = _accept_boxes(chains, base, cover2)
    if abox is None:
        return "unknown"
    iif_atoms = [n for n in cover2.maps["iif"] if n != "lo"] + [None]
    for name in iif_atoms:
        iif_id = cover2.other["iif"] if name is None else cover2.maps["iif"][name]
        uni = {
            "proto": _norm_iv([(cover2.maps["proto"]["tcp"],) * 2,
                               (cover2.maps["proto"]["udp"],) * 2]),
            "ct": [(CT_STATES.index("new"),) * 2],
            "iif": [(iif_id, iif_id)],
        }
        if cover2.covers(abox, uni) is not False:
            return "unknown"
    return y


def effective_default(chains, fam):
    """Combine the input base chains of one family into accept|drop|reject|unknown.

    ``chains`` maps chain name to chain dict (as in ``families[..]['chains']`` keyed by name).
    """
    bases = sorted(k for k, c in chains.items() if c["base"])
    if not bases:
        return "accept"
    chains = _simplified(chains, fam)
    ys = [_chain_effective(chains, b, fam) for b in bases]
    if "drop" in ys:
        return "drop"
    if "reject" in ys:
        return "reject"
    if all(y == "accept" for y in ys):
        return "accept"
    return "unknown"


# ----------------------------------------------------------------- the packet walk
def _match_rule(m, pkt, has_opaque):
    """Evaluate one rule's matchers against a packet: True, False or None (unknown)."""
    res = True
    proto = pkt.get("proto")
    if "proto" in m:
        if proto is None:
            res = None
        elif m["proto"] != proto:
            return False
    for key in ("sport", "dport"):
        if key in m:
            if proto is not None and proto not in PORT_PROTOS:
                return False
            val = pkt.get(key)
            if val is None:
                res = None
            elif not any(lo <= val <= hi for lo, hi in m[key]):
                return False
    if "icmp" in m:
        if proto is not None and proto not in ("icmp", "icmpv6"):
            return False
        val = pkt.get("icmp")
        if val is None:
            res = None
        elif val not in m["icmp"]:
            return False
    if "ct" in m:
        val = pkt.get("ct")
        if val is None:
            res = None
        elif val not in m["ct"]:
            return False
    if "iif" in m:
        val = pkt.get("iif")
        if val is None:
            res = None
        elif val == IIF_EXTERNAL:
            if m["iif"] == "lo":
                return False
            res = None
        elif val != m["iif"]:
            return False
    if "oif" in m:
        val = pkt.get("oif")
        if val is None:
            res = None
        elif val != m["oif"]:
            return False
    if "dtype" in m:
        val = pkt.get("dtype")
        if val is None:
            res = None
        elif val not in m["dtype"]:
            return False
    for key in ("src", "dst"):
        if key in m:
            val = pkt.get(key)
            if val is None:
                res = None
            else:
                ip = _ip_int(val)
                if ip is None:
                    res = None
                    continue
                if not _in_iv(_cidr_ivs(m[key]), ip):
                    return False
    if has_opaque and res is True:
        return None
    return res


def chain_outcomes(chains, base, pkt):
    """Set of possible final outcomes ({"accept","drop"} subset) of one base chain."""
    both = set(["accept", "drop"])
    policy = chains[base]["policy"]
    start = (base, 0, ())
    seen = set([start])
    work = [start]
    outs = set()

    def push(st):
        if st not in seen:
            seen.add(st)
            work.append(st)

    while work:
        name, i, stack = work.pop()
        ch = chains.get(name)
        if ch is None:
            outs |= both
            continue
        rules = ch["rules"]
        if i >= len(rules):
            if stack:
                push((stack[-1][0], stack[-1][1], stack[:-1]))
            else:
                outs.add(_policy_yield(policy))
            continue
        r = rules[i]
        res = _match_rule(r["m"], pkt, _cond_opaque(r))
        if res is not True:
            push((name, i + 1, stack))
        if res is False:
            continue
        v = r["v"]
        if v == "accept":
            outs.add("accept")
        elif v in ("drop", "reject"):
            outs.add("drop")
        elif v == "return":
            if stack:
                push((stack[-1][0], stack[-1][1], stack[:-1]))
            else:
                outs.add(_policy_yield(policy))
        elif v.startswith("jump:"):
            tgt = v[5:]
            if tgt not in chains or len(stack) >= MAX_DEPTH:
                outs |= both
            else:
                push((tgt, 0, stack + ((name, i + 1),)))
        elif v.startswith("goto:"):
            tgt = v[5:]
            if tgt not in chains:
                outs |= both
            else:
                push((tgt, 0, stack))
        else:
            outs |= both
            push((name, i + 1, stack))  # an unknown action may also fall through
    return outs


def evaluate(family, pkt):
    """Walk every input base chain of ``family`` for ``pkt``: ``allow``, ``deny`` or ``maybe``.

    ``family`` is ``model["families"]["ip4"|"ip6"]``. ``pkt`` keys (all optional; absent means
    unknown and is explored both ways): ``src, dst`` (IP strings), ``proto``, ``sport,
    dport`` (ints), ``ct`` (e.g. ``"new"``), ``iif`` (name or ``IIF_EXTERNAL``), ``oif``,
    ``icmp`` (int), ``dtype`` (e.g. ``"local"``). The result is ``allow`` only when every
    base chain can only accept the packet, ``deny`` only when no chain can accept it, and
    ``maybe`` otherwise (so an opaque rule can only widen ``deny`` to ``maybe``).
    """
    chains = dict((c["name"], c) for c in family["chains"])
    bases = sorted(k for k, c in chains.items() if c["base"])
    if not bases:
        return "allow"
    accept_possible = True
    drop_possible = False
    for b in bases:
        outs = chain_outcomes(chains, b, pkt)
        if "accept" not in outs:
            accept_possible = False
        if "drop" in outs:
            drop_possible = True
    if accept_possible and not drop_possible:
        return "allow"
    if drop_possible and not accept_possible:
        return "deny"
    return "maybe"


def src_partition(family, fam):
    """Partition the source-address space by every CIDR in ``family``'s rules.

    Returns ``[(representative_ip, [cidrs covering the atom])]`` (at most 4096 atoms) plus
    one public and one RFC1918 representative so unrelated rules cannot hide a class.
    """
    top = V4_MAX if fam == 4 else V6_MAX
    points = set([0, top + 1])
    for c in family["chains"]:
        for r in c["rules"]:
            for cidr in r["m"].get("src", []):
                _f, lo, hi = _cidr_iv(cidr)
                points.add(lo)
                points.add(hi + 1)
    extra = ["203.0.113.7", "10.255.255.1"] if fam == 4 else ["2001:db8::7", "fd00::1"]
    for e in extra:
        n = int(ipaddress.ip_address(e))
        points.add(n)
        points.add(n + 1)
    pts = sorted(points)
    out = []
    for lo, nxt in zip(pts, pts[1:]):
        if len(out) >= 4096:
            break
        hi = nxt - 1
        mk = ipaddress.IPv4Address if fam == 4 else ipaddress.IPv6Address
        out.append((str(mk(lo)), _ivs_to_cidrs([(lo, hi)], fam)))
    return out


# --------------------------------------------------------------------- confidence
def _unsafe_rules(chains):
    """Names of reasons why the walk over ``chains`` is not exact (empty list = exact)."""
    reasons = []
    accepting = {}

    def can_accept(key, visiting):
        if key in accepting:
            return accepting[key]
        if key in visiting or key not in chains:
            return key not in chains
        visiting = visiting | set([key])
        res = False
        for r in chains[key]["rules"]:
            v = r["v"]
            if v in ("accept", "opaque"):
                res = True
            elif v.startswith(("jump:", "goto:")) and can_accept(v.split(":", 1)[1], visiting):
                res = True
            if res:
                break
        accepting[key] = res
        return res

    for k in sorted(chains):
        for r in chains[k]["rules"]:
            v = r["v"]
            reason = _cond_opaque(r)
            if v == "opaque":
                reasons.append("opaque_action")
            elif v.startswith(("jump:", "goto:")):
                tgt = v.split(":", 1)[1]
                if tgt not in chains:
                    reasons.append("unresolved_jump")
                elif reason and can_accept(tgt, frozenset()):
                    reasons.append("opaque_jump")
            elif reason and v == "accept":
                reasons.append("opaque_accept")
    # jump depth / cycles
    depth_bad = False

    def depth(key, stack):
        if key in stack:
            return 99
        best = 1
        for r in chains.get(key, {"rules": []})["rules"]:
            v = r["v"]
            if v.startswith(("jump:", "goto:")):
                tgt = v.split(":", 1)[1]
                if tgt in chains:
                    best = max(best, 1 + depth(tgt, stack | frozenset([key])))
        return best

    for k in sorted(chains):
        if chains[k]["base"] and depth(k, frozenset()) > MAX_DEPTH + 1:
            depth_bad = True
    if depth_bad:
        reasons.append("jump_depth")
    return sorted(set(reasons))


def assess(dump_flags, families, ipv6_enabled, readable):
    """Return ``(confidence, reasons)``; confidence is exact|approximate|unknown."""
    reasons = []
    if dump_flags["dataplane"]:
        return "unknown", ["dataplane_" + d for d in sorted(dump_flags["dataplane"])]
    needed = ["ip4"] + (["ip6"] if ipv6_enabled else [])
    for fam in needed:
        if not readable.get(fam, False):
            reasons.append("unreadable_" + fam)
    if reasons:
        return "unknown", reasons
    if dump_flags["problems"]:
        return "unknown", ["unparsed_input"]
    if dump_flags["nat_rewrite"]:
        reasons.append("nat_rewrite")
    for f in sorted(dump_flags["features"]):
        reasons.append(f)
    for fam in needed:
        chains = dict((c["name"], c) for c in families[fam]["chains"])
        reasons.extend(_unsafe_rules(chains))
    reasons = sorted(set(reasons))
    # the DNAT-assumption marker is informational once nothing rewrites
    hard = [r for r in reasons if r != "assumes_no_dnat_without_rule"]
    if hard:
        return "approximate", reasons
    return "exact", reasons


# ------------------------------------------------------------------- build the model
def _combine_defaults(defaults):
    if "accept" in defaults:
        return "accept"
    if "unknown" in defaults or not defaults:
        return "unknown"
    return "drop" if "drop" in defaults else "reject"


def build_model(dump, backend, frontends, ipv6_enabled, readable=None):
    """Assemble the canonical model from a merged chain dump.

    ``readable`` is ``{"ip4": bool, "ip6": bool}``: whether that family's rules could be read.
    Raises ``FwTooLarge`` when more than ``MAX_RULES`` rules are modelled.
    """
    readable = dict({"ip4": True, "ip6": True}, **(readable or {}))
    resolve_ct_status(dump)
    fams = {}
    total = 0
    for name, f in (("ip4", 4), ("ip6", 6)):
        ch = _family_chains(dump, f)
        total += sum(len(c["rules"]) for c in ch.values())
        fams[name] = {"read": bool(readable[name]),
                      "chains": [ch[k] for k in sorted(ch)]}
    if total > MAX_RULES:
        raise FwTooLarge("more than %d modelled rules" % MAX_RULES)
    flags = {"dataplane": dump["dataplane"], "problems": dump["problems"],
             "nat_rewrite": dump["nat_rewrite"], "features": dump["features"]}
    confidence, reasons = assess(flags, fams, bool(ipv6_enabled), readable)
    defaults = {}
    for name, f in (("ip4", 4), ("ip6", 6)):
        if not readable[name] or confidence == "unknown":
            d = "unknown"
        else:
            d = effective_default(dict((c["name"], c) for c in fams[name]["chains"]), f)
        fams[name]["effective_default"] = d
        defaults[name] = d
    enabled = ["ip4"] + (["ip6"] if ipv6_enabled else [])
    model = {
        "v": MODEL_V,
        "backend": backend,
        "frontends": frontends,
        "ipv6_enabled": bool(ipv6_enabled),
        "families": fams,
        "flat_view": {
            "default_input_policy": _combine_defaults([defaults[n] for n in enabled]),
            "rules": _flat_rules(fams["ip4"]),
            "confidence": confidence,
        },
        "confidence_reasons": reasons[:16],
        "opaque_features": sorted(set(dump["features"]) | (set(["nat_rewrite"]) if dump["nat_rewrite"] else set())),
        "dataplane": sorted(dump["dataplane"]),
        "other_hooks": sorted(dump["other_hooks"]),
        "rule_count": total,
    }
    return model


def _flat_rules(family):
    out = []
    for c in family["chains"]:
        if not c["base"]:
            continue
        for r in c["rules"]:
            m = r["m"]
            if "opaque_reason" in r or r["v"] not in ("accept", "drop", "reject"):
                continue
            if set(m) - set(["src", "proto", "dport"]):
                continue
            srcs = m.get("src") or ["any"]
            ports = m.get("dport") or [[0, 65535]]
            for s in srcs:
                for lo, hi in ports:
                    out.append({"src_cidr": s, "proto": m.get("proto", "any"),
                                "port_lo": lo, "port_hi": hi, "action": r["v"]})
                    if len(out) >= MAX_FLAT_RULES:
                        return out
    return out


def default_inbound_all_families(model):
    """The derived rule the server uses: ``deny`` only for an exact model whose every enabled
    family's effective default is drop/reject; ``allow`` when an enabled family accepts;
    otherwise ``unknown``."""
    if model.get("flat_view", {}).get("confidence") != "exact":
        return "unknown"
    names = ["ip4"] + (["ip6"] if model.get("ipv6_enabled") else [])
    ds = [model["families"][n]["effective_default"] for n in names]
    if all(d in ("drop", "reject") for d in ds):
        return "deny"
    if any(d == "accept" for d in ds):
        return "allow"
    return "unknown"
