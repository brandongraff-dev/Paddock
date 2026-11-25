"""The typed field registry for host-config invariants, and the accessors behind it.

A field is a name (``host.sshd.maxauthtries``, ``host.listener(22).exists``), an optional
parameter, a type, the collector whose fact it reads, the highest evidence tier that fact can
reach, and an accessor. The registry is closed: an unknown field is a parse error.

Soundness rules every accessor follows:

* The accessor returns ``Known(value)`` or ``Unknown(reason)``. **Unknown is never a value**: the
  evaluator turns it into UNKNOWN (``None``), never into False.
* ``Known`` needs a *usable* fact (see ``resolve``): ``signed``, no ``conflict``, effective tier at
  least ``min_tier``, fresh, ``status == ok`` and, for fields that say so, ``conf == exact`` and
  not ``partial``. A value is only produced from data that is complete for that claim.
* A positive observation from an incomplete table is still real (a listener on port 22 exists even
  if the table is partial); a *negative* one (no listener) needs a complete table.
* The tier of a field is capped at ``max_tier`` whatever the fact says: an agent-signed fact is
  ``configured`` and this library never lifts it.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Union

from .hostfacts import Fact, HostFacts
from .kleene import Tri, k_all, k_any, k_not
from .tier import Tier

FUTURE_SLACK = dt.timedelta(minutes=5)
TYPES = ("bool", "int", "str", "set<str>", "set<cidr>")

# Blind-spot reasons, most fundamental first. A host with several reasons reports the first.
REASON_ORDER = ("no_agent", "no_sensor", "unavailable", "collector_error", "unsigned",
                "evidence_conflict", "approximate", "partial", "match_override", "no_value",
                "tier_below_min", "future_timestamp", "stale")


def reason_rank(reason: str) -> int:
    try:
        return REASON_ORDER.index(reason)
    except ValueError:
        return len(REASON_ORDER)


@dataclass(frozen=True)
class Known:
    value: Any


@dataclass(frozen=True)
class Unknown:
    reason: str


Outcome = Union[Known, Unknown]


@dataclass(frozen=True)
class ParamSpec:
    name: str
    lo: int
    hi: int


@dataclass(frozen=True)
class FieldSpec:
    name: str                         # without the parameter, e.g. "host.listener.exists"
    type: str                         # one of TYPES
    collector: str
    max_tier: Tier
    accessor: Callable[[Fact, tuple, HostFacts], Outcome]
    doc: str
    param: Optional[ParamSpec] = None  # the parameter sits right after segment ``param_after``
    param_after: int = 1
    absent: str = "unknown"           # what a missing key means: "unknown" or "empty" (set fields)
    derived: bool = False

    def display(self, params: tuple = ()) -> str:
        """``host.listener(22).exists``: the canonical spelling."""
        segs = self.name.split(".")
        if self.param is None or not params:
            return self.name
        head = ".".join(segs[:self.param_after + 1]) + "(" + ",".join(str(p) for p in params) + ")"
        rest = segs[self.param_after + 1:]
        return ".".join([head] + rest)


# --------------------------------------------------------------------------------------------
# helpers

def _need(fact: Fact, *, exact: bool, partial_ok: bool = False) -> Optional[Unknown]:
    if fact.status == "unavailable":
        return Unknown("unavailable")
    if fact.status != "ok":
        return Unknown("collector_error")
    if exact and fact.conf != "exact":
        return Unknown("approximate")
    if not partial_ok and fact.partial:
        return Unknown("partial")
    return None


def _is_map(v: Any) -> bool:
    return isinstance(v, Mapping)


def _is_seq(v: Any) -> bool:
    return isinstance(v, (tuple, list))


# --------------------------------------------------------------------------------------------
# sshd

_YESNO = frozenset(["yes", "no"])
_ROOT_LOGIN = frozenset(["yes", "no", "prohibit-password", "forced-commands-only"])
_SSHD_COMMS = frozenset(["sshd", "sshd-session", "dropbear"])


def _sshd_state(fact: Fact) -> Union[tuple[Mapping[str, Any], list[Mapping[str, Any]], list[Mapping[str, Any]]], Unknown]:
    """``(base config, deltas, variants)`` of an exact ``sshd -T`` fact, or ``Unknown``.

    ``variants`` is the base config plus the base with each probe delta applied (a delta is a
    Match block's effect for one probed user and address). Exact means every Match criterion was
    probed (``match.unprobed is False``): anything else (absent, true, a text-parsed config) is
    approximate and the caller must not conclude anything from it."""
    d = fact.data
    cfg = d.get("config")
    match = d.get("match")
    probes = d.get("probes")
    if not _is_map(cfg) or not _is_map(match) or match.get("unprobed") is not False:
        return Unknown("approximate")
    if d.get("source") == "text" or not _is_map(probes) or not _is_seq(probes.get("deltas")):
        return Unknown("approximate")
    deltas: list[Mapping[str, Any]] = []
    for item in probes["deltas"]:
        if not _is_map(item) or not _is_map(item.get("delta")):
            return Unknown("approximate")
        deltas.append(item["delta"])
    variants: list[Mapping[str, Any]] = [cfg]
    for dl in deltas:
        c = dict(cfg)
        for k, v in dl.items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        variants.append(c)
    return cfg, deltas, variants


def _sshd_scalar(key: str, allowed: Optional[frozenset]) -> Callable[[Fact, tuple, HostFacts], Outcome]:
    def acc(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        cfg, deltas, _variants = st
        if any(key in dl for dl in deltas):
            return Unknown("match_override")       # no single effective value: it varies by user/address
        v = cfg.get(key)
        if not isinstance(v, str) or not v or len(v) > 200:
            return Unknown("no_value")
        v = v.lower()
        if key == "permitrootlogin" and v == "without-password":
            v = "prohibit-password"
        if allowed is not None and v not in allowed:
            return Unknown("no_value")
        return Known(v)
    return acc


def _sshd_int(key: str) -> Callable[[Fact, tuple, HostFacts], Outcome]:
    def acc(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        cfg, deltas, _variants = st
        if any(key in dl for dl in deltas):
            return Unknown("match_override")
        v = cfg.get(key)
        if type(v) is not int or v < 0 or v > 10**9:
            return Unknown("no_value")
        return Known(v)
    return acc


def _sshd_list(key: str) -> Callable[[Fact, tuple, HostFacts], Outcome]:
    """A set of names; absent means "not configured" (the empty set) in an exact ``sshd -T`` fact."""
    def acc(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        cfg, deltas, _variants = st
        if any(key in dl for dl in deltas):
            return Unknown("match_override")
        v = cfg.get(key)
        if v is None:
            return Known(frozenset())
        if not _is_seq(v) or not all(isinstance(x, str) for x in v):
            return Unknown("no_value")
        return Known(frozenset(v))
    return acc


def _yes(c: Mapping[str, Any], key: str) -> Tri:
    v = c.get(key)
    if isinstance(v, str):
        v = v.lower()
        if v == "yes":
            return True
        if v == "no":
            return False
    return None


def _pubkey_only(c: Mapping[str, Any]) -> Tri:
    """True when AuthenticationMethods demands public keys only; False for ``any`` and anything
    that lets another method in; None when it is absent or unreadable."""
    v = c.get("authenticationmethods")
    if not isinstance(v, str):
        return None
    v = v.strip().lower()
    if not v or len(v) > 200:
        return None
    if v == "any":
        return False
    tokens = [t for alt in v.split() for t in alt.split(",")]
    if not tokens:
        return None
    return all(t == "publickey" for t in tokens)


def _password_possible(c: Mapping[str, Any]) -> Tri:
    pw = _yes(c, "passwordauthentication")
    kbd = k_all([_yes(c, "kbdinteractiveauthentication"), _yes(c, "usepam"),
                 k_not(_pubkey_only(c))])
    return k_any([pw, kbd])


def _root_possible(c: Mapping[str, Any]) -> Tri:
    v = c.get("permitrootlogin")
    if not isinstance(v, str):
        return None
    v = v.lower()
    if v == "without-password":
        v = "prohibit-password"
    if v not in _ROOT_LOGIN:
        return None
    return v == "yes"


def _sshd_derived(fn: Callable[[Mapping[str, Any]], Tri]) -> Callable[[Fact, tuple, HostFacts], Outcome]:
    def acc(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        _cfg, _deltas, variants = st
        v = k_any([fn(c) for c in variants])      # any probed user/address that can: possible
        return Unknown("no_value") if v is None else Known(v)
    return acc


def _sshd_seen_elsewhere(host: HostFacts) -> bool:
    """Does the listeners fact (usable or not) show an SSH server? Used only to veto
    ``installed == false``: it can turn that claim into UNKNOWN, never the other way."""
    lf = host.get("listeners")
    if lf is None or lf.status != "ok":
        return False
    rows = lf.data.get("listeners")
    if not _is_seq(rows):
        return False
    for r in rows:
        if not _is_map(r):
            continue
        if r.get("port") == 22 or r.get("comm") in _SSHD_COMMS:
            return True
    return False


def _sshd_installed(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    if fact.status == "ok":
        v = fact.data.get("installed")
        if v is True:
            return Known(True)
        if v is not False:
            return Unknown("no_value")
    elif fact.status == "unavailable" and fact.reason == "tool_missing":
        pass
    elif fact.status == "unavailable":
        return Unknown("unavailable")
    else:
        return Unknown("collector_error")
    # "no sshd binary was found": a claim of absence. Contradicted by a listener that looks like
    # sshd, it is not trusted.
    if _sshd_seen_elsewhere(host):
        return Unknown("evidence_conflict")
    return Known(False)


# --------------------------------------------------------------------------------------------
# firewall

_FW_DEFAULTS = frozenset(["accept", "drop", "reject", "unknown"])


def _fw_default_all(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    """``deny`` only if every *enabled* family's effective default is drop/reject and the model is
    exact; ``allow`` if one accepts (exact model); otherwise unknown."""
    bad = _need(fact, exact=True)
    if bad:
        return bad
    d = fact.data
    fv = d.get("flat_view")
    if not _is_map(fv) or fv.get("confidence") != "exact":
        return Unknown("approximate")
    if d.get("dataplane") or d.get("opaque_features"):
        return Unknown("approximate")
    v6 = d.get("ipv6_enabled")
    fams = d.get("families")
    if not isinstance(v6, bool) or not _is_map(fams):
        return Unknown("no_value")
    defaults = []
    for name in ("ip4",) + (("ip6",) if v6 else ()):
        f = fams.get(name)
        if not _is_map(f) or f.get("read") is not True or f.get("effective_default") not in _FW_DEFAULTS:
            return Unknown("no_value")
        defaults.append(f["effective_default"])
    if all(x in ("drop", "reject") for x in defaults):
        return Known("deny")
    if any(x == "accept" for x in defaults):
        return Known("allow")
    return Unknown("no_value")


def _fw_engine(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    bad = _need(fact, exact=False)
    if bad:
        return bad
    v = fact.data.get("backend")
    if v not in ("nft", "legacy", "mixed", "none"):
        return Unknown("no_value")
    return Known(v)


def _fw_ipv6(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    bad = _need(fact, exact=False)
    if bad:
        return bad
    v = fact.data.get("ipv6_enabled")
    return Known(v) if isinstance(v, bool) else Unknown("no_value")


# --------------------------------------------------------------------------------------------
# listeners

def _rows(fact: Fact) -> Union[list[Mapping[str, Any]], Unknown]:
    bad = _need(fact, exact=False, partial_ok=True)
    if bad:
        return bad
    rows = fact.data.get("listeners")
    if not _is_seq(rows):
        return Unknown("no_value")
    out = []
    for r in rows:
        if not _is_map(r) or type(r.get("port")) is not int or not isinstance(r.get("ip"), str):
            return Unknown("no_value")
        out.append(r)
    return out


def _complete(fact: Fact, rows: list) -> bool:
    """Is the listener table the whole table? Needed before any claim that something is absent."""
    return (not fact.partial and fact.conf == "exact"
            and fact.data.get("count") == len(rows))


def _at_port(rows: list, port: int) -> list:
    return [r for r in rows if r["port"] == port]


def _listener_exists(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    if _at_port(rows, params[0]):
        return Known(True)
    return Known(False) if _complete(fact, rows) else Unknown("partial")


def _listener_wildcard(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    here = _at_port(rows, params[0])
    if any(r.get("bind_class") in ("wildcard4", "wildcard6") for r in here):
        return Known(True)
    return Known(False) if _complete(fact, rows) else Unknown("partial")


def _listener_process(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    if not _complete(fact, rows):
        return Unknown("partial")
    att = fact.data.get("attribution")
    if not _is_map(att) or att.get("status") != "ok":
        return Unknown("partial")                 # some sockets could not be tied to a process
    comms = set()
    for r in _at_port(rows, params[0]):
        c = r.get("comm")
        if not isinstance(c, str) or not c:
            return Unknown("no_value")
        comms.add(c)
    return Known(frozenset(comms))


def _listeners_count(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    return Known(len(rows)) if _complete(fact, rows) else Unknown("partial")


def _listeners_addresses(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    if not _complete(fact, rows):
        return Unknown("partial")
    nets = set()
    for r in rows:
        try:
            nets.add(ipaddress.ip_network(r["ip"], strict=True))   # a bare address is a /32 or /128
        except ValueError:
            return Unknown("no_value")
    return Known(frozenset(nets))


# --------------------------------------------------------------------------------------------
# patch

def _patch_block(fact: Fact, name: str) -> Union[Mapping[str, Any], Unknown]:
    bad = _need(fact, exact=True, partial_ok=True)   # the patch section is partial whenever one block is
    if bad:
        return bad
    b = fact.data.get(name)
    if not _is_map(b) or b.get("state") != "ok":
        return Unknown("unavailable")
    return b


def _patch_security(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    b = _patch_block(fact, "pending")
    if isinstance(b, Unknown):
        return b
    v = b.get("security")
    return Known(v) if type(v) is int and 0 <= v <= 10**9 else Unknown("no_value")


def _patch_reboot(fact: Fact, params: tuple, host: HostFacts) -> Outcome:
    b = _patch_block(fact, "reboot")
    if isinstance(b, Unknown):
        return b
    v = b.get("required")
    return Known(v) if isinstance(v, bool) else Unknown("no_value")


# --------------------------------------------------------------------------------------------
# the registry

_PORT = ParamSpec("port", 1, 65535)
CFG = Tier.configured


def _specs() -> list[FieldSpec]:
    s = [
        FieldSpec("host.sshd.installed", "bool", "sshd", CFG, _sshd_installed,
                  "an SSH server is installed (false: no sshd binary, and no listener looks like one)"),
        FieldSpec("host.sshd.password_login_possible", "bool", "sshd", CFG,
                  _sshd_derived(_password_possible),
                  "any probed user/address can log in with a password: PasswordAuthentication yes, or "
                  "KbdInteractiveAuthentication yes with UsePAM yes and no public-key-only "
                  "AuthenticationMethods", derived=True),
        FieldSpec("host.sshd.root_login_possible", "bool", "sshd", CFG, _sshd_derived(_root_possible),
                  "any probed user/address allows PermitRootLogin yes (key-only root login, "
                  "prohibit-password, is not counted)", derived=True),
        FieldSpec("host.sshd.passwordauthentication", "str", "sshd", CFG,
                  _sshd_scalar("passwordauthentication", _YESNO), "sshd -T passwordauthentication"),
        FieldSpec("host.sshd.kbdinteractiveauthentication", "str", "sshd", CFG,
                  _sshd_scalar("kbdinteractiveauthentication", _YESNO),
                  "sshd -T kbdinteractiveauthentication"),
        FieldSpec("host.sshd.permitrootlogin", "str", "sshd", CFG,
                  _sshd_scalar("permitrootlogin", _ROOT_LOGIN),
                  "sshd -T permitrootlogin (without-password reads as prohibit-password)"),
        FieldSpec("host.sshd.permitemptypasswords", "str", "sshd", CFG,
                  _sshd_scalar("permitemptypasswords", _YESNO), "sshd -T permitemptypasswords"),
        FieldSpec("host.sshd.pubkeyauthentication", "str", "sshd", CFG,
                  _sshd_scalar("pubkeyauthentication", _YESNO), "sshd -T pubkeyauthentication"),
        FieldSpec("host.sshd.usepam", "str", "sshd", CFG, _sshd_scalar("usepam", _YESNO),
                  "sshd -T usepam"),
        FieldSpec("host.sshd.authenticationmethods", "str", "sshd", CFG,
                  _sshd_scalar("authenticationmethods", None), "sshd -T authenticationmethods"),
        FieldSpec("host.sshd.maxauthtries", "int", "sshd", CFG, _sshd_int("maxauthtries"),
                  "sshd -T maxauthtries"),
        FieldSpec("host.sshd.allowusers", "set<str>", "sshd", CFG, _sshd_list("allowusers"),
                  "sshd -T allowusers (empty: not configured)", absent="empty"),
        FieldSpec("host.sshd.allowgroups", "set<str>", "sshd", CFG, _sshd_list("allowgroups"),
                  "sshd -T allowgroups (empty: not configured)", absent="empty"),
        FieldSpec("host.fw.default_inbound_all_families", "str", "firewall", CFG, _fw_default_all,
                  "deny: every enabled family drops or rejects inbound by default (exact model); "
                  "allow: some family accepts; otherwise unknown", derived=True),
        FieldSpec("host.fw.engine", "str", "firewall", CFG, _fw_engine,
                  "nft | legacy | mixed | none"),
        FieldSpec("host.fw.ipv6_enabled", "bool", "firewall", CFG, _fw_ipv6,
                  "the host has a global-capable IPv6 stack"),
        FieldSpec("host.listener.exists", "bool", "listeners", CFG, _listener_exists,
                  "something listens on the port (any protocol, any address)", param=_PORT),
        FieldSpec("host.listener.wildcard", "bool", "listeners", CFG, _listener_wildcard,
                  "something listens on the port on 0.0.0.0 or ::", param=_PORT),
        FieldSpec("host.listener.process", "set<str>", "listeners", CFG, _listener_process,
                  "process names (comm) listening on the port", param=_PORT, absent="empty"),
        FieldSpec("host.listeners.count", "int", "listeners", CFG, _listeners_count,
                  "number of distinct listening sockets"),
        FieldSpec("host.listeners.addresses", "set<cidr>", "listeners", CFG, _listeners_addresses,
                  "every address something listens on, as /32 and /128 networks"),
        FieldSpec("host.patch.security_updates_pending", "int", "patch", CFG, _patch_security,
                  "installable security updates reported by the package manager"),
        FieldSpec("host.patch.reboot_required", "bool", "patch", CFG, _patch_reboot,
                  "a reboot is pending (new kernel or libraries)"),
    ]
    return s


REGISTRY: dict[str, FieldSpec] = {f.name: f for f in _specs()}


def catalog() -> list[FieldSpec]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


# --------------------------------------------------------------------------------------------
# resolving one field on one host

@dataclass(frozen=True)
class Resolved:
    """The value of one field on one host, or why there is none."""

    known: bool
    value: Any = None
    reason: str = ""
    fact: Optional[Fact] = None
    tier: Optional[Tier] = None       # effective tier: the fact's, capped at the field's max_tier


def trust_problem(fact: Fact, tier: Tier, now: dt.datetime, min_tier: Tier,
                  max_age: dt.timedelta) -> Optional[str]:
    """Why a fact cannot be relied on at all (independent of what it says), else ``None``."""
    if not fact.signed:
        return "unsigned"
    if fact.conflict:
        return "evidence_conflict"
    if tier.rank < min_tier.rank:
        return "tier_below_min"
    if fact.observed_at > now + FUTURE_SLACK:
        return "future_timestamp"
    if now - fact.observed_at > max_age:
        return "stale"
    return None


def _type_ok(typ: str, v: Any) -> bool:
    if typ == "bool":
        return isinstance(v, bool)
    if typ == "int":
        return type(v) is int
    if typ == "str":
        return isinstance(v, str)
    return isinstance(v, frozenset)


def resolve(spec: FieldSpec, params: tuple, host: Optional[HostFacts], now: dt.datetime,
            min_tier: Tier, max_age: dt.timedelta) -> Resolved:
    if host is None:
        return Resolved(False, reason="no_agent")
    fact = host.get(spec.collector)
    if fact is None:
        return Resolved(False, reason="no_sensor")
    tier = fact.tier if fact.tier.rank <= spec.max_tier.rank else spec.max_tier
    why = trust_problem(fact, tier, now, min_tier, max_age)
    if why is not None:
        return Resolved(False, reason=why, fact=fact, tier=tier)
    try:
        out = spec.accessor(fact, params, host)
    except Exception:                       # noqa: BLE001 - an accessor bug must read as UNKNOWN
        return Resolved(False, reason="no_value", fact=fact, tier=tier)
    if isinstance(out, Known) and _type_ok(spec.type, out.value):
        return Resolved(True, out.value, "", fact, tier)
    if isinstance(out, Unknown):
        return Resolved(False, reason=out.reason, fact=fact, tier=tier)
    return Resolved(False, reason="no_value", fact=fact, tier=tier)
