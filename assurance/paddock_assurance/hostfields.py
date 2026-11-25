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

from .hostfacts import Fact, HostFacts, tombstone
from .kleene import Tri, k_all, k_any, k_not
from .tier import Tier

FUTURE_SLACK = dt.timedelta(minutes=5)
TYPES = ("bool", "int", "str", "set<str>", "set<cidr>")

# Blind-spot reasons, most fundamental first. A host with several reasons reports the first.
REASON_ORDER = ("no_agent", "agent_revoked", "no_sensor", "unavailable", "collector_error",
                "unsigned", "evidence_conflict", "approximate", "reload_pending", "daemon_differs",
                "partial", "unlisted_listener", "match_override", "unrestricted", "no_value",
                "tier_below_min", "future_timestamp", "stale")


def reason_rank(reason: str) -> int:
    try:
        return REASON_ORDER.index(reason)
    except ValueError:
        return len(REASON_ORDER)


@dataclass(frozen=True)
class Known:
    value: Any
    # Other facts the value rests on (a corroborating collector): they expire too, so the verdict's
    # tier and valid_until must account for them.
    also: tuple = ()
    # A limit of the evidence a HOLDS resting on this value must state (``basis:<name>``).
    note: str = ""


@dataclass(frozen=True)
class Unknown:
    reason: str
    # A key a Match block changes has no single value, but a leaf can still be decided per variant:
    # the value in the base config and in every probed variant, in order, de-duplicated; ``None`` is
    # a variant whose value cannot be read. Empty for every other kind of unknown.
    variants: tuple = ()
    # The fact that made the value unknown when it is not the field's own collector (a corroborating
    # listener table that is future-dated turns usable five minutes before its timestamp).
    blame: Optional[Fact] = None


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
    accessor: Callable[[Fact, tuple, "HostCtx"], Outcome]
    doc: str
    param: Optional[ParamSpec] = None  # the parameter sits right after segment ``param_after``
    param_after: int = 1
    absent: str = "unknown"           # what a missing key means: "unknown" or "empty" (set fields)
    # Collectors whose facts the accessor also reads (a corroboration): listed in ``Plan.collectors``
    # so a reader learns that a stale or unsigned fact of theirs changes the verdict.
    also_collectors: tuple = ()
    derived: bool = False
    choices: Optional[frozenset] = None   # str fields: the closed vocabulary a literal may use
    aliases: Mapping[str, str] = None  # type: ignore[assignment]  # literal spellings folded to a choice

    def __post_init__(self) -> None:
        if self.aliases is None:
            object.__setattr__(self, "aliases", {})

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
# What the collector cuts (agent/paddock_agent/collectors/sshd.py: MAX_LIST_ITEMS, clean_str(.., 200)).
# A list of exactly this many names, or a string of exactly this many characters, may have been cut by
# an agent that did not say so: it is never read as the whole value.
_MAX_LIST_ITEMS = 50
_MAX_STR_CUT = 200

# A process whose name (or executable) contains one of these may be an SSH server (the agent's
# ``SSH_NAME_HINTS``; any case).
_SSH_NAME_HINTS = ("ssh", "dropbear")
# Programs known NOT to be (or front) an SSH server: the agent's ``NON_SSH_COMMS``. A public TCP
# listener of any other program (a proxy such as docker-proxy, gitea, teleport, nginx, ...) or of none
# we can name keeps "no SSH server" unproven. Deliberately short.
NON_SSH_COMMS = frozenset([
    "postgres", "postmaster", "mysqld", "mariadbd", "mongod", "redis-server", "valkey-server",
    "memcached", "named", "unbound", "dnsmasq", "chronyd", "ntpd", "cupsd", "smbd", "nmbd",
    "master", "dovecot", "exim4", "cockroach",
])
ABSENCE_NOTE = "basis:sshd_absence_from_listener_table"

# The config keys the agent's sshd collector can emit (its ALLOWLIST), always lower case. A key outside
# this set, or spelled otherwise (``MaxAuthTries``, the alias ``challengeresponseauthentication`` the
# agent normalises), in ``v.config`` or a probe delta is a fact this library cannot read: it must not
# be ignored while a lower-case key it does read says "fine".
SSHD_KEYS = frozenset([
    "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
    "permitemptypasswords", "usepam", "x11forwarding", "permituserenvironment",
    "hostbasedauthentication", "gssapiauthentication", "strictmodes", "permitrootlogin",
    "addressfamily", "allowtcpforwarding", "loglevel", "maxauthtries", "logingracetime",
    "maxsessions", "authenticationmethods", "port", "listenaddress", "allowusers", "allowgroups",
    "denyusers", "denygroups", "authorizedkeysfile", "authorizedkeyscommand"])
_ALLOW_LISTS = ("allowusers", "allowgroups")
_PATTERN_CHARS = "*?!"


def _unreadable_keys(m: Mapping[str, Any]) -> bool:
    return any(not isinstance(k, str) or k not in SSHD_KEYS for k in m)


def _list_has_pattern(v: Any) -> bool:
    """An AllowUsers / AllowGroups entry with a wildcard or a negation: the list is a set of patterns,
    not of names (``*`` lets every account in), so it is not "restricted to this set"."""
    return any(isinstance(x, str) and any(c in x for c in _PATTERN_CHARS) for x in v)


def _truncated(d: Mapping[str, Any]) -> Union[frozenset, "Unknown"]:
    """The config keys the collector says it cut (``v.truncated``; absent when nothing was cut). A
    marker that is present but unreadable makes the whole fact unusable for config claims."""
    if "truncated" not in d:
        return frozenset()
    t = d["truncated"]
    if not _is_seq(t) or not all(isinstance(x, str) and x for x in t):
        return Unknown("approximate")
    return frozenset(x.lower() for x in t)       # the agent writes lower-case keys; be liberal here


def _daemon_problem(d: Mapping[str, Any]) -> Optional["Unknown"]:
    """``sshd -T`` describes the files on disk; ``v.daemon`` is the only evidence about the running
    daemon. A config claim needs POSITIVE evidence that the daemon runs those files. A flag the agent
    could not read (null) is not evidence: with an unreadable command line the agent still computes
    ``reload_pending`` from file times alone, and a daemon started with ``-f /other`` or extra ``-o``
    options would hide behind that. So, for a running master daemon: exactly one master, the default
    config file, no extra options, the expected binary, and no reload pending. With no master daemon
    only socket activation qualifies (``found`` false, ``masters`` 0, ``reload_pending`` false: sshd
    reads the files for every connection). Anything else is unknown."""
    daemon = d.get("daemon")
    if not _is_map(daemon):
        return Unknown("approximate")
    rp = daemon.get("reload_pending")
    if rp is True:
        return Unknown("reload_pending")
    if rp is not False:
        return Unknown("approximate")
    masters = daemon.get("masters")
    found = daemon.get("found")
    if type(masters) is not int or type(found) is not bool:
        return Unknown("approximate")
    if (daemon.get("binary_matches") is False or daemon.get("config_default") is False
            or daemon.get("options_override") is True or masters > 1):
        return Unknown("daemon_differs")
    if not found:
        return None if masters == 0 else Unknown("approximate")
    if (masters != 1 or daemon.get("config_default") is not True
            or daemon.get("options_override") is not False
            or daemon.get("binary_matches") is not True):
        return Unknown("approximate")
    return None


def _sshd_state(fact: Fact) -> Union[tuple[Mapping[str, Any], list[Mapping[str, Any]],
                                           list[Mapping[str, Any]], frozenset], Unknown]:
    """``(base config, deltas, variants, truncated keys)`` of an exact ``sshd -T`` fact, or ``Unknown``.

    ``variants`` is the base config plus the base with each probe delta applied (a delta is a
    Match block's effect for one probed user and address), with every key the collector says it cut
    removed. Exact means every Match criterion was probed (``match.unprobed is False``) and the
    running daemon is known to run these files: anything else (absent, true, a text-parsed config,
    a reload pending) is approximate and the caller must not conclude anything from it."""
    d = fact.data
    cfg = d.get("config")
    match = d.get("match")
    probes = d.get("probes")
    if not _is_map(cfg) or not _is_map(match) or match.get("unprobed") is not False:
        return Unknown("approximate")
    if d.get("source") == "text" or not _is_map(probes) or not _is_seq(probes.get("deltas")):
        return Unknown("approximate")
    trunc = _truncated(d)
    if isinstance(trunc, Unknown):
        return trunc
    pending = _daemon_problem(d)
    if pending is not None:
        return pending
    if _unreadable_keys(cfg):
        return Unknown("approximate")
    deltas: list[Mapping[str, Any]] = []
    for item in probes["deltas"]:
        if not _is_map(item) or not _is_map(item.get("delta")) or _unreadable_keys(item["delta"]):
            return Unknown("approximate")
        deltas.append(item["delta"])
    base = {k: v for k, v in cfg.items() if k not in trunc}
    variants: list[Mapping[str, Any]] = [base]
    for dl in deltas:
        c = dict(base)
        for k, v in dl.items():
            if k in trunc:
                continue
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        variants.append(c)
    return cfg, deltas, variants, trunc


def _dedupe(values: list) -> tuple:
    return tuple(dict.fromkeys(values))


def _sshd_scalar_acc(key: str, parse: Callable[[Any], Any]) \
        -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    """A single-valued key. ``parse`` turns a raw value into the field's value or ``None``. A key a
    Match block changes has no single value (``match_override``) but carries its per-variant values
    so a leaf can still be decided (see ``hostconfig``): a variant that violates is a violation."""
    def acc(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        cfg, deltas, variants, trunc = st
        if key in trunc:
            return Unknown("approximate")                 # a cut value is a prefix, not the truth
        vals = [parse(c.get(key)) for c in variants]
        if not any(key in dl for dl in deltas):
            return Known(vals[0]) if vals[0] is not None else Unknown("no_value")
        if all(v is None for v in vals):
            return Unknown("match_override")
        return Unknown("match_override", variants=_dedupe(vals))
    return acc


def _sshd_scalar(key: str, allowed: Optional[frozenset]) -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    def parse(v: Any) -> Optional[str]:
        if not isinstance(v, str) or not v or len(v) >= _MAX_STR_CUT:
            return None
        v = v.lower()
        if key == "permitrootlogin" and v == "without-password":
            v = "prohibit-password"
        if allowed is not None and v not in allowed:
            return None
        return v
    return _sshd_scalar_acc(key, parse)


def _sshd_int(key: str) -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    def parse(v: Any) -> Optional[int]:
        return v if type(v) is int and 0 <= v <= 10**9 else None
    return _sshd_scalar_acc(key, parse)


def _is_cut_list(v: Any) -> bool:
    return len(v) >= _MAX_LIST_ITEMS


def _sshd_list(key: str) -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    """A set of names. **An absent key is not the empty set**: no AllowUsers / AllowGroups means every
    account may log in, and ``subset_of`` / ``count()`` over "nobody" would pass the least restricted
    host. So it has no value (``unrestricted``); ``allowusers_set`` / ``allowgroups_set`` say whether
    the key is configured. A list the collector cut (named in ``v.truncated``, or exactly as long as
    its cap) is unknown too: it is a prefix of the truth."""
    def acc(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        cfg, deltas, _variants, trunc = st
        if key in trunc:
            return Unknown("approximate")
        if any(key in dl for dl in deltas):
            return Unknown("match_override")
        v = cfg.get(key)
        if v is None or (_is_seq(v) and not v):
            return Unknown("unrestricted")
        if not _is_seq(v) or not all(isinstance(x, str) for x in v):
            return Unknown("no_value")
        if _is_cut_list(v):
            return Unknown("approximate")
        if key in _ALLOW_LISTS and _list_has_pattern(v):
            return Unknown("no_value")                 # patterns, not names: no set to reason over
        return Known(frozenset(v))
    return acc


def _sshd_listset(key: str) -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    """Is ``key`` (AllowUsers / AllowGroups) configured, for every probed user and address? False
    when some variant has none (everyone may log in there)."""
    def acc(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        _cfg, _deltas, variants, trunc = st
        if key in trunc:
            return Unknown("approximate")

        def one(c: Mapping[str, Any]) -> Tri:
            v = c.get(key)
            if v is None:
                return False
            if not _is_seq(v) or not all(isinstance(x, str) for x in v):
                return None
            if _list_has_pattern(v):
                return None                            # '*' admits everyone: not a restriction we can state
            return len(v) > 0
        v = k_all([one(c) for c in variants])
        return Unknown("no_value") if v is None else Known(v)
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
    that lets another method in; None when it is absent or unreadable (or as long as the collector's
    cap, so possibly cut: a prefix that looks all-publickey proves nothing)."""
    v = c.get("authenticationmethods")
    if not isinstance(v, str):
        return None
    if len(v) >= _MAX_STR_CUT:
        return None
    v = v.strip().lower()
    if not v:
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


def _sshd_derived(fn: Callable[[Mapping[str, Any]], Tri]) -> Callable[[Fact, tuple, "HostCtx"], Outcome]:
    def acc(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
        bad = _need(fact, exact=True)
        if bad:
            return bad
        st = _sshd_state(fact)
        if isinstance(st, Unknown):
            return st
        _cfg, _deltas, variants, _trunc = st      # cut keys are already gone from every variant
        v = k_any([fn(c) for c in variants])      # any probed user/address that can: possible
        return Unknown("no_value") if v is None else Known(v)
    return acc


def _listener_rows(lf: Fact) -> Optional[list]:
    rows = lf.data.get("listeners")
    if not _is_seq(rows):
        return None
    return list(rows)


def _name_is_ssh(name: Any) -> bool:
    """Does a process name (or an executable path's basename) look like an SSH server? Any case:
    ``sshd``, ``SSHD``, ``gitlab-sshd``, ``tinyssh``, ``dropbear``, ``sshd-session``."""
    if not isinstance(name, str):
        return False
    low = name.rsplit("/", 1)[-1].lower()
    return any(h in low for h in _SSH_NAME_HINTS)


def _sshd_seen_elsewhere(host: HostFacts) -> bool:
    """Does the listeners fact (usable or not) show an SSH server? Used only to veto
    ``installed == false``: it can turn that claim into UNKNOWN, never the other way."""
    lf = host.get("listeners")
    if lf is None or lf.status != "ok":
        return False
    rows = _listener_rows(lf)
    if rows is None:
        return True            # a listener table we cannot read cannot clear sshd either
    for r in rows:
        if not _is_map(r):
            return True
        port = r.get("port")
        if type(port) is not int or port == 22:      # a port we cannot read cannot clear port 22
            return True
        if _name_is_ssh(r.get("comm")) or _name_is_ssh(r.get("exe")):
            return True
    return False


def _unlisted_listener(rows: list) -> bool:
    """Is there a non-loopback TCP listener that is not a program known to be no SSH server (nor
    front one)? Unattributed ones, proxies (docker-proxy, rootlessport, kube-proxy, nginx, ...),
    other SSH servers (gitea, teleport, sftpgo, ...) and every name not on ``NON_SSH_COMMS`` count:
    an SSH server on port 2222 behind any of them would otherwise read as "no SSH server"."""
    for r in rows:
        if not _is_map(r):
            return True
        proto = r.get("proto")
        if isinstance(proto, str) and proto.lower().startswith("udp"):
            continue                                  # SSH is TCP (port 22 on any protocol is vetoed above)
        if r.get("bind_class") == "loopback":
            continue
        comm = r.get("comm")
        if not isinstance(comm, str) or comm.lower() not in NON_SSH_COMMS:
            return True
    return False


def _absence_corroborated(ctx: "HostCtx") -> Optional[str]:
    """Why "no sshd" cannot be believed, else ``None``.

    ``tool_missing`` only says no trusted OpenSSH ``sshd`` was found in the usual places; a daemon
    in an unusual path, dropbear, or any other SSH server (gitea, teleport, a container behind
    docker-proxy) would be missed. So the claim also needs a *usable* (signed, fresh, no conflict)
    listener table that is complete, fully attributed to processes, shows nothing on port 22 or named
    like an SSH server, and in which every public TCP listener belongs to a program known to be no
    SSH server. Anything less is UNKNOWN, never "not installed"."""
    if ctx.host.get("listeners") is None:
        return "no_sensor"
    lf = ctx.usable("listeners")
    if lf is None:
        return ctx.why_unusable("listeners")
    if lf.status != "ok":
        return "unavailable" if lf.status == "unavailable" else "collector_error"
    rows = _listener_rows(lf)
    if rows is None or not _complete(lf, rows):
        return "partial"
    att = lf.data.get("attribution")
    if not _is_map(att) or att.get("status") != "ok":
        return "partial"
    if _unlisted_listener(rows):
        return "unlisted_listener"
    return None


def _sshd_installed(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
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
    # "no sshd binary was found": a claim of absence, and ``tool_missing`` is only a weak "nothing
    # seen" signal. A listener that looks like sshd contradicts it, and without a usable, complete
    # listener table whose public listeners are all known non-SSH programs it cannot be corroborated.
    if _sshd_seen_elsewhere(ctx.host):
        return Unknown("evidence_conflict")
    why = _absence_corroborated(ctx)
    if why:
        return Unknown(why, blame=ctx.host.get("listeners"))
    lf = ctx.usable("listeners")
    return Known(False, also=(lf,) if lf is not None else (), note=ABSENCE_NOTE)


# --------------------------------------------------------------------------------------------
# firewall

_FW_DEFAULTS = frozenset(["accept", "drop", "reject", "unknown"])


def _fw_default_all(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    """``deny`` only if the model is exact and every *enabled* family's effective default is
    drop/reject; ``allow`` if an enabled family accepts (exact model); otherwise unknown. IPv6
    counts whenever it is enabled: ip4 dropping while ip6 accepts is ``allow``."""
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
        if not _is_map(f) or f.get("effective_default") not in _FW_DEFAULTS:
            return Unknown("no_value")
        defaults.append((f.get("read") is True, f["effective_default"]))
    if all(r and x in ("drop", "reject") for r, x in defaults):
        return Known("deny")
    if any(r and x == "accept" for r, x in defaults):
        return Known("allow")
    return Unknown("no_value")


def _fw_engine(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    bad = _need(fact, exact=False)
    if bad:
        return bad
    v = fact.data.get("backend")
    if v not in ("nft", "legacy", "mixed", "none"):
        return Unknown("no_value")
    return Known(v)


def _fw_ipv6(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
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


def _listener_exists(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    if _at_port(rows, params[0]):
        return Known(True)
    return Known(False) if _complete(fact, rows) else Unknown("partial")


def _listener_wildcard(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    here = _at_port(rows, params[0])
    if any(r.get("bind_class") in ("wildcard4", "wildcard6") for r in here):
        return Known(True)
    return Known(False) if _complete(fact, rows) else Unknown("partial")


def _listener_process(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
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


def _listeners_count(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    rows = _rows(fact)
    if isinstance(rows, Unknown):
        return rows
    return Known(len(rows)) if _complete(fact, rows) else Unknown("partial")


def _listeners_addresses(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
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


def _patch_security(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
    b = _patch_block(fact, "pending")
    if isinstance(b, Unknown):
        return b
    v = b.get("security")
    return Known(v) if type(v) is int and 0 <= v <= 10**9 else Unknown("no_value")


def _patch_reboot(fact: Fact, params: tuple, ctx: "HostCtx") -> Outcome:
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
                  "an SSH server is installed (false: no trusted OpenSSH sshd was found AND a usable, "
                  "complete, attributed listener table shows no public TCP listener except known "
                  "non-SSH programs: a weaker claim than it sounds, so a HOLDS resting on it says so)",
                  also_collectors=("listeners",)),
        FieldSpec("host.sshd.password_login_possible", "bool", "sshd", CFG,
                  _sshd_derived(_password_possible),
                  "any probed user/address can log in with a password: PasswordAuthentication yes, or "
                  "KbdInteractiveAuthentication yes with UsePAM yes and no public-key-only "
                  "AuthenticationMethods", derived=True),
        FieldSpec("host.sshd.root_login_possible", "bool", "sshd", CFG, _sshd_derived(_root_possible),
                  "any probed user/address allows PermitRootLogin yes (root login with a key only, "
                  "prohibit-password or forced-commands-only, is not counted)", derived=True),
        FieldSpec("host.sshd.passwordauthentication", "str", "sshd", CFG,
                  _sshd_scalar("passwordauthentication", _YESNO), "sshd -T passwordauthentication",
                  choices=_YESNO),
        FieldSpec("host.sshd.kbdinteractiveauthentication", "str", "sshd", CFG,
                  _sshd_scalar("kbdinteractiveauthentication", _YESNO),
                  "sshd -T kbdinteractiveauthentication", choices=_YESNO),
        FieldSpec("host.sshd.permitrootlogin", "str", "sshd", CFG,
                  _sshd_scalar("permitrootlogin", _ROOT_LOGIN),
                  "sshd -T permitrootlogin (without-password reads as prohibit-password)",
                  choices=_ROOT_LOGIN, aliases={"without-password": "prohibit-password"}),
        FieldSpec("host.sshd.permitemptypasswords", "str", "sshd", CFG,
                  _sshd_scalar("permitemptypasswords", _YESNO), "sshd -T permitemptypasswords",
                  choices=_YESNO),
        FieldSpec("host.sshd.pubkeyauthentication", "str", "sshd", CFG,
                  _sshd_scalar("pubkeyauthentication", _YESNO), "sshd -T pubkeyauthentication",
                  choices=_YESNO),
        FieldSpec("host.sshd.usepam", "str", "sshd", CFG, _sshd_scalar("usepam", _YESNO),
                  "sshd -T usepam", choices=_YESNO),
        FieldSpec("host.sshd.authenticationmethods", "str", "sshd", CFG,
                  _sshd_scalar("authenticationmethods", None), "sshd -T authenticationmethods"),
        FieldSpec("host.sshd.maxauthtries", "int", "sshd", CFG, _sshd_int("maxauthtries"),
                  "sshd -T maxauthtries"),
        FieldSpec("host.sshd.allowusers", "set<str>", "sshd", CFG, _sshd_list("allowusers"),
                  "sshd -T allowusers (no value when it is not configured: every account may log "
                  "in; see allowusers_set)"),
        FieldSpec("host.sshd.allowgroups", "set<str>", "sshd", CFG, _sshd_list("allowgroups"),
                  "sshd -T allowgroups (no value when it is not configured: every account may log "
                  "in; see allowgroups_set)"),
        FieldSpec("host.sshd.allowusers_set", "bool", "sshd", CFG, _sshd_listset("allowusers"),
                  "AllowUsers is configured (non-empty) for every probed user/address", derived=True),
        FieldSpec("host.sshd.allowgroups_set", "bool", "sshd", CFG, _sshd_listset("allowgroups"),
                  "AllowGroups is configured (non-empty) for every probed user/address", derived=True),
        FieldSpec("host.fw.default_inbound_all_families", "str", "firewall", CFG, _fw_default_all,
                  "deny: every enabled family drops or rejects inbound by default (exact model); "
                  "allow: some family accepts; otherwise unknown", derived=True,
                  choices=frozenset(["deny", "allow"])),
        FieldSpec("host.fw.engine", "str", "firewall", CFG, _fw_engine,
                  "nft | legacy | mixed | none",
                  choices=frozenset(["nft", "legacy", "mixed", "none"])),
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
    also: tuple = ()                  # corroborating facts the value rests on (see ``Known.also``)
    notes: tuple = ()                 # limits of the evidence a HOLDS must state (``Known.note``)
    variants: tuple = ()              # per-variant values of a key Match blocks change (``Unknown``)


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


class HostCtx:
    """One host as seen by one evaluation: its facts, the clock and the invariant's evidence policy.

    Accessors that need a second collector to corroborate a claim (an absence) must go through
    ``usable``: a stale, unsigned or conflicting fact never corroborates anything."""

    def __init__(self, host: HostFacts, now: dt.datetime, min_tier: Tier,
                 max_age: dt.timedelta) -> None:
        self.host = host
        self.now = now
        self.min_tier = min_tier
        self.max_age = max_age

    def why_unusable(self, collector: str) -> str:
        fact = self.host.get(collector)
        if fact is None:
            return "no_sensor"
        tier = fact.tier if fact.tier.rank <= CFG.rank else CFG
        return trust_problem(fact, tier, self.now, self.min_tier, self.max_age) or ""

    def usable(self, collector: str) -> Optional[Fact]:
        fact = self.host.get(collector)
        if fact is None or self.why_unusable(collector):
            return None
        return fact


def resolve(spec: FieldSpec, params: tuple, host: Optional[HostFacts], now: dt.datetime,
            min_tier: Tier, max_age: dt.timedelta) -> Resolved:
    """The value of ``spec(params)`` on ``host``, or why there is none. Never raises."""
    if host is None:
        return Resolved(False, reason="no_agent")
    if tombstone(host):
        # the agent is revoked / legacy / re-keyed: whatever it signed is not relied on, and the
        # host reads UNKNOWN until an operator closes the finding or a new agent decides it
        return Resolved(False, reason="agent_revoked")
    fact = host.get(spec.collector)
    if fact is None:
        return Resolved(False, reason="no_sensor")
    tier = fact.tier if fact.tier.rank <= spec.max_tier.rank else spec.max_tier
    why = trust_problem(fact, tier, now, min_tier, max_age)
    if why is not None:
        return Resolved(False, reason=why, fact=fact, tier=tier)
    try:
        out = spec.accessor(fact, params, HostCtx(host, now, min_tier, max_age))
    except Exception:                       # noqa: BLE001 - an accessor bug must read as UNKNOWN
        return Resolved(False, reason="no_value", fact=fact, tier=tier)
    if isinstance(out, Known) and _type_ok(spec.type, out.value):
        return Resolved(True, out.value, "", fact, tier, tuple(out.also),
                        (out.note,) if out.note else ())
    if isinstance(out, Unknown):
        if out.blame is not None:
            bt = out.blame.tier if out.blame.tier.rank <= CFG.rank else CFG
            return Resolved(False, reason=out.reason, fact=out.blame, tier=bt)
        return Resolved(False, reason=out.reason, fact=fact, tier=tier, variants=tuple(out.variants))
    return Resolved(False, reason="no_value", fact=fact, tier=tier)
