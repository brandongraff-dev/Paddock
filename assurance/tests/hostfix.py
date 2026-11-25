"""Builders for host-config tests: signed agent facts shaped like the collectors' sections."""
from __future__ import annotations

import datetime as dt
from typing import Any, Optional

from paddock_assurance import ReachGraph, compile_text

NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
FRESH = "2026-12-01T08:30:00Z"       # 30 minutes old
STALE = "2026-11-30T08:30:00Z"       # a day old: stale for every max_age used here
KEY = "0f3a9c1d77b24e5a8c10d2e4b6a8f012"


def fact(data: Optional[dict] = None, *, status: str = "ok", tier: str = "configured",
         seen: str = FRESH, signed: bool = True, conf: str = "exact", partial: bool = False,
         seq: int = 7, conflict: Any = None, reason: str = "", source: str = "agent",
         key_id: str = KEY, ref: Optional[str] = None) -> dict[str, Any]:
    f: dict[str, Any] = {"status": status, "tier": tier, "observed_at": seen, "signed": signed,
                         "source": source, "key_id": key_id, "seq": seq,
                         "evidence_ref": ref if ref is not None else f"posture:{seq}",
                         "conf": conf, "partial": partial, "data": data if data is not None else {}}
    if conflict is not None:
        f["conflict"] = conflict
    if reason:
        f["reason"] = reason
    return f


def sshd_config(**over: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
        "permitrootlogin": "no", "pubkeyauthentication": "yes", "permitemptypasswords": "no",
        "usepam": "yes", "maxauthtries": 3, "authenticationmethods": "any", "port": [22]}
    cfg.update(over)
    return cfg


def sshd_daemon(**over: Any) -> dict[str, Any]:
    """``v.daemon`` of a current agent: every key always present; ``reload_pending: false`` is the
    positive evidence that the files on disk are what the running daemon loaded."""
    d: dict[str, Any] = {
        "found": True, "masters": 1, "pid": 812, "start_epoch": 1780000000, "reexec_epoch": None,
        "config_path": None, "config_default": True, "options_override": False,
        "binary_matches": True, "config_mtime": 1770000000, "reload_pending": False}
    d.update(over)
    return d


def sshd(deltas: Optional[list] = None, unprobed: bool = False, source: str = "sshd_T",
         daemon: Any = True, truncated: Optional[list] = None, **over: Any) -> dict[str, Any]:
    """The ``data`` of an sshd fact (the collector's ``v``). ``daemon``: ``True`` = a current agent
    with nothing pending, a dict = overrides on that, ``None`` = no ``daemon`` key (an old agent).
    ``truncated`` = the ``v.truncated`` key list (absent when ``None``)."""
    v: dict[str, Any] = {
        "installed": True, "source": source, "config": sshd_config(**over),
        "probes": {"deltas": [{"user": "root", "addr": "203.0.113.7", "delta": d}
                              for d in (deltas or [])]},
        "match": {"blocks": 1 if deltas else 0, "unprobed": unprobed}}
    if daemon is not None:
        v["daemon"] = sshd_daemon(**(daemon if isinstance(daemon, dict) else {}))
    if truncated is not None:
        v["truncated"] = truncated
    return v


def firewall(ip4: str = "drop", ip6: str = "drop", *, ipv6: bool = True, confidence: str = "exact",
             backend: str = "nft", read6: bool = True, **extra: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "backend": backend, "ipv6_enabled": ipv6,
        "families": {"ip4": {"read": True, "effective_default": ip4},
                     "ip6": {"read": read6, "effective_default": ip6}},
        "flat_view": {"default_input_policy": ip4, "confidence": confidence},
        "opaque_features": [], "dataplane": []}
    d.update(extra)
    return d


def listeners(ports: tuple = (22, 443), *, comms: Optional[dict] = None, count: Optional[int] = None,
              attribution: str = "ok", ip: str = "0.0.0.0", bind: str = "wildcard4") -> dict[str, Any]:
    comms = comms or {}
    rows = [{"proto": "tcp", "ip": ip, "port": p, "bind_class": bind,
             "comm": comms.get(p, "sshd" if p == 22 else "nginx")} for p in ports]
    return {"count": len(rows) if count is None else count, "listeners": rows,
            "attribution": {"status": attribution}}


def patch(security: int = 0, reboot: bool = False) -> dict[str, Any]:
    return {"pending": {"state": "ok", "security": security},
            "reboot": {"state": "ok", "required": reboot}}


def good_facts(**over: Any) -> dict[str, Any]:
    """A hardened, fully observed server. ``over`` replaces whole collector facts."""
    f = {"sshd": fact(sshd()), "firewall": fact(firewall()), "listeners": fact(listeners()),
         "patch": fact(patch())}
    f.update(over)
    return f


def hnode(id_: str, facts: Optional[dict] = None, *, tags: tuple = ("agent", "server"),
          zone: Optional[str] = None, kind: str = "host") -> dict[str, Any]:
    n: dict[str, Any] = {"id": id_, "kind": kind, "tags": list(tags)}
    if zone:
        n["zone"] = zone
    if facts is not None:
        n["facts"] = facts
    return n


def hgraph(*nodes: dict) -> ReachGraph:
    return ReachGraph.from_dict({"version": 1, "nodes": list(nodes), "edges": []})


HOST_YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:host-rule
title: Host rule under test
severity: high
subjects: {{ to: {{ tag: [agent, server] }} }}
assert: {assert_}
evidence: {{ min_tier: configured, max_age: 6h }}
coverage: {{ require: 1.0 }}
"""


def host_plan(assert_yaml: str, extra: str = ""):
    """Compile a host-config invariant; ``assert_yaml`` is the YAML value of ``assert:``
    (indent block mappings by two spaces under a newline)."""
    text = HOST_YAML.format(assert_=assert_yaml) + extra
    return compile_text(text)


def host_plan_doc(doc: dict, *, min_tier: str = "configured", max_age: str = "6h",
                  require: float = 1.0, tag: Any = ("agent", "server")):
    """Compile from a Python mapping (assert given as data), via JSON-compatible YAML."""
    import json
    full = {"apiVersion": "paddock.dev/invariant/v1", "id": "acme:host-rule",
            "title": "Host rule under test", "severity": "high",
            "subjects": {"to": {"tag": list(tag)}}, "assert": doc,
            "evidence": {"min_tier": min_tier, "max_age": max_age},
            "coverage": {"require": require}}
    return compile_text(json.dumps(full))
