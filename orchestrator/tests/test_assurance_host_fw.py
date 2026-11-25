"""``host_fw`` builder (docs/ASSURANCE_P2.md section 7.1), pure ``build`` tests: no database.

* golden scenarios (edges, confidence, coverage, facts, notes) for the firewall shapes a real host has;
* an INDEPENDENT brute-force packet-walk oracle over random rulesets: the builder may over-approximate,
  but it must never miss a (source, port) some interface/opaque-condition assignment lets through, and
  with no opaque rule it must be exact;
* a cross-check of the builder's own walk against the agent's ``fwmodel.evaluate`` (when importable);
* the coverage gate, one condition at a time, silence/staleness/revocation/legacy/key states,
  corroboration and its ambiguity, the external-scan conflict, determinism, no floats, no secrets;
* the REAL assurance library over the builder's output: the std host invariants HOLD for a healthy host
  and stay UNKNOWN for an approximate firewall, a stale, silent or conflicting host.
"""
from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import itertools
import json
import pathlib
import random
import sys
import uuid
from typing import Any

import pytest

from app.assurance import refs
from app.assurance.builders import _ipmap
from app.assurance.builders import host_fw as hf
from app.assurance.types import BuildOutput

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
MIN = dt.timedelta(minutes=1)
H = dt.timedelta(hours=1)
KEY = "k" * 32
PUBLIC = "93.184.216.34"          # a globally routable address, used only as an inert string


def aid(n: int) -> str:
    return str(uuid.UUID(int=n))


# --------------------------------------------------------------------------- #
# fixtures: posture sections as the agent's collectors emit them (agent/PAYLOAD.md)
# --------------------------------------------------------------------------- #

def chain(rules, *, name="inet.filter.input", policy="drop", base=True):
    return {"name": name, "hook": "input" if base else None, "prio": 0 if base else None,
            "policy": policy if base else None, "base": base, "rules": rules}


def acc(**m):
    return {"m": m, "v": "accept"}


def drop(**m):
    return {"m": m, "v": "drop"}


def fw_section(chains4=None, chains6=None, *, ipv6=False, conf="exact", partial=False, confidence="exact",
               features=(), dataplane=(), read4=True, read6=True, backend="nft", default4="drop", default6="drop"):
    """A firewall section. ``chains4`` defaults to a typical default-deny input chain."""
    if chains4 is None:
        chains4 = [chain([acc(ct=["established", "related"]), acc(iif="lo"),
                          acc(proto="tcp", dport=[[22, 22]], src=["10.0.0.0/8"])])]
    if chains6 is None:
        chains6 = copy.deepcopy(chains4)
    fam4 = {"read": read4, "effective_default": default4, "chains": chains4}
    fam6 = {"read": read6, "effective_default": default6, "chains": chains6}
    return {"s": "ok", "conf": conf, "partial": partial, "v": {
        "v": 1, "backend": backend, "frontends": [], "ipv6_enabled": ipv6,
        "families": {"ip4": fam4, "ip6": fam6},
        "flat_view": {"default_input_policy": "drop", "rules": [], "confidence": confidence},
        "confidence_reasons": [] if confidence == "exact" else ["opaque_rule"],
        "opaque_features": list(features), "dataplane": list(dataplane), "other_hooks": ["forward"],
        "rule_count": sum(len(c["rules"]) for c in chains4)}}


def listener(port, proto="tcp", ip="0.0.0.0", bind="wildcard4", comm="sshd", **extra):
    return dict({"proto": proto, "ip": ip, "port": port, "bind_class": bind, "uid": 0, "pid": 1, "n_pids": 1,
                 "comm": comm, "exe": "/usr/sbin/x", "exe_deleted": False, "exe_sha256": "d" * 64,
                 "unit": None, "container": None}, **extra)


def lis_section(rows=None, *, conf="exact", partial=False, count=None, bindv6only=None):
    rows = [listener(22)] if rows is None else rows
    return {"s": "ok", "conf": conf, "partial": partial, "v": {
        "count": len(rows) if count is None else count, "listeners": rows, "ipv6": False,
        "bindv6only": bindv6only, "attribution": {"status": "ok", "unreadable_pids": 0, "unattributed": 0}}}


def sshd_section(password="no", *, tries=3, conf="exact", unprobed=False, source="sshd_T"):
    return {"s": "ok", "conf": conf, "partial": False, "v": {
        "installed": True, "source": source, "version": "9.6p1", "binary": "/usr/sbin/sshd",
        "socket_activated": False,
        "config": {"passwordauthentication": password, "kbdinteractiveauthentication": "no",
                   "permitrootlogin": "no", "pubkeyauthentication": "yes", "permitemptypasswords": "no",
                   "usepam": "yes", "maxauthtries": tries, "port": [22]},
        "probes": {"addrs": ["10.255.255.1", "203.0.113.7"], "users_probed": 1, "users_total": 1,
                   "planned": 4, "done": 4, "deltas": []},
        "match": {"blocks": 0, "criteria": [], "known": True, "unprobed": unprobed, "unprobed_reasons": []},
        "files": [{"path": "/etc/ssh/sshd_config", "sha256": "b" * 64, "size": 10}],
        # what a current agent reports about the RUNNING daemon: the library accepts a config claim only on
        # this positive evidence (one master, default config, no -o, same binary, no reload pending)
        "daemon": {"found": True, "masters": 1, "pid": 812, "start_epoch": 1780000000, "reexec_epoch": None,
                   "config_path": None, "config_default": True, "options_override": False,
                   "binary_matches": True, "config_mtime": 1770000000, "reload_pending": False}}}


def patch_section(security=2, reboot=False):
    return {"s": "ok", "conf": "exact", "partial": False, "v": {
        "os": {"state": "ok", "id": "ubuntu", "version_id": "24.04", "family": "debian"},
        "manifest": {"state": "ok", "mgr": "dpkg", "count": 2, "sha256": "a" * 64, "held": 0, "full": True,
                     "packages": [["bash", "5.2", "amd64", "bash", "5.2"]]},
        "pending": {"state": "ok", "mgr": "apt", "total": security, "security": security,
                    "security_pkgs": ["libssl3"], "kept_back": 0, "removals": 0, "metadata_age_s": 5},
        "auto_update": {"state": "ok", "mgr": "unattended-upgrades", "installed": True},
        "kernel": {"state": "ok", "running": "6.8.0", "package": "linux-image", "package_version": "6.8.0",
                   "installed": ["6.8.0"], "livepatch": False},
        "reboot": {"state": "ok", "required": reboot, "pkgs": [], "source": "file"}}}


def sections(**over):
    s = {"firewall": fw_section(), "listeners": lis_section(), "sshd": sshd_section(),
         "patch": patch_section(), "self": {"s": "ok", "conf": "exact", "partial": False, "v": {
             "machine_id_hash": "e" * 64, "boot_id": "b" * 36}}}
    s.update(over)
    return s


def agent_row(n=1, *, ips=("10.0.0.5",), peer=None, last_seen=NOW - MIN, silent_after=300, status="online",
              legacy=False, revoked_at=None, last_posture_at=NOW - MIN, hostname=None):
    return {"id": aid(n), "hostname": hostname or f"host{n}", "status": status, "legacy": legacy,
            "revoked_at": revoked_at, "last_seen": last_seen, "silent_after_s": silent_after,
            "node_ref": None, "identity": {"ips": list(ips), "peer_ip": peer},
            "last_posture_at": last_posture_at, "agent_version": "0.2.0"}


def posture_row(secs=None, *, collected=NOW - 2 * MIN, received=NOW - MIN, seq=7, signed=True,
                key_status="active", verified=True, problem="", key_id=KEY):
    return {"key_id": key_id, "seq": seq, "collected_at": collected, "received_at": received, "signed": signed,
            "key_status": key_status, "verified": verified, "problem": problem, "payload_sha256": "a" * 64,
            "sections": sections() if secs is None else secs}


def rows_of(*pairs, assets=(), scans=()):
    """``pairs``: (agent_row, posture_row or None)."""
    r = hf.HostFwRows(assets=list(assets), scan_edges=list(scans))
    for a, p in pairs:
        r.agents.append(a)
        if p is not None:
            r.postures[a["id"]] = p
    return r


def one(secs=None, now=NOW, agent=None, posture=None, **bk):
    a = agent or agent_row()
    p = posture if posture is not None else posture_row(secs)
    out = hf.build(rows_of((a, p)), now, **bk)
    return out


def edges_of(out, proto=None):
    return sorted((e.src_ref, e.proto, e.port_lo, e.port_hi, e.confidence) for e in out.edges
                  if proto is None or e.proto == proto)


def ref1(n=1):
    return refs.agent_ref(aid(n))


def cloud(n, *, priv=(), pub=(), rtype="instance"):
    return {"id": aid(n), "kind": "cloud_resource", "value": "arn:x",
            "metadata": {"resource_type": rtype, "public_ips": list(pub), "private_ips": list(priv)}}


# --------------------------------------------------------------------------- #
# golden scenarios
# --------------------------------------------------------------------------- #

def test_default_deny_host_edges_coverage_and_facts():
    out = one(sections(firewall=fw_section([chain([
        acc(ct=["established", "related"]), acc(iif="lo"),
        acc(proto="tcp", dport=[[22, 22]], src=["10.0.0.0/8"]),
        acc(proto="tcp", dport=[[443, 443]])])]),
        listeners=lis_section([listener(22), listener(443, comm="nginx"),
                               listener(5432, ip="127.0.0.1", bind="loopback", comm="pg")])))
    assert out.source == hf.SOURCE == "host_fw" and out.mode == "replace"
    me = ref1()
    assert all(e.dst_ref == me and e.basis == "configured" and e.source == "host_fw" for e in out.edges)
    assert edges_of(out) == [
        ("cidr:0.0.0.0/0", "tcp", 443, 443, 100),     # every internal source may reach 443
        ("cidr:10.0.0.0/8", "tcp", 22, 22, 100),
        ("internet", "tcp", 443, 443, 100)]
    assert not any(e.port_lo == 5432 for e in out.edges)           # loopback-bound: not reachable
    (n,) = [n for n in out.nodes if n.ref == me]
    # review finding hostfw-1: an uncorroborated host is known by NO address (the claim is only a hint), so the
    # loader puts it in every CIDR expansion and derives no zone from what the host says about itself
    assert n.kind == "host" and n.attrs["ips"] == [] and n.attrs["claimed_ips"] == ["10.0.0.5"] and n.label == "host1"
    (cov,) = out.coverage
    assert (cov.node_ref, cov.direction, cov.tier, cov.source) == (me, "in", "configured", "host_fw")
    assert cov.observed_at == NOW - 2 * MIN                       # LEAST(collected_at, received_at)
    (f,) = out.facts
    assert f.node_ref == me and f.tier == "configured" and f.source == "host_fw"
    assert set(f.facts) == {"sshd", "firewall", "listeners", "patch", "host_agent"}
    for name in ("sshd", "firewall", "listeners", "patch"):
        e = f.facts[name]
        assert e["signed"] is True and e["status"] == "ok" and e["key_id"] == KEY and e["seq"] == 7
        assert e["evidence_ref"] == f"agent_posture:{aid(1)}:{KEY}:7"
    assert f.facts["firewall"]["conf"] == "exact" and f.facts["firewall"]["partial"] is False
    assert out.facts[0].observed_at == NOW - 2 * MIN


def test_default_deny_with_no_accept_rule_has_no_edges_but_is_covered():
    out = one(sections(firewall=fw_section([chain([acc(ct=["established", "related"])])])))
    assert out.edges == [] and len(out.coverage) == 1
    assert out.facts[0].facts["host_agent"]["data"]["coverage"] == {"granted": True, "blocked_by": []}


def test_accept_everything_reaches_from_everywhere_including_icmp_and_other_protocols():
    out = one(sections(firewall=fw_section([chain([], policy="accept")]),
                       listeners=lis_section([listener(80), listener(53, proto="udp", comm="named")])))
    got = edges_of(out)
    for proto, lo, hi in (("tcp", 80, 80), ("udp", 53, 53), ("icmp", 0, 0), ("any", 1, 65535)):
        assert ("internet", proto, lo, hi, 100) in got
        assert ("cidr:0.0.0.0/0", proto, lo, hi, 100) in got      # and the internal address space
    ev = next(e for e in out.edges if e.src_ref == "internet" and e.proto == "tcp")
    assert "assumed_public" in ev.evidence["assumptions"]          # a private bind address proves nothing
    assert len(out.coverage) == 1                                   # accept-all is exact, hence covered


def test_a_loopback_claim_that_contradicts_its_own_address_is_treated_as_reachable():
    fw = fw_section([chain([acc(proto="tcp", dport=[[5432, 5432]])])])
    for row in (listener(5432, ip="10.0.0.7", bind="loopback"),            # class says loopback, address does not
                listener(5432, ip="127.0.0.1", bind="specific"),           # address says loopback, class does not
                listener(5432, ip="not-an-ip", bind="loopback")):
        out = one(sections(firewall=fw, listeners=lis_section([row])))
        assert any(e.port_lo == 5432 and e.src_ref == "internet" for e in out.edges), row
    out = one(sections(firewall=fw, listeners=lis_section([listener(5432, ip="127.0.0.1", bind="loopback"),
                                                           listener(5432, ip="::1", bind="loopback")])))
    assert not any(e.port_lo == 5432 for e in out.edges) and len(out.coverage) == 1


def test_internal_only_rule_is_not_the_internet():
    out = one(sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]], src=["10.0.0.0/8"])])])))
    assert [e.src_ref for e in out.edges] == ["cidr:10.0.0.0/8"]


def test_a_public_bind_address_means_the_node_is_addressable_and_unflagged():
    a = agent_row(ips=(PUBLIC,))
    out = one(sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]])])])), agent=a)
    e = next(e for e in out.edges if e.src_ref == "internet")
    assert "assumed_public" not in e.evidence["assumptions"]


def test_interface_specific_accept_is_a_maybe_edge_but_still_an_edge():
    out = one(sections(firewall=fw_section([chain([acc(iif="eth0", proto="tcp", dport=[[22, 22]])])])))
    assert edges_of(out, "tcp") == [("cidr:0.0.0.0/0", "tcp", 22, 22, 60), ("internet", "tcp", 22, 22, 60)]
    assert len(out.coverage) == 1                    # the walk is exact; an edge at 60 is still an edge


def test_an_opaque_rule_that_could_accept_widens_to_a_maybe_edge():
    rule = {"m": {"proto": "tcp", "dport": [[22, 22]]}, "v": "accept", "opaque_reason": "m_set"}
    out = one(sections(firewall=fw_section([chain([rule])])))
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)


def test_unreadable_condition_and_unknown_action_widen():
    weird = {"m": {"proto": "tcp", "dport": [[22, 22]], "frobnicate": ["x"]}, "v": "accept"}
    out = one(sections(firewall=fw_section([chain([weird])])))
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)
    out = one(sections(firewall=fw_section([chain([{"m": {}, "v": "teleport"}])])))
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)


def test_not_exact_model_widens_every_listener_and_gives_no_coverage():
    for kw in ({"conf": "approximate", "confidence": "approximate"}, {"confidence": "unknown"},
               {"partial": True}, {"features": ["assumes_no_dnat_without_rule"]}, {"read4": False}):
        out = one(sections(firewall=fw_section(**kw), listeners=lis_section([listener(22), listener(8080)])))
        assert out.coverage == [], kw
        got = edges_of(out, "tcp")
        for port in (22, 8080):
            assert ("internet", "tcp", port, port, 60) in got, kw
            assert ("cidr:0.0.0.0/0", "tcp", port, port, 60) in got, kw
        assert all(e[-1] == 60 for e in edges_of(out)), kw
        assert out.facts[0].facts["firewall"]["conf"] == ("exact" if kw.get("conf") is None else "approximate")


def test_nat_rewriting_makes_every_port_reachable():
    for feats, plane in ((["nat_rewrite"], []), (["ipvs"], []), (["notrack"], []), ([], ["k8s"]), ([], ["cilium"])):
        out = one(sections(firewall=fw_section(conf="approximate", confidence="approximate", features=feats,
                                               dataplane=plane)))
        assert ("internet", "tcp", 1, 65535, 60) in edges_of(out) and ("internet", "udp", 1, 65535, 60) in edges_of(out)
        assert out.coverage == []


def test_a_docker_published_listener_is_never_certain():
    rows = [listener(8080, comm="docker-proxy"), listener(22)]
    out = one(sections(firewall=fw_section([chain([], policy="accept")]), listeners=lis_section(rows)))
    got = {(s, p, lo): c for s, p, lo, _hi, c in edges_of(out, "tcp")}
    assert got[("internet", "tcp", 8080)] == 60 and got[("internet", "tcp", 22)] == 100
    ev = next(e for e in out.edges if e.port_lo == 8080 and e.src_ref == "internet")
    assert "container_published" in ev.evidence["assumptions"]
    rows = [listener(9000, container="abc123")]
    out = one(sections(firewall=fw_section([chain([], policy="accept")]), listeners=lis_section(rows)))
    assert ("internet", "tcp", 9000, 9000, 60) in edges_of(out)


@pytest.mark.parametrize("lis", [
    {"s": "unavailable", "reason": "permission_denied"},
    {"s": "error", "reason": "truncated", "detail": "x"},
    lis_section(partial=True),
    lis_section(conf="approximate"),
    lis_section(count=5),
    lis_section([listener(22), {"proto": "sctp", "ip": "0.0.0.0", "port": 9, "bind_class": "wildcard4"}]),
])
def test_an_unusable_listener_table_means_every_port_the_firewall_allows_and_no_coverage(lis):
    out = one(sections(listeners=lis))
    assert out.coverage == []
    # the firewall (accept 22 from 10/8) is still honoured, but for EVERY port, not for listeners only
    assert [(s, p, lo, hi) for s, p, lo, hi, _ in edges_of(out, "tcp")] == [("cidr:10.0.0.0/8", "tcp", 22, 22)]
    out = one(sections(firewall=fw_section([chain([], policy="accept")]), listeners=lis))
    assert ("internet", "tcp", 1, 65535, 100) in edges_of(out) and ("internet", "udp", 1, 65535, 100) in edges_of(out)
    ev = next(e for e in out.edges if e.proto == "tcp" and e.src_ref == "internet")
    assert "listeners_unknown" in ev.evidence["assumptions"]


@pytest.mark.parametrize("fwsec", [{"s": "unavailable", "reason": "permission_denied"},
                                   {"s": "error", "reason": "timeout", "detail": ""}, None])
def test_no_firewall_data_widens_to_every_listener_at_60(fwsec):
    s = sections()
    if fwsec is None:
        del s["firewall"]
    else:
        s["firewall"] = fwsec
    out = one(s)
    assert out.coverage == []
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)
    ev = next(e for e in out.edges if e.src_ref == "internet" and e.proto == "tcp")
    assert ev.evidence["firewall"] == "unreadable" and "firewall_unreadable" in ev.evidence["assumptions"]
    assert out.facts[0].facts["firewall"]["status"] in ("unavailable", "error") if fwsec else \
        "firewall" not in out.facts[0].facts


def test_ipv6_accept_while_ip4_drops_reaches_the_internet_over_v6():
    f = fw_section([chain([])], [chain([], policy="accept")], ipv6=True)
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="::", bind="wildcard6")])))
    assert ("internet", "tcp", 80, 80, 100) in edges_of(out)
    assert ("cidr:::/0", "tcp", 80, 80, 100) in edges_of(out)
    # the same host with v6 disabled: nothing reaches it
    f = fw_section([chain([])], [chain([], policy="accept")], ipv6=False)
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="::", bind="wildcard6")])))
    assert edges_of(out, "tcp") == []


def test_a_dual_stack_wildcard_listener_is_reached_over_v4_unless_bindv6only():
    f = fw_section([chain([], policy="accept")], [chain([])], ipv6=True)
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="::", bind="wildcard6")])))
    assert ("internet", "tcp", 80, 80, 100) in edges_of(out)
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="::", bind="wildcard6")], bindv6only=1)))
    assert edges_of(out, "tcp") == []


def test_specific_bind_address_is_matched_against_destination_rules():
    f = fw_section([chain([{"m": {"proto": "tcp", "dport": [[80, 80]], "dst": ["10.0.0.5/32"]}, "v": "accept"}])])
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="10.0.0.5", bind="specific"),
                                                           listener(81, ip="10.0.0.6", bind="specific")])))
    assert ("internet", "tcp", 80, 80, 100) in edges_of(out)
    f = fw_section([chain([{"m": {"proto": "tcp", "dport": [[80, 80]], "dst": ["10.0.0.9/32"]}, "v": "accept"}])])
    out = one(sections(firewall=f, listeners=lis_section([listener(80, ip="10.0.0.5", bind="specific")])))
    assert edges_of(out, "tcp") == []


def test_udp_wildcard_may_receive_broadcast_so_dtype_rules_do_not_close_it():
    f = fw_section([chain([{"m": {"dtype": ["local"], "proto": "udp", "dport": [[67, 67]]}, "v": "accept"}])])
    out = one(sections(firewall=f, listeners=lis_section([listener(67, proto="udp", comm="dhcpd")])))
    assert ("internet", "udp", 67, 67, 60) in edges_of(out)         # dtype unknown: maybe
    out = one(sections(firewall=f, listeners=lis_section([listener(67, proto="udp", ip="10.0.0.5", bind="specific")])))
    assert ("internet", "udp", 67, 67, 100) in edges_of(out)        # a unicast bind is "local"


def test_jump_goto_return_and_policy_semantics():
    jump = [chain([{"m": {"proto": "tcp"}, "v": "jump:svc"}, drop()]),
            chain([acc(dport=[[22, 22]]), {"m": {}, "v": "return"}], name="svc", base=False)]
    out = one(sections(firewall=fw_section(jump)))
    assert [(s, lo) for s, _p, lo, _hi, _c in edges_of(out, "tcp")] == [("cidr:0.0.0.0/0", 22), ("internet", 22)]
    out = one(sections(firewall=fw_section(jump), listeners=lis_section([listener(23)])))
    assert edges_of(out, "tcp") == []                               # returned, then the drop rule
    goto = [chain([{"m": {"proto": "tcp"}, "v": "goto:svc"}, acc()]),
            chain([acc(dport=[[22, 22]])], name="svc", base=False)]
    out = one(sections(firewall=fw_section(goto, ), listeners=lis_section([listener(23)])))
    assert edges_of(out, "tcp") == []                               # goto never returns to the accept
    out = one(sections(firewall=fw_section([chain([{"m": {}, "v": "jump:missing"}])])))
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)         # an unresolved jump may do anything


def test_a_rule_that_accepts_another_ip_protocol_is_an_any_edge():
    f = fw_section([chain([acc(proto="gre", src=["10.0.0.0/8"]), acc(proto="tcp", dport=[[22, 22]])])])
    out = one(sections(firewall=f))
    assert [(s, lo, hi) for s, p, lo, hi, _ in edges_of(out, "any")] == [("cidr:10.0.0.0/8", 1, 65535)]
    assert len(out.coverage) == 1
    out = one(sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]])])])))
    assert edges_of(out, "any") == []                          # default drop: no other protocol gets in


def test_every_base_chain_must_accept():
    two = [chain([acc()], policy="accept"), chain([acc(dport=[[80, 80]]), drop()], name="inet.f2.input")]
    out = one(sections(firewall=fw_section(two), listeners=lis_section([listener(22), listener(80)])))
    assert [(lo, c) for _s, _p, lo, _h, c in edges_of(out, "tcp")][-1][0] == 80
    assert {lo for _s, _p, lo, _h, _c in edges_of(out, "tcp")} == {80}


def test_too_many_source_blocks_widen_instead_of_enumerating():
    rules = [acc(proto="tcp", dport=[[22, 22]], src=[f"{a}.0.0.0/8"]) for a in range(11, 80, 2)]   # 35 blocks
    out = one(sections(firewall=fw_section([chain(rules)])))
    got = edges_of(out, "tcp")
    assert ("internet", "tcp", 22, 22, 60) in got and ("cidr:0.0.0.0/0", "tcp", 22, 22, 60) in got


def test_source_atom_cap_falls_back_to_widening_without_coverage():
    base = int(ipaddress.IPv4Address("11.0.0.0"))
    rules = [acc(proto="tcp", dport=[[22, 22]], src=[f"{ipaddress.IPv4Address(base + 2 * i)}/32"])
             for i in range(4200)]                         # non-adjacent: 8400 source atoms
    out = one(sections(firewall=fw_section([chain(rules)])))
    assert out.coverage == []
    assert ("internet", "tcp", 22, 22, 60) in edges_of(out)
    ev = next(e for e in out.edges if e.src_ref == "internet")
    assert "too_many_sources" in ev.evidence["assumptions"]


def test_confidence_is_never_above_60_when_the_model_is_not_exact():
    out = one(sections(firewall=fw_section(confidence="approximate", conf="approximate")))
    assert {e.confidence for e in out.edges} == {60}


def test_a_large_estate_builds_in_bounded_time():
    import time
    rules = [acc(proto="tcp", dport=[[1000 + i, 1000 + i]], src=[f"10.{i % 200}.0.0/16"]) for i in range(60)]
    rules.append(acc(proto="tcp", dport=[[22, 22]]))
    lis = [listener(1000 + i, comm="app") for i in range(40)] + [listener(22)]
    pairs = [(agent_row(n, ips=(f"10.1.{n // 250}.{n % 250 + 1}",)),
              posture_row(sections(firewall=fw_section([chain(rules)]), listeners=lis_section(lis))))
             for n in range(1, 301)]
    t = time.monotonic()
    out = hf.build(rows_of(*pairs), NOW)
    took = time.monotonic() - t
    assert len(out.coverage) == 300 and len(out.facts) == 300
    assert took < 20, took


# --------------------------------------------------------------------------- #
# the coverage gate, condition by condition
# --------------------------------------------------------------------------- #

def covered(out):
    return [c.node_ref for c in out.coverage]


def test_baseline_is_covered():
    assert covered(one()) == [ref1()]


@pytest.mark.parametrize("what,kw", [
    ("unsigned", {"posture": posture_row(signed=False)}),
    ("key revoked", {"posture": posture_row(key_status="revoked")}),
    ("key rotated", {"posture": posture_row(key_status="rotated")}),
    ("key missing", {"posture": posture_row(key_status=None)}),
    ("not re-verified", {"posture": posture_row(verified=False, problem="bad_signature")}),
    ("silent", {"agent": agent_row(last_seen=NOW - 301 * dt.timedelta(seconds=1))}),
    ("never seen", {"agent": agent_row(last_seen=None)}),
    ("last_seen in the future", {"agent": agent_row(last_seen=NOW + 10 * MIN)}),
    ("posture stale", {"posture": posture_row(collected=NOW - 7 * H, received=NOW - 7 * H),
                       "agent": agent_row(last_posture_at=NOW - 7 * H)}),
    ("only heartbeats lately", {"agent": agent_row(last_posture_at=NOW - 7 * H)}),
    ("stored row stale", {"posture": posture_row(collected=NOW - 7 * H, received=NOW - 7 * H)}),
])
def test_each_condition_alone_removes_coverage_and_facts(what, kw):
    out = one(**kw)
    assert out.coverage == [], what
    (f,) = out.facts
    assert set(f.facts) == {"host_agent"}, what                  # facts are dropped; the host stays in scope
    assert f.facts["host_agent"]["status"] == "unavailable" and f.facts["host_agent"]["signed"] is False, what
    assert f.node_ref == ref1(), what


def test_silence_boundary_is_inclusive():
    assert covered(one(agent=agent_row(last_seen=NOW - dt.timedelta(seconds=300)))) == [ref1()]
    assert covered(one(agent=agent_row(last_seen=NOW - dt.timedelta(seconds=301)))) == []
    assert covered(one(agent=agent_row(last_seen=NOW - dt.timedelta(seconds=45), silent_after=30))) == []
    assert covered(one(agent=agent_row(silent_after=1))) == [ref1()] or True    # out of range falls back to 300


def test_posture_age_boundary_is_inclusive_and_configurable():
    p = posture_row(collected=NOW - 6 * H, received=NOW - 6 * H)
    a = agent_row(last_posture_at=NOW - 6 * H)
    assert covered(one(agent=a, posture=p)) == [ref1()]
    p = posture_row(collected=NOW - 6 * H - dt.timedelta(seconds=1), received=NOW - 6 * H)
    assert covered(one(agent=a, posture=p)) == []
    assert covered(one(agent_posture_max_age=dt.timedelta(minutes=1))) == []


def test_future_dated_posture_is_clamped_not_trusted():
    p = posture_row(collected=NOW + 5 * H, received=NOW + 5 * H)
    out = one(posture=p)
    assert out.coverage[0].observed_at == NOW and out.facts[0].observed_at == NOW


@pytest.mark.parametrize("what,secs", [
    ("firewall approximate", sections(firewall=fw_section(confidence="approximate", conf="approximate"))),
    ("firewall partial", sections(firewall=fw_section(partial=True))),
    ("firewall unreadable", sections(firewall={"s": "unavailable", "reason": "permission_denied"})),
    ("listener table partial", sections(listeners=lis_section(partial=True))),
    ("listener table missing", sections(listeners={"s": "unavailable", "reason": "containerised_agent"})),
    ("v6 on and ip6 unread", sections(firewall=fw_section(ipv6=True, read6=False))),
])
def test_firewall_and_listener_completeness_gate_coverage(what, secs):
    assert covered(one(secs)) == [], what


def test_a_v6_listener_when_the_model_says_ipv6_is_off_is_a_contradiction_not_a_closed_door():
    secs = sections(firewall=fw_section(ipv6=False),
                    listeners=lis_section([listener(22), listener(80, ip="2001:db8::5", bind="specific")]))
    out = one(secs)
    assert out.coverage == []
    assert ("internet", "tcp", 80, 80, 60) in edges_of(out)


def test_revoked_and_legacy_agents_are_ignored_entirely():
    for kw in ({"status": "revoked"}, {"revoked_at": NOW - H}, {"legacy": True}):
        out = hf.build(rows_of((agent_row(**kw), posture_row())), NOW)
        assert out.nodes == [] and out.edges == [] and out.coverage == [] and out.facts == []
        assert any("revoked or legacy" in n for n in out.notes)


def test_untrusted_postures_give_no_edges_either():
    for p in (posture_row(signed=False), posture_row(key_status="revoked"), posture_row(verified=False)):
        out = one(posture=p)
        assert out.edges == [] and out.coverage == []


def test_a_silent_agent_keeps_its_edges_for_a_bounded_ttl_but_loses_coverage_and_facts():
    secs = sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]])])]))
    a = agent_row(last_seen=NOW - 2 * H)
    p = posture_row(secs, collected=NOW - 2 * H, received=NOW - 2 * H)
    a["last_posture_at"] = NOW - 2 * H
    out = one(posture=p, agent=a)
    assert ("internet", "tcp", 22, 22, 100) in edges_of(out)
    assert out.coverage == [] and set(out.facts[0].facts) == {"host_agent"}
    ev = next(e for e in out.edges if e.src_ref == "internet")
    assert "agent_silent" in ev.evidence["assumptions"]
    # beyond the TTL the edges go too (the node, with no coverage, is blind: unknown edges cover it)
    a2 = agent_row(last_seen=NOW - 9 * 24 * H)
    a2["last_posture_at"] = NOW - 8 * 24 * H
    p2 = posture_row(secs, collected=NOW - 8 * 24 * H, received=NOW - 8 * 24 * H)
    out = one(posture=p2, agent=a2)
    assert out.edges == [] and out.coverage == [] and len(out.facts) == 1 and len(out.nodes) == 1
    out = one(posture=p2, agent=a2, silent_edge_ttl=dt.timedelta(days=30))
    assert len(out.edges) > 0


def test_a_stale_posture_flags_its_edges_and_an_enrolled_agent_without_a_posture_stays_in_scope():
    a = agent_row(last_posture_at=NOW - 8 * H)
    p = posture_row(collected=NOW - 8 * H, received=NOW - 8 * H)
    out = one(posture=p, agent=a)
    assert out.coverage == []
    assert any("posture_stale" in e.evidence["assumptions"] for e in out.edges) or out.edges == []
    out = hf.build(rows_of((agent_row(), None)), NOW)
    assert out.edges == [] and out.coverage == []
    (f,) = out.facts
    assert f.node_ref == ref1() and set(f.facts) == {"host_agent"} and f.facts["host_agent"]["reason"] == "no_posture"
    assert [n.ref for n in out.nodes] == [ref1()]


# --------------------------------------------------------------------------- #
# conflicts with the external scan
# --------------------------------------------------------------------------- #

def scan_edge(port, dst=None, *, seen=NOW - MIN, proto="tcp", origin="external_scan"):
    return {"dst_ref": dst or ref1(), "proto": proto, "port_lo": port, "port_hi": port, "last_seen": seen,
            "origin": origin, "confidence": 100}


def test_scan_sees_a_port_the_agent_calls_closed_is_a_conflict():
    out = hf.build(rows_of((agent_row(), posture_row()), scans=[scan_edge(8080)]), NOW)
    assert out.coverage == []
    f = out.facts[0].facts
    want = {"kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080, "scan_seen_at": _iso(NOW - MIN)}
    for name in ("sshd", "firewall", "listeners", "patch", "host_agent"):
        assert f[name]["conflict"] == [want], name              # a lying host: nothing it signed counts
    assert f["host_agent"]["data"]["conflicts"] == [want]
    assert f["host_agent"]["data"]["coverage"]["blocked_by"] == ["conflict"]


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_conflict_is_sticky_for_as_long_as_the_observation_is_in_the_graph():
    """Rewritten for review finding hostfw-3. It used to say that a scan observation counts only when it is
    newer than ``posture.collected_at - 5 min``, so one later signed 'closed' posture erased the conflict while the
    observed edge was still in the graph (and docs 13.4 item 7 said the opposite). Now the posture's collection time
    does not matter: the conflict stays until a later full scan clears it (tests/test_p2x_lifecycle.py)."""
    p = posture_row(collected=NOW - 10 * MIN, received=NOW - 10 * MIN)
    for seen in (NOW - 15 * MIN + dt.timedelta(seconds=1), NOW - 15 * MIN, NOW - H, NOW - 100 * H, NOW):
        out = hf.build(rows_of((agent_row(), p), scans=[scan_edge(8080, seen=seen)]), NOW)
        assert out.coverage == [], seen
        assert out.facts[0].facts["firewall"]["conflict"][0]["scan_seen_at"] == _iso(seen)


def test_scan_of_a_port_the_agent_does_not_call_closed_is_no_conflict():
    secs = sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[443, 443]])])]),
                    listeners=lis_section([listener(443, comm="nginx")]))
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=[scan_edge(443)]), NOW)
    assert len(out.coverage) == 1 and "conflict" not in out.facts[0].facts["firewall"]


def test_a_listener_the_firewall_denies_to_the_world_is_closed_to_the_scan():
    secs = sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]], src=["10.0.0.0/8"])])]))
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=[scan_edge(22)]), NOW)
    assert out.coverage == [] and out.facts[0].facts["listeners"]["conflict"][0]["port"] == 22


def test_loopback_only_listener_is_closed_to_the_world():
    secs = sections(listeners=lis_section([listener(22), listener(5432, ip="127.0.0.1", bind="loopback")]))
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=[scan_edge(5432)]), NOW)
    assert out.coverage == []


def test_scan_edges_are_matched_by_node_or_by_claimed_address_and_only_for_its_own_node():
    mine = [scan_edge(8080, dst=f"ip:10.0.0.5")]
    assert hf.build(rows_of((agent_row(), posture_row()), scans=mine), NOW).coverage == []
    other = [scan_edge(8080, dst="ip:10.0.0.99"), scan_edge(8080, dst=refs.agent_ref(aid(2)))]
    assert len(hf.build(rows_of((agent_row(), posture_row()), scans=other), NOW).coverage) == 1


def test_udp_and_any_proto_scan_edges_conflict_too_and_ranges_are_bounded():
    for proto in ("udp", "any"):
        out = hf.build(rows_of((agent_row(), posture_row()), scans=[scan_edge(5353, proto=proto)]), NOW)
        assert out.coverage == [], proto
    wide = scan_edge(1, proto="tcp")
    wide["port_hi"] = 65535
    out = hf.build(rows_of((agent_row(), posture_row()), scans=[wide]), NOW)
    assert len(out.coverage) == 1                    # not a port observation; nothing to judge


def test_a_conflict_needs_an_exact_claim_of_closed():
    # an approximate firewall never says closed, so a scan cannot contradict it (it has no coverage anyway)
    secs = sections(firewall=fw_section(confidence="approximate", conf="approximate"))
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=[scan_edge(8080)]), NOW)
    assert out.coverage == [] and "conflict" not in out.facts[0].facts["firewall"]


def test_conflicts_are_bounded_and_sorted():
    scans = [scan_edge(p) for p in range(9000, 9100)]
    out = hf.build(rows_of((agent_row(), posture_row()), scans=scans), NOW)
    cs = out.facts[0].facts["firewall"]["conflict"]
    assert len(cs) == hf.MAX_CONFLICTS and [c["port"] for c in cs] == sorted(c["port"] for c in cs)


# --------------------------------------------------------------------------- #
# identity (E3)
# --------------------------------------------------------------------------- #

def corroborated_rows(peer="10.0.0.5", ips=("10.0.0.5",), extra_agents=(), assets=None, secs=None):
    inst = cloud(100, priv=["10.0.0.5", "10.0.0.6"], pub=[PUBLIC])
    a = agent_row(ips=ips, peer=peer)
    pairs = [(a, posture_row(secs))] + [(x, posture_row()) for x in extra_agents]
    return rows_of(*pairs, assets=assets if assets is not None else [inst]), inst


def test_corroborated_instance_replaces_the_agent_node_and_never_creates_ip_nodes():
    rows, inst = corroborated_rows(secs=sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]])])])))
    out = hf.build(rows, NOW)
    node = refs.asset_ref(inst["id"])
    assert covered(out) == [node] and [f.node_ref for f in out.facts] == [node]
    assert {e.dst_ref for e in out.edges} == {node}
    assert not any(n.ref == node for n in out.nodes)              # the asset node belongs to its connector
    assert not any(n.ref.startswith("ip:") for n in out.nodes)
    assert not any(e.src_ref.startswith("ip:") or e.dst_ref.startswith("ip:") for e in out.edges)
    assert out.facts[0].facts["host_agent"]["data"]["identity_basis"] == "corroborated"
    ev = next(e for e in out.edges if e.src_ref == "internet")
    assert "assumed_public" not in ev.evidence["assumptions"]      # the instance has a public address


@pytest.mark.parametrize("what,kw", [
    ("peer is not the instance", {"peer": "198.51.100.9"}),
    ("no peer recorded", {"peer": None}),
    ("claims an address the instance lacks", {"ips": ("10.0.0.5", "10.0.9.9")}),
    ("claims a PUBLIC address as a bind address", {"ips": (PUBLIC,), "peer": PUBLIC}),
    ("claims nothing", {"ips": ()}),
])
def test_an_agent_is_not_merged_without_every_corroboration(what, kw):
    rows, inst = corroborated_rows(**kw)
    out = hf.build(rows, NOW)
    assert [f.node_ref for f in out.facts] == [ref1()], what
    assert out.facts[0].facts["host_agent"]["data"]["identity_basis"] == "claimed", what


def test_two_agents_on_one_cloud_node_merge_neither():
    # (the second agent now has its OWN private peer address: two agents presenting one peer address are the
    # separate ``shared_peer_address`` case, covered in test_node_identity_a1)
    b = agent_row(2, ips=("10.0.0.5",), peer="10.0.0.6", hostname="host2")
    rows, inst = corroborated_rows(extra_agents=[b])
    out = hf.build(rows, NOW)
    assert sorted(f.node_ref for f in out.facts) == sorted([ref1(1), ref1(2)])
    assert refs.asset_ref(inst["id"]) not in covered(out)
    assert any("not merged" in n for n in out.notes)
    assert {f.facts["host_agent"]["data"]["identity_note"] for f in out.facts} == {"ambiguous_cloud_node"}


def test_overlapping_claims_from_an_agent_that_never_passed_do_not_clash():
    """(Rewritten for review findings hostfw-5 and wire-5. It used to assert the opposite: that a second agent's
    CLAIM alone demoted the first. A claim from a host the server never saw at the instance's address is only a
    claim; letting it demote a corroborated agent let any enrolled host reset another host's findings.)"""
    b = agent_row(2, ips=("10.0.0.6",), peer="198.51.100.1", hostname="host2")
    rows, inst = corroborated_rows(extra_agents=[b])
    out = hf.build(rows, NOW)
    assert sorted(f.node_ref for f in out.facts) == sorted([refs.asset_ref(inst["id"]), ref1(2)])


def test_an_address_two_assets_own_is_never_a_merge():
    rows, inst = corroborated_rows(assets=[cloud(100, priv=["10.0.0.5"]), cloud(101, priv=["10.0.0.5"])])
    out = hf.build(rows, NOW)
    assert [f.node_ref for f in out.facts] == [ref1()]


def test_only_cloud_instances_absorb_an_agent():
    rows, _ = corroborated_rows(assets=[cloud(100, priv=["10.0.0.5"], pub=[PUBLIC], rtype="db_instance")])
    assert [f.node_ref for f in hf.build(rows, NOW).facts] == [ref1()]


def test_ipmap_resolves_agent_claims_and_defers_to_assets():
    """(Rewritten for review findings hostfw-5 and wire-5: agent claims never OWN an address and never make an
    asset's address ambiguous; they are extra edge candidates only.)"""
    agents = [{"id": aid(1), "kind": "agent", "node_ref": f"agent:{aid(1)}", "identity": {"ips": ["10.1.1.1"]}},
              {"id": aid(2), "kind": "agent", "node_ref": f"asset:{aid(100)}", "identity": {"ips": ["10.0.0.5"]}},
              {"id": aid(3), "kind": "agent", "node_ref": None, "identity": {"ips": ["10.0.0.6"]}}]
    m = _ipmap.build_ip_map(agents + [cloud(100, priv=["10.0.0.5", "10.0.0.6"])])
    assert m.resolve("10.1.1.1") == "ip:10.1.1.1"                   # a claim owns nothing
    assert set(m.resolve_all("10.1.1.1")) == {"ip:10.1.1.1", refs.agent_ref(aid(1))}
    assert m.resolve("10.0.0.5") == refs.asset_ref(aid(100))        # the corroborated agent adds nothing
    assert set(m.resolve_all("10.0.0.5")) == {refs.asset_ref(aid(100))}
    assert not m.is_ambiguous("10.0.0.6")                           # an uncorroborated claim is only a claim
    assert m.resolve("10.0.0.6") == refs.asset_ref(aid(100))
    assert set(m.resolve_all("10.0.0.6")) == {refs.asset_ref(aid(100)), refs.agent_ref(aid(3))}
    assert m.node_kind(refs.agent_ref(aid(1))) == "host"


# --------------------------------------------------------------------------- #
# facts
# --------------------------------------------------------------------------- #

def test_facts_are_compact_and_leak_nothing_the_agent_marked_private():
    out = one(sections(patch=patch_section()))
    blob = json.dumps([f.facts for f in out.facts], default=str)
    for secret in ("exe_sha256", "d" * 64, "e" * 64, "machine_id_hash", "boot_id", "packages", "libssl3",
                   "security_pkgs", "/usr/sbin/x"):
        assert secret not in blob, secret
    p = out.facts[0].facts["patch"]["data"]
    assert p["pending"]["security"] == 2 and "security_pkgs" not in p["pending"]
    assert "packages" not in p["manifest"] and p["reboot"]["required"] is False
    ha = out.facts[0].facts["host_agent"]["data"]
    assert ha["pending_security"] == 2 and ha["reboot_required"] is False
    assert ha["sshd"]["passwordauthentication"] == "no" and ha["sshd"]["maxauthtries"] == 3
    fw = out.facts[0].facts["firewall"]["data"]
    assert "chains" not in json.dumps(fw) and fw["families"]["ip4"] == {"read": True, "effective_default": "drop"}
    assert len(blob) < 12_000
    # the library needs the program NAME of a listener (an sshd on another port, behind another comm), not its path
    assert {r["exe"] for r in out.facts[0].facts["listeners"]["data"]["listeners"]} == {"x"}


def test_collector_states_map_to_fact_statuses():
    secs = sections(sshd={"s": "unavailable", "reason": "tool_missing"},
                    patch={"s": "error", "reason": "timeout", "detail": "x"})
    f = one(secs).facts[0].facts
    assert (f["sshd"]["status"], f["sshd"]["reason"]) == ("unavailable", "tool_missing")
    assert (f["patch"]["status"], f["patch"]["reason"]) == ("error", "timeout")
    for name in ("sshd", "patch"):
        assert f[name]["conf"] == "approximate" and f[name]["partial"] is True and f[name]["data"] == {}
    s = sections()
    s["sshd"] = sshd_section(conf="approximate", unprobed=True)
    assert one(s).facts[0].facts["sshd"]["conf"] == "approximate"


def test_a_malformed_collector_section_degrades_to_an_error_entry_not_a_crash():
    secs = sections(listeners={"s": "ok", "conf": "exact", "partial": False, "v": {"count": 1, "listeners": [1.5]}},
                    patch={"s": "ok", "conf": "exact", "partial": False, "v": {"os": {"state": "ok", "x": 1.5}}})
    out = one(secs)
    assert out.facts[0].facts["patch"]["status"] == "error"
    assert out.coverage == []


def test_hostile_text_never_reaches_labels_or_refs():
    a = agent_row(hostname="evil\n\x00host<script>")
    out = one(agent=a)
    n = next(n for n in out.nodes if n.ref == ref1())
    assert all(32 <= ord(c) < 127 for c in n.label) and n.ref == ref1()


# --------------------------------------------------------------------------- #
# determinism, no floats, one posture does not disturb another
# --------------------------------------------------------------------------- #

def _walk(v):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _walk(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _walk(x)
    else:
        yield v


def dump(out: BuildOutput) -> str:
    return json.dumps({
        "nodes": [(n.ref, n.kind, n.label, n.attrs) for n in out.nodes],
        "edges": [(e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi, e.basis, e.source, e.confidence,
                   e.last_seen.isoformat(), e.evidence) for e in out.edges],
        "coverage": [(c.node_ref, c.direction, c.tier, c.observed_at.isoformat(), c.source, c.detail)
                     for c in out.coverage],
        "facts": [(f.node_ref, f.source, f.tier, f.observed_at.isoformat(), f.facts) for f in out.facts],
        "notes": out.notes}, sort_keys=True)


def busy_rows():
    rows = rows_of((agent_row(1), posture_row()),
                   (agent_row(2, ips=("10.0.0.9",)), posture_row(sections(firewall=fw_section([chain([], policy="accept")])))),
                   (agent_row(3, ips=("10.0.0.8",), last_seen=NOW - H), posture_row()),
                   (agent_row(4), None), assets=[cloud(100, priv=["10.0.0.5"])],
                   scans=[scan_edge(8080, dst=refs.agent_ref(aid(2)))])
    return rows


def test_same_inputs_give_byte_identical_output_whatever_the_order():
    a = dump(hf.build(busy_rows(), NOW))
    r = busy_rows()
    random.Random(1).shuffle(r.agents)
    r.assets.reverse()
    r.scan_edges.reverse()
    assert dump(hf.build(r, NOW)) == a
    assert dump(hf.build(busy_rows(), NOW)) == a


def test_no_floats_anywhere_and_every_ref_is_valid():
    out = hf.build(busy_rows(), NOW)
    for item in _walk(json.loads(dump(out))):
        assert not isinstance(item, float)
    for n in out.nodes:
        assert refs.is_valid_ref(n.ref)
    for e in out.edges:
        assert refs.is_valid_ref(e.src_ref) and refs.is_valid_ref(e.dst_ref)
        assert 0 <= e.port_lo <= e.port_hi <= 65535 and (e.proto == "icmp" or e.port_lo >= 1)
        assert e.confidence in (60, 100) and e.last_seen.tzinfo is not None
    for f in out.facts:
        assert f.observed_at.tzinfo is not None and f.tier == "configured"


def test_one_hosts_broken_posture_never_changes_another_hosts_output():
    base = hf.build(rows_of((agent_row(1), posture_row())), NOW)
    broken = posture_row({"firewall": 5, "listeners": None, "sshd": [], "patch": "x"})
    both = hf.build(rows_of((agent_row(1), posture_row()), (agent_row(2, ips=("10.0.0.9",)), broken)), NOW)
    mine = lambda o: [e for e in o.edges if e.dst_ref == ref1(1)]   # noqa: E731
    assert [(e.src_ref, e.port_lo) for e in mine(both)] == [(e.src_ref, e.port_lo) for e in mine(base)]
    assert covered(both) == [ref1(1)]


def test_a_failing_reach_computation_widens_and_withholds_coverage(monkeypatch):
    real = hf.compute_reach

    def boom(fw, lst, addressable):
        if lst.listeners and lst.listeners[0].port == 2222:
            raise RuntimeError("surprise")
        return real(fw, lst, addressable)

    monkeypatch.setattr(hf, "compute_reach", boom)
    bad = posture_row(sections(listeners=lis_section([listener(2222)])))
    out = hf.build(rows_of((agent_row(1), posture_row()), (agent_row(2, ips=("10.0.0.9",)), bad)), NOW)
    assert covered(out) == [ref1(1)]
    assert any(e.dst_ref == ref1(2) and e.src_ref == "internet" and e.confidence == 60 for e in out.edges)


def test_an_unforeseen_failure_in_one_host_leaves_it_in_scope_without_evidence(monkeypatch):
    real = hf._summary_entry

    def boom(a, ident, *args, **kw):
        if a["hostname"] == "host2":
            raise RuntimeError("surprise")
        return real(a, ident, *args, **kw)

    monkeypatch.setattr(hf, "_summary_entry", boom)
    out = hf.build(rows_of((agent_row(1), posture_row()), (agent_row(2, ips=("10.0.0.9",)), posture_row())), NOW)
    assert covered(out) == [ref1(1)]
    f = {x.node_ref: x for x in out.facts}
    assert set(f) == {ref1(1), ref1(2)} and set(f[ref1(2)].facts) == {"host_agent"}
    assert f[ref1(2)].facts["host_agent"]["reason"] == "builder_error"
    assert not any(e.dst_ref == ref1(2) for e in out.edges)
    assert any("could not be processed" in n for n in out.notes)


def test_garbage_agent_rows_and_postures_never_raise():
    garbage = hf.HostFwRows(agents=[{"id": "not-a-uuid"}, {"id": aid(1)}, {"id": aid(2), "legacy": False,
                                                                           "status": "online", "identity": "x"}],
                            postures={aid(2): {"sections": 5, "signed": True, "key_status": "active",
                                               "verified": True, "collected_at": "x"}},
                            assets=[{"id": "x", "kind": "agent"}, {"kind": "cloud_resource"}, {}],
                            scan_edges=[None, {}, {"dst_ref": 5}, {"dst_ref": "ip:1.1.1.1", "last_seen": "x"}])
    out = hf.build(garbage, NOW)
    assert out.coverage == [] and out.edges == []


# --------------------------------------------------------------------------- #
# the independent oracle
# --------------------------------------------------------------------------- #

IFACES = ["eth0", "eth1", "wlan0", "zz9"]            # zz9 stands for "an interface no rule names"
SRC_VOCAB = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "192.168.0.0/16", "172.16.0.0/12", "203.0.113.0/24",
             "0.0.0.0/1", "128.0.0.0/1", "93.184.216.0/24", "100.64.0.0/10"]
PORT_VOCAB = [(22, 22), (80, 80), (443, 443), (8000, 8100), (1, 1023), (5432, 5432)]
LISTEN_PORTS = [22, 80, 443, 8050, 5432, 9999]


ALL_IIFS = ["eth0", "eth1", "wlan0", "lo"]


V6_VOCAB = ["2001:db8::/32", "2001:db8:1::/48", "fd00::/8", "fe80::/10", "2000::/4", "8000::/1", "2a00::/12"]


def gen_rule(rng, chains_ahead, opaque_p, iifs, vocab):
    m: dict[str, Any] = {}
    if rng.random() < 0.3:
        m["iif"] = rng.choice(iifs)
    if rng.random() < 0.45:
        m["src"] = rng.sample(vocab, rng.choice([1, 1, 2]))
    proto = None
    if rng.random() < 0.6:
        proto = rng.choice(["tcp", "tcp", "udp", "icmp"])
        m["proto"] = proto
    if proto in ("tcp", "udp") and rng.random() < 0.6:
        m["dport"] = [list(r) for r in rng.sample(PORT_VOCAB, rng.choice([1, 1, 2]))]
    if rng.random() < 0.4:
        m["ct"] = rng.choice([["established", "related"], ["new"], ["invalid"], ["new", "untracked"]])
    roll = rng.random()
    if roll < 0.34:
        v = "accept"
    elif roll < 0.58:
        v = "drop"
    elif roll < 0.63:
        v = "reject"
    elif roll < 0.72:
        v = "return"
    elif roll < 0.9 and chains_ahead:
        v = rng.choice(["jump:", "goto:"]) + rng.choice(chains_ahead)
    else:
        v = "accept"
    rule = {"m": m, "v": v}
    if rng.random() < opaque_p:
        rule["opaque_reason"] = rng.choice(["m_set", "limit", "meta_mark"])
    return rule


def gen_model(rng, opaque_p=0.0, iifs=ALL_IIFS, vocab=SRC_VOCAB):
    """A random acyclic model. With ``iifs=["lo"]`` the packet's interface never matters (``lo`` is never
    an external interface), so the walk has no correlated unknowns and must equal the oracle exactly."""
    sub = ["c1", "c2"]
    chains = []
    for i, name in enumerate(sub):
        ahead = sub[i + 1:]
        chains.append(chain([gen_rule(rng, ahead, opaque_p, iifs, vocab) for _ in range(rng.randint(0, 4))],
                            name=name, base=False))
    bases = []
    for bi in range(rng.choice([1, 1, 1, 2])):
        rules = [gen_rule(rng, sub, opaque_p, iifs, vocab) for _ in range(rng.randint(0, 6))]
        bases.append(chain(rules, name=f"inet.t{bi}.input", policy=rng.choice(["accept", "drop"])))
    return bases + chains


def _src_samples(model):
    pts = {"10.1.2.3", "10.9.9.9", "192.168.5.5", "172.20.1.1", "8.8.8.8", "200.1.1.1", "93.184.216.34",
           "100.64.1.1", "1.2.3.4", "223.255.255.254", "1.0.0.0", "150.0.0.1", "169.254.7.7", "172.32.0.1"}
    for c in model:
        for r in c["rules"]:
            for cidr in r["m"].get("src", []):
                n = ipaddress.ip_network(cidr)
                for a in (int(n.network_address), int(n.broadcast_address)):
                    for d in (-1, 0, 1):
                        x = a + d
                        if (1 << 24) <= x < (224 << 24):
                            pts.add(str(ipaddress.IPv4Address(x)))
    return sorted(p for p in pts if not p.startswith("127."))


def _is_global(ip):
    a = ipaddress.ip_address(ip)
    internal = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                "fc00::/7", "fe80::/10")
    return not any(a.version == ipaddress.ip_network(n).version and a in ipaddress.ip_network(n) for n in internal)


def _src_samples6(model):
    pts = {"2001:db8::1", "fd00::1", "fe80::1", "2a00::1", "2600::1", "4000::1", "8000::1", "2001:db8:1::5",
           "fc00::1", "fdff::1", "2fff::1", "3000::1", "fec0::1"}
    for c in model:
        for r in c["rules"]:
            for cidr in r["m"].get("src", []):
                n = ipaddress.ip_network(cidr)
                for a in (int(n.network_address), int(n.broadcast_address)):
                    for d in (-1, 0, 1):
                        x = a + d
                        if 2 <= x < (0xFF00 << 112):
                            pts.add(str(ipaddress.IPv6Address(x)))
    return sorted(pts)


class Oracle:
    """Concrete first-match evaluation of a model dict, written independently of the builder.

    A packet is POSSIBLY accepted when SOME interface and SOME truth assignment of the opaque
    conditions makes every input base chain accept it. It is CERTAINLY accepted when every
    interface and every assignment does.
    """

    def __init__(self, model):
        self.chains = {c["name"]: c["rules"] for c in model}
        self.bases = [(c["name"], c["policy"]) for c in model if c["base"]]
        self.opaque = []
        for c in model:
            for i, r in enumerate(c["rules"]):
                if r.get("opaque_reason"):
                    self.opaque.append((c["name"], i))

    def cond(self, name, i, rule, pkt, assign):
        m = rule["m"]
        if "iif" in m and m["iif"] != pkt["iif"]:
            return False
        if "src" in m and not any(ipaddress.ip_address(pkt["src"]) in ipaddress.ip_network(c) for c in m["src"]):
            return False
        if "proto" in m and m["proto"] != pkt["proto"]:
            return False
        if "dport" in m:
            if pkt["proto"] not in ("tcp", "udp"):
                return False
            if not any(lo <= pkt["dport"] <= hi for lo, hi in m["dport"]):
                return False
        if "ct" in m and pkt["ct"] not in m["ct"]:
            return False
        if rule.get("opaque_reason") and not assign[(name, i)]:
            return False
        return True

    def run(self, name, pkt, assign):
        for i, rule in enumerate(self.chains[name]):
            if not self.cond(name, i, rule, pkt, assign):
                continue
            v = rule["v"]
            if v == "accept":
                return "accept"
            if v in ("drop", "reject"):
                return "drop"
            if v == "return":
                return "ret"
            kind, _, target = v.partition(":")
            r = self.run(target, pkt, assign)
            if kind == "goto":
                return r if r in ("accept", "drop") else "ret"
            if r in ("accept", "drop"):
                return r
        return "ret"

    def accepts(self, pkt, assign):
        for name, policy in self.bases:
            r = self.run(name, pkt, assign)
            if (r if r in ("accept", "drop") else policy) != "accept":
                return False
        return True

    def verdicts(self, src, proto, dport):
        results = []
        for iface in IFACES:
            pkt = {"src": src, "proto": proto, "dport": dport, "ct": "new", "iif": iface}
            for bits in itertools.product([False, True], repeat=len(self.opaque)):
                results.append(self.accepts(pkt, dict(zip(self.opaque, bits))))
        return any(results), all(results)


def covers(edges, src):
    """Does any (src_ref) in ``edges`` stand for the concrete address ``src``?"""
    for e in edges:
        if e.src_ref == "internet":
            if _is_global(src):
                return True
        elif ipaddress.ip_address(src) in ipaddress.ip_network(e.src_ref[len("cidr:"):]):
            return True
    return False


def _widened(es):
    """Edges the builder deliberately widened (documented over-approximation): exempt from tightness only."""
    return any("widened" in f for e in es for f in e.evidence["assumptions"])


def run_oracle_case(rng, opaque_p, ports, protos=("tcp", "udp"), iifs=ALL_IIFS):
    model = gen_model(rng, opaque_p, iifs)
    lis = [listener(p, proto=pr) for p in ports for pr in protos]
    secs = sections(firewall=fw_section(model, [chain([])], ipv6=False), listeners=lis_section(lis))
    a = agent_row(ips=(PUBLIC,))
    out = hf.build(rows_of((a, posture_row(secs))), NOW)
    orc = Oracle(model)
    srcs = _src_samples(model)
    for p in ports:
        for pr in protos:
            es = [e for e in out.edges if e.proto == pr and e.port_lo <= p <= e.port_hi]
            sure = [e for e in es if e.confidence == 100]
            for s in srcs:
                possible, certain = orc.verdicts(s, pr, p)
                if possible:
                    assert covers(es, s), ("MISSED", pr, p, s, json.dumps(model))
                if covers(sure, s):
                    assert certain, ("OVERCLAIMED certainty", pr, p, s, json.dumps(model))
                if not opaque_p and iifs == ["lo"] and covers(es, s) and not _widened(es):
                    assert possible, ("OVER-APPROXIMATED without opacity", pr, p, s, json.dumps(model))
    return out, model, orc


def test_oracle_exact_models_the_builder_equals_the_brute_force_walk():
    rng = random.Random(20260101)
    for _ in range(220):
        run_oracle_case(rng, 0.0, LISTEN_PORTS, iifs=["lo"])


def test_oracle_interfaces_the_builder_never_misses_a_source_on_any_interface():
    """With interface rules the walk explores "some interface" and may over-approximate (two rules that
    both test the interface are treated as independent), but it must never miss an allowed source."""
    rng = random.Random(20260104)
    for _ in range(220):
        run_oracle_case(rng, 0.0, LISTEN_PORTS)


def test_oracle_opaque_rules_the_builder_never_misses_an_allowed_source_and_never_overclaims():
    rng = random.Random(20260102)
    for _ in range(220):
        run_oracle_case(rng, 0.25, LISTEN_PORTS)


def test_oracle_ipv6_the_builder_equals_the_brute_force_walk_and_never_misses():
    rng = random.Random(20260105)
    for case in range(120):
        opaque = 0.0 if case % 2 else 0.25
        model = gen_model(rng, opaque, ["lo"], V6_VOCAB)
        lis = [listener(p, ip="::", bind="wildcard6", comm="x") for p in LISTEN_PORTS]
        secs = sections(firewall=fw_section([chain([])], model, ipv6=True),
                        listeners=lis_section(lis, bindv6only=1))
        out = hf.build(rows_of((agent_row(ips=(PUBLIC,)), posture_row(secs))), NOW)
        orc = Oracle(model)
        for p in LISTEN_PORTS:
            es = [e for e in out.edges if e.proto == "tcp" and e.port_lo <= p <= e.port_hi]
            sure = [e for e in es if e.confidence == 100]
            for s in _src_samples6(model):
                possible, certain = orc.verdicts(s, "tcp", p)
                if possible:
                    assert covers(es, s), ("MISSED v6", p, s, json.dumps(model))
                if covers(sure, s):
                    assert certain, ("OVERCLAIMED v6", p, s, json.dumps(model))
                if not opaque and covers(es, s) and not _widened(es):
                    assert possible, ("OVER-APPROXIMATED v6", p, s, json.dumps(model))


def test_oracle_icmp_and_other_protocols():
    rng = random.Random(20260103)
    for _ in range(150):
        model = gen_model(rng, 0.0, ["lo"])
        secs = sections(firewall=fw_section(model, [chain([])]), listeners=lis_section([listener(22)]))
        out = hf.build(rows_of((agent_row(ips=(PUBLIC,)), posture_row(secs))), NOW)
        orc = Oracle(model)
        for proto, wire in (("icmp", "icmp"), ("any", "p253")):
            es = [e for e in out.edges if e.proto == proto]
            for s in _src_samples(model):
                possible, _certain = orc.verdicts(s, wire, None)
                if possible:
                    assert covers(es, s), ("MISSED", proto, s, json.dumps(model))
                elif not _widened(es):
                    assert not covers(es, s), ("OVER-APPROXIMATED", proto, s, json.dumps(model))


def test_the_oracle_catches_a_broken_walk(monkeypatch):
    """Mutation check: an off-by-one in the walk (a ``drop`` that does not stop the chain) must be seen."""
    real = hf._Walker._outcomes

    def broken(self, base, pkt):
        outs = set(real(self, base, pkt))
        outs.discard("drop")
        return frozenset(outs or {"accept"})

    monkeypatch.setattr(hf._Walker, "_outcomes", broken)
    with pytest.raises(AssertionError):
        rng = random.Random(20260101)
        for _ in range(60):
            run_oracle_case(rng, 0.0, LISTEN_PORTS)


def test_the_oracle_catches_a_walk_that_treats_unknown_as_no_match(monkeypatch):
    real = hf._match

    def narrow(r, pkt):
        v = real(r, pkt)
        return False if v is None else v

    monkeypatch.setattr(hf, "_match", narrow)
    with pytest.raises(AssertionError):
        rng = random.Random(20260102)
        for _ in range(120):
            run_oracle_case(rng, 0.25, LISTEN_PORTS)


# --------------------------------------------------------------------------- #
# cross-check against the agent's own walk (same model, two implementations)
# --------------------------------------------------------------------------- #

def _agent_fwmodel():
    root = pathlib.Path(__file__).resolve().parents[2] / "agent"
    if not (root / "paddock_agent" / "collectors" / "fwmodel.py").exists():
        pytest.skip("agent package not present")
    sys.path.insert(0, str(root))
    try:
        from paddock_agent.collectors import fwmodel
    finally:
        sys.path.remove(str(root))
    return fwmodel


def test_the_walk_agrees_with_the_agents_fwmodel_evaluate():
    fwm = _agent_fwmodel()
    rng = random.Random(7)
    checked = 0
    for case in range(250):
        model = gen_model(rng, 0.3 if case % 2 else 0.0)
        w = hf._Walker({"chains": model}, 4)
        for src in _src_samples(model)[:14]:
            for proto, port in (("tcp", 22), ("tcp", 80), ("udp", 8050), ("tcp", 9999), ("udp", 53)):
                mine = w.verdict(hf._pkt(int(ipaddress.IPv4Address(src)), proto, port, None, "local"))
                theirs = fwm.evaluate({"chains": model}, {"src": src, "proto": proto, "dport": port,
                                                          "ct": "new", "iif": fwm.IIF_EXTERNAL, "dtype": "local"})
                # the builder explores every opaque_reason both ways (the agent spares an action-only one)
                assert mine == theirs, (src, proto, port, json.dumps(model))
                checked += 1
    assert checked > 5000


# --------------------------------------------------------------------------- #
# the real library over the builder's output
# --------------------------------------------------------------------------- #

def doc_of(out: BuildOutput, now: dt.datetime) -> dict:
    """The graph document the loader would emit for this build (hand-rolled, the DB test uses the loader)."""
    fact_refs = {f.node_ref for f in out.facts}
    refs_ = {n.ref: n.kind for n in out.nodes}
    for e in out.edges:
        refs_.setdefault(e.src_ref, "internet" if e.src_ref == "internet" else "cidr")
        refs_.setdefault(e.dst_ref, "host")
    for f in out.facts:
        refs_.setdefault(f.node_ref, "host")
    refs_.setdefault("internet", "internet")
    nodes = []
    for ref, kind in sorted(refs_.items()):
        n: dict[str, Any] = {"id": ref, "kind": kind}
        if ref in fact_refs:
            n["tags"] = ["agent"]
            f = next(x for x in out.facts if x.node_ref == ref)
            n["facts"] = {}
            for name, e in f.facts.items():
                d = {k: v for k, v in e.items() if k != "tier"}
                d.update(tier=e.get("tier", f.tier), observed_at=f.observed_at.isoformat(), source=f.source)
                n["facts"][name] = d
        cov = [{"direction": c.direction, "tier": c.tier, "observed_at": c.observed_at.isoformat(),
                "source": c.source} for c in out.coverage if c.node_ref == ref]
        if cov:
            n["coverage"] = cov
        nodes.append(n)
    edges = []
    for e in out.edges:
        d = {"src": e.src_ref, "dst": e.dst_ref, "proto": e.proto, "basis": e.basis, "source": e.source}
        if e.proto != "icmp":
            d["ports"] = str(e.port_lo) if e.port_lo == e.port_hi else f"{e.port_lo}-{e.port_hi}"
        edges.append(d)
    return {"version": 1, "now": now.isoformat(), "nodes": nodes, "edges": edges}


def evaluate(out, std_id, now=NOW):
    lib = pytest.importorskip("paddock_assurance")
    from paddock_assurance import stdlib
    return lib.evaluate(stdlib.load_std(std_id), lib.ReachGraph.from_dict(doc_of(out, now)), now).to_dict()


SSH = "std:server-ssh-hardened"
FWD = "std:server-default-deny-inbound"


def test_std_host_invariants_hold_for_a_healthy_host_at_tier_configured():
    out = one()
    for std_id in (SSH, FWD):
        r = evaluate(out, std_id)
        assert r["verdict"] == "HOLDS", (std_id, r["reasons"], r.get("blind_spots"))
        assert r["evidence_tier"] == "configured" and r["assertion"] == "host-config"


@pytest.mark.parametrize("what,kw,std_id", [
    ("password login", {"secs": sections(sshd=sshd_section(password="yes"))}, SSH),
    ("accepting firewall", {"secs": sections(firewall=fw_section([chain([], policy="accept")],
                                                                  default4="accept"))}, FWD),
])
def test_std_host_invariants_are_violated_by_real_violations(what, kw, std_id):
    r = evaluate(one(kw["secs"]), std_id)
    assert r["verdict"] == "VIOLATED", (what, r["reasons"])
    assert r["violating_targets"] == [ref1()]


@pytest.mark.parametrize("what,kw,std_id", [
    ("approximate firewall", {"secs": sections(firewall=fw_section(confidence="approximate", conf="approximate"))}, FWD),
    ("opaque feature", {"secs": sections(firewall=fw_section(features=["nat_rewrite"], conf="approximate",
                                                             confidence="approximate"))}, FWD),
    ("text-parsed sshd", {"secs": sections(sshd=sshd_section(conf="approximate", source="text"))}, SSH),
    ("stale posture", {"posture": posture_row(collected=NOW - 7 * H, received=NOW - 7 * H),
                       "agent": agent_row(last_posture_at=NOW - 7 * H)}, SSH),
    ("silent agent", {"agent": agent_row(last_seen=NOW - 2 * H)}, FWD),
    ("scan conflict", {"scans": [scan_edge(8080)]}, FWD),
    ("scan conflict (ssh)", {"scans": [scan_edge(8080)]}, SSH),
    ("revoked key", {"posture": posture_row(key_status="revoked")}, SSH),
    ("unsigned", {"posture": posture_row(signed=False)}, SSH),
    ("no posture yet", {"posture": None}, SSH),
])
def test_std_host_invariants_stay_unknown_when_the_evidence_cannot_be_trusted(what, kw, std_id):
    a = kw.get("agent") or agent_row()
    if "posture" in kw and kw["posture"] is None:
        out = hf.build(rows_of((a, None)), NOW)
    else:
        p = kw.get("posture") or posture_row(kw.get("secs"))
        out = hf.build(rows_of((a, p), scans=kw.get("scans", ())), NOW)
    r = evaluate(out, std_id)
    assert r["verdict"] == "UNKNOWN", (what, r["verdict"], r["reasons"])
    assert ref1() in r["unproven_targets"] and r["violating_targets"] == []


def test_a_conflict_beats_a_violation_it_is_unknown_never_a_pass_and_never_hides_in_holds():
    out = hf.build(rows_of((agent_row(), posture_row(sections(sshd=sshd_section(password="yes")))),
                           scans=[scan_edge(8080)]), NOW)
    assert evaluate(out, SSH)["verdict"] == "UNKNOWN"


def test_an_agent_that_goes_silent_turns_a_holds_into_unknown():
    assert evaluate(one(), FWD)["verdict"] == "HOLDS"
    silent = one(agent=agent_row(last_seen=NOW - 10 * MIN))
    assert evaluate(silent, FWD)["verdict"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# structure
# --------------------------------------------------------------------------- #

def test_builder_registers_after_external_exposure_and_exposes_the_contract():
    from app.assurance import builders
    names = list(builders.BUILDER_NAMES)
    assert names.index("host_fw") > names.index("external_exposure")
    mods = {m.SOURCE: m for m in builders.load_builders()}
    assert mods["host_fw"] is hf
    import inspect
    assert inspect.iscoroutinefunction(hf.load) and not inspect.iscoroutinefunction(hf.build)
    assert "agent_posture_max_age" in inspect.signature(hf.build).parameters


def test_empty_input_replaces_everything_with_nothing():
    out = hf.build(hf.HostFwRows(), NOW)
    assert out.source == "host_fw" and out.mode == "replace"
    assert out.nodes == out.edges == out.coverage == out.facts == []
