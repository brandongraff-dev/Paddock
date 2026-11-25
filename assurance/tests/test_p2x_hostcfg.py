"""P2 adversarial-review regressions for the host-config library (hostcfg-1 .. hostcfg-8 and the
passing-target / tombstone interface). Each test names the finding it pins; every one of them failed
against the unreviewed source for the reason in its comment."""
from __future__ import annotations

import datetime as dt
import importlib
import json
import re

import pytest

from paddock_assurance import ReachGraph, Verdict, evaluate, stdlib
from paddock_assurance import hostfields as HF
from paddock_assurance.graph import GraphError
from paddock_assurance.tier import Tier
from tests.hostfix import (FRESH, NOW, fact, good_facts, hgraph, hnode, host_plan, host_plan_doc,
                           listeners, sshd)

EV = importlib.import_module("paddock_assurance.evaluate")     # the module (the package shadows it)
MAX_AGE = dt.timedelta(hours=6)
SSH = "std:server-ssh-hardened"


def host_of(facts):
    return hgraph(hnode("h", facts)).nodes["h"].host


def res(field, params, facts, *, min_tier=Tier.configured, now=NOW, max_age=MAX_AGE):
    return HF.resolve(HF.REGISTRY[field], params, host_of(facts), now, min_tier, max_age)


def sshd_facts(deltas=None, **kw):
    return good_facts(sshd=fact(sshd(deltas=deltas, **kw)))


def verdict(assert_yaml, facts, extra=""):
    return evaluate(host_plan(assert_yaml, extra), hgraph(hnode("h", facts)), NOW)


def std(facts, sid=SSH):
    return evaluate(stdlib.load_std(sid), hgraph(hnode("h", facts)), NOW)


# --------------------------------------------------------------------------------------------
# hostcfg-1: an absent AllowUsers / AllowGroups means "everyone may log in", not "nobody"
# failed before: `host.sshd.allowusers subset_of ["deploy"]` -> HOLDS on a host with no AllowUsers

@pytest.mark.parametrize("pred", [
    'host.sshd.allowusers subset_of ["deploy"]',
    'host.sshd.allowgroups subset_of ["ops"]',
    "count(host.sshd.allowusers) <= 1",
    "count(host.sshd.allowgroups) == 0",
    'host.sshd.allowusers == ["deploy"]',
])
def test_hostcfg1_an_unrestricted_sshd_never_satisfies_an_allow_list_predicate(pred):
    r = verdict(f'"{pred}"' if '"' not in pred else "'" + pred + "'", sshd_facts())
    assert r.verdict is not Verdict.HOLDS, pred
    assert r.verdict is Verdict.UNKNOWN and not r.violating_targets


def test_hostcfg1_the_field_has_no_value_when_the_key_is_absent():
    for f in ("host.sshd.allowusers", "host.sshd.allowgroups"):
        r = res(f, (), sshd_facts())
        assert not r.known and r.reason == "unrestricted"


def test_hostcfg1_a_configured_list_is_still_evaluated():
    f = sshd_facts(allowusers=["deploy"], allowgroups=["ops", "sre"])
    assert res("host.sshd.allowusers", (), f).value == frozenset(["deploy"])
    assert verdict("'host.sshd.allowusers subset_of [\"deploy\", \"bob\"]'", f).verdict is Verdict.HOLDS
    assert verdict("'host.sshd.allowusers subset_of [\"bob\"]'", f).verdict is Verdict.VIOLATED
    assert verdict("'count(host.sshd.allowgroups) <= 2'", f).verdict is Verdict.HOLDS


def test_hostcfg1_derived_booleans_say_whether_a_list_is_set():
    assert res("host.sshd.allowusers_set", (), sshd_facts()).value is False
    assert res("host.sshd.allowgroups_set", (), sshd_facts()).value is False
    f = sshd_facts(allowusers=["deploy"], allowgroups=[])
    assert res("host.sshd.allowusers_set", (), f).value is True
    assert res("host.sshd.allowgroups_set", (), f).value is False      # an empty list restricts nobody
    # a Match block that clears it for one user/address makes it unrestricted there
    f = sshd_facts(deltas=[{"allowusers": None}], allowusers=["deploy"])
    assert res("host.sshd.allowusers_set", (), f).value is False
    # unreadable value: unknown, never false
    f = sshd_facts(allowusers="deploy")
    assert not res("host.sshd.allowusers_set", (), f).known
    assert verdict('"host.sshd.allowusers_set == true"', sshd_facts()).verdict is Verdict.VIOLATED
    assert verdict('"host.sshd.allowusers_set == true"',
                   sshd_facts(allowusers=["a"])).verdict is Verdict.HOLDS


# --------------------------------------------------------------------------------------------
# hostcfg-2: `installed == false` must not be concluded from a process-name heuristic
# failed before: comm=docker-proxy/gitea/sftpgo/gitlab-sshd/tinyssh/teleport/SSHD all gave HOLDS

def absent_facts(ports=((443, "postgres"),), **lst):
    comms = {p: c for p, c in ports}
    return good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                      listeners=fact(listeners(ports=tuple(p for p, _ in ports), comms=comms), **lst))


@pytest.mark.parametrize("comm", ["docker-proxy", "gitea", "sftpgo", "gitlab-sshd", "tinyssh",
                                  "teleport", "SSHD", "Sshd", "ssh", "nginx", "rootlessport",
                                  "kube-proxy", "haproxy", "socat", "", None])
def test_hostcfg2_an_unlisted_or_ssh_like_listener_blocks_the_absence_claim(comm):
    f = absent_facts(ports=((2222, comm),))
    r = res("host.sshd.installed", (), f)
    assert not r.known, comm
    assert std(f).verdict is not Verdict.HOLDS, comm


@pytest.mark.parametrize("comm", ["POSTGRES", "postgres", "redis-server", "named", "Dnsmasq"])
def test_hostcfg2_listeners_of_known_non_ssh_programs_still_corroborate(comm):
    f = absent_facts(ports=((5432, comm),))
    r = res("host.sshd.installed", (), f)
    assert r.known and r.value is False
    assert len(r.also) == 1                       # the listener table is part of what the claim rests on


def test_hostcfg2_the_claim_needs_every_public_tcp_listener_to_be_listed():
    f = absent_facts(ports=((5432, "postgres"), (8443, "docker-proxy")))
    assert not res("host.sshd.installed", (), f).known


def test_hostcfg2_loopback_listeners_do_not_block_but_a_loopback_ssh_does():
    def lst(comm, port=53):
        d = listeners(ports=(port,), comms={port: comm}, ip="127.0.0.53", bind="loopback")
        return good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                          listeners=fact(d))
    assert res("host.sshd.installed", (), lst("systemd-resolve")).value is False
    assert not res("host.sshd.installed", (), lst("sshd", 2200)).known
    assert not res("host.sshd.installed", (), lst("systemd-resolve", 22)).known


def test_hostcfg2_a_udp_listener_is_not_an_ssh_server_but_port_22_always_is():
    d = listeners(ports=(5353, 22), comms={5353: "avahi-daemon", 22: "x"})
    d["listeners"][0]["proto"] = "udp"
    d["listeners"][1]["proto"] = "udp"
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"), listeners=fact(d))
    assert not res("host.sshd.installed", (), f).known            # udp/22 still vetoes
    d2 = listeners(ports=(5353,), comms={5353: "avahi-daemon"})
    d2["listeners"][0]["proto"] = "udp"
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"), listeners=fact(d2))
    assert res("host.sshd.installed", (), f).value is False


def test_hostcfg2_a_holds_resting_on_an_absence_says_so():
    f = absent_facts()
    r = std(f)
    assert r.verdict is Verdict.HOLDS
    assert "basis:sshd_absence_from_listener_table" in r.reasons
    # a HOLDS that rests on an installed sshd that is hardened carries no such note
    assert "basis:sshd_absence_from_listener_table" not in std(good_facts()).reasons
    assert std(f).to_dict() == std(f).to_dict()                   # deterministic


# --------------------------------------------------------------------------------------------
# hostcfg-3: a truncated config value is a prefix, not the truth
# failed before: count(host.sshd.allowusers) < 100 -> HOLDS with 50 names and no marker

def test_hostcfg3_a_key_named_in_truncated_is_unknown_everywhere():
    names = [f"u{i:03d}" for i in range(50)]
    f = good_facts(sshd=fact(sshd(allowusers=names, truncated=["allowusers"])))
    r = res("host.sshd.allowusers", (), f)
    assert not r.known
    assert verdict("'count(host.sshd.allowusers) < 100'", f).verdict is Verdict.UNKNOWN
    assert not res("host.sshd.allowusers_set", (), f).known
    # unrelated keys of the same fact stay readable
    assert res("host.sshd.maxauthtries", (), f).value == 3


def test_hostcfg3_a_list_of_exactly_fifty_names_is_unknown_even_without_the_marker():
    names = [f"u{i:03d}" for i in range(50)]
    f = good_facts(sshd=fact(sshd(allowusers=names)))
    assert not res("host.sshd.allowusers", (), f).known
    assert verdict("'count(host.sshd.allowusers) < 100'", f).verdict is Verdict.UNKNOWN
    f = good_facts(sshd=fact(sshd(allowgroups=names[:49])))
    assert res("host.sshd.allowgroups", (), f).known              # 49 is not a cut


def cut_methods():
    return ("publickey " * 20)[:200]                          # a cut that happens to look all-publickey


@pytest.mark.parametrize("truncated", [["authenticationmethods"], None])
def test_hostcfg3_a_cut_authenticationmethods_never_proves_no_password_login(truncated):
    m = cut_methods()
    assert len(m) == 200
    f = good_facts(sshd=fact(sshd(passwordauthentication="no", kbdinteractiveauthentication="yes",
                                  usepam="yes", authenticationmethods=m, truncated=truncated)))
    r = res("host.sshd.password_login_possible", (), f)
    assert not r.known, "a 200-character cut cannot show that every method is publickey"
    assert std(f).verdict is not Verdict.HOLDS
    assert not res("host.sshd.authenticationmethods", (), f).known


def test_hostcfg3_a_malformed_truncated_marker_is_unknown_not_ignored():
    for bad in ("allowusers", [1], {"allowusers": True}, [""]):
        f = good_facts(sshd=fact(sshd(allowusers=["a"], truncated=bad)))
        assert not res("host.sshd.allowusers", (), f).known, bad


def test_hostcfg3_a_cut_key_inside_a_probe_delta_counts_too():
    # the agent merges the keys cut in probes into v.truncated: a derived field that reads a cut key
    # (authenticationmethods) is unknown for every variant
    f = good_facts(sshd=fact(sshd(deltas=[{"kbdinteractiveauthentication": "yes"}],
                                  authenticationmethods="publickey",
                                  truncated=["authenticationmethods"])))
    assert not res("host.sshd.password_login_possible", (), f).known


# --------------------------------------------------------------------------------------------
# hostcfg-4: a Match block that weakens a scalar is a violation, not UNKNOWN
# failed before: delta-empty -> UNKNOWN (match_override), delta-maxauth -> UNKNOWN

@pytest.mark.parametrize("delta", [
    {"permitemptypasswords": "yes"},
    {"pubkeyauthentication": "no"},
    {"maxauthtries": 10},
])
def test_hostcfg4_a_weakening_match_delta_violates_the_std_invariant(delta):
    r = std(sshd_facts(deltas=[delta]))
    assert r.verdict is Verdict.VIOLATED, delta
    key = next(iter(delta))
    w = next(x.detail for x in r.witnesses if x.detail["field"] == f"host.sshd.{key}")
    assert w["observed"] == str(delta[key])          # the violating variant, not the base value


def test_hostcfg4_a_tightening_match_delta_keeps_a_compliant_host_compliant():
    r = std(sshd_facts(deltas=[{"maxauthtries": 2}]))
    assert r.verdict is Verdict.HOLDS
    assert std(sshd_facts(deltas=[{"pubkeyauthentication": "yes"}], pubkeyauthentication="no")
               ).verdict is Verdict.VIOLATED                 # the base itself violates


def test_hostcfg4_resolve_still_has_no_single_value_for_a_varying_key():
    r = res("host.sshd.maxauthtries", (), sshd_facts(deltas=[{"maxauthtries": 10}]))
    assert not r.known and r.reason == "match_override"
    assert r.variants == (3, 10)


def test_hostcfg4_an_unreadable_variant_alone_is_unknown_never_true():
    f = sshd_facts(deltas=[{"permitemptypasswords": None}])
    assert verdict("'host.sshd.permitemptypasswords == \"no\"'", f).verdict is Verdict.UNKNOWN
    # ... but a readable variant that violates still decides it
    f = sshd_facts(deltas=[{"permitemptypasswords": None}, {"permitemptypasswords": "yes"}])
    assert verdict("'host.sshd.permitemptypasswords == \"no\"'", f).verdict is Verdict.VIOLATED


def test_hostcfg4_under_not_a_varying_key_stays_unknown():
    # not(x == "yes") over a key that varies by user cannot be read as "no user has yes"
    f = sshd_facts(deltas=[{"permitemptypasswords": "yes"}])
    plan = host_plan_doc({"not": 'host.sshd.permitemptypasswords == "yes"'})
    r = evaluate(plan, hgraph(hnode("h", f)), NOW)
    assert r.verdict is Verdict.UNKNOWN
    assert r.verdict is not Verdict.HOLDS


def test_hostcfg4_the_oracle_of_the_rule_every_variant_must_satisfy_the_leaf():
    f = sshd_facts(deltas=[{"maxauthtries": 2}, {"maxauthtries": 9}])
    assert verdict("'host.sshd.maxauthtries <= 4'", f).verdict is Verdict.VIOLATED
    assert verdict("'host.sshd.maxauthtries <= 9'", f).verdict is Verdict.HOLDS
    assert verdict("'host.sshd.maxauthtries in [2, 3, 9]'", f).verdict is Verdict.HOLDS
    assert verdict("'host.sshd.maxauthtries != 9'", f).verdict is Verdict.VIOLATED


# --------------------------------------------------------------------------------------------
# hostcfg-5: ReachGraph.from_json / from_file

def deep(n):
    return '{"nodes":[{"id":"a","facts":{"x":{"data":' + "[" * n + "]" * n + "}}}]}"


def test_hostcfg5_deep_nesting_is_a_graph_error_not_a_recursion_error():
    for n in (100_000, 2_000, 200):
        with pytest.raises(GraphError, match="nested"):
            ReachGraph.from_json(deep(n))


def test_hostcfg5_a_huge_integer_is_a_graph_error():
    with pytest.raises(GraphError):
        ReachGraph.from_json('{"version":1,"nodes":[],"edges":[],"x":' + "9" * 5000 + "}")


@pytest.mark.parametrize("text", [
    '{"version":1,"nodes":[{"id":"a","id":"b"}]}',
    '{"version":1,"version":1,"nodes":[]}',
    '{"version":1,"nodes":[{"id":"a","facts":{"sshd":{"signed":false,"signed":true}}}]}',
])
def test_hostcfg5_duplicate_keys_are_refused(text):
    with pytest.raises(GraphError, match="duplicate"):
        ReachGraph.from_json(text)


@pytest.mark.parametrize("const", ["NaN", "Infinity", "-Infinity"])
def test_hostcfg5_non_finite_constants_are_refused(const):
    with pytest.raises(GraphError):
        ReachGraph.from_json('{"version":1,"nodes":[],"edges":[],"x":' + const + "}")


def test_hostcfg5_oversized_input_is_refused(monkeypatch):
    from paddock_assurance import graph as G
    monkeypatch.setattr(G, "MAX_JSON_BYTES", 100, raising=False)
    with pytest.raises(GraphError, match="larger"):
        ReachGraph.from_json('{"version":1,"nodes":[],"edges":[],"pad":"' + "x" * 200 + '"}')


def test_hostcfg5_from_file_wraps_the_same_errors(tmp_path):
    p = tmp_path / "g.json"
    p.write_text(deep(100_000), encoding="utf-8")
    with pytest.raises(GraphError):
        ReachGraph.from_file(p)
    p.write_bytes(b'{"version":1,"nodes":[],"x":"\xff\xfe"}')
    with pytest.raises(GraphError):
        ReachGraph.from_file(p)
    p.write_text('{"version":1,"nodes":[{"id":"a"}],"edges":[]}', encoding="utf-8")
    assert list(ReachGraph.from_file(p).nodes) == ["a"]


def test_hostcfg5_a_normal_document_still_loads():
    g = ReachGraph.from_json(json.dumps({"version": 1, "nodes": [hnode("h", good_facts())],
                                         "edges": []}))
    assert "h" in g.nodes and g.nodes["h"].host is not None


# --------------------------------------------------------------------------------------------
# hostcfg-6: sshd -T is the file on disk; the evidence must say the daemon runs that file
# failed before: reload_pending true/null/absent still gave HOLDS at conf exact

@pytest.mark.parametrize("daemon", [{"reload_pending": True}, {"reload_pending": None},
                                    {"binary_matches": False}, {"config_default": False},
                                    {"options_override": True}])
def test_hostcfg6_a_daemon_that_may_not_run_this_config_is_unknown(daemon):
    f = good_facts(sshd=fact(sshd(daemon=daemon)))
    assert not res("host.sshd.password_login_possible", (), f).known
    assert not res("host.sshd.maxauthtries", (), f).known
    r = std(f)
    assert r.verdict is Verdict.UNKNOWN, daemon


@pytest.mark.parametrize("bad", [None, "no", 0, "false"])
def test_hostcfg6_an_old_or_malformed_daemon_block_is_unknown(bad):
    d = sshd(daemon=None)
    if bad is not None:
        d["daemon"] = bad
    f = good_facts(sshd=fact(d))
    assert std(f).verdict is Verdict.UNKNOWN


def test_hostcfg6_a_missing_reload_pending_key_is_unknown():
    d = sshd()
    del d["daemon"]["reload_pending"]
    assert std(good_facts(sshd=fact(d))).verdict is Verdict.UNKNOWN


def test_hostcfg6_pending_reload_never_turns_a_violation_into_a_pass_or_a_closure():
    f = good_facts(sshd=fact(sshd(passwordauthentication="yes", daemon={"reload_pending": True})))
    assert std(f).verdict is Verdict.UNKNOWN          # approximate on-disk view: neither pass nor fail


def test_hostcfg6_nothing_pending_still_holds():
    assert std(good_facts()).verdict is Verdict.HOLDS


def test_hostcfg6_installed_true_does_not_need_the_daemon_block():
    d = sshd(daemon=None)
    assert res("host.sshd.installed", (), good_facts(sshd=fact(d))).value is True


def test_hostcfg6_the_std_text_says_what_is_measured():
    inv = stdlib.load_std(SSH).invariant
    assert "on-disk" in inv.description and "running daemon" in inv.description
    assert "effective sshd configuration" not in inv.description


# --------------------------------------------------------------------------------------------
# hostcfg-7: host-controlled text is not echoed into witnesses beyond a restricted alphabet
# failed before: observed == "publickey <img src=x onerror=alert(1)> [click](http://evil.example/x) ..."

SAFE = re.compile(r"[A-Za-z0-9._:/@,?-]*")


def test_hostcfg7_observed_free_text_is_restricted_and_marked():
    evil = "publickey <img src=x onerror=alert(1)> [click](http://evil.example/x) IGNORE PREVIOUS"
    f = good_facts(sshd=fact(sshd(authenticationmethods=evil)))
    r = verdict("'host.sshd.authenticationmethods == \"publickey\"'", f)
    assert r.verdict is Verdict.VIOLATED
    obs = r.witnesses[0].detail["observed"]
    assert SAFE.fullmatch(obs), obs
    assert "<" not in obs and "[" not in obs and "(" not in obs and " " not in obs
    assert "?" in obs                                  # the marker for what was not shown


def test_hostcfg7_set_elements_and_process_names_are_restricted_too():
    f = good_facts(sshd=fact(sshd(allowusers=["a<b>", "ok.user"])))
    r = verdict("'host.sshd.allowusers subset_of [\"x\"]'", f)
    obs = r.witnesses[0].detail["observed"]
    assert SAFE.fullmatch(obs) and "ok.user" in obs and "<" not in obs
    lst = listeners(ports=(22,), comms={22: "<b>x</b>[l](http://e)"})
    f = good_facts(listeners=fact(lst))
    r = verdict("'host.listener(22).process == [\"sshd\"]'", f)
    assert r.verdict is Verdict.VIOLATED
    assert SAFE.fullmatch(r.witnesses[0].detail["observed"])


def test_hostcfg7_observed_is_capped():
    f = good_facts(sshd=fact(sshd(authenticationmethods="a" * 190)))
    r = verdict("'host.sshd.authenticationmethods == \"publickey\"'", f)
    assert len(r.witnesses[0].detail["observed"]) <= 120
    names = [f"user{i:03d}" for i in range(40)]
    r = verdict("'host.sshd.allowusers subset_of [\"x\"]'", good_facts(sshd=fact(sshd(allowusers=names))))
    assert len(r.witnesses[0].detail["observed"]) <= 120


def test_hostcfg7_ordinary_values_are_unchanged():
    f = good_facts(sshd=fact(sshd(maxauthtries=9, passwordauthentication="yes")))
    r = std(f)
    got = {w.detail["field"]: w.detail["observed"] for w in r.witnesses}
    assert got["host.sshd.maxauthtries"] == "9"
    assert got["host.sshd.password_login_possible"] == "true"


# --------------------------------------------------------------------------------------------
# hostcfg-8: the std text says what is checked; secondary collectors are declared
# failed before: collectors == ('sshd',); the text said "no root login"

def test_hostcfg8_std_ssh_text_matches_what_the_registry_checks():
    inv = stdlib.load_std(SSH).invariant
    text = (inv.title + " " + inv.description).lower()
    assert "root key login is allowed" in text
    assert "by password" in text
    assert "no root login" not in text.replace("no root login by password", "")


def test_hostcfg8_plan_collectors_include_the_listener_table():
    p = stdlib.load_std(SSH)
    assert p.collectors == ("listeners", "sshd")
    p2 = host_plan("'host.sshd.installed == false'")
    assert p2.collectors == ("listeners", "sshd")
    assert host_plan("'host.sshd.maxauthtries <= 4'").collectors == ("sshd",)


def test_hostcfg8_render_output_lists_every_collector():
    from paddock_assurance import render
    plan = stdlib.load_std(SSH)
    g = hgraph(hnode("h", good_facts()))
    text = render.render_explain(plan, g, evaluate(plan, g, NOW), NOW)
    assert "signed facts from listeners, sshd" in text


# --------------------------------------------------------------------------------------------
# interface for the finding lifecycle: passing_targets and tombstones

def estate(*nodes):
    return hgraph(*nodes)


def test_passing_targets_lists_the_definitely_true_hosts_sorted():
    g = estate(hnode("c", good_facts()), hnode("a", good_facts()),
               hnode("b", good_facts(sshd=fact(sshd(passwordauthentication="yes")))),
               hnode("d", good_facts(sshd=fact(sshd(), signed=False))))
    r = evaluate(stdlib.load_std(SSH), g, NOW)
    assert r.verdict is Verdict.VIOLATED
    assert r.passing_targets == ["a", "c"] and r.passing_truncated is False
    assert r.violating_targets == ["b"] and r.unproven_targets == ["d"]
    d = r.to_dict()
    assert d["passing_targets"] == ["a", "c"] and d["passing_truncated"] is False


def test_passing_targets_is_present_and_empty_for_a_host_result_without_passers():
    g = estate(hnode("b", good_facts(sshd=fact(sshd(passwordauthentication="yes")))))
    d = evaluate(stdlib.load_std(SSH), g, NOW).to_dict()
    assert d["passing_targets"] == [] and d["passing_truncated"] is False


def test_passing_targets_is_capped_and_flagged(monkeypatch):
    monkeypatch.setattr(EV, "MAX_VIOLATING_TARGETS", 3)
    g = estate(*[hnode(f"h{i}", good_facts()) for i in range(5)])
    r = evaluate(stdlib.load_std(SSH), g, NOW)
    assert r.verdict is Verdict.HOLDS
    assert r.passing_targets == ["h0", "h1", "h2"] and r.passing_truncated is True
    assert r.to_dict()["passing_truncated"] is True


def test_passing_targets_is_not_part_of_other_assertions():
    g = ReachGraph.from_dict({"version": 1, "nodes": [{"id": "a"}], "edges": []})
    d = evaluate(stdlib.load_std("std:coverage-complete"), g, NOW).to_dict()
    assert "passing_targets" not in d and "passing_truncated" not in d


def test_passing_targets_serialisation_is_deterministic():
    g = estate(*[hnode(f"h{i}", good_facts()) for i in (3, 1, 2)])
    a = json.dumps(evaluate(stdlib.load_std(SSH), g, NOW).to_dict(), sort_keys=True)
    b = json.dumps(evaluate(stdlib.load_std(SSH), g, NOW).to_dict(), sort_keys=True)
    assert a == b and '"passing_targets": ["h1", "h2", "h3"]' in a


@pytest.mark.parametrize("marker", [
    {"data": {"agent_status": "revoked"}},
    {"data": {"agent_status": "legacy"}},
    {"data": {"agent_status": "rekeyed"}},
    {"data": {"status": "revoked"}},
    {"reason": "agent_revoked"},
])
def test_tombstoned_host_is_unknown_with_a_distinct_reason(marker):
    kw = dict(marker)
    data = kw.pop("data", {})
    tomb = fact(data, status="unavailable", signed=False, partial=True, conf="approximate", **kw)
    g = estate(hnode("gone", {"host_agent": tomb}), hnode("ok", good_facts()))
    r = evaluate(stdlib.load_std(SSH), g, NOW)
    assert r.verdict is Verdict.UNKNOWN
    assert r.unproven_targets == ["gone"] and r.passing_targets == ["ok"]
    assert [(b.node, b.reason, b.collector) for b in r.blind_spots] == [("gone", "agent_revoked", None)]


def test_a_tombstone_wins_over_facts_that_look_usable():
    # a revoked agent's old facts are never relied on, a violation included: the host reads UNKNOWN
    facts = good_facts(host_agent=fact({"agent_status": "revoked"}, status="unavailable",
                                       signed=False))
    r = std(facts)
    assert r.verdict is Verdict.UNKNOWN and r.hosts["unknown"] == 1
    assert res("host.sshd.maxauthtries", (), facts).reason == "agent_revoked"
    bad = good_facts(sshd=fact(sshd(passwordauthentication="yes")),
                     host_agent=fact({"agent_status": "legacy"}, status="unavailable", signed=False))
    assert std(bad).verdict is Verdict.UNKNOWN


def test_a_live_host_agent_summary_is_not_a_tombstone():
    facts = good_facts(host_agent=fact({"agent_status": "active", "agent_id": "x"}))
    assert std(facts).verdict is Verdict.HOLDS


def test_a_tombstone_reason_ranks_right_after_no_agent():
    assert HF.REASON_ORDER.index("no_agent") < HF.REASON_ORDER.index("agent_revoked") \
        < HF.REASON_ORDER.index("no_sensor")


# --------------------------------------------------------------------------------------------
# REWORK ROUND (verifier report on the first fix)
#
# hostcfg-4 regression: a per-variant leaf is False when SOME variant fails it. Under an `any` with
# another variant-dependent child, "A fails somewhere" and "B fails somewhere" does not mean "A and B
# both fail in one variant", so the `any` must not be False. failed before: VIOLATED ['witness_found']

def _any(*leaves):
    return host_plan_doc({"any": list(leaves)})


def _run(plan, facts):
    return evaluate(plan, hgraph(hnode("h", facts)), NOW)


def test_hostcfg4r_any_of_two_variant_leaves_is_not_violated_when_each_variant_satisfies_one():
    f = sshd_facts(deltas=[{"permitrootlogin": "prohibit-password"}], permitrootlogin="no")
    r = _run(_any('host.sshd.permitrootlogin == "no"',
                  'host.sshd.permitrootlogin == "prohibit-password"'), f)
    assert r.verdict is not Verdict.VIOLATED and r.violating_targets == []
    assert r.verdict is Verdict.UNKNOWN              # undecided, never a false finding
    assert [b.reason for b in r.blind_spots] == ["match_override"]
    f = sshd_facts(deltas=[{"maxauthtries": 2}], maxauthtries=6)
    r = _run(_any("host.sshd.maxauthtries <= 3", "host.sshd.maxauthtries >= 5"), f)
    assert r.verdict is Verdict.UNKNOWN and r.violating_targets == []


def test_hostcfg4r_an_all_inside_an_any_is_not_a_witness_either():
    f = sshd_facts(deltas=[{"maxauthtries": 2}], maxauthtries=6)
    plan = host_plan_doc({"any": [{"all": ["host.sshd.maxauthtries <= 3",
                                           'host.sshd.pubkeyauthentication == "yes"']},
                                  "host.sshd.maxauthtries >= 5"]})
    r = _run(plan, f)
    assert r.verdict is Verdict.UNKNOWN and r.violating_targets == []


def test_hostcfg4r_a_variant_that_violates_still_decides_when_the_other_branches_are_uniform():
    # the std shape: `any [installed == false, all [...]]`; installed is the same in every variant
    f = sshd_facts(deltas=[{"maxauthtries": 10}])
    r = _run(_any("host.sshd.installed == false", "host.sshd.maxauthtries <= 3"), f)
    assert r.verdict is Verdict.VIOLATED
    assert std(sshd_facts(deltas=[{"permitemptypasswords": "yes"}])).verdict is Verdict.VIOLATED


def test_hostcfg4r_true_is_still_decided_per_variant_under_any():
    f = sshd_facts(deltas=[{"maxauthtries": 2}], maxauthtries=6)
    assert _run(_any("host.sshd.maxauthtries <= 9", "host.sshd.installed == false"), f).verdict \
        is Verdict.HOLDS
    assert _run(_any("host.sshd.maxauthtries >= 5", "host.sshd.maxauthtries <= 9"), f).verdict \
        is Verdict.HOLDS


def test_hostcfg4r_soundness_against_the_semantics_for_every_small_shape():
    """The meaning: the host passes when the expression holds in EVERY variant. Whatever the
    evaluator says must agree with it: VIOLATED only if some variant fails it, HOLDS only if all
    satisfy it (UNKNOWN is always allowed)."""
    import itertools
    leaves = {
        "a": ("host.sshd.maxauthtries <= 3", lambda m: m <= 3),
        "b": ("host.sshd.maxauthtries >= 5", lambda m: m >= 5),
        "c": ("host.sshd.maxauthtries == 4", lambda m: m == 4),
        "t": ("host.sshd.installed == true", lambda m: True),
        "f": ("host.sshd.installed == false", lambda m: False),
    }

    def shapes(depth):
        base = list(leaves)
        if depth == 0:
            return base
        sub = shapes(depth - 1)
        out = list(base)
        for kind in ("all", "any"):
            for x, y in itertools.combinations_with_replacement(sub, 2):
                out.append((kind, x, y))
        return out

    def to_doc(s):
        if isinstance(s, str):
            return leaves[s][0]
        return {s[0]: [to_doc(s[1]), to_doc(s[2])]}

    def truth(s, m):
        if isinstance(s, str):
            return leaves[s][1](m)
        a, b = truth(s[1], m), truth(s[2], m)
        return (a and b) if s[0] == "all" else (a or b)

    checked = 0
    for base_v, delta_v in itertools.product((2, 4, 6), (2, 4, 6, 9)):
        f = sshd_facts(deltas=[{"maxauthtries": delta_v}], maxauthtries=base_v)
        for s in shapes(1) + shapes(2)[::9]:
            r = _run(host_plan_doc({"any": [to_doc(s)]} if isinstance(s, str) else to_doc(s)), f)
            vals = [truth(s, base_v), truth(s, delta_v)]
            if r.verdict is Verdict.VIOLATED:
                assert not all(vals), (base_v, delta_v, s)
            if r.verdict is Verdict.HOLDS:
                assert all(vals), (base_v, delta_v, s)
            checked += 1
    assert checked > 1000


# hostcfg-6 hole: a daemon whose command line / binary could not be read has null flags and
# reload_pending false (mtimes only). failed before: HOLDS ['no_counterexample']

@pytest.mark.parametrize("daemon", [
    {"config_default": None, "options_override": None, "binary_matches": None},
    {"config_default": None},
    {"options_override": None},
    {"binary_matches": None},
    {"found": None},
    {"found": "yes"},
    {"found": False},                    # not found, but not socket activation: 1 master was counted
    {"masters": True},
    {"masters": None},
    {"masters": 0},                      # found says a daemon, masters says none
])
def test_hostcfg6r_a_daemon_we_could_not_fully_see_never_reads_as_a_pass(daemon):
    f = good_facts(sshd=fact(sshd(daemon=daemon)))
    assert not res("host.sshd.password_login_possible", (), f).known, daemon
    r = std(f)
    assert r.verdict is Verdict.UNKNOWN, daemon
    bad = good_facts(sshd=fact(sshd(daemon=daemon, passwordauthentication="yes")))
    assert std(bad).verdict is Verdict.UNKNOWN, daemon        # approximate view: no finding either


def test_hostcfg6r_socket_activation_is_still_accepted():
    # no master daemon, reload_pending false: the agent emits that only for socket activation
    d = {"found": False, "masters": 0, "pid": None, "start_epoch": None, "config_default": None,
         "options_override": None, "binary_matches": None, "reload_pending": False}
    assert std(good_facts(sshd=fact(sshd(daemon=d)))).verdict is Verdict.HOLDS
    d["masters"] = 1
    assert std(good_facts(sshd=fact(sshd(daemon=d)))).verdict is Verdict.UNKNOWN
    d.update(masters=0, reload_pending=None)
    assert std(good_facts(sshd=fact(sshd(daemon=d)))).verdict is Verdict.UNKNOWN


# hostcfg-5 hole: the depth pre-scan was quadratic on `"\\"` repeated (3.7 s for 32 KB)

def test_hostcfg5r_the_prescan_is_linear_on_a_hostile_document():
    import time
    for text in ('"\\' * 40_000, '[' + '"\\' * 40_000, '"' * 80_000, '{"a":' + '"x\\' * 40_000):
        t0 = time.monotonic()
        with pytest.raises(GraphError):
            ReachGraph.from_json(text)
        assert time.monotonic() - t0 < 1.0, len(text)


def test_hostcfg5r_strings_with_escapes_and_brackets_do_not_count_as_nesting():
    doc = {"version": 1, "nodes": [{"id": "a[{[{", "tags": ["x\"]\\"]}], "edges": []}
    g = ReachGraph.from_json(json.dumps(doc))
    assert list(g.nodes) == ["a[{[{"]
    with pytest.raises(GraphError, match="nested"):
        ReachGraph.from_json('{"x":' + "[" * 70 + "]" * 70 + "}")


# smaller hardening the verifier noted: a port that is not an integer cannot clear "no sshd on 22",
# and a cut key is matched whatever its case. failed before: HOLDS-capable / still readable

@pytest.mark.parametrize("port", ["22", " 22", "22/tcp", None, True, "ssh"])
def test_hostcfg2r_a_port_that_is_not_an_integer_never_clears_the_absence(port):
    d = listeners(ports=(5432,), comms={5432: "postgres"})
    d["listeners"][0]["port"] = port
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"), listeners=fact(d))
    assert not res("host.sshd.installed", (), f).known, port
    assert std(f).verdict is not Verdict.HOLDS, port


def test_hostcfg3r_a_cut_key_is_matched_whatever_its_case():
    f = good_facts(sshd=fact(sshd(truncated=["PasswordAuthentication"])))
    assert not res("host.sshd.passwordauthentication", (), f).known


def test_fresh_constant_is_used():           # keeps the import honest for linters
    assert FRESH.endswith("Z")
