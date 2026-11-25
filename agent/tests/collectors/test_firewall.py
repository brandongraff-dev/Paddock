"""firewall collector: tool selection, failure classification and frontends (no OS needed)."""
import json

import pytest

from paddock_agent.collectors import base, firewall, fwmodel, payload_bytes

from .helpers import FakeRunner, fixture, make_ctx, res

U = "ubuntu2404/"
S = "synthetic/firewall/"
NFT_BIN = ["/usr/sbin/nft"]
NFT_REAL = fixture(U + "nft_json_unshare.json")
NFT_EMPTY = json.dumps({"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]})
V6 = {"/proc/net/if_inet6": "fe80000000000000000000000000dead 02 40 20 80 eth0\n"}
NO_V6 = {"/proc/net/if_inet6": "00000000000000000000000000000001 01 80 10 80 lo\n"}


def nft_runner(out, rc=0, err="", extra=None):
    table = {"nft": lambda argv: res(out, rc=rc, err=err)}
    table.update(extra or {})
    return FakeRunner(table)


def collect(tmp_path, runner, files=None, bins=NFT_BIN, **kw):
    ctx = make_ctx(tmp_path, runner=runner, files=files if files is not None else NO_V6, bins=bins, **kw)
    sec = firewall.collect(ctx)
    base.validate_section(sec)
    return sec


# ------------------------------------------------------------------ nft as the source of truth
def test_real_nft_capture_is_exact_and_deterministic(tmp_path):
    sec = collect(tmp_path, nft_runner(NFT_REAL))
    # the captured ruleset contains a `meta mark` accept: opaque, so the model is approximate
    assert sec["s"] == "ok" and sec["conf"] == "approximate" and sec["partial"] is False
    m = sec["v"]
    assert m["backend"] == "nft" and m["v"] == 1 and m["ipv6_enabled"] is False
    assert m["families"]["ip4"]["read"] is True
    assert payload_bytes(sec) == payload_bytes(collect(tmp_path / "again", nft_runner(NFT_REAL)))
    assert m["families"]["ip4"]["effective_default"] == "drop"
    assert fwmodel.default_inbound_all_families(m) == "unknown"  # never deny from an approximate model


def test_empty_ruleset_is_an_exact_accept_not_an_unknown(tmp_path):
    sec = collect(tmp_path, nft_runner(NFT_EMPTY))
    m = sec["v"]
    assert sec["conf"] == "exact" and m["backend"] == "none"
    assert m["families"]["ip4"]["effective_default"] == "accept"
    assert fwmodel.default_inbound_all_families(m) == "allow"


def test_frontends_are_recorded_but_never_truth(tmp_path):
    runner = nft_runner(NFT_EMPTY, extra={
        "ufw": res(fixture(S + "ufw_status_active.txt")),
        "firewall-cmd": lambda argv: res("running\n") if argv[-1] == "--state" else res("public\n")})
    sec = collect(tmp_path, runner, bins=NFT_BIN + ["/usr/sbin/ufw", "/usr/bin/firewall-cmd"])
    fe = dict((f["name"], f) for f in sec["v"]["frontends"])
    assert fe["ufw"] == {"name": "ufw", "state": "active", "default_incoming": "deny", "rules": 3}
    assert fe["firewalld"]["state"] == "running" and fe["firewalld"]["default_zone"] == "public"
    # ufw claims "deny incoming" but the kernel has no filter chain: the model says accept
    assert sec["v"]["families"]["ip4"]["effective_default"] == "accept"
    assert fwmodel.default_inbound_all_families(sec["v"]) == "allow"


def test_frontend_failure_is_unknown_state_not_active(tmp_path):
    runner = nft_runner(NFT_EMPTY, extra={"ufw": res("", rc=1, err="ERROR: You need to be root")})
    sec = collect(tmp_path, runner, bins=NFT_BIN + ["/usr/sbin/ufw"])
    assert sec["v"]["frontends"][0]["state"] == "unknown"


def test_ipv6_enabled_without_v6_rules_is_not_a_deny(tmp_path):
    obj = {"nftables": [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "filter", "handle": 1}},
        {"chain": {"family": "ip", "table": "filter", "name": "input", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "drop"}}]}
    sec = collect(tmp_path, nft_runner(json.dumps(obj)), files=V6)
    m = sec["v"]
    assert m["ipv6_enabled"] is True and m["families"]["ip4"]["effective_default"] == "drop"
    assert m["families"]["ip6"]["effective_default"] == "accept"
    assert fwmodel.default_inbound_all_families(m) == "allow"


# ------------------------------------------------------------------ failures never become ok
@pytest.mark.parametrize("kw,state,reason", [
    (dict(rc=1, err="Error: Operation not permitted (you must be root)"), "unavailable", "permission_denied"),
    (dict(rc=1, err="netlink: Error: cache initialization failed"), "error", "exit_nonzero"),
])
def test_nft_failure_without_legacy_is_classified(tmp_path, kw, state, reason):
    sec = collect(tmp_path, nft_runner("", **kw))
    assert sec["s"] == state and sec["reason"] == reason


def test_nft_timeout_and_truncation(tmp_path):
    sec = collect(tmp_path, FakeRunner({"nft": res("", timed_out=True, rc=None)}))
    assert sec == {"s": "error", "reason": "timeout", "detail": "nft timed out"}
    sec = collect(tmp_path / "t", FakeRunner({"nft": res("{", truncated=True)}))
    assert sec["s"] == "error" and sec["reason"] == "truncated"


@pytest.mark.parametrize("out", ["", "not json", "[]", '{"nftables": 3}', '{"nftables": [1, 2]}x'])
def test_nft_garbage_is_parse_error_never_an_empty_ok(tmp_path, out):
    sec = collect(tmp_path, nft_runner(out))
    assert sec["s"] == "error" and sec["reason"] == "parse_error"


def test_non_root_without_net_admin_is_permission_denied(tmp_path):
    ctx = make_ctx(tmp_path, runner=nft_runner(NFT_REAL), files=NO_V6, bins=NFT_BIN, is_root=False)
    ctx._cap_eff = 0
    assert firewall.collect(ctx) == {"s": "unavailable", "reason": "permission_denied"}


def test_no_tool_at_all_and_platform_and_container(tmp_path):
    assert collect(tmp_path, FakeRunner(), bins=[]) == {"s": "unavailable", "reason": "tool_missing"}
    ctx = make_ctx(tmp_path / "c", runner=nft_runner(NFT_REAL), bins=NFT_BIN, containerised=True)
    assert firewall.collect(ctx) == {"s": "unavailable", "reason": "containerised_agent"}
    ctx = make_ctx(tmp_path / "d", runner=nft_runner(NFT_REAL), bins=NFT_BIN)
    ctx.platform = "darwin"
    assert firewall.collect(ctx) == {"s": "unavailable", "reason": "unsupported_platform"}


def test_more_than_2000_rules_is_truncated_not_a_silent_cut(tmp_path):
    rules = [{"rule": {"family": "ip", "table": "f", "chain": "input", "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                   "right": 1000 + i % 30000}}, {"accept": None}]}} for i in range(2100)]
    obj = {"nftables": [{"table": {"family": "ip", "name": "f", "handle": 1}},
                        {"chain": {"family": "ip", "table": "f", "name": "input", "type": "filter",
                                   "hook": "input", "prio": 0, "policy": "drop"}}] + rules}
    sec = collect(tmp_path, nft_runner(json.dumps(obj)))
    assert sec["s"] == "error" and sec["reason"] == "truncated"


# ------------------------------------------------------------------ legacy iptables
LEGACY_SAVE = fixture(S + "ufw_iptables_save.txt")
IPT_LEGACY_BINS = ["/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save",
                   "/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save", "/usr/sbin/iptables"]
LOADED4 = {"/proc/net/ip_tables_names": "filter\nnat\n"}


def legacy_runner(flavour="legacy", out=LEGACY_SAVE, rc=0, err=""):
    return FakeRunner({
        "iptables-legacy-save": res(out, rc=rc, err=err),
        "ip6tables-legacy-save": res("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"),
        "iptables": res("iptables v1.8.10 (%s)\n" % flavour)})


def test_legacy_iptables_without_nft_binary_is_read_when_nf_tables_is_absent(tmp_path):
    files = dict(NO_V6, **LOADED4)
    files["/proc/modules"] = "ip_tables 32768 1 iptable_filter, Live 0x0\n"
    sec = collect(tmp_path, legacy_runner(), files=files, bins=IPT_LEGACY_BINS)
    assert sec["s"] == "ok" and sec["v"]["backend"] == "legacy"
    assert sec["v"]["families"]["ip4"]["read"] is True and sec["partial"] is False
    assert sec["v"]["families"]["ip4"]["effective_default"] in ("drop", "reject")


def test_no_nft_binary_but_nf_tables_loaded_means_unknown_not_exact(tmp_path):
    files = dict(NO_V6, **LOADED4)
    files["/proc/modules"] = "nf_tables 278528 85 nft_compat, Live 0x0\n"
    sec = collect(tmp_path, legacy_runner(), files=files, bins=IPT_LEGACY_BINS)
    assert sec["s"] == "ok" and sec["conf"] == "approximate" and sec["partial"] is True
    assert sec["v"]["flat_view"]["confidence"] == "unknown"
    assert sec["v"]["families"]["ip4"]["effective_default"] == "unknown"
    assert fwmodel.default_inbound_all_families(sec["v"]) == "unknown"


def test_no_nft_binary_and_unreadable_module_list_is_unknown(tmp_path):
    sec = collect(tmp_path, legacy_runner(), files=dict(NO_V6, **LOADED4), bins=IPT_LEGACY_BINS)
    assert sec["v"]["flat_view"]["confidence"] == "unknown" and sec["partial"] is True


def test_nft_failed_but_legacy_readable_is_unknown_never_exact(tmp_path):
    runner = legacy_runner()
    runner.table["nft"] = res("", rc=1, err="Error: Could not process rule: Operation not supported")
    sec = collect(tmp_path, runner, files=dict(NO_V6, **LOADED4), bins=NFT_BIN + IPT_LEGACY_BINS)
    assert sec["s"] == "ok" and sec["partial"] is True
    assert sec["v"]["flat_view"]["confidence"] == "unknown"
    assert sec["v"]["families"]["ip4"]["read"] is False
    assert fwmodel.default_inbound_all_families(sec["v"]) == "unknown"


def test_nft_ok_plus_loaded_legacy_tables_are_merged(tmp_path):
    runner = legacy_runner()
    runner.table["nft"] = res(NFT_EMPTY)
    sec = collect(tmp_path, runner, files=dict(NO_V6, **LOADED4), bins=NFT_BIN + IPT_LEGACY_BINS)
    assert sec["v"]["backend"] == "mixed"
    names = [c["name"] for c in sec["v"]["families"]["ip4"]["chains"]]
    assert any(n.startswith("legacy4.filter.") for n in names)
    assert sec["v"]["families"]["ip4"]["effective_default"] in ("drop", "reject")


def test_nft_ok_and_legacy_tables_loaded_but_no_legacy_tool_is_unreadable(tmp_path):
    runner = FakeRunner({"nft": res(NFT_EMPTY), "iptables": res("iptables v1.8.10 (nf_tables)\n")})
    sec = collect(tmp_path, runner, files=dict(NO_V6, **LOADED4),
                  bins=NFT_BIN + ["/usr/sbin/iptables-save", "/usr/sbin/iptables"])
    assert sec["v"]["families"]["ip4"]["read"] is False and sec["partial"] is True
    assert sec["v"]["flat_view"]["confidence"] == "unknown"
    assert sec["v"]["families"]["ip4"]["effective_default"] == "unknown"


def test_nft_ok_and_legacy_table_list_unreadable_is_unknown(tmp_path):
    runner = legacy_runner()
    runner.table["nft"] = res(NFT_EMPTY)
    ctx = make_ctx(tmp_path, runner=runner, files=NO_V6, bins=NFT_BIN + IPT_LEGACY_BINS)
    import os
    p = ctx.fs_path("/proc/net/ip_tables_names")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    os.mkdir(p)  # reading a directory is an OSError that is not "missing"
    sec = firewall.collect(ctx)
    assert sec["v"]["families"]["ip4"]["read"] is False
    assert sec["v"]["flat_view"]["confidence"] == "unknown"


def test_legacy_save_failure_is_not_an_empty_ruleset(tmp_path):
    files = dict(NO_V6, **LOADED4)
    files["/proc/modules"] = "ip_tables 32768 1 iptable_filter, Live 0x0\n"
    sec = collect(tmp_path, legacy_runner(out="", rc=1, err="iptables-save: Permission denied (you must be root)"),
                  files=files, bins=IPT_LEGACY_BINS)
    assert sec == {"s": "unavailable", "reason": "permission_denied"}


def test_dormant_nft_table_filters_nothing():
    obj = {"nftables": [
        {"table": {"family": "inet", "name": "f", "handle": 1, "flags": ["dormant"]}},
        {"chain": {"family": "inet", "table": "f", "name": "input", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "drop"}}]}
    m = fwmodel.build_model(fwmodel.normalise_nft(obj), "nft", [], False)
    assert m["families"]["ip4"]["chains"] == [] and m["families"]["ip4"]["effective_default"] == "accept"


def test_parsers_ufw_and_firewalld_and_flavour():
    assert firewall.parse_ufw_status(fixture(S + "ufw_status_inactive.txt"))["state"] == "inactive"
    assert firewall.parse_ufw_status("garbage")["state"] == "unknown"
    assert firewall.parse_firewalld_state(0, "running\n")["state"] == "running"
    assert firewall.parse_firewalld_state(252, "not running\n")["state"] == "not_running"
    assert firewall.parse_firewalld_state(1, "")["state"] == "unknown"
    assert firewall.parse_ipt_flavour("iptables v1.8.10 (nf_tables)") == "nft"
    assert firewall.parse_ipt_flavour("iptables v1.8.10 (legacy)") == "legacy"
    assert firewall.parse_ipt_flavour("iptables v1.4.21") == "legacy"
    assert firewall.parse_ipt_flavour("") == "unknown"
