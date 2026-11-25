"""Regression tests for the P2 adversarial review (findings agent-1 .. agent-12, pkg-3, pkg-11, wire-1-canon).

Every test here failed against the pre-fix source for the reason named in its docstring; the unsafe input must
never produce a success / HOLDS-like outcome, and the fail-safe direction (refuse, retry, UNKNOWN) wins.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
import types
import uuid

import pytest

from paddock_agent import envelope
from paddock_agent.actions import Action
from paddock_agent.agent import EXIT_OK, EXIT_RE_ENROLL, MAX_AUTH_FAILURES, Agent, AgentError
from paddock_agent.client import FleetClient, FleetClientError, normalize_server
from paddock_agent.config import AgentConfig
from paddock_agent.platform_block import CompletedLike, EnforcerError, LinuxEnforcer, RevertRefused
from paddock_agent.state import State
from tests.test_agent import Rig, _server_action

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_IP = "192.0.2.10"


def _resolver(host, port, *a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SERVER_IP, port))]


class FakeIptables:
    """A stateful iptables: -I/-C/-D over a rule list, so tests see the real effect of a command sequence."""

    def __init__(self, rules=None, fail=None):
        self.rules = list(rules or [])
        self.calls = []
        self.fail = fail                  # callable(cmd) -> True to make that command fail
        self.on_first = None              # hook run before the very first command

    def __call__(self, cmd):
        if self.on_first is not None and not self.calls:
            hook, self.on_first = self.on_first, None
            hook()
        self.calls.append(list(cmd))
        if cmd[0] != "iptables":
            return CompletedLike(127, "", "not iptables")
        if self.fail is not None and self.fail(cmd):
            return CompletedLike(1, "", "boom")
        op, chain, spec = cmd[1], cmd[2], tuple(cmd[3:])
        if op == "-I":
            self.rules.insert(0, (chain, spec))
            return CompletedLike(0)
        if op == "-C":
            return CompletedLike(0 if (chain, spec) in self.rules else 1)
        if op == "-D":
            if (chain, spec) in self.rules:
                self.rules.remove((chain, spec))
                return CompletedLike(0)
            return CompletedLike(1, "", "Bad rule (does a matching rule exist in that chain?)")
        return CompletedLike(2)


def _linux_rig(tmp_path, runner=None, **kw):
    runner = runner or FakeIptables()
    enf = LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"), hosts_path=str(tmp_path / "hosts"))
    r = Rig(tmp_path, enforcer=enf, **kw)
    r.agent._resolver = _resolver
    r.enroll()
    return r, runner, enf


def _revert_action_dict(rid, plan):
    return {"id": rid, "action_type": "revert", "target": "x", "status": "approved", "dry_run": False,
            "revert_of": "a", "result": {"revert": plan}}


# --------------------------------------------------------------------------- #
# agent-1 / pkg-3: a key rotated by another process must not silence the daemon
# --------------------------------------------------------------------------- #

def test_daemon_picks_up_a_key_rotated_by_another_process(tmp_path):
    """agent-1/pkg-3: the daemon kept signing with the retired key (401 key_not_active x10, exit 7)."""
    r = Rig(tmp_path)
    r.enroll()
    daemon = r.agent
    assert daemon.step() == "ok"                                  # the daemon caches its key
    cli = r.fresh_agent()
    new_kid = cli.rotate_key()                                    # `sudo paddock rotate-key`
    assert daemon.step() == "ok"                                  # a 401 -> reload from disk -> one retry
    assert daemon._auth_failures == 0
    assert r.fleet.accepted[-1][1]["kid"] == new_kid
    assert daemon.run(max_iterations=15, sleep=r.clock.sleep) == EXIT_OK


def test_a_401_with_unchanged_keys_still_counts_as_an_auth_failure(tmp_path):
    r = Rig(tmp_path)
    r.enroll()
    r.fleet.fail.append(401)
    assert r.agent.step() == "auth"
    assert r.agent._auth_failures == 1


def test_enroll_force_by_another_process_is_picked_up_too(tmp_path):
    r = Rig(tmp_path)
    r.enroll()
    daemon = r.agent
    assert daemon.step() == "ok"
    cli = r.fresh_agent()
    cli.enroll(r.fleet.new_token(), hostname="web-01.example", force=True)
    assert daemon.step() == "ok"
    assert r.fleet.accepted[-1][1]["kid"] == r.fleet.active_key()


# --------------------------------------------------------------------------- #
# agent-2 / pkg-11: only an explicit structured verdict is terminal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status", [401, 403, 404])
def test_bare_infrastructure_refusals_never_end_the_loop(tmp_path, status):
    """agent-2/pkg-11: ten bare 401/403/404 (a WAF, an ingress) ended the daemon with exit 7 (no restart)."""
    r = Rig(tmp_path)
    r.enroll()
    r.fleet.fail.extend([status] * (MAX_AUTH_FAILURES + 5))
    assert r.agent.run(max_iterations=MAX_AUTH_FAILURES + 5, sleep=r.clock.sleep) == EXIT_OK
    assert max(r.clock.slept) <= 300.0                             # still the capped backoff
    assert r.agent.run(max_iterations=2, sleep=r.clock.sleep) == EXIT_OK
    assert r.fleet.accepted                                        # and it recovers when the server answers


def test_a_non_json_refusal_mentioning_the_verdict_is_not_terminal(tmp_path):
    r = Rig(tmp_path)
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (403, {}, "<html>agent_revoked re_enroll_required</html>")
    assert r.agent.step() == "auth"
    r.fleet.handle = real


@pytest.mark.parametrize("body", [{"error": "agent_revoked", "detail": "x", "reason": "agent_revoked"},
                                  {"error": "re_enroll_required"}])
def test_an_explicit_structured_verdict_is_terminal_at_once(tmp_path, body):
    """agent-2: the server's own `agent_revoked` answer was not even recognised."""
    r = Rig(tmp_path)
    r.enroll()
    r.fleet.handle = lambda m, p, h, b: (403, {}, body)
    assert r.agent.run(max_iterations=5, sleep=r.clock.sleep) == EXIT_RE_ENROLL
    assert r.clock.slept == []


# --------------------------------------------------------------------------- #
# agent-3: a poisoned action id / outbox item never wedges the heartbeat
# --------------------------------------------------------------------------- #

def test_a_non_uuid_action_id_is_refused_not_applied_and_does_not_wedge(tmp_path, enforcer):
    """agent-3: id 'zzz' was applied, its result queued forever, and the outbox head blocked every heartbeat."""
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    r.fleet.pending_actions = [_server_action(id="zzz")]
    r.agent.heartbeat()
    assert enforcer.state == set()                                 # refused before it touched the host
    assert len(r.state.outbox) == 0
    before = len([k for k, _ in r.fleet.accepted if k == "heartbeat"])
    for _ in range(3):
        assert r.agent.step() == "ok"
    assert len([k for k, _ in r.fleet.accepted if k == "heartbeat"]) == before + 3


def test_action_from_server_validates_the_id():
    with pytest.raises(Exception):
        Action.from_server({"id": "zzz", "action_type": "block_ip", "target": "203.0.113.10"})
    ok = Action.from_server({"id": str(uuid.uuid4()).upper(), "action_type": "block_ip", "target": "203.0.113.10"})
    assert ok.id == ok.id.lower() and len(ok.id) == 36


def test_a_local_validation_error_is_permanent_not_transient():
    """agent-3: _check_agent_id raised a status-None error, classified transient and queued forever."""
    c = FleetClient("https://paddock.test", agent_id=str(uuid.uuid4()), agent_token="fat_x",
                    transport=lambda *a: (200, {}, b"{}"))
    with pytest.raises(FleetClientError) as e:
        c.post_result("not-a-uuid", status="applied", output={})
    assert e.value.transient is False


def test_a_queued_result_that_keeps_failing_never_blocks_the_heartbeat(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (503, {}, {}) if "/actions/" in p else real(m, p, h, b)
    r.state.outbox.put({"kind": "result", "action_id": str(uuid.uuid4()), "status": "applied", "output": {}})
    for _ in range(3):
        r.agent.step()
    assert len([k for k, _ in r.fleet.accepted if k == "heartbeat"]) == 3      # liveness was not blocked
    for _ in range(30):
        r.agent.step()
    assert len(r.state.outbox) == 0                                # a per-item attempt limit isolates it


def test_an_expired_result_item_is_dropped(tmp_path, enforcer):
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    real = r.fleet.handle
    r.fleet.handle = lambda m, p, h, b: (503, {}, {}) if "/actions/" in p else real(m, p, h, b)
    r.state.outbox.put({"kind": "result", "action_id": str(uuid.uuid4()), "status": "applied", "output": {},
                        "issued": int(r.clock.time()) - 10 * 365 * 86400})
    r.agent.flush_outbox()
    assert len(r.state.outbox) == 0


# --------------------------------------------------------------------------- #
# agent-4: a revert is bound to something this agent applied
# --------------------------------------------------------------------------- #

def test_revert_without_a_local_record_never_deletes_an_admin_rule(tmp_path):
    """agent-4: `-D INPUT -p tcp --dport 3306 -j DROP` removed an admin's rule the agent never created."""
    admin = ("INPUT", ("-p", "tcp", "--dport", "3306", "-j", "DROP"))
    r, runner, _enf = _linux_rig(tmp_path, FakeIptables([admin]))
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), {
        "mechanism": "iptables", "action_type": "firewall_rule", "target": "in:tcp:3306"})]
    r.agent.heartbeat()
    assert admin in runner.rules
    assert not [c for c in runner.calls if c[1] == "-D"]
    assert r.fleet.results[0][1]["status"] == "failed"


def test_apply_tags_the_rule_and_revert_removes_only_the_tagged_rule_once(tmp_path):
    admin = ("INPUT", ("-p", "tcp", "--dport", "3306", "-j", "DROP"))
    r, runner, _enf = _linux_rig(tmp_path, FakeIptables([admin]))
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid, action_type="firewall_rule", target="in:tcp:3306")]
    r.agent.heartbeat()
    tagged = [x for x in runner.rules if "paddock:%s" % aid in " ".join(x[1])]
    assert len(tagged) == 1 and admin in runner.rules
    plan = r.fleet.results[0][1]["revert"]
    rid = str(uuid.uuid4())
    r.fleet.pending_actions = [_revert_action_dict(rid, plan)]
    r.agent.heartbeat()
    assert runner.rules == [admin]                                  # only ours went; the admin's stays
    assert r.fleet.results[-1][1]["status"] == "applied"
    # the record is spent: a second revert (new action id) is refused and removes nothing
    calls = len(runner.calls)
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan)]
    r.agent.heartbeat()
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert runner.rules == [admin] and not [c for c in runner.calls[calls:] if c[1] == "-D"]


def test_iptables_is_checked_before_it_is_deleted(tmp_path):
    r, runner, _enf = _linux_rig(tmp_path)
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid)]
    r.agent.heartbeat()
    plan = r.fleet.results[0][1]["revert"]
    runner.calls.clear()
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan)]
    r.agent.heartbeat()
    ops = [c[1] for c in runner.calls]
    assert ops.index("-C") < ops.index("-D")


# --------------------------------------------------------------------------- #
# agent-5: quarantine_file does not follow symlinks and spares the agent's own state
# --------------------------------------------------------------------------- #

@pytest.fixture
def qenf(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    return LinuxEnforcer(quarantine_dir=str(state / "quarantine"), hosts_path=str(tmp_path / "hosts")), tmp_path


def test_apply_refuses_a_symlinked_parent_directory(qenf):
    """agent-5: <d>/tmp/x swapped for a symlink to <d>/etc moved <d>/etc/passwd away."""
    enf, tmp = qenf
    (tmp / "etc").mkdir()
    (tmp / "etc" / "passwd").write_text("root:x:0:0\n")
    (tmp / "tmp").mkdir()
    os.symlink(str(tmp / "etc"), str(tmp / "tmp" / "x"))
    with pytest.raises(EnforcerError):
        enf.apply("quarantine_file", str(tmp / "tmp" / "x" / "passwd"))
    assert (tmp / "etc" / "passwd").exists()


def test_apply_refuses_a_symlinked_final_component_and_a_directory(qenf):
    enf, tmp = qenf
    (tmp / "secret").write_text("s")
    os.symlink(str(tmp / "secret"), str(tmp / "link"))
    with pytest.raises(EnforcerError):
        enf.apply("quarantine_file", str(tmp / "link"))
    (tmp / "adir").mkdir()
    with pytest.raises(EnforcerError):
        enf.apply("quarantine_file", str(tmp / "adir"))
    assert os.path.islink(str(tmp / "link")) and (tmp / "adir").is_dir()


def test_restore_refuses_a_parent_swapped_for_a_symlink(qenf):
    """agent-5: after a 'false positive' revert the file landed in <d>/etc/cron.d through a symlinked parent."""
    enf, tmp = qenf
    (tmp / "tmp" / "y").mkdir(parents=True)
    (tmp / "etc" / "cron.d").mkdir(parents=True)
    victim = tmp / "tmp" / "y" / "backdoor"
    victim.write_text("payload")
    res = enf.apply("quarantine_file", str(victim))
    os.rmdir(str(tmp / "tmp" / "y"))
    os.symlink(str(tmp / "etc" / "cron.d"), str(tmp / "tmp" / "y"))
    with pytest.raises(RevertRefused):
        enf.revert(res["revert"])
    assert os.listdir(str(tmp / "etc" / "cron.d")) == []
    assert os.path.isfile(res["output"]["moved"]["dest"])           # still quarantined


def test_restore_refuses_a_file_whose_mode_changed_in_quarantine(qenf):
    enf, tmp = qenf
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    os.chmod(str(victim), 0o640)
    res = enf.apply("quarantine_file", str(victim))
    os.chmod(res["output"]["moved"]["dest"], 0o4755)
    with pytest.raises(RevertRefused):
        enf.revert(res["revert"])
    assert not victim.exists()


def test_restore_keeps_mode_and_content(qenf):
    enf, tmp = qenf
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    os.chmod(str(victim), 0o640)
    res = enf.apply("quarantine_file", str(victim))
    enf.revert(res["revert"])
    assert victim.read_text() == "payload" and (victim.stat().st_mode & 0o7777) == 0o640


def test_the_agents_own_state_and_quarantine_cannot_be_quarantined(tmp_path):
    """agent-5: quarantining <state>/keys/ed25519.key was 'applied' and bricked the agent."""
    r = Rig(tmp_path)                                                # the real Linux enforcer over the Agent's dirs
    r.enroll()
    key = os.path.join(r.cfg.state_dir, "keys", "ed25519.key")
    r.fleet.pending_actions = [_server_action(action_type="quarantine_file", target=key)]
    r.agent.heartbeat()
    assert os.path.isfile(key)
    assert r.fleet.results[-1][1]["status"] == "failed"
    os.makedirs(r.cfg.quarantine_dir, exist_ok=True)
    manifest = os.path.join(r.cfg.quarantine_dir, ".paddock-manifest.json")
    open(manifest, "w").write("{}")
    r.fleet.pending_actions = [_server_action(id=str(uuid.uuid4()), action_type="quarantine_file", target=manifest)]
    r.agent.heartbeat()
    assert os.path.isfile(manifest)


# --------------------------------------------------------------------------- #
# agent-6: /etc/hosts
# --------------------------------------------------------------------------- #

def _hosts_enf(tmp_path, text):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(text.encode())
    return LinuxEnforcer(runner=FakeIptables(), quarantine_dir=str(tmp_path / "q"), hosts_path=str(hosts)), hosts


def test_block_domain_does_not_glue_onto_a_last_line_without_a_newline(tmp_path):
    """agent-6: '10.0.0.5 db' + sinkhole line became '10.0.0.5 db127.0.0.1 evil.example ...'."""
    enf, hosts = _hosts_enf(tmp_path, "127.0.0.1 localhost\n10.0.0.5 db")
    res = enf.apply("block_domain", "evil.example")
    assert hosts.read_text() == ("127.0.0.1 localhost\n10.0.0.5 db\n"
                                 "127.0.0.1 evil.example  # paddock-agent block\n")
    enf.revert(res["revert"])
    assert hosts.read_text() == "127.0.0.1 localhost\n10.0.0.5 db\n"


def test_hosts_revert_that_removes_nothing_reports_failure(tmp_path):
    enf, hosts = _hosts_enf(tmp_path, "127.0.0.1 localhost\n")
    plan = {"mechanism": "hosts-sinkhole", "action_type": "block_domain", "target": "evil.example"}
    with pytest.raises(EnforcerError):
        enf.revert(plan)
    assert hosts.read_text() == "127.0.0.1 localhost\n"


def test_hosts_revert_leaves_unrelated_lines_byte_identical(tmp_path):
    """agent-6: splitlines() also split on \\x0b/\\x0c/U+2028 and the rewrite re-joined with \\n."""
    odd = "10.0.0.1 a\x0bb # odd\r\n10.0.0.2 c d\n"
    enf, hosts = _hosts_enf(tmp_path, odd)
    res = enf.apply("block_domain", "evil.example")
    enf.revert(res["revert"])
    assert hosts.read_bytes() == odd.encode()


def test_hosts_write_preserves_mode_and_is_atomic(tmp_path):
    enf, hosts = _hosts_enf(tmp_path, "127.0.0.1 localhost\n")
    os.chmod(str(hosts), 0o640)
    ino = os.stat(str(hosts)).st_ino
    enf.apply("block_domain", "evil.example")
    st = os.stat(str(hosts))
    assert (st.st_mode & 0o7777) == 0o640 and st.st_ino != ino      # replaced atomically, not truncated in place


# --------------------------------------------------------------------------- #
# agent-7: apply is crash safe
# --------------------------------------------------------------------------- #

def test_a_failing_second_command_rolls_the_first_back(tmp_path):
    """agent-7: the INPUT DROP stayed on the host, unrecorded, when the OUTPUT insert failed."""
    runner = FakeIptables(fail=lambda c: c[1] == "-I" and c[2] == "OUTPUT")
    enf = LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"), hosts_path=str(tmp_path / "h"))
    with pytest.raises(EnforcerError):
        enf.apply("block_ip", "203.0.113.9")
    assert runner.rules == []


def test_an_intent_record_is_written_before_the_first_command(tmp_path):
    """agent-7: nothing was on disk until after the effect."""
    r, runner, _enf = _linux_rig(tmp_path)
    seen = {}
    aid = str(uuid.uuid4())
    runner.on_first = lambda: seen.update(r.state.load_handled())
    r.fleet.pending_actions = [_server_action(id=aid)]
    r.agent.heartbeat()
    assert seen[aid]["status"] == "applying"


def test_a_crash_before_the_record_is_final_does_not_apply_twice(tmp_path):
    """agent-7: a kill between the effect and handled.json re-applied: the INPUT rule was inserted twice."""
    r, runner, _enf = _linux_rig(tmp_path)
    aid = str(uuid.uuid4())
    real = State.save_handled
    boom = {"on": True}

    def crashing(self, items, *a, **k):
        if boom["on"] and any(v.get("status") in ("applied", "failed") for v in items.values()):
            raise OSError("killed")
        return real(self, items, *a, **k)

    State.save_handled = crashing
    try:
        r.fleet.pending_actions = [_server_action(id=aid)]
        r.agent.heartbeat()
    finally:
        State.save_handled = real
    boom["on"] = False
    again = r.fresh_agent(enforcer=LinuxEnforcer(runner=runner, quarantine_dir=str(tmp_path / "q"),
                                                 hosts_path=str(tmp_path / "hosts")))
    again._resolver = _resolver
    r.fleet.pending_actions = [_server_action(id=aid)]
    again.heartbeat()
    inputs = [x for x in runner.rules if x[0] == "INPUT"]
    assert len(inputs) == 1
    # and the one revert plan still undoes everything
    plan = r.fleet.results[-1][1]["revert"]
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan)]
    again.heartbeat()
    assert runner.rules == []


# --------------------------------------------------------------------------- #
# agent-8: dry-run parsing is fail-safe
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", ["y", "Y", "t", "enabled", "ture", "dry-run", "2", "disable", "  maybe "])
def test_unrecognised_dry_run_values_keep_dry_run(monkeypatch, value):
    """agent-8: PADDOCK_DRY_RUN=y (or a typo) turned live enforcement ON."""
    monkeypatch.setenv("PADDOCK_DRY_RUN", value)
    assert AgentConfig().dry_run is True


@pytest.mark.parametrize("value,expected", [("0", False), ("false", False), ("No", False), ("OFF", False),
                                            ("1", True), ("true", True), ("yes", True), ("on", True), ("", True)])
def test_explicit_dry_run_values(monkeypatch, value, expected):
    monkeypatch.setenv("PADDOCK_DRY_RUN", value)
    assert AgentConfig().dry_run is expected


def test_imds_stays_off_for_anything_but_an_explicit_true(monkeypatch):
    for v in ("enabled", "y", "maybe"):
        monkeypatch.setenv("PADDOCK_ENABLE_IMDS", v)
        assert AgentConfig().enable_imds is False
    monkeypatch.setenv("PADDOCK_ENABLE_IMDS", "true")
    assert AgentConfig().enable_imds is True


# --------------------------------------------------------------------------- #
# agent-9: no self-lockout
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("atype,target", [
    ("block_ip", SERVER_IP), ("block_ip", "127.0.0.1"), ("block_ip", "0.0.0.0"), ("block_ip", "255.255.255.255"),
    ("firewall_rule", "out:tcp:443"), ("firewall_rule", "out:udp:443"), ("block_domain", "paddock.test"),
])
def test_actions_that_would_cut_the_agent_off_are_refused(tmp_path, atype, target):
    """agent-9: the server's own address, loopback, 0.0.0.0, outbound 443 were all applied."""
    r, runner, _enf = _linux_rig(tmp_path)
    r.fleet.pending_actions = [_server_action(action_type=atype, target=target)]
    r.agent.heartbeat()
    assert runner.rules == [] and not (tmp_path / "hosts").exists()
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert "lockout" in json.dumps(r.fleet.results[-1][1]["output"])


def test_a_dry_run_refuses_the_same_targets_without_touching_server_state(tmp_path):
    r, runner, _enf = _linux_rig(tmp_path, dry_run=True)
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target=SERVER_IP)]
    r.agent.heartbeat()
    assert runner.calls == [] and r.fleet.results == []


def test_ordinary_blocks_are_still_applied(tmp_path):
    r, runner, _enf = _linux_rig(tmp_path)
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.10"),
                               _server_action(id=str(uuid.uuid4()), action_type="firewall_rule",
                                              target="out:tcp:8443")]
    r.agent.heartbeat()
    assert len(runner.rules) == 3


def test_an_unresolvable_server_refuses_ip_blocks(tmp_path):
    """Fail safe: if we cannot prove the target is not the server, we do not block it."""
    r, runner, _enf = _linux_rig(tmp_path)

    def nope(*a, **k):
        raise socket.gaierror("no")
    r.agent._resolver = nope
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert runner.rules == []


def test_dead_man_timer_reverts_a_block_the_server_never_confirmed(tmp_path):
    """agent-9: a block that cut the agent off from the server could never be reverted (the revert rides the
    channel just cut)."""
    r, runner, _enf = _linux_rig(tmp_path)
    real = r.fleet.handle
    down = {"on": False}

    def handle(m, p, h, b):
        if down["on"] or "/actions/" in p:
            raise ConnectionResetError("cut off")
        return real(m, p, h, b)

    r.fleet.handle = handle
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()                                            # applied; the result could not be delivered
    down["on"] = True
    assert len(runner.rules) == 2
    r.clock.t += 60
    r.agent.step()
    assert len(runner.rules) == 2                                  # not yet: the dead-man window has not passed
    r.clock.t += 11 * 60
    r.agent.step()
    assert runner.rules == []
    rec = list(r.state.load_handled().values())[0]
    assert rec["rule"]["reverted"] is True


def test_a_confirmed_block_survives_a_later_outage(tmp_path):
    r, runner, _enf = _linux_rig(tmp_path)
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()                                            # applied AND the result was accepted
    real = r.fleet.handle
    r.fleet.handle = lambda *a: (_ for _ in ()).throw(ConnectionResetError("outage"))
    r.clock.t += 3600
    r.agent.step()
    assert len(runner.rules) == 2
    r.fleet.handle = real


# --------------------------------------------------------------------------- #
# agent-10: the state directory is exclusive
# --------------------------------------------------------------------------- #

_SEQ_WORKER = textwrap.dedent("""
    import sys
    sys.path.insert(0, %r)
    from paddock_agent.state import State
    st = State(sys.argv[1])
    out = open(sys.argv[2], "w")
    for _ in range(int(sys.argv[3])):
        out.write("%%d\\n" %% st.next_seq())
    out.close()
""") % AGENT_DIR


def test_two_processes_never_hand_out_the_same_seq(tmp_path):
    """agent-10: 600 reservations by two processes gave ~310 distinct numbers."""
    sd = tmp_path / "state"
    State(str(sd)).ensure_dir()
    procs = [subprocess.Popen([sys.executable, "-c", _SEQ_WORKER, str(sd), str(tmp_path / ("o%d" % i)), "200"])
             for i in range(3)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0]
    seqs = [int(x) for i in range(3) for x in (tmp_path / ("o%d" % i)).read_text().split()]
    assert len(seqs) == 600 and len(set(seqs)) == 600


def test_fast_forward_cannot_lower_the_counter_under_a_race(tmp_path):
    st = State(str(tmp_path / "state"))
    for _ in range(5):
        st.next_seq()
    assert st.fast_forward(3) is False and st.current_seq() == 5


def test_a_second_daemon_on_the_same_state_dir_is_refused(tmp_path):
    """agent-10/agent-1: nothing stopped two daemons (or a daemon and `enroll --force`) sharing one state dir."""
    r = Rig(tmp_path)
    r.enroll()
    inside, release = threading.Event(), threading.Event()
    errors = []

    def wait(_s):
        inside.set()
        release.wait(10)

    def first():
        try:
            r.agent.run(max_iterations=2, sleep=wait)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=first)
    t.start()
    assert inside.wait(10)
    try:
        other = r.fresh_agent()
        with pytest.raises(AgentError, match="already running"):
            other.run(max_iterations=1, sleep=lambda s: None)
        with pytest.raises(AgentError, match="already running"):
            other.enroll(r.fleet.new_token(), hostname="web-01.example", force=True)
    finally:
        release.set()
        t.join(10)
    assert errors == []
    assert r.fresh_agent().run(max_iterations=1, sleep=lambda s: None) == EXIT_OK      # the lock is released


def test_rotate_key_tells_a_running_daemon_to_reload(tmp_path, monkeypatch):
    """agent-1: the documented `sudo paddock rotate-key` ran in a second process the daemon never heard of."""
    from paddock_agent import cli
    from tests.fake_fleet import FakeFleet
    fleet = FakeFleet()
    httpd, url = fleet.serve()
    for k in list(os.environ):
        if k.startswith("PADDOCK_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("PADDOCK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("PADDOCK_SERVER", url)
    monkeypatch.setenv("PADDOCK_QUARANTINE_DIR", str(tmp_path / "q"))
    monkeypatch.setenv("PADDOCK_INVENTORY_SEC", "0")
    monkeypatch.setenv(cli.TOKEN_ENV, fleet.token)
    assert cli.main(["enroll", "--hostname", "web-01.example"]) == 0
    got = threading.Event()
    old = signal.signal(signal.SIGHUP, lambda *a: got.set())
    cfg = AgentConfig().with_server(url)
    cfg.inventory_interval_s = 0
    daemon = Agent(cfg, collect_fn=lambda ctx: {"schema": 2, "sections": {}}, encode_fn=envelope.canon,
                   ctx_factory=lambda seq, key_id: types.SimpleNamespace(seq=seq, key_id=key_id))
    inside, release = threading.Event(), threading.Event()
    t = threading.Thread(target=lambda: daemon.run(max_iterations=2, sleep=lambda s: (inside.set(), release.wait(20))))
    try:
        t.start()
        assert inside.wait(10)
        assert cli.main(["rotate-key"]) == 0
        assert got.wait(5)                                          # the daemon (this process) was signalled
    finally:
        release.set()
        t.join(10)
        signal.signal(signal.SIGHUP, old)
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# agent-11: the 24 h full manifest is really forced
# --------------------------------------------------------------------------- #

def test_the_forced_full_manifest_is_consumed_by_a_posture_not_by_any_step(tmp_path):
    """agent-11: the deadline was advanced by whatever step crossed it, so no posture saw the flag (0 in 5 of 6 runs)."""
    r = Rig(tmp_path)
    r.cfg.posture_interval_s = 420                                   # 14 ticks: not aligned with 24 h of 30 s ticks
    r.enroll()
    r.agent.run(max_iterations=5800, sleep=r.clock.sleep)           # ~48 h
    forced = [c for c in r.ctxs if c.force_full_manifest is True]
    assert 1 <= len(forced) <= 3
    positions = [i for i, c in enumerate(r.ctxs) if c.force_full_manifest is True]
    assert all(b - a > 100 for a, b in zip(positions, positions[1:]))      # at most one per 24 h window


# --------------------------------------------------------------------------- #
# agent-12: client hardening
# --------------------------------------------------------------------------- #

def test_deeply_nested_json_is_a_client_error_not_a_recursion_error():
    """agent-12(a): a 4 MiB reply of nested brackets escaped as RecursionError."""
    evil = b"[" * 200000 + b"]" * 200000
    c = FleetClient("https://paddock.test", agent_id=str(uuid.uuid4()), agent_token="fat_x",
                    transport=lambda *a: (200, {}, evil))
    with pytest.raises(FleetClientError):
        c.post_inventory({})


def test_an_upper_case_scheme_is_normalised_so_the_ca_context_is_installed(tmp_path):
    """agent-12(d): HTTPS://host skipped the custom CA handler (base.startswith('https://') was case-sensitive)."""
    assert normalize_server("HTTPS://Paddock.Example:8443/") == "https://paddock.example:8443"
    assert FleetClient("HTTP://127.0.0.1:8000").base == "http://127.0.0.1:8000"


def test_a_server_that_dribbles_bytes_cannot_stall_a_request_past_the_deadline():
    """agent-12(b): the timeout was per socket operation; one byte every few seconds held the loop for hours."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = srv.accept()
        try:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
            end = time.time() + 20
            while time.time() < end and not stop.is_set():
                conn.sendall(b" ")
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    result = {}

    def call():
        c = FleetClient("http://127.0.0.1:%d" % srv.getsockname()[1], agent_id=str(uuid.uuid4()),
                        agent_token="fat_x", timeout_s=1)
        c._deadline = 2.0                                           # the knob is internal; the default is 3x timeout
        t0 = time.time()
        try:
            c.post_inventory({})
        except FleetClientError as exc:
            result["err"] = exc
        result["took"] = time.time() - t0

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(12)
    stop.set()
    srv.close()
    assert not t.is_alive(), "the request was still running long after any sane deadline"
    assert "err" in result and result["took"] < 10


def test_a_server_override_that_differs_from_the_enrolled_server_is_refused(tmp_path):
    """agent-12(c): PADDOCK_SERVER beat creds.server, so the agent credential went to whatever the env named."""
    r = Rig(tmp_path)
    r.enroll()
    cfg = AgentConfig(server="https://evil.example", state_dir=r.cfg.state_dir, platform_name="linux")
    with pytest.raises(AgentError, match="enrolled"):
        Agent(cfg).client
    ok = AgentConfig(server="https://PADDOCK.test/", state_dir=r.cfg.state_dir, platform_name="linux")
    assert Agent(ok).client.base == "https://paddock.test"


# --------------------------------------------------------------------------- #
# wire-1-canon (agent side)
# --------------------------------------------------------------------------- #

def _hdr(**kw):
    base = dict(kid="k" * 32, agent_id=str(uuid.uuid4()), tenant_id=str(uuid.uuid4()), kind="heartbeat", seq=1,
                issued_at=1_790_000_000, nonce=envelope.new_nonce(), payload_type="t", payload=b"{}",
                collectors={"agent": "1"})
    base.update(kw)
    return envelope.build_header(**base)


def test_seq_is_capped_at_2_pow_53_minus_1():
    """wire-1-canon: seq up to 2^62 printed differently under RFC 8785 (IEEE doubles)."""
    assert _hdr(seq=2 ** 53 - 1)["seq"] == 2 ** 53 - 1
    with pytest.raises(envelope.EnvelopeError):
        _hdr(seq=2 ** 53)
    from paddock_agent import state
    assert state.MAX_SEQ == 2 ** 53 - 1


@pytest.mark.parametrize("key", ["Agent", "\U00010000", "￿", "a b", "", "x" * 65, "sshd/1", "é"])
def test_collector_keys_are_restricted_to_ascii_names(key):
    """wire-1-canon: non-ASCII keys sort by code point here and by UTF-16 unit under RFC 8785."""
    with pytest.raises(envelope.EnvelopeError):
        _hdr(collectors={key: "1"})


def test_ordinary_collector_keys_are_accepted():
    assert _hdr(collectors={"agent": "1", "patch.v2": "1", "a-b_c0": "x"})["collectors"]["patch.v2"] == "1"


# --------------------------------------------------------------------------- #
# agent-7 follow-ups: idempotent re-runs, leftovers stay revertable, the ledger is never trimmed away
# --------------------------------------------------------------------------- #

def test_a_quarantine_re_run_after_a_crash_is_idempotent(qenf):
    """agent-7: a re-run after the move reported `failed` for a file that was already in quarantine."""
    enf, tmp = qenf
    victim = tmp / "evil.bin"
    victim.write_text("payload")
    first = enf.apply("quarantine_file", str(victim))
    again = enf.apply("quarantine_file", str(victim))                 # the record was lost, the server re-offers it
    assert again["output"]["moved"]["dest"] == first["output"]["moved"]["dest"]
    enf.revert(again["revert"])
    assert victim.read_text() == "payload"


def test_a_hosts_line_is_never_appended_twice(tmp_path):
    enf, hosts = _hosts_enf(tmp_path, "127.0.0.1 localhost\n")
    enf.apply("block_domain", "evil.example")
    enf.apply("block_domain", "evil.example")
    assert hosts.read_text().count("evil.example") == 1


def test_a_failed_rollback_leaves_a_revertable_record(tmp_path):
    """agent-7: when the OUTPUT insert fails AND the rollback fails, a DROP stays on the host; the agent must
    know about it (and so be able to revert it), not forget it."""
    runner = FakeIptables(fail=lambda c: (c[1] == "-I" and c[2] == "OUTPUT") or (c[1] == "-D"))
    r, _runner, _enf = _linux_rig(tmp_path, runner)
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid)]
    r.agent.heartbeat()
    body = r.fleet.results[-1][1]
    assert body["status"] == "failed" and body["output"]["partial"] is True and body["revert"]
    rec = r.state.load_handled()[aid]
    assert rec["rule"]["partial"] is True and not rec["rule"]["reverted"]
    runner.fail = None                                               # iptables works again: the leftover goes
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), body["revert"])]
    r.agent.heartbeat()
    assert runner.rules == [] and r.fleet.results[-1][1]["status"] == "applied"


def test_an_iptables_probe_error_is_not_mistaken_for_absent(tmp_path):
    runner = FakeIptables(fail=lambda c: False)
    real = runner.__call__

    def probe_error(cmd):
        if cmd[1] == "-C":
            runner.calls.append(list(cmd))
            return CompletedLike(4, "", "resource problem")
        return real(cmd)
    enf = LinuxEnforcer(runner=probe_error, quarantine_dir=str(tmp_path / "q"), hosts_path=str(tmp_path / "h"))
    with pytest.raises(EnforcerError):
        enf.apply("block_ip", "203.0.113.9")
    assert runner.rules == []


def test_trimming_handled_never_drops_a_rule_still_in_force(tmp_path):
    """agent-4: handled.json keeps 256 records; a live block older than that must stay revertable."""
    st = State(str(tmp_path / "state"))
    items = {"old": {"at": 1, "status": "applied", "rule": {"action_type": "block_ip", "target": "203.0.113.9",
                                                            "reverted": False}}}
    for i in range(300):
        items["n%d" % i] = {"at": 10 + i, "status": "applied"}
    items["spent"] = {"at": 2, "status": "applied", "rule": {"action_type": "block_ip", "target": "203.0.113.8",
                                                             "reverted": True}}
    st.save_handled(items)
    kept = st.load_handled()
    assert "old" in kept and "spent" not in kept and len(kept) == 257


def test_apply_then_revert_through_the_agent_with_any_enforcer(tmp_path, enforcer):
    """The agent passes its ledger to every enforcer's validate_revert (the test double accepts it)."""
    r = Rig(tmp_path, enforcer=enforcer)
    r.enroll()
    r.fleet.pending_actions = [_server_action()]
    r.agent.heartbeat()
    plan = r.fleet.results[-1][1]["revert"]
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan)]
    r.agent.heartbeat()
    assert enforcer.state == set() and r.fleet.results[-1][1]["status"] == "applied"
