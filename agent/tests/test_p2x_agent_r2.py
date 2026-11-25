"""Round-2 regression tests for the P2 agent daemon (findings K-1 .. K-7 of the round-1 verifiers).

Every test here failed against the round-1 source for the reason named in its docstring. The unsafe input must
never end in a success / false-HOLDS-like outcome; the fail-safe direction (refuse, retry, say less) wins.
"""
from __future__ import annotations

import errno
import http.server
import json
import os
import socket
import stat
import threading
import time
import uuid

import pytest

from paddock_agent.client import FleetClient, FleetClientError
from paddock_agent.platform_block import EnforcerError, LinuxEnforcer
from tests.test_agent import _server_action
from tests.test_p2x_agent import (
    SERVER_IP,
    FakeIptables,
    _hosts_enf,
    _linux_rig,
    _revert_action_dict,
)

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tagged(runner, aid):
    return [x for x in runner.rules if "paddock:%s" % aid in " ".join(x[1])]


# --------------------------------------------------------------------------- #
# K-1: reverts work in any order; each removes exactly its own tagged rule
# --------------------------------------------------------------------------- #

def test_reverting_the_older_of_two_blocks_of_the_same_target_removes_only_its_own_rules(tmp_path):
    """K-1: revert_plan_rejected 'revert tag differs from this host's own record' for the older block."""
    r, runner, _enf = _linux_rig(tmp_path)
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=a, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    r.clock.t += 5
    r.fleet.pending_actions = [_server_action(id=b, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert len(runner.rules) == 4 and len(_tagged(runner, a)) == 2 and len(_tagged(runner, b)) == 2
    plan_a = r.fleet.results[0][1]["revert"]
    plan_b = r.fleet.results[1][1]["revert"]
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan_a)]
    r.agent.heartbeat()                                       # the OLDER block first (not LIFO)
    assert r.fleet.results[-1][1]["status"] == "applied", r.fleet.results[-1][1]["output"]
    assert _tagged(runner, a) == [] and len(_tagged(runner, b)) == 2
    handled = r.state.load_handled()
    assert handled[a].get("reverted") is True and not handled[b].get("reverted")
    # the newer one is still revertable, and only then is the host clean; a spent record is refused
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan_b)]
    r.agent.heartbeat()
    assert r.fleet.results[-1][1]["status"] == "applied" and runner.rules == []
    calls = len(runner.calls)
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan_a)]
    r.agent.heartbeat()
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert not [c for c in runner.calls[calls:] if c[1] == "-D"]


def test_a_revert_with_a_tag_this_host_never_wrote_is_still_refused(tmp_path):
    """K-1 guard: matching by tag must not let a foreign tag (or an untagged admin rule) be deleted."""
    admin = ("INPUT", ("-s", "203.0.113.10", "-j", "DROP"))
    r, runner, _enf = _linux_rig(tmp_path, FakeIptables([admin]))
    a = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=a, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    plan = dict(r.fleet.results[0][1]["revert"])
    foreign = "paddock:%s" % uuid.uuid4()
    plan["tag"] = foreign
    plan["commands"] = [[c for c in cmd] for cmd in plan["commands"]]
    for cmd in plan["commands"]:
        cmd[cmd.index("paddock:%s" % a)] = foreign
    before = list(runner.rules)
    r.fleet.pending_actions = [_revert_action_dict(str(uuid.uuid4()), plan)]
    r.agent.heartbeat()
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert runner.rules == before and admin in runner.rules


# --------------------------------------------------------------------------- #
# K-2: the cross-filesystem quarantine copy keeps setuid / setgid, or refuses
# --------------------------------------------------------------------------- #

@pytest.fixture
def qenf2(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    return LinuxEnforcer(quarantine_dir=str(state / "quarantine"), hosts_path=str(tmp_path / "hosts")), tmp_path


def _force_exdev(monkeypatch):
    real = os.rename

    def rename(src, dst, *a, **k):
        if k.get("src_dir_fd") is not None:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real(src, dst, *a, **k)
    monkeypatch.setattr(os, "rename", rename)


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o6750])
def test_exdev_quarantine_keeps_setuid_and_setgid_and_restores(qenf2, monkeypatch, mode):
    """K-2: the copy was 0755 (S_IMODE 493, expected 2541): fchown after fchmod cleared the bits."""
    enf, tmp = qenf2
    victim = tmp / "suid.bin"
    victim.write_text("payload")
    os.chmod(str(victim), mode)
    assert stat.S_IMODE(victim.stat().st_mode) == mode
    _force_exdev(monkeypatch)
    res = enf.apply("quarantine_file", str(victim))
    dest = res["output"]["moved"]["dest"]
    assert stat.S_IMODE(os.stat(dest).st_mode) == mode
    assert not victim.exists()
    enf.revert(res["revert"])                                  # the restore check accepts it again
    assert stat.S_IMODE(victim.stat().st_mode) == mode and victim.read_text() == "payload"


def test_exdev_quarantine_refuses_rather_than_lose_the_bits_when_ownership_cannot_be_kept(
        qenf2, monkeypatch):
    """K-2: if the owner cannot be preserved a setuid file must not be copied as a setuid file of somebody
    else (or silently lose the bit): the quarantine is refused, nothing is moved."""
    enf, tmp = qenf2
    victim = tmp / "suid.bin"
    victim.write_text("payload")
    os.chown(str(victim), 12345, 12345)
    os.chmod(str(victim), 0o4755)
    _force_exdev(monkeypatch)

    def nochown(fd, uid, gid):
        raise PermissionError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(os, "fchown", nochown)
    with pytest.raises(EnforcerError):
        enf.apply("quarantine_file", str(victim))
    monkeypatch.undo()
    st = os.stat(str(victim))
    assert stat.S_IMODE(st.st_mode) == 0o4755 and st.st_uid == 12345       # the original is untouched
    qdir = tmp / "state" / "quarantine"
    leftovers = [n for n in os.listdir(str(qdir)) if not n.startswith(".")] if qdir.exists() else []
    assert leftovers == []
    assert not enf._manifest()


# --------------------------------------------------------------------------- #
# K-3: block_domain never replaces a symlinked hosts file with a regular file
# --------------------------------------------------------------------------- #

def test_block_domain_writes_through_a_symlinked_hosts_file(tmp_path):
    """K-3: os.replace swapped the symlink for a regular file (the managed link was detached)."""
    real = tmp_path / "hosts.real"
    real.write_text("127.0.0.1 localhost\n")
    link = tmp_path / "hosts"
    os.symlink(str(real), str(link))
    enf = LinuxEnforcer(runner=FakeIptables(), quarantine_dir=str(tmp_path / "q"), hosts_path=str(link))
    res = enf.apply("block_domain", "evil.example")
    assert os.path.islink(str(link)) and os.readlink(str(link)) == str(real)
    assert "evil.example" in real.read_text()
    enf.revert(res["revert"])
    assert os.path.islink(str(link)) and real.read_text() == "127.0.0.1 localhost\n"


def test_block_domain_refuses_a_symlink_that_leaves_the_hosts_directory(tmp_path):
    """K-3: a hosts symlink to a file elsewhere was silently replaced; now it is refused and untouched."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "elsewhere").mkdir()
    target = tmp_path / "elsewhere" / "victim"
    target.write_text("do not touch\n")
    link = tmp_path / "etc" / "hosts"
    os.symlink(str(target), str(link))
    enf = LinuxEnforcer(runner=FakeIptables(), quarantine_dir=str(tmp_path / "q"), hosts_path=str(link))
    with pytest.raises(EnforcerError):
        enf.apply("block_domain", "evil.example")
    assert os.path.islink(str(link)) and target.read_text() == "do not touch\n"


def test_block_domain_refuses_a_dangling_hosts_symlink(tmp_path):
    link = tmp_path / "hosts"
    os.symlink(str(tmp_path / "nowhere"), str(link))
    enf = LinuxEnforcer(runner=FakeIptables(), quarantine_dir=str(tmp_path / "q"), hosts_path=str(link))
    with pytest.raises(EnforcerError):
        enf.apply("block_domain", "evil.example")
    assert os.path.islink(str(link)) and not (tmp_path / "nowhere").exists()


def test_a_plain_hosts_file_is_still_replaced_atomically(tmp_path):
    enf, hosts = _hosts_enf(tmp_path, "127.0.0.1 localhost\n")
    ino = os.stat(str(hosts)).st_ino
    enf.apply("block_domain", "evil.example")
    assert os.stat(str(hosts)).st_ino != ino and not os.path.islink(str(hosts))


# --------------------------------------------------------------------------- #
# K-4: the README states the exit-7 rule the code implements
# --------------------------------------------------------------------------- #

def test_readme_does_not_promise_exit_7_after_ten_bare_401s():
    """K-4: agent/README.md still said exit 7 follows ten consecutive 401/403."""
    text = open(os.path.join(AGENT_DIR, "README.md"), encoding="utf-8").read()
    assert "ten consecutive" not in text.lower()
    assert "agent_revoked" in text and "re_enroll_required" in text


# --------------------------------------------------------------------------- #
# K-5: the self-lockout guard knows the proxy and the address the agent really connected to
# --------------------------------------------------------------------------- #

PROXY_IP = "198.51.100.7"


def _proxy_resolver(host, port, *a, **k):
    ip = PROXY_IP if host == "proxy.example" else SERVER_IP
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


@pytest.mark.parametrize("var", ["https_proxy", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "http_proxy"])
def test_blocking_the_proxy_the_agent_reaches_its_server_through_is_refused(tmp_path, monkeypatch, var):
    """K-5: block_ip of the environment proxy's address was applied (the guard resolved only the server)."""
    monkeypatch.setenv(var, "http://proxy.example:3128")
    r, runner, _enf = _linux_rig(tmp_path)
    r.agent._resolver = _proxy_resolver
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target=PROXY_IP)]
    r.agent.heartbeat()
    assert runner.rules == []
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert "lockout" in json.dumps(r.fleet.results[-1][1]["output"])


@pytest.mark.parametrize("atype,target", [("block_domain", "proxy.example"), ("firewall_rule", "out:tcp:3128")])
def test_blocking_the_proxy_by_name_or_port_is_refused(tmp_path, monkeypatch, atype, target):
    monkeypatch.setenv("https_proxy", "http://proxy.example:3128")
    r, runner, _enf = _linux_rig(tmp_path)
    r.agent._resolver = _proxy_resolver
    r.fleet.pending_actions = [_server_action(action_type=atype, target=target)]
    r.agent.heartbeat()
    assert runner.rules == [] and not (tmp_path / "hosts").exists()
    assert r.fleet.results[-1][1]["status"] == "failed"
    assert "lockout" in json.dumps(r.fleet.results[-1][1]["output"])


def test_an_unresolvable_proxy_refuses_ip_blocks(tmp_path, monkeypatch):
    """Fail safe: a proxy we cannot resolve might be the target, so no IP block is applied."""
    monkeypatch.setenv("https_proxy", "http://proxy.example:3128")
    r, runner, _enf = _linux_rig(tmp_path)

    def only_server(host, port, *a, **k):
        if host == "proxy.example":
            raise socket.gaierror("no")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SERVER_IP, port))]
    r.agent._resolver = only_server
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert runner.rules == []


def test_blocking_an_address_the_client_actually_connected_to_is_refused(tmp_path):
    """K-5: the connected peer (e.g. one of several A records, or a proxy) is part of the guard."""
    r, runner, _enf = _linux_rig(tmp_path)
    r.client.peers.add("203.0.113.77")
    r.fleet.pending_actions = [_server_action(action_type="block_ip", target="203.0.113.77")]
    r.agent.heartbeat()
    assert runner.rules == []
    assert "lockout" in json.dumps(r.fleet.results[-1][1]["output"])


def test_the_client_records_the_peer_it_connected_to():
    """K-5: FleetClient.peers lists the addresses its sockets really reached."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        c = FleetClient("http://127.0.0.1:%d" % httpd.server_address[1])
        assert c.peers == set()
        c._req("GET", "/x")
        assert "127.0.0.1" in c.peers
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# K-6: a dead-man revert is recorded durably and reported truthfully
# --------------------------------------------------------------------------- #

def _cut_off_rig(tmp_path):
    r, runner, _enf = _linux_rig(tmp_path)
    real = r.fleet.handle
    down = {"on": False}

    def handle(m, p, h, b):
        if down["on"] or "/actions/" in p:
            raise ConnectionResetError("cut off")
        return real(m, p, h, b)
    r.fleet.handle = handle
    return r, runner, down, real


def test_a_dead_man_revert_replaces_the_queued_applied_result_with_a_truthful_one(tmp_path):
    """K-6: the queued result still said 'applied' with a revert plan after the timer removed the rule."""
    r, runner, down, real = _cut_off_rig(tmp_path)
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert len(r.state.outbox) == 1 and len(runner.rules) == 2
    down["on"] = True
    r.clock.t += 11 * 60
    r.agent.step()
    assert runner.rules == []
    # durable local ledger
    rec = r.state.load_handled()[aid]
    assert rec["rule"]["reverted"] is True and rec["rule"]["deadman_reverted_at"]
    assert rec["status"] == "failed" and rec["revert"] is None
    assert rec["output"]["error"] == "deadman_reverted"
    # connectivity returns: the server hears the truth, never 'applied'
    down["on"] = False
    r.fleet.handle = real
    r.clock.t += 60
    r.agent.step()
    posted = [res for res in r.fleet.results if res[0] == aid]
    assert posted and all(p[1]["status"] == "failed" for p in posted)
    assert posted[-1][1]["output"]["error"] == "deadman_reverted"
    assert not any(p[1]["status"] == "applied" for p in posted)
    assert len(r.state.outbox) == 0


def test_a_re_offered_action_after_a_dead_man_revert_is_not_reported_as_applied(tmp_path):
    """K-6: with the queued item gone, the re-offer path re-sent the handled record's 'applied'."""
    r, runner, down, real = _cut_off_rig(tmp_path)
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    for path in r.state.outbox.files():
        r.state.outbox.delete(path)                          # the queued item was dropped (age / attempts)
    down["on"] = True
    r.clock.t += 11 * 60
    r.agent.step()
    assert runner.rules == []
    down["on"] = False
    r.fleet.handle = real
    r.fleet.results.clear()
    r.fleet.pending_actions = [_server_action(id=aid, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert runner.rules == []                                # never re-applied
    assert [p[1]["status"] for p in r.fleet.results if p[0] == aid] == ["failed"]


# --------------------------------------------------------------------------- #
# K-7: a name lookup that never returns cannot hold the request past the deadline
# --------------------------------------------------------------------------- #

def test_a_stalled_name_lookup_is_bounded_by_the_total_deadline(monkeypatch):
    """K-7: the worker thread sat in getaddrinfo for as long as the resolver took (and the call waited an
    extra 5 s for it); now the lookup itself is bounded and the worker ends at the deadline."""
    gate = threading.Event()
    real = socket.getaddrinfo

    def stalled(host, *a, **k):
        if host == "stall.example":
            gate.wait(30)
            raise socket.gaierror("late")
        return real(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", stalled)
    c = FleetClient("https://stall.example", deadline_s=1.0, timeout_s=5)
    t0 = time.monotonic()
    try:
        with pytest.raises(FleetClientError):
            c._req("GET", "/x")
        took = time.monotonic() - t0
        assert took < 3.0, took                          # deadline (1 s) + slack, not deadline + 5 s join
        time.sleep(0.2)
        assert not [t for t in threading.enumerate() if t.name == "paddock-http" and t.is_alive()]
    finally:
        gate.set()
