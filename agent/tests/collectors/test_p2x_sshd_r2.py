"""Round-2 regressions for the P2 review (library host-config / collector residuals): symlink
retargeting (hostcfg-6), linear-time pattern matching, ``sshd -g``, an unknown reload state, and a
garbled ``if_inet6`` (coll-4). Each test failed against the round-1 source for the reason in its
comment."""
import os
import signal
import time
import types

from paddock_agent import runner as _runner
from paddock_agent.collectors import base, firewall, sshd

from .helpers import make_ctx, put
from .test_p2x_sshd import (HARD, START, _age_all, _daemon, _daemon_ctx, _daemon_collect,
                            _ctime_equals_mtime)  # noqa: F401  (fixture re-used)
from .test_sshd import BINS, sshd_runner, ubuntu_files


# ----------------------------------------------------------------------------- L-1 / L-9
def test_l1_repointing_the_sshd_config_symlink_after_the_daemon_started_is_a_pending_reload(tmp_path, monkeypatch):
    """Real filesystem times. /etc/ssh/sshd_config -> weak.conf; the daemon starts (loads weak.conf);
    the admin repoints the link to hardened.conf (an OLDER file) without a reload. Before the fix the
    result was reload_pending False and conf exact: os.stat follows the link, so neither file's times
    changed and /etc/ssh itself was not tracked."""
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    monkeypatch.setattr(_runner.Ctx, "change_ns", _real_change_ns, raising=False)
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS)
    root = os.path.join(str(tmp_path), "root")
    put(root, "/etc/ssh/hardened.conf", "PasswordAuthentication no\n")
    put(root, "/etc/ssh/weak.conf", "PasswordAuthentication yes\n")
    os.remove(root + "/etc/ssh/sshd_config")
    os.symlink("weak.conf", root + "/etc/ssh/sshd_config")
    for n in os.listdir(root + "/etc/ssh/sshd_config.d"):
        os.remove(root + "/etc/ssh/sshd_config.d/" + n)
    start = int(time.time()) + 1                          # the daemon starts in the next whole second
    time.sleep(max(0.0, start - time.time()) + 0.05)
    os.remove(root + "/etc/ssh/sshd_config")
    os.symlink("hardened.conf", root + "/etc/ssh/sshd_config")
    _daemon(ctx, start=1000, btime=start - 10)            # start_epoch = btime + 1000 / 100 = start
    sec = sshd.collect(ctx)
    d = sec["v"]["daemon"]
    assert d["start_epoch"] == start
    assert d["reload_pending"] is True, d                 # was False: "exact False 0 -2 []"
    assert sec["conf"] == "approximate" and "reload_pending" in sec["v"]["match"]["unprobed_reasons"]


def _real_change_ns(self, path):
    st = os.stat(self.fs_path(path))
    return max(st.st_mtime_ns, st.st_ctime_ns)


def _lstat_with(monkeypatch, times, fake=()):
    """``os.lstat`` of the listed real paths reports the given change time (ns); others are real."""
    real = os.lstat

    def lstat(p, *a, **kw):
        st = real(p, *a, **kw)
        if str(p) in times:
            return types.SimpleNamespace(st_mode=st.st_mode, st_mtime_ns=times[str(p)],
                                         st_ctime_ns=times[str(p)])
        return st
    monkeypatch.setattr(_runner.os, "lstat", lstat)


def test_l1_a_symlinked_directory_component_retargeted_later_is_a_pending_reload(tmp_path, monkeypatch):
    # /etc/ssh -> /etc/ssh-real is a link whose own change time is after the daemon start
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    _age_all(tmp_path, START - 3600)
    root = os.path.join(str(tmp_path), "root")
    os.makedirs(root + "/etc/real-d")
    put(root, "/etc/real-d/x", "x")
    os.symlink("real-d", root + "/etc/linkdir")
    _lstat_with(monkeypatch, {})
    # include a file via the link: /etc/linkdir/x is not in the config; use the helper directly
    assert ctx.link_change_ns("/etc/linkdir/x") is not None
    _lstat_with(monkeypatch, {root + "/etc/linkdir": (START + 600) * 1000000000})
    ns, doubt = ctx.link_change_ns("/etc/linkdir/x")
    assert ns == (START + 600) * 1000000000 and doubt is False


def test_l1_a_symlink_loop_is_doubt_and_never_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    _age_all(tmp_path, START - 3600)
    root = os.path.join(str(tmp_path), "root")
    os.symlink("b", root + "/etc/ssh/a")
    os.symlink("a", root + "/etc/ssh/b")
    ns, doubt = ctx.link_change_ns("/etc/ssh/a")
    assert doubt is True
    # the collector: a config path that cannot be resolved gives no positive evidence
    os.remove(root + "/etc/ssh/sshd_config")
    os.symlink("a", root + "/etc/ssh/sshd_config")
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["reload_pending"] is not False
    assert sec["conf"] == "approximate"


def test_l1_an_unchanged_symlinked_config_is_still_current(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    root = os.path.join(str(tmp_path), "root")
    put(root, "/etc/ssh/real.conf", "PasswordAuthentication no\n")
    os.remove(root + "/etc/ssh/sshd_config")
    os.symlink("real.conf", root + "/etc/ssh/sshd_config")
    _age_all(tmp_path, START - 3600)
    _lstat_with(monkeypatch, {root + "/etc/ssh/sshd_config": (START - 3600) * 1000000000})
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["reload_pending"] is False and sec["conf"] == "exact"


# ----------------------------------------------------------------------------- L-2
class _Hang(Exception):
    pass


def _alarm(seconds):
    def handler(signum, frame):
        raise _Hang("pattern matching did not finish in %ds" % seconds)
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)


def test_l2_pattern_matching_is_linear_on_the_pathological_pattern():
    _alarm(4)
    try:
        _l2_body()
    finally:
        signal.alarm(0)


def _l2_body():
    # '*a' * k + 'b' against 'a' * 40 took 10.6 s at k=10 and never finished at k=30 (regex backtracking)
    t0 = time.time()
    assert sshd.pattern_list_match("a" * 40, "*a" * 30 + "b") == 0
    assert sshd.pattern_list_match("a" * 40, "*a" * 200 + "b") == 0
    assert sshd.pattern_list_match("a" * 40, ",".join(["*a" * 30 + "b"] * 15)) == 0
    assert time.time() - t0 < 0.5


def test_l2_wildcard_semantics_are_unchanged():
    m = sshd.pattern_list_match
    assert m("alice", "al*") == 1 and m("alice", "*ce") == 1 and m("alice", "a?ice") == 1
    assert m("alice", "a*c*e") == 1 and m("alice", "a*c*x") == 0 and m("alice", "") == 0
    assert m("", "") == 1 and m("", "*") == 1 and m("a", "?") == 1 and m("", "?") == 0
    assert m("a.b", "a.b") == 1 and m("axb", "a.b") == 0 and m("a[b]", "a[b]") == 1
    assert m("bob", "*,!bob") == -1 and m("tom", "*,!bob") == 1
    assert m("a\nb", "a?b") == 1


def test_l2_an_oversized_pattern_is_refused_so_the_probe_set_is_unprobeable(tmp_path):
    big = "*a" * 3000 + "b"
    try:
        sshd.pattern_list_match("a" * 40, big)
    except sshd.PatternTooComplex:
        pass
    else:
        raise AssertionError("an oversized pattern list must not be matched")
    cfg = "PasswordAuthentication no\nMatch User " + big + "\n  PasswordAuthentication yes\n"
    files = {"/etc/ssh/sshd_config": cfg, "/etc/passwd": "root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/h:/bin/bash\n"}
    t0 = time.time()
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(HARD), files=files, bins=BINS))
    assert time.time() - t0 < 5
    base.validate_section(sec)
    assert sec["conf"] == "approximate" and sec["v"]["match"]["unprobed"] is True
    assert "user_pattern" in sec["v"]["match"]["unprobed_reasons"]


# ----------------------------------------------------------------------------- L-3
def test_l3_sshd_dash_g_is_a_configuration_override(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    for i, cmd in enumerate(["/usr/sbin/sshd\0-D\0-g\x005\0", "/usr/sbin/sshd\0-Dg5\0",
                             "/usr/sbin/sshd\0-g\x0030\0-D\0"]):
        sec = _daemon_collect(tmp_path / ("g%d" % i), cfg_mtime=START - 3600, cmdline=cmd)
        d = sec["v"]["daemon"]
        assert d["options_override"] is True, cmd             # was False
        assert sec["conf"] == "approximate" and d["reload_pending"] is True, cmd


# ----------------------------------------------------------------------------- L-7
def test_l7_an_unknown_reload_state_is_never_exact(tmp_path):
    # no daemon visible (not socket activated): reload_pending is null; was conf "exact"
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS))
    assert sec["v"]["daemon"]["reload_pending"] is None
    assert sec["conf"] == "approximate"
    assert "daemon_unverified" in sec["v"]["match"]["unprobed_reasons"]


def test_l7_unreadable_btime_is_never_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    _age_all(tmp_path, START - 3600)
    os.remove(os.path.join(ctx.proc_root, "stat"))            # no btime: the start time is unknown
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["reload_pending"] is None
    assert sec["conf"] == "approximate"


def test_l7_socket_activation_and_a_verified_daemon_stay_exact(tmp_path, monkeypatch):
    f = ubuntu_files({"/etc/systemd/system/sockets.target.wants/ssh.socket": ""})
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(HARD), files=f, bins=BINS))
    assert sec["v"]["daemon"]["reload_pending"] is False and sec["conf"] == "exact"


# ----------------------------------------------------------------------------- coll-4 nit (L-8)
def test_l8_a_garbled_if_inet6_is_unknown_not_disabled(tmp_path):
    for i, body in enumerate(["garbage\n", "xyz 02 40 00 80 eth0\n", "20010db8000000000000000000000001 02\n",
                              "\x00\x01binary\n"]):
        ctx = make_ctx(tmp_path / ("g%d" % i), files={"/proc/net/if_inet6": body})
        assert firewall.ipv6_enabled(ctx) is None, body       # was False
    # a positive address still wins over a garbled line; loopback-only and empty stay False
    mixed = "garbage\n20010db8000000000000000000000001 02 40 00 80 eth0\n"
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "m", files={"/proc/net/if_inet6": mixed})) is True
    lo = "00000000000000000000000000000001 01 80 10 80 lo\n"
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "l", files={"/proc/net/if_inet6": lo})) is False
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "e", files={"/proc/net/if_inet6": ""})) is False
