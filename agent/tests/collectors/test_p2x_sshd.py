"""Regression tests for the P2 adversarial review (coll-1, coll-5, hostcfg-2, hostcfg-3, hostcfg-6): sshd."""
import json
import os

import pytest

from paddock_agent import runner as _runner
from paddock_agent.collectors import base, payload_bytes, sshd

from .helpers import FakeRunner, fixture, make_ctx, put, res
from .test_sshd import BINS, S, sshd_runner, ubuntu_files

HARD = fixture(S + "sshd_T.hardened.txt")
PW_YES = HARD.replace("passwordauthentication no", "passwordauthentication yes")
PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "alice:x:1001:1001::/home/alice:/bin/bash\n")
CFG_GROUP = "PasswordAuthentication no\nMatch Group sftponly\n  PasswordAuthentication yes\n"


CTIME_OVERRIDE = {}


@pytest.fixture(autouse=True)
def _ctime_equals_mtime(monkeypatch):
    """A real filesystem cannot be given an old ctime: the change time of a fixture file is always
    "now". Model the ordinary case (ctime == mtime); a test sets CTIME_OVERRIDE[path] to simulate an
    mtime-preserving write (cp -p, rsync -a, tar)."""
    CTIME_OVERRIDE.clear()

    def change_ns(self, path):
        key = self.stat_key(path)
        if key is None:
            return None
        return max(key[2], CTIME_OVERRIDE.get(path, 0))
    monkeypatch.setattr(_runner.Ctx, "change_ns", change_ns, raising=False)


def run_collect(tmp_path, passwd, config, who, group=None, extra=None, bins=BINS):
    """sshd.collect where ``-T -C user=U`` shows password auth for the users in ``who``."""
    files = {"/etc/ssh/sshd_config": config, "/etc/passwd": passwd}
    if group is not None:
        files["/etc/group"] = group
    files.update(extra or {})
    runner = sshd_runner(HARD, lambda u, a: PW_YES if u in who else HARD)
    sec = sshd.collect(make_ctx(tmp_path, runner=runner, files=files, bins=bins))
    base.validate_section(sec)
    return sec, runner


def delta_users(sec):
    return sorted(set(d["user"] for d in sec["v"]["probes"]["deltas"]))


# ------------------------------------------------------------------------- coll-1
def test_coll1_match_group_member_with_nologin_shell_is_probed(tmp_path):
    passwd = PASSWD + "sftp1:x:2001:2001::/srv/sftp:/usr/sbin/nologin\n"
    sec, _ = run_collect(tmp_path, passwd, CFG_GROUP, {"sftp1"}, group="sftponly:x:3000:sftp1\n")
    assert delta_users(sec) == ["sftp1"], "the nologin SFTP user selected by the Match Group was never probed"


def test_coll1_match_group_by_primary_gid_is_probed(tmp_path):
    passwd = PASSWD + "sftp2:x:2002:3000::/srv/sftp:/bin/false\n"
    sec, _ = run_collect(tmp_path, passwd, CFG_GROUP, {"sftp2"}, group="sftponly:x:3000:\n")
    assert delta_users(sec) == ["sftp2"]


def test_coll1_uppercase_match_user_is_probed(tmp_path):
    passwd = PASSWD + "Bob:x:2003:2003::/home/Bob:/usr/sbin/nologin\n"
    cfg = "PasswordAuthentication no\nMatch User Bob\n  PasswordAuthentication yes\n"
    sec, _ = run_collect(tmp_path, passwd, cfg, {"Bob"})
    assert delta_users(sec) == ["Bob"]
    assert "Bob" in sshd.match_user_names([[("user", "Bob")]])


def test_coll1_wildcard_match_user_selects_nologin_accounts(tmp_path):
    passwd = PASSWD + "svc1:x:998:998::/srv:/usr/sbin/nologin\nsvc2:x:999:999::/srv:/usr/sbin/nologin\n"
    cfg = "PasswordAuthentication no\nMatch User svc*\n  PasswordAuthentication yes\n"
    sec, runner = run_collect(tmp_path, passwd, cfg, {"svc1", "svc2"})
    assert delta_users(sec) == ["svc1"]                   # one representative of the selection class
    assert sec["conf"] == "exact"


def test_coll1_negated_group_pattern_follows_openssh_semantics():
    assert sshd.pattern_list_match("bob", "bob") == 1
    assert sshd.pattern_list_match("Bob", "bob") == 0           # case-sensitive
    assert sshd.pattern_list_match("bob", "*,!bob") == -1       # a negated match always wins
    assert sshd.pattern_list_match("tom", "*,!bob") == 1
    assert sshd.pattern_list_match("x1", "x?") == 1 and sshd.pattern_list_match("x12", "x?") == 0


def test_coll1_nss_beyond_files_makes_users_unknown(tmp_path):
    nss = {"/etc/nsswitch.conf": "passwd: files sss\ngroup: files sss\nshadow: files\n"}
    sec, _ = run_collect(tmp_path, PASSWD, CFG_GROUP, set(), group="", extra=nss)
    assert sec["s"] == "ok" and sec["conf"] == "approximate"
    assert "nss_users_unknown" in sec["v"]["match"]["unprobed_reasons"]


def test_coll1_files_only_nss_stays_exact_and_unrelated_nss_is_ignored(tmp_path):
    files_only = {"/etc/nsswitch.conf": "passwd: files systemd\ngroup: files systemd\nhosts: files dns\n"}
    sec, _ = run_collect(tmp_path / "a", PASSWD, CFG_GROUP, set(), group="", extra=files_only)
    assert sec["conf"] == "exact" and sec["v"]["match"]["unprobed_reasons"] == []
    # no user/group Match block at all: the user databases do not matter
    sec, _ = run_collect(tmp_path / "b", PASSWD, "PasswordAuthentication no\n", set(),
                         extra={"/etc/nsswitch.conf": "passwd: files ldap\ngroup: files ldap\n"})
    assert sec["conf"] == "exact" and sec["v"]["match"]["unprobed_reasons"] == []


def test_coll1_nis_compat_markers_in_passwd_are_unknown_users(tmp_path):
    sec, _ = run_collect(tmp_path, PASSWD + "+::::::\n", CFG_GROUP, set(), group="",
                         extra={"/etc/nsswitch.conf": "passwd: compat\ngroup: compat\n"})
    assert sec["conf"] == "approximate" and "nss_users_unknown" in sec["v"]["match"]["unprobed_reasons"]


def test_coll1_dropped_passwd_rows_are_counted_and_make_user_matches_unprobeable(tmp_path):
    passwd = PASSWD + "bad name:x:1500:1500::/h:/bin/bash\n"
    sec, _ = run_collect(tmp_path / "a", passwd, "PasswordAuthentication no\n", set())
    p = sec["v"]["probes"]
    assert p["users_total"] == 2 and p["users_probed"] == 2       # alice + the dropped row; root, alice probed
    # a pattern that only the unprobeable name satisfies: no probed account behaves like it
    sec, _ = run_collect(tmp_path / "b", passwd, "PasswordAuthentication no\nMatch User bad*\n  X11Forwarding no\n", set())
    assert "user_name_unprobeable" in sec["v"]["match"]["unprobed_reasons"] and sec["conf"] == "approximate"


def test_coll1_user_at_host_pattern_cannot_be_enumerated(tmp_path):
    cfg = "PasswordAuthentication no\nMatch User bob@10.*\n  PasswordAuthentication yes\n"
    sec, _ = run_collect(tmp_path, PASSWD, cfg, set())
    assert "user_pattern" in sec["v"]["match"]["unprobed_reasons"] and sec["conf"] == "approximate"


def test_coll1_too_many_selection_classes_is_users_over_cap(tmp_path):
    # 30 nologin users in 30 different groups, one Match Group pattern per group
    passwd = PASSWD + "".join("n%02d:x:%d:%d::/h:/usr/sbin/nologin\n" % (i, 3000 + i, 3000 + i) for i in range(30))
    group = "".join("g%02d:x:%d:\n" % (i, 3000 + i) for i in range(30))
    cfg = "PasswordAuthentication no\n" + "".join("Match Group g%02d\n  X11Forwarding no\n" % i for i in range(30))
    sec, _ = run_collect(tmp_path, passwd, cfg, set(), group=group)
    assert sec["conf"] == "approximate" and "users_over_cap" in sec["v"]["match"]["unprobed_reasons"]


# ------------------------------------------------------------------------- coll-5
def _runner_log():
    return sshd_runner(HARD)


def test_coll5_a_group_writable_usr_local_sshd_is_never_executed(tmp_path):
    runner = _runner_log()
    ctx = make_ctx(tmp_path, runner=runner, files=ubuntu_files(), bins=["/usr/bin/ssh"])
    put(os.path.join(str(tmp_path), "root"), "/usr/local/sbin/sshd", "#!/bin/sh\n", mode=0o775)
    os.chmod(os.path.join(str(tmp_path), "root/usr/local/sbin/sshd"), 0o775)
    os.chmod(os.path.join(str(tmp_path), "root/usr/local/sbin"), 0o775)
    assert sshd.find_sshd(ctx) is None
    sec = sshd.collect(ctx)
    assert sec["s"] != "ok" and sec == {"s": "unavailable", "reason": "no_data"}
    assert not any(c and c[0] == "/usr/local/sbin/sshd" for c in runner.calls)


def test_coll5_system_path_wins_over_usr_local(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=BINS)
    monkeypatch.setattr(sshd, "TRUSTED_UID", os.geteuid())
    put(os.path.join(str(tmp_path), "root"), "/usr/local/sbin/sshd", "#!/bin/sh\n", mode=0o755)
    for d in ("usr/local", "usr/local/sbin"):
        os.chmod(os.path.join(str(tmp_path), "root", d), 0o755)
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"


def test_coll5_root_owned_usr_local_sshd_is_accepted_as_a_fallback(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=["/usr/bin/ssh"])
    monkeypatch.setattr(sshd, "TRUSTED_UID", os.geteuid())
    put(os.path.join(str(tmp_path), "root"), "/usr/local/sbin/sshd", "#!/bin/sh\n", mode=0o755)
    for d in ("usr/local", "usr/local/sbin"):
        os.chmod(os.path.join(str(tmp_path), "root", d), 0o755)
    assert sshd.find_sshd(ctx) == "/usr/local/sbin/sshd"


def _daemon(ctx, pid=700, uid=0, comm="sshd", ppid=1, exe="/usr/sbin/sshd", start=5000,
            cmdline="sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\0", btime=1700000000):
    """A fake sshd process under ``ctx.proc_root``."""
    d = os.path.join(ctx.proc_root, str(pid))
    os.makedirs(d, exist_ok=True)
    put(d, "comm", comm + "\n")
    put(d, "cmdline", cmdline)
    put(d, "status", "Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % (comm, uid, uid, uid, uid))
    tail = " ".join(["0"] * 17 + [str(start)] + ["0"] * 10)       # fields 5..21, then starttime (22)
    rest = "S %d %s" % (ppid, tail)
    put(d, "stat", "%d (%s) %s\n" % (pid, comm, rest))
    if exe is not None:
        if os.path.lexists(os.path.join(d, "exe")):
            os.remove(os.path.join(d, "exe"))
        os.symlink(exe, os.path.join(d, "exe"))
    put(ctx.proc_root, "stat", "cpu  1 2 3\nbtime %d\n" % btime)
    return d


def test_coll5_the_binary_of_the_running_root_sshd_is_preferred(tmp_path):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/bin/ssh"])
    _daemon(ctx, exe="/usr/bin/sshd")
    assert sshd.find_sshd(ctx) == "/usr/bin/sshd"


def test_coll5_a_non_root_process_named_sshd_is_not_trusted(tmp_path):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=["/usr/sbin/sshd", "/usr/bin/ssh"])
    put(os.path.join(str(tmp_path), "root"), "/tmp/evil/sshd", "#!/bin/sh\n", mode=0o755)
    _daemon(ctx, uid=1000, exe="/tmp/evil/sshd")
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"


def test_coll5_a_deleted_or_wrongly_named_exe_is_ignored(tmp_path):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=["/usr/sbin/sshd", "/usr/bin/ssh"])
    _daemon(ctx, exe="/usr/sbin/sshd (deleted)")
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"
    _daemon(ctx, pid=701, exe="/usr/lib/openssh/sshd-session")
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"


# ------------------------------------------------------------------------- hostcfg-3
def _t_with(extra_lines):
    return HARD + extra_lines


def test_hostcfg3_a_cut_allowusers_list_is_flagged_and_never_exact(tmp_path):
    names = " ".join("user%03d" % i for i in range(60))
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(_t_with("allowusers " + names + "\n")),
                                files=ubuntu_files(), bins=BINS))
    v = sec["v"]
    assert len(v["config"]["allowusers"]) == sshd.MAX_LIST_ITEMS
    assert v["truncated"] == ["allowusers"]
    assert sec["conf"] == "approximate" and "config_truncated" in v["match"]["unprobed_reasons"]


def test_hostcfg3_a_cut_authenticationmethods_is_flagged(tmp_path):
    methods = ",".join(["publickey,keyboard-interactive:pam"] * 8)
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(
        HARD.replace("authenticationmethods any", "authenticationmethods " + methods)),
        files=ubuntu_files(), bins=BINS))
    assert len(methods) > 200 and sec["v"]["truncated"] == ["authenticationmethods"]
    assert sec["conf"] == "approximate"


def test_hostcfg3_untruncated_sections_have_no_flag_and_stay_exact(tmp_path):
    names = " ".join("user%03d" % i for i in range(sshd.MAX_LIST_ITEMS))
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(_t_with("allowusers " + names + "\n")),
                                files=ubuntu_files(), bins=BINS))
    assert "truncated" not in sec["v"] and sec["conf"] == "exact"


def test_hostcfg3_normalise_reports_the_truncated_keys():
    cfg, problems, trunc = sshd.normalise_config_ex({"allowgroups": ["g%03d" % i for i in range(51)],
                                                      "listenaddress": ["a" * 100],
                                                      "denyusers": ["x"]})
    assert problems == [] and trunc == ["allowgroups", "listenaddress"]
    assert sshd.normalise_config({"denyusers": ["x"]})[0] == {"denyusers": ["x"]}


# ------------------------------------------------------------------------- hostcfg-6
CFG_PATH = "/etc/ssh/sshd_config"


def _touch(tmp_path, path, t):
    full = os.path.join(str(tmp_path), "root", path.lstrip("/"))
    os.utime(full, (t, t))


def _daemon_collect(tmp_path, cfg_mtime, start=5000, btime=1700000000, cmdline=None, pidfile_mtime=None,
                    exe="/usr/sbin/sshd", clk=100):
    files = ubuntu_files()
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=files, bins=BINS)
    kw = {"start": start, "btime": btime, "exe": exe}
    if cmdline is not None:
        kw["cmdline"] = cmdline
    _daemon(ctx, **kw)
    for p in (CFG_PATH, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"):
        _touch(tmp_path, p, cfg_mtime)
    if os.path.isdir(os.path.join(str(tmp_path), "root/etc/ssh/sshd_config.d")):
        _touch(tmp_path, "/etc/ssh/sshd_config.d", cfg_mtime)
    if pidfile_mtime is not None:
        put(os.path.join(str(tmp_path), "root"), "/run/sshd.pid", "700\n")
        _touch(tmp_path, "/run/sshd.pid", pidfile_mtime)
    sec = sshd.collect(ctx)
    base.validate_section(sec)
    return sec


START = 1700000000 + 5000 // 100        # btime + starttime / CLK_TCK


def test_hostcfg6_config_edited_after_the_daemon_started_is_a_pending_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    sec = _daemon_collect(tmp_path, cfg_mtime=START + 600)
    d = sec["v"]["daemon"]
    assert d["found"] is True and d["pid"] == 700 and d["start_epoch"] == START
    assert d["config_mtime"] == START + 600 and d["reload_pending"] is True
    assert d["config_path"] is None and d["config_default"] is True and d["options_override"] is False
    assert sec["conf"] == "approximate" and "reload_pending" in sec["v"]["match"]["unprobed_reasons"]


def test_hostcfg6_config_older_than_the_daemon_is_current(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    sec = _daemon_collect(tmp_path, cfg_mtime=START - 3600)
    d = sec["v"]["daemon"]
    assert d["reload_pending"] is False and d["binary_matches"] is True
    assert sec["conf"] == "exact"


def test_hostcfg6_a_pidfile_rewritten_by_the_reexec_after_the_edit_clears_it(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    sec = _daemon_collect(tmp_path, cfg_mtime=START + 600, pidfile_mtime=START + 900)
    d = sec["v"]["daemon"]
    assert d["reload_pending"] is False and d["reexec_epoch"] == START + 900
    assert sec["conf"] == "exact"


def test_hostcfg6_a_pidfile_of_another_pid_does_not_count(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    files = ubuntu_files({"/run/sshd.pid": "999\n"})
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=files, bins=BINS)
    _daemon(ctx)
    os.utime(os.path.join(str(tmp_path), "root/run/sshd.pid"), (START + 900, START + 900))
    for p in (CFG_PATH, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"):
        _touch(tmp_path, p, START + 600)
    assert sshd.collect(ctx)["v"]["daemon"]["reload_pending"] is True


def test_hostcfg6_a_non_default_config_file_on_the_cmdline_is_reported_path_only(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    sec = _daemon_collect(tmp_path, cfg_mtime=START - 3600, cmdline=(
        "sshd: /usr/sbin/sshd -f /etc/ssh/other_config -D [listener] 0 of 10-100 startups\0"))
    d = sec["v"]["daemon"]
    assert d["config_path"] == "/etc/ssh/other_config" and d["config_default"] is False
    assert sec["conf"] == "approximate" and "daemon_config_differs" in sec["v"]["match"]["unprobed_reasons"]
    assert d["reload_pending"] is True


def test_hostcfg6_command_line_overrides_are_a_flag_never_content(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    sec = _daemon_collect(tmp_path, cfg_mtime=START - 3600, cmdline=(
        "/usr/sbin/sshd\0-D\0-o\0PasswordAuthentication=hunter2yes\0"))
    assert sec["v"]["daemon"]["options_override"] is True
    assert sec["conf"] == "approximate" and "daemon_config_differs" in sec["v"]["match"]["unprobed_reasons"]
    assert b"hunter2yes" not in payload_bytes(sec) and b"PasswordAuthentication=" not in payload_bytes(sec)


def test_hostcfg6_the_running_binary_is_the_one_evaluated(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    monkeypatch.setattr(sshd, "TRUSTED_UID", os.geteuid())     # /opt is outside the system PATH: owner-checked
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS + ["/opt/other/sshd"])
    _daemon(ctx, exe="/opt/other/sshd")
    sec = sshd.collect(ctx)
    assert sec["v"]["binary"] == "/opt/other/sshd" and sec["v"]["daemon"]["binary_matches"] is True


def test_hostcfg6_a_replaced_binary_on_disk_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS)
    _daemon(ctx, exe="/usr/sbin/sshd (deleted)")
    for p in (CFG_PATH, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf",
              "/etc/ssh/sshd_config.d"):
        _touch(tmp_path, p, START - 3600)
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["binary_matches"] is False
    assert sec["conf"] == "approximate" and "daemon_binary_differs" in sec["v"]["match"]["unprobed_reasons"]


def test_hostcfg6_no_daemon_found_is_unknown_not_current(tmp_path):
    sec = sshd.collect(make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS))
    d = sec["v"]["daemon"]
    assert d["found"] is False and d["reload_pending"] is None and d["pid"] is None
    f = ubuntu_files({"/etc/systemd/system/sockets.target.wants/ssh.socket": ""})
    sec = sshd.collect(make_ctx(tmp_path / "s", runner=sshd_runner(HARD), files=f, bins=BINS))
    assert sec["v"]["daemon"]["found"] is False and sec["v"]["daemon"]["reload_pending"] is False


def test_hostcfg6_children_are_not_the_master(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=ubuntu_files(), bins=BINS)
    _daemon(ctx, pid=700, ppid=1)
    _daemon(ctx, pid=800, ppid=700, start=9000, cmdline="sshd: alice [priv]\0")
    d = sshd.collect(ctx)["v"]["daemon"]
    assert d["pid"] == 700


# ------------------------------------------------------------------------- hostcfg-2
TCP_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _tcp_row(n, hexip, port, inode):
    return "   %d: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1\n" % (
        n, hexip, port, inode)


def _listener_ctx(tmp_path, rows, procs, runner=None):
    files = {"/proc/net/tcp": TCP_HDR + "".join(rows), "/proc/net/udp": TCP_HDR}
    ctx = make_ctx(tmp_path, runner=runner or FakeRunner(), files=files)
    for pid, (comm, sockets) in procs.items():
        d = os.path.join(ctx.proc_root, str(pid))
        os.makedirs(os.path.join(d, "fd"), exist_ok=True)
        for i, ino in enumerate(sockets):
            os.symlink("socket:[%d]" % ino, os.path.join(d, "fd", str(3 + i)))
        put(d, "comm", comm + "\n")
    return ctx


def test_hostcfg2_ssh_behind_docker_proxy_is_not_proof_of_absence(tmp_path):
    ctx = _listener_ctx(tmp_path, [_tcp_row(0, "00000000", 2222, 900)], {40: ("docker-proxy", [900])})
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "no_data"}


def test_hostcfg2_comm_match_is_case_insensitive_and_covers_other_ssh_daemons(tmp_path):
    for i, comm in enumerate(["SSHD", "Dropbear", "gitlab-sshd", "tinyssh", "sftpgo-ssh"]):
        ctx = make_ctx(tmp_path / str(i), files={"/proc/%d/comm" % (50 + i): comm + "\n"})
        assert sshd.collect(ctx)["reason"] == "no_data", comm


def test_hostcfg2_an_unattributed_public_listener_cannot_clear_ssh(tmp_path):
    ctx = _listener_ctx(tmp_path, [_tcp_row(0, "00000000", 2222, 901)], {})
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "no_data"}


def test_hostcfg2_attributed_non_ssh_listeners_and_loopback_do_not_block_tool_missing(tmp_path):
    ctx = _listener_ctx(tmp_path, [_tcp_row(0, "00000000", 5432, 902), _tcp_row(1, "0100007F", 2222, 903)],
                        {41: ("postgres", [902, 903])})
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "tool_missing"}


def test_hostcfg2_a_public_listener_of_an_unlisted_program_is_not_proof_of_absence(tmp_path):
    # gitea / sftpgo / teleport / podman's rootlessport / kube-proxy can all front an SSH server: only
    # listeners of programs known not to speak SSH may leave "tool_missing" standing
    for i, comm in enumerate(["gitea", "sftpgo", "teleport", "rootlessport", "kube-proxy", "nginx", "myapp"]):
        ctx = _listener_ctx(tmp_path / str(i), [_tcp_row(0, "00000000", 2222, 910)], {42: (comm, [910])})
        assert sshd.collect(ctx) == {"s": "unavailable", "reason": "no_data"}, comm


def test_hostcfg2_known_non_ssh_public_listeners_still_allow_tool_missing(tmp_path):
    ctx = _listener_ctx(tmp_path, [_tcp_row(0, "00000000", 5432, 920), _tcp_row(1, "00000000", 6379, 921)],
                        {43: ("postgres", [920]), 44: ("redis-server", [921])})
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "tool_missing"}


# ----------------------------------------------------- hostcfg-6 rework (verifier bypasses)
def _daemon_ctx(tmp_path, files=None, cmdline=None):
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=files or ubuntu_files(), bins=BINS)
    kw = {} if cmdline is None else {"cmdline": cmdline}
    _daemon(ctx, **kw)
    return ctx


def _age_all(tmp_path, t, skip=()):
    root = os.path.join(str(tmp_path), "root", "etc", "ssh")
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            full = os.path.join(dp, n)
            if full not in skip:
                os.utime(full, (t, t))
    os.utime(root, (t, t))


def test_hostcfg6_deleting_the_last_include_dropin_is_a_pending_reload(tmp_path, monkeypatch):
    # Ubuntu's 50-cloud-init.conf said PasswordAuthentication yes; it was removed after the daemon
    # started (no reload). No file is left in the Include directory: only the directory mtime shows it.
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    f = ubuntu_files()
    del f["/etc/ssh/sshd_config.d/50-cloud-init.conf"]
    del f["/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"]
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=f, bins=BINS)
    os.makedirs(os.path.join(str(tmp_path), "root/etc/ssh/sshd_config.d"), exist_ok=True)
    _daemon(ctx)
    _age_all(tmp_path, START - 3600)
    _touch(tmp_path, "/etc/ssh/sshd_config.d", START + 600)
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["reload_pending"] is True
    assert sec["conf"] == "approximate" and "reload_pending" in sec["v"]["match"]["unprobed_reasons"]


def test_hostcfg6_a_removed_include_directory_is_seen_through_its_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    f = ubuntu_files()
    del f["/etc/ssh/sshd_config.d/50-cloud-init.conf"]
    del f["/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"]
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=f, bins=BINS)
    _daemon(ctx)
    _age_all(tmp_path, START - 3600)
    _touch(tmp_path, "/etc/ssh", START + 600)                  # rmdir sshd_config.d touched /etc/ssh
    assert sshd.collect(ctx)["v"]["daemon"]["reload_pending"] is True


def test_hostcfg6_an_include_directory_equal_to_etc_ssh_is_tracked(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    f = ubuntu_files({"/etc/ssh/sshd_config": "Include /etc/ssh/*.conf\nPasswordAuthentication no\n",
                      "/etc/ssh/local.conf": "X11Forwarding no\n"})
    ctx = make_ctx(tmp_path, runner=sshd_runner(HARD), files=f, bins=BINS)
    _daemon(ctx)
    _age_all(tmp_path, START - 3600)
    _touch(tmp_path, "/etc/ssh", START + 600)                  # a *.conf file there was deleted
    assert sshd.collect(ctx)["v"]["daemon"]["reload_pending"] is True


def test_hostcfg6_an_mtime_preserving_write_is_a_pending_reload(tmp_path, monkeypatch):
    # cp -p / rsync -a / install -p / tar set the mtime back before the daemon start; ctime is "now"
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    _age_all(tmp_path, START - 3600)
    CTIME_OVERRIDE["/etc/ssh/sshd_config.d/50-cloud-init.conf"] = (START + 600) * 1000000000
    sec = sshd.collect(ctx)
    d = sec["v"]["daemon"]
    assert d["reload_pending"] is True and d["config_mtime"] == START + 600
    assert sec["conf"] == "approximate"


def test_hostcfg6_untouched_files_are_still_current(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    ctx = _daemon_ctx(tmp_path)
    _age_all(tmp_path, START - 3600)
    sec = sshd.collect(ctx)
    assert sec["v"]["daemon"]["reload_pending"] is False and sec["conf"] == "exact"


def test_hostcfg6_grouped_short_options_are_read_like_getopt(tmp_path, monkeypatch):
    monkeypatch.setattr(sshd, "_clk_tck", lambda: 100)
    cases = [("/usr/sbin/sshd\0-Df\0/etc/ssh/alt_config\0", "/etc/ssh/alt_config", False),
             ("/usr/sbin/sshd\0-Df/etc/ssh/alt_config\0", "/etc/ssh/alt_config", False),
             ("/usr/sbin/sshd\0-Do\0PasswordAuthentication=yes\0", None, True),
             ("/usr/sbin/sshd\0-D4\0", None, True),
             ("/usr/sbin/sshd\0-Dp\0" + "2222\0", None, True),
             ("/usr/sbin/sshd\0-De\0", None, False),          # -D -e: not configuration
             ("/usr/sbin/sshd\0-Dz\0", None, True)]           # unknown flag: do not guess
    for i, (cmd, path, override) in enumerate(cases):
        sec = _daemon_collect(tmp_path / ("c%d" % i), cfg_mtime=START - 3600, cmdline=cmd)
        d = sec["v"]["daemon"]
        assert (d["config_path"], d["options_override"]) == (path, override), cmd
        if path or override:
            assert sec["conf"] == "approximate" and d["reload_pending"] is True, cmd
        else:
            assert d["config_default"] is True and sec["conf"] == "exact", cmd


# ----------------------------------------------------- coll-1 rework (verifier bypasses)
def test_coll1_duplicate_gid_resolves_to_the_first_group_name_like_getgrgid(tmp_path):
    # glibc getgrgid(3000) is the FIRST entry ("staff"): the user's primary group is "staff", so
    # 'Match Group staff' selects it. The old parser kept the LAST name and missed the user.
    passwd = PASSWD + "sftp1:x:2001:3000::/srv/sftp:/usr/sbin/nologin\n"
    cfg = "PasswordAuthentication no\nMatch Group staff\n  PasswordAuthentication yes\n"
    sec, _ = run_collect(tmp_path, passwd, cfg, {"sftp1"}, group="staff:x:3000:\nsftponly:x:3000:\n")
    assert delta_users(sec) == ["sftp1"]


def test_coll1_duplicate_gid_second_name_is_not_a_group_of_the_user(tmp_path):
    passwd = PASSWD + "sftp1:x:2001:3000::/srv/sftp:/usr/sbin/nologin\n"
    cfg = "PasswordAuthentication no\nMatch Group sftponly\n  PasswordAuthentication yes\n"
    sec, _ = run_collect(tmp_path, passwd, cfg, set(), group="staff:x:3000:\nsftponly:x:3000:\n")
    assert sshd.parse_group("staff:x:3000:\nsftponly:x:3000:\n")[0] == {3000: "staff"}
    assert delta_users(sec) == [] and sec["conf"] == "exact"


def test_coll1_duplicate_gid_member_entry_counts_under_the_first_name():
    by_gid, members, _ = sshd.parse_group("staff:x:3000:\nsftponly:x:3000:bob\n")
    assert members["bob"] == {"staff"}


def test_coll1_selection_extras_checks_the_collector_budget():
    rows = [{"name": "u%d" % i, "uid": 3000 + i, "gid": 3000 + i, "login": False, "ok": True} for i in range(5000)]
    calls = []
    sshd.selection_extras(rows, "", [[("user", "zzz")]], [], check=lambda: calls.append(1))
    assert len(calls) >= 4


def test_coll5_the_exe_of_a_root_sshd_process_gets_the_same_trust_check(tmp_path):
    # a root process named sshd (another mount namespace, a container) whose exe path names a
    # group-writable planted file on this host must not be run as root
    runner = _runner_log()
    ctx = make_ctx(tmp_path, runner=runner, files=ubuntu_files(), bins=["/usr/sbin/sshd", "/usr/bin/ssh"])
    p = put(os.path.join(str(tmp_path), "root"), "/usr/local/sbin/sshd", "#!/bin/sh\n", mode=0o775)
    os.chmod(p, 0o775)
    os.chmod(os.path.dirname(p), 0o2775)
    _daemon(ctx, exe="/usr/local/sbin/sshd")
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"
    sshd.collect(ctx)
    assert not any(c and c[0] == "/usr/local/sbin/sshd" for c in runner.calls)


def test_coll5_the_exe_of_a_root_sshd_process_outside_the_system_path_needs_a_trusted_owner(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, runner=_runner_log(), files=ubuntu_files(), bins=["/usr/sbin/sshd", "/opt/ossh/sbin/sshd"])
    _daemon(ctx, exe="/opt/ossh/sbin/sshd")
    monkeypatch.setattr(sshd, "TRUSTED_UID", os.geteuid() + 1)
    assert sshd.find_sshd(ctx) == "/usr/sbin/sshd"             # owner is not the trusted uid
    monkeypatch.setattr(sshd, "TRUSTED_UID", os.geteuid())
    assert sshd.find_sshd(ctx) == "/opt/ossh/sbin/sshd"
