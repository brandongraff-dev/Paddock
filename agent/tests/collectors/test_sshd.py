import json

from paddock_agent.collectors import base, payload_bytes, sshd

from .helpers import FakeRunner, fixture, make_ctx, res

VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024"
BINS = ["/usr/sbin/sshd", "/usr/bin/ssh"]
S = "synthetic/sshd/"
# Positive evidence about the daemon (socket activation); without any, reload_pending is null and the
# section is approximate (P2 round 2, L-7), which is not what these tests are about.
ACTIVATED = {"/etc/systemd/system/sockets.target.wants/ssh.socket": ""}


def sshd_runner(base_text, probe=None, rc=0, err=""):
    """Fake ``sshd``/``ssh``: ``probe(user, addr) -> text`` answers ``-T -C``."""
    def run(argv):
        if os_base(argv) == "ssh":
            return res("", err=VERSION)
        if "-C" in argv:
            spec = dict(kv.split("=", 1) for kv in argv[argv.index("-C") + 1].split(","))
            if probe is None:
                return res(base_text)
            out = probe(spec["user"], spec["addr"])
            return out if isinstance(out, dict) else res(out)
        return res(base_text, rc=rc, err=err)
    return FakeRunner({"sshd": run, "ssh": run})


def os_base(argv):
    return argv[0].rsplit("/", 1)[-1]


def ubuntu_files(extra=None):
    f = {"/etc/ssh/sshd_config": fixture(S + "sshd_config.ubuntu2404.txt"),
         "/etc/ssh/sshd_config.d/50-cloud-init.conf": fixture(S + "50-cloud-init.conf"),
         "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf": fixture(S + "60-cloudimg-settings.conf"),
         "/etc/passwd": fixture(S + "passwd.sample")}
    f.update(extra or {})
    return f


# ------------------------------------------------------------------ pure parsers
def test_normalise_keeps_only_the_allowlist_and_normalises_values():
    cfg, problems = sshd.normalise_config(sshd.parse_sshd_T(fixture(S + "sshd_T.ubuntu2404.txt")))
    assert problems == []
    assert set(cfg) <= sshd.ALLOWLIST
    for leaked in ("ciphers", "macs", "hostkey", "subsystem", "acceptenv", "pidfile",
                   "kexalgorithms", "modulifile"):
        assert leaked not in cfg
    assert cfg["permitrootlogin"] == "prohibit-password"  # without-password normalised
    assert cfg["passwordauthentication"] == "yes" and cfg["usepam"] == "yes"
    assert cfg["maxauthtries"] == 6 and isinstance(cfg["maxauthtries"], int)
    assert cfg["port"] == [22]
    assert cfg["listenaddress"] == ["0.0.0.0:22", "[::]:22"]
    assert cfg["authorizedkeysfile"] == [".ssh/authorized_keys", ".ssh/authorized_keys2"]
    assert cfg["authorizedkeyscommand"] == "none" and cfg["loglevel"] == "info"
    assert cfg["authenticationmethods"] == "any"
    json.dumps(cfg)


def test_authorizedkeyscommand_value_is_redacted_to_presence():
    cfg, _ = sshd.normalise_config(sshd.parse_sshd_T("authorizedkeyscommand /usr/bin/secret-lookup %u\n"))
    assert cfg["authorizedkeyscommand"] == "set"


def test_challengeresponse_alias_on_old_openssh():
    cfg, _ = sshd.normalise_config(sshd.parse_sshd_T(fixture(S + "sshd_T.old_openssh7.txt")))
    assert cfg["kbdinteractiveauthentication"] == "no" and "challengeresponseauthentication" not in cfg
    assert cfg["permitrootlogin"] == "yes"


def test_bad_values_are_reported_not_guessed():
    _cfg, problems = sshd.normalise_config(sshd.parse_sshd_T("passwordauthentication maybe\nmaxauthtries lots\n"))
    assert sorted(problems) == ["bad_value:maxauthtries", "bad_value:passwordauthentication"]


def test_config_delta_semantics():
    a = {"x": "1", "y": "2", "l": [1]}
    assert sshd.config_delta(a, dict(a)) == {}
    assert sshd.config_delta(a, {"x": "1", "y": "3", "l": [1], "z": "n"}) == {"y": "3", "z": "n"}
    assert sshd.config_delta(a, {"x": "1"}) == {"y": None, "l": None}


def test_login_users():
    assert sshd.login_users(fixture(S + "passwd.sample")) == ["postgres", "ubuntu", "alice"]


def test_split_directive_forms():
    assert sshd.split_directive("  PasswordAuthentication   no  ") == ("passwordauthentication", ["no"])
    assert sshd.split_directive("MaxAuthTries=3") == ("maxauthtries", ["3"])
    assert sshd.split_directive("MaxAuthTries = 3") == ("maxauthtries", ["3"])
    assert sshd.split_directive('AllowUsers "a b" c # trailing') == ("allowusers", ["a b", "c"])
    assert sshd.split_directive("# Port 22") is None and sshd.split_directive("   ") is None


def test_address_probe_points():
    addrs, why = sshd.address_probe_points(["10.0.0.0/8,!10.1.0.0/16"])
    assert why is None
    assert {"10.0.0.0", "10.1.0.0", "10.2.0.0", "11.0.0.0"} <= set(addrs)
    assert sshd.address_probe_points(["*"]) == ([], None)
    assert sshd.address_probe_points(["10.*"])[1] == "address_pattern"
    assert sshd.address_probe_points(["host.example.com"])[1] == "address_pattern"
    many = ",".join("10.%d.0.0/16" % i for i in range(20))
    assert sshd.address_probe_points([many])[1] == "address_atoms"


def test_text_config_parse_first_value_wins_and_match_scoping():
    files = ubuntu_files()

    def rf(p):
        if p in files:
            return "ok", files[p].encode()
        return "missing", b""

    def rd(p):
        names = sorted(k.rsplit("/", 1)[1] for k in files if k.rsplit("/", 1)[0] == p)
        return ("ok", names) if names else ("missing", [])
    tc = sshd.parse_sshd_config(rf, rd)
    assert tc["complete"] and tc["raw"]["passwordauthentication"] == ["yes"]  # 50-cloud-init wins
    assert [f["path"].rsplit("/", 1)[1] for f in tc["files"]] == [
        "sshd_config", "50-cloud-init.conf", "60-cloudimg-settings.conf"]
    assert all(len(f["sha256"]) == 64 for f in tc["files"])

    files = {"/etc/ssh/sshd_config": fixture(S + "sshd_config.match.txt")}
    tc = sshd.parse_sshd_config(rf, rd)
    assert tc["raw"]["port"] == ["22", "2222"] and tc["raw"]["allowusers"] == ["alice", "bob", "carol"]
    assert tc["raw"]["passwordauthentication"] == ["no"]  # Match-scoped yes is not global
    assert tc["raw"]["maxauthtries"] == ["3"] and tc["raw"]["permitrootlogin"] == ["no"]
    assert tc["matches"] == [[("group", "sftponly")],
                             [("address", "10.0.0.0/8,!10.1.0.0/16"), ("user", "deploy")]]


def test_text_config_unreadable_include_marks_incomplete():
    def rf(p):
        if p == "/etc/ssh/sshd_config":
            return "ok", b"Include /etc/ssh/sshd_config.d/*.conf\n"
        return "denied", b""

    def rd(p):
        return "denied", []
    tc = sshd.parse_sshd_config(rf, rd)
    assert tc["complete"] is False


def test_text_config_include_cycle_terminates():
    def rf(p):
        return "ok", b"Include /etc/ssh/sshd_config\nPort 22\n"
    tc = sshd.parse_sshd_config(rf, lambda p: ("missing", []))
    assert tc["raw"]["port"] == ["22"]


# --------------------------------------------------------------------- collector
def test_not_installed_is_tool_missing_only_without_any_evidence(tmp_path):
    ctx = make_ctx(tmp_path / "a")
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "tool_missing"}
    ctx = make_ctx(tmp_path / "b", files={"/etc/ssh/sshd_config": "Port 22\n"})
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "no_data"}
    ctx = make_ctx(tmp_path / "c", files={"/proc/321/comm": "sshd\n"})
    assert sshd.collect(ctx)["reason"] == "no_data"
    tcp = "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1\n"
    ctx = make_ctx(tmp_path / "d", files={"/proc/net/tcp": tcp})
    assert sshd.collect(ctx)["reason"] == "no_data"


def test_containerised_and_non_linux(tmp_path):
    assert sshd.collect(make_ctx(tmp_path / "a", containerised=True, bins=BINS)) == {
        "s": "unavailable", "reason": "containerised_agent"}
    ctx = make_ctx(tmp_path / "b", bins=BINS)
    ctx.platform = "darwin"
    assert sshd.collect(ctx)["reason"] == "unsupported_platform"


def test_exact_collection_without_match_blocks(tmp_path):
    files = ubuntu_files({"/etc/ssh/sshd_config": "PasswordAuthentication no\nUsePAM yes\n", **ACTIVATED})
    del files["/etc/ssh/sshd_config.d/50-cloud-init.conf"]
    runner = sshd_runner(fixture(S + "sshd_T.hardened.txt"))
    ctx = make_ctx(tmp_path, runner=runner, files=files, bins=BINS)
    sec = sshd.collect(ctx)
    base.validate_section(sec)
    assert sec["s"] == "ok" and sec["conf"] == "exact" and sec["partial"] is False
    v = sec["v"]
    assert v["source"] == "sshd_T" and v["version"] == "9.6p1" and v["installed"] is True
    assert v["config"]["passwordauthentication"] == "no" and v["config"]["maxauthtries"] == 3
    assert v["match"] == {"blocks": 0, "criteria": [], "known": True, "unprobed": False,
                          "unprobed_reasons": []}
    p = v["probes"]
    # users_total counts the login-shell row dropped for its unprobeable name ("Bad User") too (P2
    # review coll-1: it was 3 and silently omitted that row); probed = root + postgres, ubuntu, alice
    assert p["users_total"] == 4 and p["users_probed"] == 4
    assert p["planned"] == p["done"] == 5 * 2 and p["deltas"] == []
    assert p["addrs"] == ["10.255.255.1", "203.0.113.7"]
    assert all(len(f["sha256"]) == 64 for f in v["files"])
    probe_calls = [c for c in runner.calls if "-C" in c]
    assert probe_calls[0] == ["/usr/sbin/sshd", "-T", "-C", "user=root,host=probe.invalid,addr=203.0.113.7"]
    users = sorted(set(c[c.index("-C") + 1].split(",")[0] for c in probe_calls))
    assert users == ["user=alice", "user=paddock-nonexistent-probe", "user=postgres", "user=root", "user=ubuntu"]
    assert payload_bytes(sec)


def test_probe_matrix_records_only_deltas(tmp_path):
    hardened = fixture(S + "sshd_T.hardened.txt")
    pw_yes = hardened.replace("passwordauthentication no", "passwordauthentication yes")
    no_tries = "\n".join(ln for ln in hardened.splitlines() if not ln.startswith("maxauthtries"))

    def probe(user, addr):
        if user == "root" and addr == "203.0.113.7":
            return pw_yes
        if user == "paddock-nonexistent-probe":
            return no_tries
        return hardened
    ctx = make_ctx(tmp_path, runner=sshd_runner(hardened, probe), files=ubuntu_files(), bins=BINS)
    sec = sshd.collect(ctx)
    d = sec["v"]["probes"]["deltas"]
    assert [(x["user"], x["addr"]) for x in d] == [
        ("<nonexistent>", "10.255.255.1"), ("<nonexistent>", "203.0.113.7"),
        ("root", "203.0.113.7")]
    assert d[0]["delta"] == {"maxauthtries": None}
    assert d[2]["delta"] == {"passwordauthentication": "yes"}
    # no Match block is visible in the text, yet probes disagree: our view is wrong => approximate
    assert sec["conf"] == "approximate"
    assert "unexplained_delta" in sec["v"]["match"]["unprobed_reasons"]


def test_unexplained_delta_without_visible_match_block_is_approximate(tmp_path):
    hardened = fixture(S + "sshd_T.hardened.txt")
    ctx = make_ctx(tmp_path, runner=sshd_runner(
        hardened, lambda u, a: hardened.replace("passwordauthentication no", "passwordauthentication yes")
        if u == "alice" else hardened), files=ubuntu_files(), bins=BINS)
    sec = sshd.collect(ctx)
    assert sec["conf"] == "approximate"
    assert "unexplained_delta" in sec["v"]["match"]["unprobed_reasons"]


def test_match_group_and_address_blocks_are_probed(tmp_path):
    hardened = fixture(S + "sshd_T.hardened.txt")
    pw_yes = hardened.replace("passwordauthentication no", "passwordauthentication yes")
    seen_addrs = set()

    def probe(user, addr):
        seen_addrs.add(addr)
        return pw_yes if user == "alice" else hardened
    ctx = make_ctx(tmp_path, runner=sshd_runner(hardened, probe),
                   files={"/etc/ssh/sshd_config": fixture(S + "sshd_config.match.txt"),
                          "/etc/passwd": fixture(S + "passwd.sample"), **ACTIVATED}, bins=BINS)
    sec = sshd.collect(ctx)
    v = sec["v"]
    assert v["match"]["blocks"] == 2 and v["match"]["criteria"] == ["address", "group", "user"]
    assert v["match"]["unprobed"] is False and sec["conf"] == "exact"
    assert {"10.0.0.0", "10.1.0.0", "10.2.0.0", "11.0.0.0", "203.0.113.7"} <= seen_addrs
    alice = [x for x in v["probes"]["deltas"] if x["user"] == "alice"]
    assert len(alice) == v["probes"]["planned"] // 6 and all(  # root, 3 login users, deploy, nonexistent
        x["delta"] == {"passwordauthentication": "yes"} for x in alice)
    assert all(x["user"] == "alice" for x in v["probes"]["deltas"])


def test_unprobable_match_criteria_make_it_approximate(tmp_path):
    cfg = "PasswordAuthentication no\nMatch Host *.corp.example\n  PasswordAuthentication yes\n"
    ctx = make_ctx(tmp_path, runner=sshd_runner(fixture(S + "sshd_T.hardened.txt")),
                   files={"/etc/ssh/sshd_config": cfg, "/etc/passwd": fixture(S + "passwd.sample"),
                          **ACTIVATED}, bins=BINS)
    sec = sshd.collect(ctx)
    assert sec["conf"] == "approximate" and sec["v"]["match"]["unprobed_reasons"] == ["criterion_host"]
    assert sec["v"]["source"] == "sshd_T"


def test_more_than_twenty_login_users_with_match_user_is_approximate(tmp_path):
    passwd = "".join("u%02d:x:%d:%d::/home/u:/bin/bash\n" % (i, 1000 + i, 1000 + i) for i in range(25))
    cfg = "PasswordAuthentication no\nMatch User u24\n  PasswordAuthentication yes\n"
    runner = sshd_runner(fixture(S + "sshd_T.hardened.txt"))
    ctx = make_ctx(tmp_path, runner=runner, files={"/etc/ssh/sshd_config": cfg, "/etc/passwd": passwd}, bins=BINS)
    sec = sshd.collect(ctx)
    assert sec["v"]["probes"]["users_total"] == 25 and sec["v"]["probes"]["users_probed"] == 22
    assert sec["conf"] == "approximate" and "users_over_cap" in sec["v"]["match"]["unprobed_reasons"]
    # a literal `Match User` name is probed even beyond the 20-user cap; the other users stay unprobed
    assert any("user=u24," in " ".join(c) for c in runner.calls)
    assert not any("user=u23," in " ".join(c) for c in runner.calls)


def test_match_user_naming_a_nologin_account_is_probed(tmp_path):
    hardened = fixture(S + "sshd_T.hardened.txt")
    pw_yes = hardened.replace("passwordauthentication no", "passwordauthentication yes")
    passwd = fixture(S + "passwd.sample") + "svc:x:998:998::/srv:/usr/sbin/nologin\n"
    cfg = "PasswordAuthentication no\nMatch User svc,!bob,*admin\n  PasswordAuthentication yes\n"
    runner = sshd_runner(hardened, lambda u, a: pw_yes if u == "svc" else hardened)
    ctx = make_ctx(tmp_path, runner=runner, files={"/etc/ssh/sshd_config": cfg, "/etc/passwd": passwd},
                   bins=BINS)
    sec = sshd.collect(ctx)
    assert sshd.match_user_names([[("user", "svc,!bob,*admin")]]) == ["svc"]
    assert {x["user"] for x in sec["v"]["probes"]["deltas"]} == {"svc"}


def test_probe_failure_is_never_exact(tmp_path):
    hardened = fixture(S + "sshd_T.hardened.txt")

    def probe(user, addr):
        return res("", rc=255, err="Bad configuration option") if user == "ubuntu" else hardened
    ctx = make_ctx(tmp_path, runner=sshd_runner(hardened, probe), files=ubuntu_files(), bins=BINS)
    sec = sshd.collect(ctx)
    assert sec["conf"] == "approximate"
    assert {"probe_failed", "probe_incomplete"} <= set(sec["v"]["match"]["unprobed_reasons"])
    assert sec["v"]["probes"]["done"] < sec["v"]["probes"]["planned"]


def test_unreadable_config_makes_match_unknown_hence_approximate(tmp_path):
    ctx = make_ctx(tmp_path, runner=sshd_runner(fixture(S + "sshd_T.hardened.txt")),
                   files={"/etc/passwd": fixture(S + "passwd.sample")}, bins=BINS)
    sec = sshd.collect(ctx)  # /etc/ssh/sshd_config absent in the fake root
    assert sec["conf"] == "approximate" and "config_unreadable" in sec["v"]["match"]["unprobed_reasons"]


def test_text_fallback_never_claims_exact(tmp_path):
    runner = sshd_runner("", rc=255, err="sshd: no hostkeys available -- exiting.")
    ctx = make_ctx(tmp_path, runner=runner, files=ubuntu_files(), bins=BINS, is_root=False)
    sec = sshd.collect(ctx)
    assert sec["s"] == "ok" and sec["conf"] == "approximate"
    v = sec["v"]
    assert v["source"] == "text" and v["config"]["passwordauthentication"] == "yes"  # 50-cloud-init first
    assert v["probes"] == {"addrs": [], "users_probed": 0, "users_total": 0, "planned": 0,
                           "done": 0, "deltas": []}
    assert v["match"]["unprobed"] is True and "text_source" in v["match"]["unprobed_reasons"]
    assert "usepam" in v["config"]


def test_text_fallback_on_any_failure_and_even_for_a_hardened_config(tmp_path):
    cfg = "PasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\nMaxAuthTries 3\n"
    for runner in (sshd_runner("", rc=1, err="whatever"),
                   FakeRunner({"sshd": res(timed_out=True, rc=None), "ssh": res("", err=VERSION)})):
        ctx = make_ctx(tmp_path / str(id(runner)), runner=runner, files={"/etc/ssh/sshd_config": cfg}, bins=BINS)
        sec = sshd.collect(ctx)
        assert sec["conf"] == "approximate" and sec["v"]["source"] == "text"


def test_failure_without_a_readable_config_is_never_an_ok(tmp_path):
    ctx = make_ctx(tmp_path / "a", runner=sshd_runner("", rc=255, err="no hostkeys available"), bins=BINS)
    assert sshd.collect(ctx) == {"s": "unavailable", "reason": "permission_denied"}
    ctx = make_ctx(tmp_path / "b", runner=FakeRunner({"sshd": res(timed_out=True, rc=None)}), bins=BINS)
    sec = sshd.collect(ctx)
    assert sec["s"] == "error" and sec["reason"] == "timeout"


def test_garbage_or_empty_output_is_parse_error_not_empty_ok(tmp_path):
    for text in ("this is not sshd output\nat all\n", "passwordauthentication maybe\n"):
        ctx = make_ctx(tmp_path / str(len(text)), runner=sshd_runner(text), files=ubuntu_files(), bins=BINS)
        sec = sshd.collect(ctx)
        assert sec["s"] == "error" and sec["reason"] == "parse_error"


def test_socket_activation_detected(tmp_path):
    f = ubuntu_files({"/etc/systemd/system/sockets.target.wants/ssh.socket": ""})
    ctx = make_ctx(tmp_path, runner=sshd_runner(fixture(S + "sshd_T.hardened.txt")), files=f, bins=BINS)
    assert sshd.collect(ctx)["v"]["socket_activated"] is True
    ctx = make_ctx(tmp_path / "n", runner=sshd_runner(fixture(S + "sshd_T.hardened.txt")),
                   files=ubuntu_files(), bins=BINS)
    assert sshd.collect(ctx)["v"]["socket_activated"] is False


def test_probe_arguments_cannot_be_injected(tmp_path):
    passwd = "root:x:0:0::/root:/bin/bash\nevil,host=x:x:1000:1000::/h:/bin/bash\nok:x:1001:1001::/h:/bin/bash\n"
    runner = sshd_runner(fixture(S + "sshd_T.hardened.txt"))
    ctx = make_ctx(tmp_path, runner=runner, files={"/etc/ssh/sshd_config": "Port 22\n", "/etc/passwd": passwd}, bins=BINS)
    sshd.collect(ctx)
    for c in runner.calls:
        if "-C" in c:
            assert c[c.index("-C") + 1].count("=") == 3 and "evil" not in c[c.index("-C") + 1]


def test_collection_is_deterministic(tmp_path):
    def run(tp):
        return sshd.collect(make_ctx(tp, runner=sshd_runner(fixture(S + "sshd_T.hardened.txt")),
                                     files=ubuntu_files(), bins=BINS))
    assert payload_bytes(run(tmp_path / "a")) == payload_bytes(run(tmp_path / "b"))
