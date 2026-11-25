"""patch (lite) collector: pure parsers over captured output, then the collector with a fake host."""
import pytest

from paddock_agent.collectors import base, patch, payload_bytes

from .helpers import FakeRunner, fixture, make_ctx, res

U = "ubuntu2404/"
S = "synthetic/patch/"
DQ = fixture(U + "dpkg_query_full.ubuntu2404.tsv")
APT_REAL = fixture(U + "apt_get_s_dist_upgrade.ubuntu2404.txt")
DEB_BINS = ["/usr/bin/dpkg-query", "/usr/bin/apt-get", "/usr/bin/apt-config"]
RPM_BINS = ["/usr/bin/rpm", "/usr/bin/dnf", "/usr/bin/needs-restarting"]


# ------------------------------------------------------------------------ parsers
def test_os_release_identity():
    u = patch.parse_os_release(fixture(U + "os-release.ubuntu2404.txt"))
    assert u["id"] == "ubuntu" and u["family"] == "debian" and u["version_id"] == "24.04"
    assert u["codename"] == "noble" and u["id_like"] == ["debian"]
    r = patch.parse_os_release(fixture(S + "os-release.rhel9.txt"))
    assert r["family"] == "rhel" and r["version_id"] == "9.4" and r["codename"] is None
    d = patch.parse_os_release(fixture(S + "os-release.debian12.txt"))
    assert d["family"] == "debian" and d["codename"] == "bookworm"
    assert patch.parse_os_release("")["family"] == "other"
    assert patch.parse_os_release("ID=alpine\n")["family"] == "alpine"


def test_dpkg_query_real_capture():
    rows, bad, held = patch.parse_dpkg_query(DQ)
    assert bad == 0 and held == 0 and len(rows) == len(DQ.splitlines()) == 837
    by = dict((r[0], r) for r in rows)
    assert by["automake"] == ["automake", "1:1.16.5-1.3ubuntu1", "all", "automake-1.16", "1:1.16.5-1.3ubuntu1"]
    assert by["clang"][3:] == ["llvm-defaults", "0.59~exp2"]       # source version differs from binary
    assert "binutils-common" in by and "binutils-common:amd64" not in by  # multiarch qualifier dropped
    assert by["bsdutils"][3] == "util-linux"
    assert all(len(r) == 5 and all(isinstance(x, str) and x for x in r) for r in rows)


def test_dpkg_query_status_filter_and_bad_lines():
    text = ("a\t1\tamd64\tii \ta\t1\n"
            "b\t2\tamd64\trc \tb\t2\n"          # removed, config files remain: not installed
            "c\t3\tamd64\thi \tc\t3\n"           # held but installed
            "d\t4\tamd64\tiU \td\t4\n"           # unpacked only: second letter U
            "garbage line\n")
    rows, bad, held = patch.parse_dpkg_query(text)
    assert [r[0] for r in rows] == ["a", "c"] and bad == 1 and held == 1


def test_dpkg_status_fallback():
    rows, bad, held = patch.parse_dpkg_status(fixture(S + "dpkg_status_sample.txt"))
    assert bad == 0 and held == 1
    by = dict((r[0], r) for r in rows)
    assert set(by) == {"bash", "libssl3", "heldpkg", "linux-image-6.1.0-25-amd64"}
    assert by["libssl3"] == ["libssl3", "3.0.11-1~deb12u1", "amd64", "openssl", "3.0.11-1~deb12u1"]
    assert by["linux-image-6.1.0-25-amd64"][3:] == ["linux-signed-amd64", "6.1.106+1"]
    assert by["bash"][3] == "bash"


def test_rpm_qf():
    rows, bad = patch.parse_rpm_qf(fixture(S + "rpm_qa_el9.tsv"))
    by = dict(((r[0], r[1]), r) for r in rows)
    assert bad == 0 and not any(r[0] == "gpg-pubkey" for r in rows)
    assert by[("openssl", "1:3.0.7-27.el9")] == ["openssl", "1:3.0.7-27.el9", "x86_64", "openssl", "1:3.0.7-27.el9"]
    assert by[("bash", "5.1.8-6.el9_1")][3] == "bash"
    assert by[("foo", "1.0-1")][3] == "foo"                       # (none) source rpm: falls back to the name
    assert patch.parse_rpm_qf("a\tb\n")[1] == 1


def test_manifest_digest_is_order_independent_and_sensitive():
    rows, _b, _h = patch.parse_dpkg_query(DQ)
    d1, o1 = patch.manifest_digest(rows)
    d2, o2 = patch.manifest_digest(list(reversed(rows)))
    assert d1 == d2 and o1 == o2 and len(d1) == 64
    changed = [list(r) for r in rows]
    changed[5][1] += "x"
    assert patch.manifest_digest(changed)[0] != d1
    assert patch.manifest_digest(rows[:-1])[0] != d1


def test_apt_sim_real_capture_counts_security_including_trailing_brackets():
    p = patch.parse_apt_sim(APT_REAL)
    assert p["total"] == 18 and p["unparsed"] == 0 and p["kept_back"] == 2 and p["removals"] == 0
    # `libheif-plugin-aomdec ... ) [libheif1:amd64 ]` carries a trailing bracket group
    assert p["security_pkgs"] == ["libheif-plugin-aomdec", "libheif1", "libssh-4", "libssh-gcrypt-4",
                                  "linux-libc-dev", "python3-oauthlib", "tzdata"]
    assert p["security"] == 7


def test_apt_sim_synthetic_security_pockets():
    p = patch.parse_apt_sim(fixture(S + "apt_sim_security_debian.txt"))
    assert p["security_pkgs"] == ["libssl3", "openssl"]   # tzdata is stable-updates; `-security-tools` is not
    assert p["total"] == 5 and p["removals"] == 1 and p["kept_back"] == 1
    assert patch.parse_apt_sim(fixture(S + "apt_sim_empty.txt")) == {
        "total": 0, "security": 0, "unparsed": 0, "security_pkgs": [], "kept_back": 0, "removals": 0}


def test_apt_sim_unreadable_output_is_not_zero_updates():
    assert patch.parse_apt_sim("") is None
    assert patch.parse_apt_sim("E: Could not open lock file\n") is None
    p = patch.parse_apt_sim("Inst weird line\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    assert p["unparsed"] == 1


def test_dnf_and_yum_parsers():
    d = patch.parse_dnf_updateinfo(fixture(S + "dnf_updateinfo_security.el9.txt"))
    assert d["security"] == 2 and d["security_pkgs"] == ["kernel-core", "openssl", "openssl-libs"]
    y = patch.parse_yum_check_update(fixture(S + "yum_check_update_el7.txt"))
    assert y["security_pkgs"] == ["kernel", "openssl"] and y["security"] == 2
    assert patch.parse_dnf_updateinfo("")["security"] == 0


def test_small_parsers():
    assert patch.parse_apt_periodic(fixture(S + "apt_config_periodic.txt")) == 1
    assert patch.parse_apt_periodic("APT::Periodic::Enable \"0\";") is None
    assert patch.parse_auto_conf(fixture(S + "dnf_automatic.conf")) is True
    assert patch.parse_auto_conf("apply_updates = no\n") is False
    assert patch.parse_auto_conf("") is None
    rows = [["linux-image-6.8.0-45-generic", "6.8.0-45.45", "amd64", "linux", "6.8.0-45.45"],
            ["linux-image-unsigned-6.9.1", "6.9.1-1", "amd64", "linux", "6.9.1-1"],
            ["linux-image-generic", "6.8.0", "amd64", "linux", "6.8.0"]]
    assert [k[0] for k in patch.kernel_packages(rows, "dpkg")] == ["6.8.0-45-generic", "6.9.1"]
    rr = [["kernel-core", "5.14.0-427.el9", "x86_64", "kernel", "5.14.0-427.el9"]]
    assert patch.kernel_packages(rr, "rpm")[0][0] == "5.14.0-427.el9.x86_64"


# ---------------------------------------------------------------------- collector
def deb_runner(dq=DQ, apt=APT_REAL, dq_res=None, apt_res=None):
    return FakeRunner({
        "dpkg-query": dq_res or res(dq),
        "apt-get": apt_res or res(apt),
        "apt-config": res(fixture(S + "apt_config_periodic.txt"))})


def deb_files(extra=None):
    f = {"/etc/os-release": fixture(U + "os-release.ubuntu2404.txt"),
         "/proc/sys/kernel/osrelease": "6.8.0-45-generic\n"}
    f.update(extra or {})
    return f


def run_collect(tmp_path, runner, files, bins=DEB_BINS, **kw):
    ctx = make_ctx(tmp_path, runner=runner, files=files, bins=bins, **kw)
    sec = patch.collect(ctx)
    base.validate_section(sec)
    return ctx, sec


def test_debian_collection_end_to_end(tmp_path):
    kern = "linux-image-6.8.0-45-generic\t6.8.0-45.45\tamd64\tii \tlinux\t6.8.0-45.45\n"
    ctx, sec = run_collect(tmp_path, deb_runner(dq=DQ + kern), deb_files({
        "/var/lib/apt/periodic/update-success-stamp": "", "/var/run/reboot-required": "*** reboot ***\n",
        "/var/run/reboot-required.pkgs": "linux-image-6.8.0-45-generic\nlibc6\nlibc6\n"}))
    assert sec["s"] == "ok" and sec["conf"] == "exact" and sec["partial"] is False
    v = sec["v"]
    assert set(v) == {"os", "manifest", "pending", "auto_update", "kernel", "reboot"}
    assert v["os"]["state"] == "ok" and v["os"]["id"] == "ubuntu" and v["os"]["arch"] == "x86_64"
    man = v["manifest"]
    assert man["state"] == "ok" and man["mgr"] == "dpkg" and man["count"] == 838 and man["full"] is True
    assert len(man["packages"]) == 838 and len(man["sha256"]) == 64 and man["held"] == 0
    assert v["pending"]["state"] == "ok" and v["pending"]["mgr"] == "apt" and v["pending"]["security"] == 7
    assert v["pending"]["metadata_age_s"] == 0 and isinstance(v["pending"]["metadata_age_s"], int)
    assert v["auto_update"] == {"state": "ok", "mgr": "unattended-upgrades", "installed": False,
                                "interval_days": 1, "timer_enabled": False}
    assert v["kernel"]["state"] == "ok" and v["kernel"]["package"] == "linux-image-6.8.0-45-generic"
    assert v["kernel"]["running"] == "6.8.0-45-generic" and v["kernel"]["livepatch"] is False
    assert v["reboot"] == {"state": "ok", "required": True, "source": "file",
                           "pkgs": ["libc6", "linux-image-6.8.0-45-generic"]}
    ctx2, sec2 = run_collect(tmp_path / "two", deb_runner(dq=DQ + kern), deb_files({
        "/var/lib/apt/periodic/update-success-stamp": "", "/var/run/reboot-required": "*** reboot ***\n",
        "/var/run/reboot-required.pkgs": "linux-image-6.8.0-45-generic\nlibc6\nlibc6\n"}))
    assert payload_bytes(sec) == payload_bytes(sec2)


def test_apt_is_simulated_only_and_never_updates(tmp_path):
    runner = deb_runner()
    run_collect(tmp_path, runner, deb_files())
    apt_calls = [c for c in runner.calls if c[0].endswith("apt-get")]
    assert apt_calls == [["/usr/bin/apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"]]
    assert not any("update" == a for c in runner.calls for a in c[1:2])


def test_manifest_full_list_only_when_the_digest_changes(tmp_path):
    ctx, sec = run_collect(tmp_path, deb_runner(), deb_files())
    digest = sec["v"]["manifest"]["sha256"]
    ctx2 = make_ctx(tmp_path / "b", runner=deb_runner(), files=deb_files(), bins=DEB_BINS)
    ctx2.known_manifest_sha = digest
    m = patch.collect(ctx2)["v"]["manifest"]
    assert m["full"] is False and "packages" not in m and m["sha256"] == digest and m["count"] == 837
    ctx3 = make_ctx(tmp_path / "c", runner=deb_runner(), files=deb_files(), bins=DEB_BINS)
    ctx3.known_manifest_sha = "0" * 64
    assert patch.collect(ctx3)["v"]["manifest"]["full"] is True
    ctx4 = make_ctx(tmp_path / "d", runner=deb_runner(), files=deb_files(), bins=DEB_BINS)
    ctx4.known_manifest_sha, ctx4.force_full_manifest = digest, True
    assert "packages" in patch.collect(ctx4)["v"]["manifest"]


def test_running_kernel_not_owned_by_a_package_is_unmanaged_not_ok(tmp_path):
    _c, sec = run_collect(tmp_path, deb_runner(), deb_files({"/proc/sys/kernel/osrelease": "6.18.44-fc-v819\n"}))
    k = sec["v"]["kernel"]
    assert k["state"] == "unavailable" and k["reason"] == "unmanaged_kernel" and k["running"] == "6.18.44-fc-v819"
    assert sec["partial"] is True


def test_truncated_package_listing_is_an_error_never_a_silent_cut(tmp_path):
    _c, sec = run_collect(tmp_path, deb_runner(dq_res=res(DQ[:5000], truncated=True)), deb_files())
    man = sec["v"]["manifest"]
    assert man["state"] == "error" and man["reason"] == "truncated" and "packages" not in man
    assert sec["partial"] is True and sec["v"]["pending"]["state"] == "ok"  # other sub-blocks survive
    assert sec["v"]["kernel"]["state"] == "unavailable"


def test_more_than_the_package_cap_is_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(patch, "MAX_PACKAGES", 100)
    _c, sec = run_collect(tmp_path, deb_runner(), deb_files())
    assert sec["v"]["manifest"]["state"] == "error" and sec["v"]["manifest"]["reason"] == "truncated"


def test_unparseable_or_empty_package_output_is_parse_error(tmp_path):
    for out in ("garbage without tabs\n", ""):
        _c, sec = run_collect(tmp_path / ("x%d" % len(out)), deb_runner(dq_res=res(out)), deb_files())
        assert sec["v"]["manifest"]["state"] == "error" and sec["v"]["manifest"]["reason"] == "parse_error"
        assert "packages" not in sec["v"]["manifest"]


def test_one_bad_line_among_good_ones_is_a_parse_error_not_a_silent_skip(tmp_path):
    _c, sec = run_collect(tmp_path, deb_runner(dq_res=res(DQ + "broken\tline\n")), deb_files())
    man = sec["v"]["manifest"]
    assert man["state"] == "error" and man["reason"] == "parse_error" and "packages" not in man
    runner = FakeRunner({"rpm": res(fixture(S + "rpm_qa_el9.tsv") + "oops\n"), "dnf": res("")})
    _c, sec = run_collect(tmp_path / "rpm", runner, {"/etc/os-release": fixture(S + "os-release.rhel9.txt")},
                          bins=RPM_BINS)
    assert sec["v"]["manifest"]["state"] == "error" and sec["v"]["manifest"]["reason"] == "parse_error"


def test_pending_failures_are_classified_not_zero(tmp_path):
    for apt_res, state, reason in [
            (res("", rc=100, err="E: Could not open lock file"), "error", "exit_nonzero"),
            (res("", timed_out=True, rc=None), "error", "timeout"),
            (res("E: weird\n"), "error", "parse_error"),
            (res("Inst a [1] (2 X:1/x [amd64]) [] weird\nInst b (x\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"),
             "error", "parse_error")]:
        _c, sec = run_collect(tmp_path / reason / str(len(apt_res["out"])), deb_runner(apt_res=apt_res), deb_files())
        p = sec["v"]["pending"]
        assert p["state"] == state and p["reason"] == reason and "security" not in p, p
        assert sec["partial"] is True


def test_dpkg_status_file_fallback_without_dpkg_query(tmp_path):
    files = deb_files({"/var/lib/dpkg/status": fixture(S + "dpkg_status_sample.txt")})
    _c, sec = run_collect(tmp_path, deb_runner(), files, bins=["/usr/bin/apt-get"])
    man = sec["v"]["manifest"]
    assert man["state"] == "ok" and man["count"] == 4 and man["held"] == 1


def test_nothing_usable_is_a_section_failure_not_an_empty_ok(tmp_path):
    ctx = make_ctx(tmp_path, runner=FakeRunner(), files={}, bins=[])
    sec = patch.collect(ctx)
    base.validate_section(sec)
    assert sec["s"] == "unavailable"
    ctx = make_ctx(tmp_path / "b", runner=FakeRunner({"dpkg-query": res("", timed_out=True, rc=None)}),
                   files={}, bins=["/usr/bin/dpkg-query"])
    sec = patch.collect(ctx)
    assert sec["s"] == "error" and sec["reason"] == "timeout"


def test_containerised_and_non_linux(tmp_path):
    ctx = make_ctx(tmp_path, runner=deb_runner(), files=deb_files(), bins=DEB_BINS, containerised=True)
    assert patch.collect(ctx) == {"s": "unavailable", "reason": "containerised_agent"}
    ctx = make_ctx(tmp_path / "b", runner=deb_runner(), files=deb_files(), bins=DEB_BINS)
    ctx.platform = "win32"
    assert patch.collect(ctx) == {"s": "unavailable", "reason": "unsupported_platform"}


def test_rhel_flow_with_reboot_and_security_updates(tmp_path):
    runner = FakeRunner({
        "rpm": res(fixture(S + "rpm_qa_el9.tsv")),
        "dnf": res(fixture(S + "dnf_updateinfo_security.el9.txt")),
        "needs-restarting": res("Core libraries or services have been updated\n", rc=1)})
    files = {"/etc/os-release": fixture(S + "os-release.rhel9.txt"),
             "/proc/sys/kernel/osrelease": "5.14.0-427.13.1.el9_4.x86_64\n"}
    _c, sec = run_collect(tmp_path, runner, files, bins=RPM_BINS)
    v = sec["v"]
    assert v["os"]["family"] == "rhel" and v["manifest"]["mgr"] == "rpm" and v["manifest"]["count"] == 6
    assert v["pending"]["mgr"] == "dnf" and v["pending"]["security"] == 2
    assert v["kernel"]["state"] == "ok" and v["kernel"]["package"] == "kernel-core"
    assert v["reboot"] == {"state": "ok", "required": True, "pkgs": [], "source": "needs-restarting"}
    assert [c for c in runner.calls if c[0].endswith("dnf")][0][:4] == ["/usr/bin/dnf", "-C", "-q", "updateinfo"]
    runner2 = FakeRunner({"rpm": res(fixture(S + "rpm_qa_el9.tsv")), "dnf": res(""),
                          "needs-restarting": res("No core libraries\n", rc=0)})
    _c, sec2 = run_collect(tmp_path / "b", runner2, files, bins=RPM_BINS)
    assert sec2["v"]["reboot"]["required"] is False and sec2["v"]["pending"]["security"] == 0
    runner3 = FakeRunner({"rpm": res(fixture(S + "rpm_qa_el9.tsv")), "dnf": res(""),
                          "needs-restarting": res("boom", rc=3)})
    _c, sec3 = run_collect(tmp_path / "c", runner3, files, bins=RPM_BINS)
    assert sec3["v"]["reboot"]["state"] == "error"      # an unknown exit code is never "no reboot"


def test_dnf_cache_only_without_a_cache_is_no_data_not_zero_updates(tmp_path):
    runner = FakeRunner({"rpm": res(fixture(S + "rpm_qa_el9.tsv")),
                         "dnf": res("", rc=1, err="Error: Cache-only enabled but no cache for 'baseos'"),
                         "needs-restarting": res("", rc=0)})
    _c, sec = run_collect(tmp_path, runner, {"/etc/os-release": fixture(S + "os-release.rhel9.txt")},
                          bins=RPM_BINS)
    assert sec["v"]["pending"] == {"state": "unavailable", "reason": "no_data"}


def test_no_floats_anywhere(tmp_path):
    _c, sec = run_collect(tmp_path, deb_runner(), deb_files())
    payload_bytes(sec)  # raises on any float


@pytest.mark.parametrize("bad", [{"state": "bogus"}])
def test_subblock_helpers_reject_unknown_reasons(bad):
    with pytest.raises(ValueError):
        patch._sb_unavailable("because")
    with pytest.raises(ValueError):
        patch._sb_error("because")
