"""collect_all: shape, isolation of failing collectors, self-health and redaction."""
import json
import re

import pytest

from paddock_agent import collectors
from paddock_agent.collectors import base, collect_all, health, payload_bytes
from paddock_agent.runner import CollectorTimeout

from .helpers import FakeRunner, fixture, make_ctx, put, res

SECTIONS = {"sshd", "listeners", "firewall", "patch", "self"}
RAW_MACHINE_ID = "0123456789abcdef0123456789abcdef"
SECRET = "S3CR3T-TOKEN-VALUE"


def host_files():
    return {
        "/etc/os-release": fixture("ubuntu2404/os-release.ubuntu2404.txt"),
        "/etc/machine-id": RAW_MACHINE_ID + "\n",
        "/proc/sys/kernel/random/boot_id": "11111111-2222-3333-4444-555555555555\n",
        "/proc/uptime": "12345.67 9999.99\n",
        "/proc/self/status": "Name:\tpaddock\nCapEff:\t0000000000081004\n",
        "/proc/net/tcp": fixture("ubuntu2404/proc_net_tcp.container.txt"),
        "/proc/net/udp": fixture("ubuntu2404/proc_net_udp.container.txt"),
        "/etc/ssh/sshd_config": "PasswordAuthentication no\n",
    }


def fake_runner():
    return FakeRunner({
        "dpkg-query": res(fixture("ubuntu2404/dpkg_query_sample.ubuntu2404.tsv")),
        "apt-get": res(fixture("synthetic/patch/apt_sim_empty.txt")),
        "nft": res('{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]}'),
        "sshd": res(fixture("synthetic/sshd/sshd_T.hardened.txt")),
        "ssh": res("", err="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13"),
    })


def full_ctx(tmp_path, **kw):
    bins = ["/usr/sbin/sshd", "/usr/bin/ssh", "/usr/sbin/nft", "/usr/bin/dpkg-query", "/usr/bin/apt-get"]
    return make_ctx(tmp_path, runner=fake_runner(), files=host_files(), bins=bins, **kw)


def test_shape_is_exactly_the_pinned_contract(tmp_path):
    out = collect_all(full_ctx(tmp_path))
    assert set(out) == {"schema", "collected_at", "sections"} and out["schema"] == 2
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", out["collected_at"])
    assert out["collected_at"] == "2026-11-18T11:06:40Z"      # ctx.now = 1795000000
    assert set(out["sections"]) == SECTIONS
    for sec in out["sections"].values():
        base.validate_section(sec)
    json.loads(payload_bytes(out).decode("utf-8"))             # JSON-serialisable, no floats/NaN


def test_sections_reflect_real_state_not_defaults(tmp_path):
    s = collect_all(full_ctx(tmp_path))["sections"]
    assert s["sshd"]["s"] == "ok" and s["sshd"]["v"]["config"]["passwordauthentication"] == "no"
    assert s["listeners"]["s"] == "ok" and s["listeners"]["v"]["count"] >= 1
    assert s["firewall"]["s"] == "ok" and s["firewall"]["v"]["backend"] == "none"
    assert s["patch"]["s"] == "ok" and s["patch"]["v"]["pending"]["security"] == 0
    assert s["self"]["s"] == "ok"


def test_output_is_deterministic(tmp_path):
    a = payload_bytes(collect_all(full_ctx(tmp_path / "a")))
    b = payload_bytes(collect_all(full_ctx(tmp_path / "b")))
    # only `ms` timings may differ between runs
    strip = lambda raw: re.sub(rb'"ms":\d+', b'"ms":0', raw)  # noqa: E731
    assert strip(a) == strip(b)


def test_self_health_reports_every_collector_and_hides_the_machine_id(tmp_path):
    ctx = full_ctx(tmp_path, clock_skew_ms=-42)
    out = collect_all(ctx)
    v = out["sections"]["self"]["v"]
    assert set(v["collectors"]) == {"sshd", "listeners", "firewall", "patch"}
    for name, st in v["collectors"].items():
        assert st["status"] == out["sections"][name]["s"] and isinstance(st["ms"], int)
    assert v["seq"] == 7 and v["key_id"] == "k" * 32 and v["clock_skew_ms"] == -42
    assert v["boot_id"] == "11111111-2222-3333-4444-555555555555" and v["uptime_s"] == 12345
    assert v["caps"] == {"cap_eff": "0000000000081004", "net_admin": True, "sys_ptrace": True,
                         "dac_read_search": True}
    assert v["machine_id_hash"] == health.machine_id_hash(b"salt", RAW_MACHINE_ID)
    assert len(v["machine_id_hash"]) == 64 and v["imds_enabled"] is False
    assert v["payload_bytes"] > 100
    assert RAW_MACHINE_ID not in payload_bytes(out).decode("utf-8")


def test_machine_id_hash_is_salted():
    a = health.machine_id_hash(b"s1", "abc")
    assert a != health.machine_id_hash(b"s2", "abc") != health.machine_id_hash(b"s1", "abd")
    assert a == health.machine_id_hash(b"s1", "abc\n")


def test_self_section_is_sent_even_when_every_collector_fails(tmp_path, monkeypatch):
    def boom(ctx):
        raise RuntimeError(SECRET)
    monkeypatch.setattr(collectors, "_DATA_COLLECTORS",
                        tuple((n, boom) for n, _f in collectors._DATA_COLLECTORS))
    out = collect_all(full_ctx(tmp_path))
    assert set(out["sections"]) == SECTIONS
    for name in ("sshd", "listeners", "firewall", "patch"):
        assert out["sections"][name]["s"] == "error" and out["sections"][name]["reason"] == "exception"
    assert out["sections"]["self"]["s"] == "ok"
    assert out["sections"]["self"]["v"]["collectors"]["sshd"] == {"status": "error", "ms": out[
        "sections"]["self"]["v"]["collectors"]["sshd"]["ms"], "reason": "exception"}
    assert SECRET not in payload_bytes(out).decode("utf-8")   # the exception message is not echoed


def test_one_failing_collector_does_not_stop_the_others(tmp_path, monkeypatch):
    items = list(collectors._DATA_COLLECTORS)
    items[1] = ("listeners", lambda ctx: (_ for _ in ()).throw(ValueError("x")))
    monkeypatch.setattr(collectors, "_DATA_COLLECTORS", tuple(items))
    out = collect_all(full_ctx(tmp_path))
    assert out["sections"]["listeners"]["reason"] == "exception"
    assert out["sections"]["firewall"]["s"] == "ok" and out["sections"]["patch"]["s"] == "ok"


def test_malformed_section_is_an_error_not_passed_through(tmp_path, monkeypatch):
    items = list(collectors._DATA_COLLECTORS)
    items[0] = ("sshd", lambda ctx: {"s": "ok", "v": {}})            # missing conf/partial
    items[1] = ("listeners", lambda ctx: {"s": "ok", "v": {"x": 1.5}, "conf": "exact", "partial": False})
    monkeypatch.setattr(collectors, "_DATA_COLLECTORS", tuple(items))
    out = collect_all(full_ctx(tmp_path))
    assert out["sections"]["sshd"]["s"] == "error" and out["sections"]["listeners"]["s"] == "error"
    payload_bytes(out)  # no float leaked


def test_timeout_is_an_error_section(tmp_path, monkeypatch):
    def slow(ctx):
        raise CollectorTimeout("budget")
    items = list(collectors._DATA_COLLECTORS)
    items[3] = ("patch", slow)
    monkeypatch.setattr(collectors, "_DATA_COLLECTORS", tuple(items))
    out = collect_all(full_ctx(tmp_path))
    assert out["sections"]["patch"]["s"] == "error" and out["sections"]["patch"]["reason"] == "timeout"


def test_exhausted_total_budget_marks_the_rest_as_timeouts(tmp_path):
    ctx = full_ctx(tmp_path, total_budget_s=0)
    out = collect_all(ctx)
    for name in ("sshd", "listeners", "firewall", "patch"):
        assert out["sections"][name]["s"] == "error" and out["sections"][name]["reason"] == "timeout"
    assert out["sections"]["self"]["s"] == "ok"


def test_real_collector_deadline_stops_a_stuck_runner(tmp_path):
    seen = {}

    def slow_runner(argv, timeout, max_bytes):
        seen["timeout"] = timeout
        return res("", timed_out=True, rc=None)
    bins = ["/usr/sbin/nft"]
    ctx = make_ctx(tmp_path, runner=slow_runner, files=host_files(), bins=bins, collector_budget_s=3)
    out = collect_all(ctx)
    assert out["sections"]["firewall"] == {"s": "error", "reason": "timeout", "detail": "nft timed out"}
    assert seen["timeout"] <= 3.01       # a command can never outlive the collector's budget


def test_redaction_nothing_sensitive_leaves_the_host(tmp_path):
    """Command lines, environments, key material and file contents never reach the payload."""
    files = host_files()
    files["/proc/4242/cmdline"] = "/usr/sbin/sshd\0--password=%s\0" % SECRET
    files["/proc/4242/environ"] = "API_KEY=%s\0" % SECRET
    files["/proc/4242/comm"] = "sshd\n"
    files["/root/.ssh/authorized_keys"] = "ssh-ed25519 AAAA%s comment@host\n" % SECRET
    files["/etc/shadow"] = "root:$6$%s:19000::::::\n" % SECRET
    files["/etc/ssh/sshd_config"] = "# %s\nPasswordAuthentication no\nHostKey /etc/ssh/%s\n" % (SECRET, SECRET)
    ctx = full_ctx(tmp_path)
    put(ctx.proc_root, "/4242/cmdline", files["/proc/4242/cmdline"])
    put(ctx.proc_root, "/4242/environ", files["/proc/4242/environ"])
    put(ctx.proc_root, "/4242/comm", files["/proc/4242/comm"])
    put(ctx.host_root, "/root/.ssh/authorized_keys", files["/root/.ssh/authorized_keys"])
    put(ctx.host_root, "/etc/shadow", files["/etc/shadow"])
    put(ctx.host_root, "/etc/ssh/sshd_config", files["/etc/ssh/sshd_config"])
    text = payload_bytes(collect_all(ctx)).decode("utf-8")
    assert SECRET not in text and RAW_MACHINE_ID not in text
    for banned in ("cmdline", "environ", "argv", "ssh-ed25519", "$6$"):
        assert banned not in text.lower().replace("authorizedkeys", "").replace("permituserenvironment", ""), banned


def test_clock_and_version_fields_are_ints_and_strings(tmp_path):
    out = collect_all(full_ctx(tmp_path))
    v = out["sections"]["self"]["v"]
    assert v["agent_version"] == "0.2.0-test" and isinstance(v["python"], str)
    assert v["clock_skew_ms"] is None


@pytest.mark.parametrize("name", ["sshd", "listeners", "firewall", "patch", "self"])
def test_versions_table_matches_sections(name):
    assert collectors.COLLECTOR_VERSIONS[name] == "1" and name in collectors.SECTION_NAMES
