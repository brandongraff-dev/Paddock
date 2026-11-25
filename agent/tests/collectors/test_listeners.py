import hashlib
import ipaddress
import os

import pytest

from paddock_agent.collectors import base, listeners, payload_bytes

from .helpers import fixture, make_ctx, put

U = "ubuntu2404/"
HDR6 = ("  sl  local_address                         remote_address                        st "
        "tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")


def enc6(ip):
    packed = ipaddress.IPv6Address(ip).packed
    return "".join(packed[i:i + 4][::-1].hex().upper() for i in range(0, 16, 4))


def line6(n, ip, port, inode, uid=0, state="0A", rip="::", rport=0):
    return "  %d: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n" % (
        n, enc6(ip), port, enc6(rip), rport, state, uid, inode)


def line4(n, hexip, port, inode, uid=0, state="0A", rhex="00000000", rport=0):
    return "   %d: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n" % (
        n, hexip, port, rhex, rport, state, uid, inode)


def test_decode_addr():
    assert listeners.decode_addr("0100007F") == ("127.0.0.1", 4)
    assert listeners.decode_addr("00000000") == ("0.0.0.0", 4)
    assert listeners.decode_addr("020200C0") == ("192.0.2.2", 4)
    assert listeners.decode_addr(enc6("::1")) == ("::1", 6)
    assert listeners.decode_addr(enc6("::")) == ("::", 6)
    assert listeners.decode_addr(enc6("fe80::1234")) == ("fe80::1234", 6)
    assert listeners.decode_addr(enc6("::ffff:10.1.2.3")) == ("10.1.2.3", 4)
    with pytest.raises(ValueError):
        listeners.decode_addr("0102")


def test_real_capture_listen_rows_only():
    rows, bad = listeners.parse_proc_net(fixture(U + "proc_net_tcp.container.txt"), "tcp", 4)
    assert bad == 0
    got = [(r["ip"], r["port"], r["uid"], r["bind_class"]) for r in rows]
    assert got == [("0.0.0.0", 2024, 0, "wildcard4"), ("127.0.0.1", 39423, 0, "loopback"),
                   ("127.0.0.1", 39845, 0, "loopback"), ("127.0.0.1", 5432, 102, "loopback"),
                   ("127.0.0.1", 5433, 102, "loopback")]
    assert [r["inode"] for r in rows][:2] == [1921, 55]
    assert listeners.parse_proc_net(fixture(U + "proc_net_udp.container.txt"), "udp", 4) == ([], 0)


def test_tcp6_and_mapped_and_udp_rules():
    t6 = (HDR6 + line6(0, "::", 22, 10) + line6(1, "::1", 8080, 11, uid=1000)
          + line6(2, "::ffff:127.0.0.1", 80, 12) + line6(3, "fe80::1", 443, 13)
          + line6(4, "::", 9, 14, state="01", rip="2001:db8::1", rport=5000))
    rows, bad = listeners.parse_proc_net(t6, "tcp", 6)
    assert bad == 0
    assert [(r["ip"], r["port"], r["bind_class"], r["fam"]) for r in rows] == [
        ("::", 22, "wildcard6", 6), ("::1", 8080, "loopback", 6),
        ("127.0.0.1", 80, "loopback", 4), ("fe80::1", 443, "specific", 6)]
    udp = ("  sl  local_address rem_address   st\n" + line4(0, "00000000", 68, 20, state="07")
           + line4(1, "0100007F", 5353, 21, state="01", rhex="0100007F", rport=9)
           + line4(2, "00000000", 123, 22, state="07", rhex="0100007F", rport=9)
           + line4(3, "0100007F", 323, 23, state="07"))
    rows, _ = listeners.parse_proc_net(udp, "udp", 4)
    assert [r["port"] for r in rows] == [68, 323]


def test_garbage_lines_are_counted():
    txt = "  sl  local_address\n   0: 00000000:0016 00000000:0000 0A\nnot a line at all\n" + line4(2, "00000000", 80, 5)
    rows, bad = listeners.parse_proc_net(txt, "tcp", 4)
    assert len(rows) == 1 and bad == 2


@pytest.mark.parametrize("text,unit,container", [
    ("0::/system.slice/ssh.service\n", "ssh.service", None),
    ("0::/system.slice/docker-" + "ab" * 32 + ".scope\n", None, "abababababab"),
    ("12:cpu:/docker/" + "cd" * 32 + "\n0::/\n", None, "cdcdcdcdcdcd"),
    ("1:name=systemd:/kubepods/burstable/pod123/" + "ef" * 32 + "\n", None, "efefefefefef"),
    ("0::/user.slice/user-1000.slice/session-3.scope\n", "session-3.scope", None),
    ("0::/\n", None, None),
    ("", None, None),
    ("0::/system.slice/we ird$.service\n", None, None),
])
def test_parse_cgroup(text, unit, container):
    assert listeners.parse_cgroup(text) == (unit, container)


# ------------------------------------------------------------------- collector
def fake_proc(tmp_path, tcp=None, tcp6=None, udp=None, procs=None, extra=None):
    files = {"/proc/net/tcp": tcp if tcp is not None else fixture(U + "proc_net_tcp.container.txt"),
             "/proc/net/udp": udp if udp is not None else fixture(U + "proc_net_udp.container.txt")}
    if tcp6 is not None:
        files["/proc/net/tcp6"] = tcp6
    files.update(extra or {})
    ctx = make_ctx(tmp_path, files=files)
    for pid, spec in (procs or {}).items():
        d = os.path.join(ctx.proc_root, str(pid))
        os.makedirs(os.path.join(d, "fd"), exist_ok=True)
        for i, inode in enumerate(spec.get("sockets", [])):
            os.symlink("socket:[%d]" % inode, os.path.join(d, "fd", str(3 + i)))
        if "exe" in spec:
            os.symlink(spec["exe"], os.path.join(d, "exe"))
        put(d, "comm", spec.get("comm", "prog") + "\n")
        put(d, "cgroup", spec.get("cgroup", "0::/\n"))
        put(d, "cmdline", spec.get("cmdline", "prog\0--password=hunter2\0"))
        put(d, "environ", "SECRET_TOKEN=abc123\0")
    return ctx


def test_collect_with_attribution_and_redaction(tmp_path):
    exe = tmp_path / "bin" / "postgres"
    exe.parent.mkdir()
    exe.write_bytes(b"\x7fELF fake postgres")
    ctx = fake_proc(tmp_path / "t", procs={
        4242: {"sockets": [897, 1921], "exe": str(exe), "comm": "postgres",
               "cgroup": "0::/system.slice/postgresql.service\n"},
        4300: {"sockets": [897], "exe": str(exe), "comm": "postgres"},
        4400: {"sockets": [], "exe": "/gone (deleted)", "comm": "other"}})
    sec = listeners.collect(ctx)
    base.validate_section(sec)
    assert sec["s"] == "ok" and sec["conf"] == "exact" and sec["partial"] is False
    v = sec["v"]
    by_port = {l["port"]: l for l in v["listeners"]}
    assert by_port[5432]["pid"] == 4242  # lowest pid of the owners
    pgw = [l for l in v["listeners"] if l["pid"] == 4242]
    assert {l["port"] for l in pgw} == {5432, 2024}
    for l in pgw:
        assert l["exe"] == str(exe) and l["exe_sha256"] == hashlib.sha256(b"\x7fELF fake postgres").hexdigest()
        assert l["comm"] == "postgres" and l["unit"] == "postgresql.service" and l["exe_deleted"] is False
    assert [l for l in v["listeners"] if l["port"] == 2024][0]["n_pids"] == 1
    assert [l for l in v["listeners"] if l["port"] == 5432][0]["n_pids"] == 2
    assert v["attribution"]["status"] == "partial" and v["attribution"]["unattributed"] == 3
    assert v["ipv6"] is False and v["count"] == 5
    blob = payload_bytes(sec).decode()
    for secret in ("hunter2", "SECRET_TOKEN", "abc123", "--password"):
        assert secret not in blob


def test_deleted_executable_is_flagged(tmp_path):
    ctx = fake_proc(tmp_path, procs={77: {"sockets": [1921], "exe": "/usr/bin/old-daemon (deleted)"}})
    l = [x for x in listeners.collect(ctx)["v"]["listeners"] if x["port"] == 2024][0]
    assert l["exe"] == "/usr/bin/old-daemon" and l["exe_deleted"] is True and l["exe_sha256"] is None


def test_reuseport_sockets_are_deduplicated(tmp_path):
    tcp = ("  sl  local_address rem_address   st\n" + line4(0, "00000000", 80, 501)
           + line4(1, "00000000", 80, 502) + line4(2, "00000000", 80, 503))
    ctx = fake_proc(tmp_path, tcp=tcp, procs={10: {"sockets": [501]}, 11: {"sockets": [502]}, 12: {"sockets": [503]}})
    v = listeners.collect(ctx)["v"]
    assert v["count"] == 1 and v["listeners"][0]["n_pids"] == 3 and v["listeners"][0]["pid"] == 10


def test_no_attribution_is_reported_not_hidden(tmp_path):
    ctx = fake_proc(tmp_path)
    ctx._is_root = False
    v = listeners.collect(ctx)["v"]
    assert v["count"] == 5 and v["attribution"] == {"status": "denied", "unreadable_pids": 0, "unattributed": 5}
    assert all(l["pid"] is None and l["exe"] is None for l in v["listeners"])


def test_unreadable_pid_dirs_are_counted(tmp_path, monkeypatch):
    ctx = fake_proc(tmp_path, procs={5: {"sockets": [1921]}, 6: {"sockets": [897]}})
    real = ctx.listdir

    def listdir(path):
        if path == "/proc/5/fd":
            return "denied", []
        return real(path)
    monkeypatch.setattr(ctx, "listdir", listdir)
    v = listeners.collect(ctx)["v"]
    assert v["attribution"]["unreadable_pids"] == 1 and v["attribution"]["status"] == "partial"
    assert [l for l in v["listeners"] if l["port"] == 2024][0]["pid"] is None


def test_ipv6_present_and_bindv6only(tmp_path):
    t6 = HDR6 + line6(0, "::", 22, 90) + line6(1, "::1", 631, 91)
    ctx = fake_proc(tmp_path, tcp6=t6, extra={"/proc/sys/net/ipv6/bindv6only": "0\n"})
    v = listeners.collect(ctx)["v"]
    assert v["ipv6"] is True and v["bindv6only"] == 0
    assert {l["bind_class"] for l in v["listeners"]} == {"wildcard4", "loopback", "wildcard6"}
    assert listeners.collect(fake_proc(tmp_path / "x"))["v"]["bindv6only"] is None


def test_missing_and_denied_tables_are_not_empty_listener_lists(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path / "a")
    assert listeners.collect(ctx) == {"s": "unavailable", "reason": "unsupported_platform"}
    ctx = fake_proc(tmp_path / "b")
    real = ctx.read_bytes
    monkeypatch.setattr(ctx, "read_bytes", lambda p, m=1 << 20: ("denied", b"") if p.endswith("/net/tcp") else real(p, m))
    assert listeners.collect(ctx) == {"s": "unavailable", "reason": "permission_denied"}
    ctx = fake_proc(tmp_path / "c")
    monkeypatch.setattr(ctx, "read_bytes", lambda p, m=1 << 20: ("error", b""))
    assert listeners.collect(ctx)["s"] == "error"


def test_bad_lines_make_the_table_partial(tmp_path):
    tcp = fixture(U + "proc_net_tcp.container.txt") + "garbage line\n"
    sec = listeners.collect(fake_proc(tmp_path, tcp=tcp))
    assert sec["s"] == "ok" and sec["partial"] is True


def test_missing_udp_table_is_partial(tmp_path):
    ctx = make_ctx(tmp_path, files={"/proc/net/tcp": fixture(U + "proc_net_tcp.container.txt")})
    sec = listeners.collect(ctx)
    assert sec["s"] == "ok" and sec["partial"] is True


def test_cap_over_2000_is_truncated_error_not_a_silent_cut(tmp_path):
    tcp = "  sl  local_address rem_address   st\n" + "".join(
        line4(i, "00000000", 1 + i, 1000 + i) for i in range(2001))
    sec = listeners.collect(fake_proc(tmp_path, tcp=tcp))
    assert sec["s"] == "error" and sec["reason"] == "truncated"
    tcp = "  sl  local_address rem_address   st\n" + "".join(
        line4(i, "00000000", 1 + i, 1000 + i) for i in range(2000))
    assert listeners.collect(fake_proc(tmp_path / "ok", tcp=tcp))["v"]["count"] == 2000


def test_containerised_agent_is_unavailable(tmp_path):
    ctx = fake_proc(tmp_path)
    ctx._containerised = True
    assert listeners.collect(ctx) == {"s": "unavailable", "reason": "containerised_agent"}


def test_exe_hash_is_cached_by_dev_inode_mtime(tmp_path, monkeypatch):
    exe = tmp_path / "prog"
    exe.write_bytes(b"abc")
    listeners._HASH_CACHE.clear()
    ctx = fake_proc(tmp_path / "t", procs={9: {"sockets": [1921], "exe": str(exe)}})
    calls = []
    real = ctx.sha256_file
    monkeypatch.setattr(ctx, "sha256_file", lambda p, m=0: calls.append(p) or real(p, m or 1 << 27))
    listeners.collect(ctx)
    listeners.collect(ctx)
    assert len(calls) == 1
    exe.write_bytes(b"abcd")  # size/mtime change invalidates
    listeners.collect(ctx)
    assert len(calls) == 2


def test_oversized_executable_is_not_hashed(tmp_path, monkeypatch):
    exe = tmp_path / "big"
    exe.write_bytes(b"x")
    listeners._HASH_CACHE.clear()
    ctx = fake_proc(tmp_path / "t", procs={9: {"sockets": [1921], "exe": str(exe)}})
    monkeypatch.setattr(listeners, "EXE_HASH_CAP", 0)
    l = [x for x in listeners.collect(ctx)["v"]["listeners"] if x["port"] == 2024][0]
    assert l["exe"] == str(exe) and l["exe_sha256"] is None


def test_deterministic_and_sorted(tmp_path):
    a = payload_bytes(listeners.collect(fake_proc(tmp_path / "a")))
    b = payload_bytes(listeners.collect(fake_proc(tmp_path / "b")))
    assert a == b
    ports = [l["port"] for l in listeners.collect(fake_proc(tmp_path / "c"))["v"]["listeners"]]
    assert ports == sorted(ports)
