"""Inventory shape + that collection is read-only, host-local and needs no psutil (v1, unsigned path)."""
from __future__ import annotations

import socket

from paddock_agent import inventory

TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 ffff 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 22222 1 ffff 100 0 0 10 0
   2: 0A000001:D431 0A000002:01BB 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 ffff 100 0 0 10 0
garbage line
"""
TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 ffff 100 0 0 10 0
"""
UDP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout ref pointer drops
   5: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 55555 2 ffff 0
"""


def test_no_psutil_or_httpx_dependency_anywhere():
    import ast
    import os
    pkg = os.path.dirname(inventory.__file__)
    for root, _dirs, files in os.walk(pkg):
        for f in files:
            if f.endswith(".py"):
                tree = ast.parse(open(os.path.join(root, f), encoding="utf-8").read())
                for n in ast.walk(tree):
                    mods = []
                    if isinstance(n, ast.Import):
                        mods = [a.name for a in n.names]
                    elif isinstance(n, ast.ImportFrom) and n.module:
                        mods = [n.module]
                    assert not [m for m in mods if m.split(".")[0] in ("psutil", "httpx")], (f, mods)


def test_os_info_shape():
    info = inventory.collect_os_info()
    assert set(info) >= {"system", "release", "hostname", "machine", "python"}
    assert info["hostname"] == socket.gethostname()


def test_parse_proc_net_only_listening_rows():
    rows = inventory.parse_proc_net(TCP, "tcp")
    assert [(r["ip"], r["port"]) for r in rows] == [("0.0.0.0", 22), ("127.0.0.1", 5432)]  # ESTABLISHED row excluded
    rows6 = inventory.parse_proc_net(TCP6, "tcp")
    assert [(r["ip"], r["port"]) for r in rows6] == [("::1", 80)]
    assert inventory.parse_proc_net(UDP, "udp")[0]["port"] == 53


def test_collect_listeners_from_a_fake_proc_with_pids(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(TCP)
    (net / "tcp6").write_text(TCP6)
    (net / "udp").write_text(UDP)
    fd = tmp_path / "4321" / "fd"
    fd.mkdir(parents=True)
    (fd / "3").symlink_to("socket:[11111]")
    (fd / "4").symlink_to("/dev/null")
    rows = inventory.collect_listeners(proc_root=str(tmp_path))
    by_port = {(r["proto"], r["port"]): r for r in rows}
    assert set(by_port) == {("tcp", 22), ("tcp", 5432), ("tcp", 80), ("udp", 53)}
    assert by_port[("tcp", 22)]["pid"] == 4321
    assert by_port[("tcp", 5432)]["pid"] is None
    assert all(set(r) == {"ip", "port", "proto", "pid"} for r in rows)


def test_collect_listeners_missing_proc_is_empty(tmp_path):
    assert inventory.collect_listeners(proc_root=str(tmp_path / "nope")) == []


def test_packages_parse_dpkg():
    def runner(cmd):
        if cmd[:1] == ["dpkg-query"]:
            return "openssl\t3.0.2\nbash\t5.1\n"
        return ""
    pkgs = inventory.collect_packages(runner=runner)
    assert {p["name"] for p in pkgs} == {"openssl", "bash"}
    assert pkgs[0]["manager"] == "dpkg"


def test_packages_fallback_to_rpm():
    def runner(cmd):
        if cmd[:1] == ["rpm"]:
            return "glibc\t2.34\n"
        return ""
    pkgs = inventory.collect_packages(runner=runner)
    assert pkgs == [{"name": "glibc", "version": "2.34", "manager": "rpm"}]


def test_posture_detects_ufw():
    def runner(cmd):
        if cmd[:1] == ["ufw"]:
            return "Status: active\n"
        return ""
    posture = inventory.collect_posture(runner=runner)
    assert posture["firewall"] == "ufw"
    assert posture["ufw_active"] is True


def test_full_inventory_shape(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(TCP)
    inv = inventory.collect_inventory(
        proc_root=str(tmp_path),
        runner=lambda cmd: "Status: active\n" if cmd[:1] == ["ufw"] else "",
        include_packages=False,
    )
    assert set(inv) == {"os_info", "packages", "listeners", "posture"}
    assert inv["packages"] == []
    assert len(inv["listeners"]) == 2


def test_hex_ip_follows_the_host_byte_order(monkeypatch):
    # coll-8: the kernel prints host-endian u32 words; a big-endian host's hex is already network order
    import sys
    monkeypatch.setattr(sys, "byteorder", "little")
    assert inventory._hex_ip("0100007F") == "127.0.0.1"
    assert inventory._hex_ip("0302010A") == "10.1.2.3"
    monkeypatch.setattr(sys, "byteorder", "big")
    assert inventory._hex_ip("7F000001") == "127.0.0.1"          # was 1.0.0.127
    assert inventory._hex_ip("0A010203") == "10.1.2.3"            # was 3.2.1.10
    assert inventory._hex_ip("00000000") == "0.0.0.0"
    assert inventory._hex_ip("00000000000000000000000000000001") == "::1"
    assert inventory._hex_ip("20010DB8000000000000000000000001") == "2001:db8::1"
