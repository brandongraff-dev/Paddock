"""Inventory shape + that collection is read-only and host-local."""
from __future__ import annotations

import socket

from palantir_agent import inventory


class _FakeConn:
    def __init__(self, ip, port, status="LISTEN", kind=socket.SOCK_STREAM, pid=123):
        self.laddr = type("A", (), {"ip": ip, "port": port})()
        self.status = status
        self.type = kind
        self.pid = pid


class _FakePsutil:
    def net_connections(self, kind="inet"):
        return [
            _FakeConn("0.0.0.0", 22),
            _FakeConn("127.0.0.1", 5432),
            _FakeConn("10.0.0.1", 54321, status="ESTABLISHED"),  # not a listener
        ]


def test_os_info_shape():
    info = inventory.collect_os_info()
    assert set(info) >= {"system", "release", "hostname", "machine", "python"}
    assert info["hostname"] == socket.gethostname()


def test_listeners_only_listening_sockets():
    rows = inventory.collect_listeners(psutil_mod=_FakePsutil())
    assert len(rows) == 2                      # the ESTABLISHED one is excluded
    ports = {r["port"] for r in rows}
    assert ports == {22, 5432}
    assert all(r["proto"] == "tcp" for r in rows)


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


def test_full_inventory_shape():
    inv = inventory.collect_inventory(
        psutil_mod=_FakePsutil(),
        runner=lambda cmd: "Status: active\n" if cmd[:1] == ["ufw"] else "",
        include_packages=False,
    )
    assert set(inv) == {"os_info", "packages", "listeners", "posture"}
    assert inv["packages"] == []
    assert len(inv["listeners"]) == 2
