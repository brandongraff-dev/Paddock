# SPDX-License-Identifier: Apache-2.0
"""``udp:<ip>[:port]`` (with TCP fallback on truncation) and ``system`` (the nameservers of resolv.conf).

A plaintext channel cannot vouch for the AD flag, so these resolvers always report ``ad=None``.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import time
from typing import List

from . import doh
from .resolver import DnsAnswer, error_answer


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _udp_exchange(host: str, port: int, query: bytes, qid: int, deadline: float):
    s = socket.socket(_family(host), socket.SOCK_DGRAM)
    try:
        s.connect((host, port))                        # the kernel then drops datagrams from other sources
        s.send(query)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout()
            s.settimeout(left)
            data = s.recv(65535)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                return data
    finally:
        s.close()


def _tcp_exchange(host: str, port: int, query: bytes, deadline: float) -> bytes:
    left = deadline - time.monotonic()
    if left <= 0:
        raise socket.timeout()
    s = socket.create_connection((host, port), timeout=left)
    try:
        s.sendall(struct.pack(">H", len(query)) + query)
        head = _recv_exact(s, 2, deadline)
        size = struct.unpack(">H", head)[0]
        if size > doh.MAX_MESSAGE:
            raise OSError("response over %d bytes" % doh.MAX_MESSAGE)
        return _recv_exact(s, size, deadline)
    finally:
        s.close()


def _recv_exact(s: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout()
        s.settimeout(left)
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


class UdpResolver(object):
    network = True

    def __init__(self, host: str, port: int = 53) -> None:
        ipaddress.ip_address(host)                     # ValueError for anything but an IP literal
        if not 1 <= port <= 65535:
            raise ValueError("bad port")
        self.host, self.port = host, port
        self.name = "udp:%s:%d" % (("[%s]" % host) if ":" in host else host, port)

    def resolve_txt(self, qname: str, timeout: float) -> DnsAnswer:
        try:
            qid = secrets.randbelow(65535) + 1
            query = doh.build_query(qname, doh.TYPE_TXT, qid)
        except ValueError:
            return error_answer(self.name)
        deadline = time.monotonic() + max(0.05, float(timeout))
        try:
            data = _udp_exchange(self.host, self.port, query, qid, deadline)
            ans = doh.parse_response(data, qid, qname, self.name)
            if ans.truncated:
                data = _tcp_exchange(self.host, self.port, query, deadline)
                ans = doh.parse_response(data, qid, qname, self.name)
        except (socket.timeout, TimeoutError):
            return DnsAnswer("timeout", [], None, self.name)
        except Exception:
            return error_answer(self.name)
        return ans._replace(ad=None) if ans.status != "error" else ans


def read_nameservers(path: str = "/etc/resolv.conf") -> List[str]:
    out = []  # type: List[str]
    try:
        with open(path, "r", encoding="ascii", errors="replace") as fh:
            for line in fh.read(65536).splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    out.append(parts[1])
    except OSError:
        return []
    return out


class SystemResolver(object):
    network = True
    name = "system"

    def __init__(self, resolv_conf: str = "/etc/resolv.conf") -> None:
        self._conf = resolv_conf

    def resolve_txt(self, qname: str, timeout: float) -> DnsAnswer:
        servers = read_nameservers(self._conf)
        if not servers:
            return error_answer(self.name)
        last = error_answer(self.name)
        for host in servers[:3]:
            ans = UdpResolver(host, 53).resolve_txt(qname, timeout)
            if ans.status in ("ok", "nxdomain", "nodata"):
                return ans._replace(source=self.name)
            last = ans._replace(source=self.name)
        return last
