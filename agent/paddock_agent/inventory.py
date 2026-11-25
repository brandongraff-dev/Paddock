"""Best-effort host inventory collection: the v1, UNSIGNED path.

Returns a dict shaped for ``POST /v1/fleet/{id}/inventory``:
    {os_info, packages, listeners, posture}

This feeds the Fleet page only. The server marks it ``unsigned`` and it is never evidence
(docs/ASSURANCE_P2.md section 2); the signed posture envelope is what invariants read.

Everything is best-effort and read-only and uses the standard library only (owner decision O1):
listening sockets are parsed from ``/proc/net/{tcp,tcp6,udp,udp6}`` (no ``psutil``), packages and
firewall posture come from read-only tool output. None of it reaches off the host.
"""
from __future__ import annotations

import os
import platform as _platform
import socket
import subprocess
from typing import Any, Callable, Dict, List, Optional

Runner = Callable[[List[str]], str]

MAX_LISTENERS = 2000
_TCP_LISTEN = "0A"
_UDP_BOUND = "07"


def _safe_run(cmd: List[str], timeout: int = 8) -> str:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,  # noqa: S603
                             stdin=subprocess.DEVNULL, env=env)
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_os_info() -> Dict[str, Any]:
    uname = _platform.uname()
    return {
        "system": uname.system,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "hostname": socket.gethostname(),
        "python": _platform.python_version(),
    }


# --------------------------------------------------------------------------- #
# listeners from /proc
# --------------------------------------------------------------------------- #

def _hex_ip(hexaddr: str) -> Optional[str]:
    """/proc/net addresses are the in-memory (little-endian per 32-bit word) hex of the address."""
    try:
        raw = bytes.fromhex(hexaddr)
    except ValueError:
        return None
    if len(raw) not in (4, 16):
        return None
    words = [raw[i:i + 4][::-1] for i in range(0, len(raw), 4)]
    packed = b"".join(words)
    try:
        return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, packed)
    except (OSError, ValueError):
        return None


def parse_proc_net(text: str, proto: str) -> List[Dict[str, Any]]:
    """Listening (TCP ``0A``) / bound (UDP ``07``) rows of one /proc/net table. Pure; skips junk lines."""
    want = _TCP_LISTEN if proto == "tcp" else _UDP_BOUND
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] != want:
            continue
        addr, _, port_hex = parts[1].rpartition(":")
        ip = _hex_ip(addr)
        try:
            port = int(port_hex, 16)
            inode = int(parts[9])
        except ValueError:
            continue
        if ip is None:
            continue
        rows.append({"ip": ip, "port": port, "proto": proto, "inode": inode})
    return rows


def _inode_to_pid(proc_root: str) -> Dict[int, int]:
    mapping: Dict[int, int] = {}
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        return mapping
    for pid in pids:
        fd_dir = os.path.join(proc_root, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:[") and link.endswith("]"):
                try:
                    mapping.setdefault(int(link[8:-1]), int(pid))
                except ValueError:
                    pass
    return mapping


def collect_listeners(proc_root: str = "/proc") -> List[Dict[str, Any]]:
    """Listening sockets on the local host from /proc (the pid is best effort and needs privilege)."""
    rows: List[Dict[str, Any]] = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(os.path.join(proc_root, "net", name), "r", encoding="utf-8", errors="replace") as fh:
                rows.extend(parse_proc_net(fh.read(4 * 1024 * 1024), proto))
        except OSError:
            continue
    pids = _inode_to_pid(proc_root) if rows else {}
    out = []
    for r in sorted(rows, key=lambda r: (r["proto"], r["port"], r["ip"]))[:MAX_LISTENERS]:
        out.append({"ip": r["ip"], "port": r["port"], "proto": r["proto"], "pid": pids.get(r["inode"])})
    return out


# --------------------------------------------------------------------------- #
# packages, posture
# --------------------------------------------------------------------------- #

def collect_packages(runner: Runner = _safe_run, limit: int = 2000) -> List[Dict[str, Any]]:
    """Best-effort installed-package list (dpkg, then rpm). Empty if neither."""
    out = runner(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    manager = "dpkg"
    if not out:
        out = runner(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"])
        manager = "rpm"
    if not out:
        return []
    pkgs: List[Dict[str, Any]] = []
    for line in out.splitlines()[:limit]:
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        pkgs.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "", "manager": manager})
    return pkgs


def collect_posture(runner: Runner = _safe_run) -> Dict[str, Any]:
    """Host firewall posture (read-only)."""
    posture: Dict[str, Any] = {"firewall": "unknown"}
    ufw = runner(["ufw", "status"])
    if ufw:
        posture["firewall"] = "ufw"
        posture["ufw_active"] = "Status: active" in ufw
        return posture
    nft = runner(["nft", "list", "ruleset"])
    if nft:
        posture["firewall"] = "nftables"
        posture["has_rules"] = bool(nft.strip())
        return posture
    ipt = runner(["iptables", "-S"])
    if ipt:
        posture["firewall"] = "iptables"
        posture["rule_count"] = len([ln for ln in ipt.splitlines() if ln.startswith("-A")])
    return posture


def collect_inventory(
    *,
    proc_root: str = "/proc",
    runner: Runner = _safe_run,
    include_packages: bool = True,
) -> Dict[str, Any]:
    return {
        "os_info": collect_os_info(),
        "packages": collect_packages(runner) if include_packages else [],
        "listeners": collect_listeners(proc_root),
        "posture": collect_posture(runner),
    }
