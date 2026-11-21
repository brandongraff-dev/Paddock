"""Best-effort host inventory collection.

Returns a dict shaped for ``POST /v1/fleet/{id}/inventory``:
    {os_info, packages, listeners, posture}

Everything is best-effort and read-only: listing ports, reading os-release,
asking the package manager what is installed, and checking firewall posture.
None of it reaches off the host. ``psutil`` and the subprocess probes are all
optional/injectable so this stays unit-testable without them.
"""
from __future__ import annotations

import platform as _platform
import socket
import subprocess
from typing import Any, Callable

Runner = Callable[[list[str]], str]


def _safe_run(cmd: list[str], timeout: int = 8) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_os_info() -> dict[str, Any]:
    uname = _platform.uname()
    return {
        "system": uname.system,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "hostname": socket.gethostname(),
        "python": _platform.python_version(),
    }


def collect_listeners(psutil_mod: Any | None = None) -> list[dict[str, Any]]:
    """Listening sockets on the local host, via psutil when available."""
    if psutil_mod is None:
        try:
            import psutil as psutil_mod  # type: ignore
        except Exception:  # noqa: BLE001
            return []
    listeners: list[dict[str, Any]] = []
    try:
        conns = psutil_mod.net_connections(kind="inet")
    except Exception:  # noqa: BLE001 -- needs privilege on some OSes
        return []
    for c in conns:
        if getattr(c, "status", None) != "LISTEN":
            continue
        laddr = getattr(c, "laddr", None)
        ip = getattr(laddr, "ip", None) if laddr else None
        port = getattr(laddr, "port", None) if laddr else None
        listeners.append({
            "ip": ip,
            "port": port,
            "proto": "tcp" if getattr(c, "type", None) == socket.SOCK_STREAM else "udp",
            "pid": getattr(c, "pid", None),
        })
    return listeners


def collect_packages(runner: Runner = _safe_run, limit: int = 2000) -> list[dict[str, Any]]:
    """Best-effort installed-package list (dpkg, then rpm). Empty if neither."""
    out = runner(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    manager = "dpkg"
    if not out:
        out = runner(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"])
        manager = "rpm"
    if not out:
        return []
    pkgs: list[dict[str, Any]] = []
    for line in out.splitlines()[:limit]:
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        pkgs.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "", "manager": manager})
    return pkgs


def collect_posture(runner: Runner = _safe_run) -> dict[str, Any]:
    """Host firewall posture (read-only)."""
    posture: dict[str, Any] = {"firewall": "unknown"}
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
        posture["rule_count"] = len([l for l in ipt.splitlines() if l.startswith("-A")])
    return posture


def collect_inventory(
    *,
    psutil_mod: Any | None = None,
    runner: Runner = _safe_run,
    include_packages: bool = True,
) -> dict[str, Any]:
    return {
        "os_info": collect_os_info(),
        "packages": collect_packages(runner) if include_packages else [],
        "listeners": collect_listeners(psutil_mod),
        "posture": collect_posture(runner),
    }
