"""Port scan via naabu (ProjectDiscovery).

Polite defaults: ``-rate 100 -c 25``. Default port set is ``top-100``.
Falls back to a ``tool_unavailable`` finding if the binary is missing.

The summary is the contract with the assurance ``external_exposure`` builder (docs/ASSURANCE_P1.md
4.2): ``ports_scanned``, ``tool_exit_ok`` and (added by the worker once every bulk post succeeded)
``results_posted``. Any tool failure fails the scan instead of completing it.
"""
from __future__ import annotations

import ipaddress
import json
import time
from typing import Any

import structlog

from app.config import settings
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeDenied, ScopeGuard, normalize_target
from app.util import runner
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


_SERVICE_BY_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    3306: "mysql", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


_RATE = 100          # naabu -rate: packets/sec, the polite default (never raised here)
_FULL_PORTS = 65535
_TIMEOUT_SLACK_SEC = 60


def _port_count(spec: str) -> int:
    """How many ports ``spec`` names; unknown specs count as a full scan (the conservative estimate)."""
    s = (spec or "").strip().lower()
    if s.startswith("top-") and s[4:].isdigit():
        return int(s[4:])
    n = _count_ranges(s)
    return n if n is not None else _FULL_PORTS


def _count_ranges(s: str) -> int | None:
    intervals = _intervals(s)
    if intervals is None:
        return None
    return sum(hi - lo + 1 for lo, hi in intervals)


def _intervals(s: str) -> list[tuple[int, int]] | None:
    """Merged inclusive intervals for ``22,80,1000-2000`` or ``full``; ``None`` for anything else."""
    if s == "full":
        return [(1, _FULL_PORTS)]
    items: list[tuple[int, int]] = []
    for part in s.split(","):
        a, sep, b = part.strip().partition("-")
        try:
            lo = int(a)
            hi = int(b) if sep else lo
        except ValueError:
            return None
        if not 1 <= lo <= hi <= _FULL_PORTS:
            return None
        items.append((lo, hi))
    if not items:
        return None
    merged: list[list[int]] = []
    for lo, hi in sorted(items):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(a, b) for a, b in merged]


def ports_marker(spec: str) -> str:
    """The ``ports_scanned`` coverage marker: ``"1-65535"`` iff the spec is exactly every TCP port.

    Anything else is recorded as given (``top-100``, ``22,443``...). The assurance builder asserts
    coverage only for the literal full range, so the marker must never say more than was scanned.
    """
    s = (spec or "").strip().lower()
    return "1-65535" if _intervals(s) == [(1, _FULL_PORTS)] else (s or "top-100")


def naabu_needed_sec(ports: str) -> int:
    """Seconds naabu needs for ``ports`` at the polite rate, with 50% headroom and fixed slack."""
    return int(_port_count(ports) / _RATE * 1.5) + _TIMEOUT_SLACK_SEC


def naabu_timeout_sec(ports: str) -> int:
    """Subprocess budget: at least the configured timeout, and enough for ``ports`` at ``-rate 100``.

    At the polite rate a full 65535-port scan needs ~655 s, over the 600 s default; a timeout is
    now a failed scan (never coverage), so without this a full scan could never succeed.
    """
    return max(int(settings.subprocess_timeout_sec), naabu_needed_sec(ports))


def _target_ident(target: str) -> tuple[str, str]:
    """``(exact lower-cased IP literal, asset kind)``; the full literal, never ``_host_of``'s split.

    ``_host_of('2606:4700::1111')`` is ``'2606'``, which mis-keyed the tool-failure findings for IPv6
    (builders-2). Non-IP targets fall back to ``_host_of`` and kind ``ipv4`` as before.
    """
    t = target.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return _host_of(target), "ipv4"
    return str(ip), "ipv6" if ip.version == 6 else "ipv4"


def _failed(spec: str, reason: str, findings: list[dict]) -> dict[str, Any]:
    """A scan that did not run to completion: markers say so; the worker fails the scan on it."""
    return {"assets": [], "edges": [], "findings": findings, "summary": {
        "ports": 0, "ports_scanned": ports_marker(spec), "tool_exit_ok": False, "tool_error": reason}}


async def scan(
    target_ip: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    ports: str = "top-100",
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Run naabu. The summary carries the coverage markers the assurance builder reads:
    ``ports_scanned`` (the spec actually scanned), ``tool_exit_ok`` (naabu exited 0 and its output
    parsed cleanly). ``results_posted`` is added by the worker only after every bulk post is 2xx.
    A tool failure returns ``tool_exit_ok: False`` and the worker FAILS the scan (never completes it).
    """
    await scope.allow(target_ip)
    ident, ip_kind = _target_ident(target_ip)
    host = ident
    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []

    args = [
        "-host", target_ip,
        "-p", ports,
        "-rate", str(_RATE),
        "-c", "25",
        "-json",
        "-silent",
        "-stats-interval", "0",
    ]

    t0 = time.monotonic()
    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            result = await runner.run(
                "naabu", args, timeout=naabu_timeout_sec(ports),
            )
    except runner.ToolUnavailable:
        return _failed(ports, "naabu is not installed on this worker",
                       [_tool_missing_finding(ident, ip_kind, "naabu")])
    except runner.ToolTimeout as e:
        await orchestrator.outbound_log(new_outbound_row(
            target=target_ip, tool="naabu",
            request_summary=" ".join(args), error=f"timeout {e.timeout}s",
            scope_matched=True,
        ))
        msg = f"timeout after {e.timeout}s"
        return _failed(ports, msg, [_tool_error_finding(ident, ip_kind, "naabu", msg)])
    except runner.ToolFailed as e:
        # Fail closed: a non-zero exit used to be read as "no open ports" and the scan completed.
        # An earlier naabu may exit non-zero on an empty result; we cannot tell that from a crash,
        # so the scan fails and the host simply gets no full-scan coverage.
        log.warning("naabu.nonzero", returncode=e.returncode, stderr=e.stderr[:200])
        msg = f"naabu exited {e.returncode}: {e.stderr[:200]}"
        return _failed(ports, msg, [_tool_error_finding(ident, ip_kind, "naabu", msg)])
    duration_ms = int((time.monotonic() - t0) * 1000)

    await orchestrator.outbound_log(new_outbound_row(
        target=target_ip, tool="naabu",
        request_summary=" ".join(args), duration_ms=duration_ms,
        response_code=None, scope_matched=True,
    ))

    ip_canonical = normalize_target(target_ip)
    assets.append({
        "kind": ip_kind,
        "value": target_ip,
        "canonical": ip_canonical,
        "source": "port_scan",
        "metadata": {},
    })

    open_ports: list[int] = []
    malformed = 0
    for line in result.lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(obj, dict):
            malformed += 1
            continue
        port = obj.get("port")
        row_host = obj.get("host") or obj.get("ip") or target_ip
        # Filter output: drop any row for a host that has fallen out of scope.
        try:
            await scope.allow(row_host)
        except ScopeDenied:
            log.warning("naabu.drop_out_of_scope", host=row_host, port=port)
            continue
        if not isinstance(port, int) or isinstance(port, bool):
            malformed += 1
            continue
        open_ports.append(port)
        port_value = f"{row_host}:{port}"
        assets.append({
            "kind": "port",
            "value": port_value,
            "canonical": port_value.lower(),
            "source": "port_scan",
            "metadata": {"port": port, "protocol": obj.get("protocol", "tcp")},
        })
        edges.append({
            "src_kind": ip_kind, "src_canonical": ip_canonical,
            "dst_kind": "port", "dst_canonical": port_value.lower(),
            "kind": "hosts",
        })
        svc = _SERVICE_BY_PORT.get(port)
        if svc:
            svc_canonical = f"{port_value}/{svc}".lower()
            assets.append({
                "kind": "service",
                "value": f"{port_value}/{svc}",
                "canonical": svc_canonical,
                "source": "port_scan",
                "metadata": {"guessed_from": "port_number", "service": svc},
            })
            edges.append({
                "src_kind": "port", "src_canonical": port_value.lower(),
                "dst_kind": "service", "dst_canonical": svc_canonical,
                "kind": "runs",
            })

    if malformed:
        # Output we could not read may hide open ports: never let it back a "scanned everything" claim.
        msg = f"naabu output had {malformed} unreadable line(s)"
        out = _failed(ports, msg, findings + [_tool_error_finding(ident, ip_kind, "naabu", msg)])
        out["assets"], out["edges"] = assets, edges
        out["summary"]["ports"] = len(open_ports)
        out["summary"]["open_ports"] = open_ports
        return out
    return {
        "assets": assets, "edges": edges, "findings": findings,
        "summary": {"ports": len(open_ports), "open_ports": open_ports,
                    "ports_scanned": ports_marker(ports), "tool_exit_ok": True},
    }


def _tool_missing_finding(host: str, kind: str, tool: str) -> dict:
    return {
        "target_host": host,
        "target_canonical": host,
        "target_kind": kind,
        "rule_id": f"tool-unavailable-{tool}",
        "rule_source": "policy",
        "severity": "info",
        "title": f"{tool} is not installed on this worker",
        "description": f"The {tool} binary is not on PATH; this scan was skipped.",
        "remediation": f"Install {tool} in the worker image and re-run.",
        "evidence": {"tool": tool},
    }


def _tool_error_finding(host: str, kind: str, tool: str, msg: str) -> dict:
    return {
        "target_host": host,
        "target_canonical": host,
        "target_kind": kind,
        "rule_id": f"tool-error-{tool}",
        "rule_source": "policy",
        "severity": "info",
        "title": f"{tool} failed to complete",
        "description": msg,
        "evidence": {"tool": tool, "error": msg},
    }
