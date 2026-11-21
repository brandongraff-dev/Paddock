"""Port scan via naabu (ProjectDiscovery).

Polite defaults: ``-rate 100 -c 25``. Default port set is ``top-100``.
Falls back to a ``tool_unavailable`` finding if the binary is missing.
"""
from __future__ import annotations

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


async def scan(
    target_ip: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    ports: str = "top-100",
    scan_id: str | None = None,
) -> dict[str, Any]:
    await scope.allow(target_ip)
    host = _host_of(target_ip)
    assets: list[dict] = []
    edges: list[dict] = []
    findings: list[dict] = []

    args = [
        "-host", target_ip,
        "-p", ports,
        "-rate", "100",
        "-c", "25",
        "-json",
        "-silent",
        "-stats-interval", "0",
    ]

    try:
        async with politeness.acquire(host):
            t0 = time.monotonic()
            result = await runner.run(
                "naabu", args, timeout=settings.subprocess_timeout_sec,
            )
    except runner.ToolUnavailable:
        findings.append(_tool_missing_finding(host, "naabu"))
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"ports": 0}}
    except runner.ToolTimeout as e:
        await orchestrator.outbound_log(new_outbound_row(
            target=target_ip, tool="naabu",
            request_summary=" ".join(args), error=f"timeout {e.timeout}s",
            scope_matched=True,
        ))
        findings.append(_tool_error_finding(host, "naabu", f"timeout after {e.timeout}s"))
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"ports": 0}}
    except runner.ToolFailed as e:
        # Some naabu versions exit non-zero when no ports found.
        log.info("naabu.nonzero", returncode=e.returncode, stderr=e.stderr[:200])
        result = None
    else:
        pass
    duration_ms = int((time.monotonic() - t0) * 1000) if result else None
    if result is None:
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {"ports": 0}}

    await orchestrator.outbound_log(new_outbound_row(
        target=target_ip, tool="naabu",
        request_summary=" ".join(args), duration_ms=duration_ms,
        response_code=None, scope_matched=True,
    ))

    ip_canonical = normalize_target(target_ip)
    ip_kind = "ipv4"  # port_scan expects an IP; v6 gets the same kind label in metadata.
    assets.append({
        "kind": ip_kind,
        "value": target_ip,
        "canonical": ip_canonical,
        "source": "port_scan",
        "metadata": {},
    })

    open_ports: list[int] = []
    for line in result.lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        port = obj.get("port")
        row_host = obj.get("host") or obj.get("ip") or target_ip
        # Filter output: drop any row for a host that has fallen out of scope.
        try:
            await scope.allow(row_host)
        except ScopeDenied:
            log.warning("naabu.drop_out_of_scope", host=row_host, port=port)
            continue
        if not isinstance(port, int):
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

    return {
        "assets": assets, "edges": edges, "findings": findings,
        "summary": {"ports": len(open_ports), "open_ports": open_ports},
    }


def _tool_missing_finding(host: str, tool: str) -> dict:
    return {
        "target_host": host,
        "target_canonical": host,
        "target_kind": "ipv4",
        "rule_id": f"tool-unavailable-{tool}",
        "rule_source": "policy",
        "severity": "info",
        "title": f"{tool} is not installed on this worker",
        "description": f"The {tool} binary is not on PATH; this scan was skipped.",
        "remediation": f"Install {tool} in the worker image and re-run.",
        "evidence": {"tool": tool},
    }


def _tool_error_finding(host: str, tool: str, msg: str) -> dict:
    return {
        "target_host": host,
        "target_canonical": host,
        "target_kind": "ipv4",
        "rule_id": f"tool-error-{tool}",
        "rule_source": "policy",
        "severity": "info",
        "title": f"{tool} failed to complete",
        "description": msg,
        "evidence": {"tool": tool, "error": msg},
    }
