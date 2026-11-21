"""TLS inspection via tlsx (ProjectDiscovery).

``tlsx -tls-version -cipher -cert -json`` for each host:port. Emits a
certificate asset + findings for expired/self-signed/weak cipher/missing TLS 1.3
/ oversized SAN lists.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

import structlog

from app.config import settings
from app.orchestrator import OrchestratorClient, new_outbound_row
from app.scope_guard import ScopeDenied, ScopeGuard, normalize_target
from app.util import runner
from app.util.politeness import PolitenessLimiter, _host_of

log = structlog.get_logger(__name__)


_WEAK_CIPHER_FRAGMENTS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "anon", "_MD5")


async def gather_facts(
    target: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Run tlsx once for ``target`` and return the raw, scope-filtered rows.

    This is the single handshake point: ``inspect`` (findings/assets) and
    ``tls_grade`` (posture score) both consume the result rather than probing
    the host twice.

    Returns a facts dict:
        ``{"host", "port", "available": bool, "error": str|None, "rows": [obj,...]}``
    where ``available`` is False only when the tlsx binary is missing, and
    ``rows`` is the list of parsed JSON objects whose host is still in scope.
    """
    await scope.allow(target)
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else 443
    host_key = host.lower()

    args = [
        "-host", host,
        "-port", str(port),
        "-tls-version",
        "-cipher",
        "-cert",
        "-san",
        "-json",
        "-silent",
    ]

    try:
        async with politeness.acquire(host_key):
            t0 = time.monotonic()
            result = await runner.run("tlsx", args, timeout=settings.subprocess_timeout_sec)
    except runner.ToolUnavailable:
        return {"host": host_key, "port": port, "available": False,
                "error": "tlsx-unavailable", "rows": []}
    except (runner.ToolTimeout, runner.ToolFailed) as e:
        log.warning("tlsx.error", error=str(e))
        return {"host": host_key, "port": port, "available": True,
                "error": str(e), "rows": []}

    duration_ms = int((time.monotonic() - t0) * 1000)
    await orchestrator.outbound_log(new_outbound_row(
        target=f"{host}:{port}", tool="tlsx", method="tls_handshake",
        duration_ms=duration_ms, scope_matched=True,
    ))

    rows: list[dict] = []
    for line in result.lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        row_host = (obj.get("host") or host).lower()
        try:
            await scope.allow(row_host)
        except ScopeDenied:
            log.warning("tlsx.drop_out_of_scope", host=row_host)
            continue
        obj.setdefault("host", row_host)
        rows.append(obj)

    return {"host": host_key, "port": port, "available": True, "error": None, "rows": rows}


async def inspect(
    target: str,
    *,
    scope: ScopeGuard,
    politeness: PolitenessLimiter,
    orchestrator: OrchestratorClient,
    scan_id: str | None = None,
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """target is ``host`` or ``host:port`` (default 443).

    Pass ``facts`` (from :func:`gather_facts`) to reuse an already-performed
    handshake instead of running tlsx again.
    """
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else 443
    host_key = host.lower()

    findings: list[dict] = []
    assets: list[dict] = []
    edges: list[dict] = []

    if facts is None:
        facts = await gather_facts(
            target, scope=scope, politeness=politeness,
            orchestrator=orchestrator, scan_id=scan_id,
        )

    if not facts.get("available"):
        findings.append({
            "target_host": host_key,
            "target_canonical": f"{host_key}:{port}",
            "target_kind": "endpoint",
            "rule_id": "tool-unavailable-tlsx",
            "rule_source": "policy",
            "severity": "info",
            "title": "tlsx not installed on this worker",
            "description": "Skipping TLS inspection; binary missing.",
            "evidence": {"tool": "tlsx"},
        })
        return {"assets": assets, "edges": edges, "findings": findings, "summary": {}}
    if facts.get("error"):
        return {"assets": assets, "edges": edges, "findings": findings,
                "summary": {"error": facts["error"]}}

    for obj in facts.get("rows", []):
        row_host = (obj.get("host") or host).lower()
        cert = _normalize_cert(obj)
        if cert:
            cert_canonical = f"sha256:{cert['sha256']}"
            assets.append({
                "kind": "certificate",
                "value": cert["subject"] or cert_canonical,
                "canonical": cert_canonical,
                "source": "tls_inspect",
                "metadata": cert,
            })
            edges.append({
                "src_kind": "endpoint", "src_canonical": f"{row_host}:{port}",
                "dst_kind": "certificate", "dst_canonical": cert_canonical,
                "kind": "issued_for",
            })
            findings.extend(_cert_findings(row_host, port, cert))

        tls_versions = obj.get("tls_version") or obj.get("tls-version") or obj.get("version") or []
        if isinstance(tls_versions, str):
            tls_versions = [tls_versions]
        cipher = obj.get("cipher") or obj.get("cipher_suite")
        findings.extend(_protocol_findings(row_host, port, tls_versions, cipher))

    return {"assets": assets, "edges": edges, "findings": findings, "summary": {"certs": len(assets)}}


def _normalize_cert(obj: dict) -> dict | None:
    """Pull the cert bits we care about out of tlsx's JSON."""
    cert = obj.get("certificate") or obj
    subject = cert.get("subject_cn") or cert.get("subject") or ""
    issuer = cert.get("issuer_cn") or cert.get("issuer") or ""
    not_before = cert.get("not_before")
    not_after = cert.get("not_after")
    sha256 = cert.get("fingerprint_hash", {}).get("sha256") if isinstance(cert.get("fingerprint_hash"), dict) else cert.get("sha256") or cert.get("fingerprint")
    sans = cert.get("subject_an") or cert.get("subject_alt_names") or cert.get("san") or []
    if not sha256 and not subject:
        return None
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sha256": sha256 or "",
        "sans": sans if isinstance(sans, list) else [sans],
        "self_signed": bool(cert.get("self_signed")),
        "wildcard_cert": bool(cert.get("wildcard_certificate")),
    }


def _cert_findings(host: str, port: int, cert: dict) -> list[dict]:
    out: list[dict] = []
    canonical = f"{host}:{port}"
    now = datetime.now(timezone.utc)

    not_after = _parse_ts(cert.get("not_after"))
    if not_after and not_after < now:
        out.append(_finding(
            host, canonical, "expired-certificate", "high",
            "TLS certificate is expired",
            f"not_after={cert.get('not_after')}",
            "Renew the certificate (ACME / your issuer).",
            {"cert_sha256": cert.get("sha256")},
        ))
    elif not_after and (not_after - now).days < 14:
        out.append(_finding(
            host, canonical, "expiring-certificate", "medium",
            "TLS certificate expires within 14 days",
            f"not_after={cert.get('not_after')}",
            "Renew the certificate before expiry.",
            {"cert_sha256": cert.get("sha256"), "days_remaining": (not_after - now).days},
        ))

    if cert.get("self_signed") and settings.env == "prod":
        out.append(_finding(
            host, canonical, "self-signed-certificate", "high",
            "Self-signed certificate in production",
            "Clients cannot verify the identity of the server.",
            "Issue a certificate from a publicly trusted CA.",
            {"cert_sha256": cert.get("sha256")},
        ))

    sans = cert.get("sans") or []
    if len(sans) > 50:
        out.append(_finding(
            host, canonical, "san-fanout", "low",
            f"Certificate has {len(sans)} SANs",
            "Large SAN lists expand the compromise blast radius if the key leaks.",
            "Split into per-service certificates.",
            {"san_count": len(sans)},
        ))
    return out


def _protocol_findings(host: str, port: int, versions: list[str], cipher: str | None) -> list[dict]:
    out: list[dict] = []
    canonical = f"{host}:{port}"
    v_norm = {v.upper().replace("V", "").replace("TLS", "TLS") for v in versions}
    if versions and not any(v in v_norm for v in ("TLSV1.3", "TLS1.3", "TLS 1.3", "1.3")):
        out.append(_finding(
            host, canonical, "missing-tls-1-3", "low",
            "Server does not advertise TLS 1.3",
            "Older protocols have less forward secrecy / stronger cipher bias.",
            "Enable TLS 1.3 on the TLS terminator.",
            {"versions": sorted(v_norm)},
        ))
    legacy = {"TLSV1.0", "TLS1.0", "TLSV1.1", "TLS1.1", "SSLV3", "SSL3"}
    if legacy & v_norm:
        out.append(_finding(
            host, canonical, "legacy-tls-version", "medium",
            "Server supports a legacy TLS/SSL version",
            "Deprecated protocols are known to be weak.",
            "Disable TLS 1.0/1.1 and SSLv3.",
            {"versions": sorted(v_norm)},
        ))
    if cipher and any(f in cipher.upper() for f in _WEAK_CIPHER_FRAGMENTS):
        out.append(_finding(
            host, canonical, "weak-cipher", "medium",
            f"Server negotiates a weak cipher: {cipher}",
            "Weak ciphers may be broken by a reachable adversary.",
            "Restrict ciphers to the Mozilla Intermediate / Modern set.",
            {"cipher": cipher},
        ))
    return out


def _finding(host: str, canonical: str, rule_id: str, severity: str,
             title: str, description: str, remediation: str, evidence: dict) -> dict:
    return {
        "target_host": host,
        "target_canonical": canonical,
        "target_kind": "endpoint",
        "rule_id": rule_id,
        "rule_source": "tls_check",
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
    }


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        from dateutil.parser import isoparse

        dt = isoparse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None
