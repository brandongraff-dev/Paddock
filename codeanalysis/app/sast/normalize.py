"""Normalize SAST hits into ``code_findings`` rows and unified findings.

A "hit" (from Semgrep or the bundled taint scanner) maps to:
  * a ``code_findings`` row (rule, message, severity, file, lines, source,
    sink, dataflow steps, cwe), and
  * a unified ``findings`` item posted via ``POST /v1/findings/bulk`` with
    ``rule_source='sast'``, severity mapped, evidence=dataflow, attached to the
    project's repository asset (or ``asset_value`` = project name).

No remediation text here is exploit guidance -- it is generic hardening advice.
"""
from __future__ import annotations

from typing import Any, Optional

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_VALID_SEV = set(_SEV_RANK)

_CLASS_TITLE = {
    "sql_injection": "SQL injection",
    "command_injection": "OS command injection",
    "path_traversal": "Path traversal",
    "insecure_deserialization": "Insecure deserialization",
    "ssrf": "Server-side request forgery (SSRF)",
    "weak_crypto": "Weak cryptography",
    "hardcoded_secret": "Hardcoded secret",
    "code_injection": "Code injection",
    "insecure_transport": "TLS verification disabled",
}

_CLASS_REMEDIATION = {
    "sql_injection": "Use parameterised queries / prepared statements; never build SQL by string concatenation.",
    "command_injection": "Avoid shells; pass argument lists to exec APIs and validate/allow-list inputs.",
    "path_traversal": "Resolve and confine paths to an allow-listed base directory; reject '..' segments.",
    "insecure_deserialization": "Do not deserialize untrusted data; use safe formats (JSON) or yaml.safe_load / a SafeLoader.",
    "ssrf": "Validate and allow-list outbound hosts; block internal/metadata ranges and disable redirects.",
    "weak_crypto": "Use SHA-256+ (integrity) and a password hash (bcrypt/argon2/scrypt) for credentials.",
    "hardcoded_secret": "Remove the secret from source; load it from a secrets manager or environment and rotate it.",
    "code_injection": "Never pass untrusted input to eval/Function/vm; parse data with a real parser instead.",
    "insecure_transport": "Keep certificate verification on; trust a private CA explicitly instead of disabling checks.",
}


def normalize_severity(sev: Optional[str]) -> str:
    s = (sev or "").lower()
    return s if s in _VALID_SEV else "medium"


def dedupe(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse hits sharing (rule, file, start_line); keep the worst severity.

    Mirrors the ``code_findings`` UNIQUE(project_id, rule, file, start_line).
    """
    out: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    for h in hits:
        key = (h.get("rule"), h.get("file"), h.get("start_line"))
        existing = out.get(key)
        if existing is None:
            out[key] = dict(h)
            continue
        if _SEV_RANK.get(normalize_severity(h.get("severity")), 0) > \
           _SEV_RANK.get(normalize_severity(existing.get("severity")), 0):
            out[key] = dict(h)
    return list(out.values())


def code_finding_row(hit: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    """Build kwargs for ``Database.upsert_code_finding``."""
    return {
        "project_id": project.get("id"),
        "asset_id": project.get("asset_id"),
        "engine": hit.get("engine") or "semgrep",
        "rule": str(hit.get("rule") or "rule"),
        "message": str(hit.get("message") or hit.get("rule") or "code weakness"),
        "severity": normalize_severity(hit.get("severity")),
        "file": str(hit.get("file") or ""),
        "start_line": hit.get("start_line"),
        "end_line": hit.get("end_line"),
        "source": hit.get("source"),
        "sink": hit.get("sink"),
        "dataflow": hit.get("dataflow") or [],
        "cwe": hit.get("cwe"),
        "metadata": {
            "rule_class": hit.get("rule_class"),
            "language": hit.get("language"),
            "engine": hit.get("engine"),
        },
    }


def build_sast_finding(hit: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    """Build a ``POST /v1/findings/bulk`` item (rule_source='sast')."""
    cls = hit.get("rule_class") or "code_weakness"
    title_cls = _CLASS_TITLE.get(cls, "Code weakness")
    rule = str(hit.get("rule") or cls)
    file = str(hit.get("file") or "")
    line = hit.get("start_line")
    where = f"{file}:{line}" if line else file
    severity = normalize_severity(hit.get("severity"))
    cwe = hit.get("cwe")
    dataflow = hit.get("dataflow") or []

    item: dict[str, Any] = {
        "rule_id": f"sast:{rule}",
        "rule_source": "sast",
        "severity": severity,
        "title": f"{title_cls} in {file}" if file else title_cls,
        "description": str(hit.get("message") or title_cls) + (f" (at {where})" if where else ""),
        "impact": _impact(cls),
        "remediation": _CLASS_REMEDIATION.get(cls, "Review and fix the flagged code path."),
        "evidence": {
            "engine": hit.get("engine"),
            "rule": rule,
            "rule_class": cls,
            "file": file,
            "start_line": line,
            "end_line": hit.get("end_line"),
            "source": hit.get("source"),
            "sink": hit.get("sink"),
            "dataflow": dataflow,
            "cwe": cwe,
            "language": hit.get("language"),
        },
        "references": [f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"]
        if cwe and cwe.startswith("CWE-") else [],
        "metadata": {"source": "sast", "project": project.get("name"), "cwe": cwe},
    }
    if project.get("asset_id"):
        item["asset_id"] = project["asset_id"]
    else:
        item["asset_value"] = project.get("name") or file or "codeanalysis"
        item["asset_kind"] = "repository"
    return item


def _impact(cls: str) -> str:
    return {
        "sql_injection": "An attacker could read or modify database contents via crafted input.",
        "command_injection": "An attacker could execute arbitrary OS commands on the host.",
        "path_traversal": "An attacker could read or write files outside the intended directory.",
        "insecure_deserialization": "An attacker could achieve remote code execution via crafted payloads.",
        "ssrf": "An attacker could coerce the server into making requests to internal systems.",
        "weak_crypto": "Weak hashing undermines credential and integrity protections.",
        "hardcoded_secret": "A leaked secret grants unauthorized access if the source is exposed.",
        "code_injection": "An attacker could run arbitrary code inside the application process.",
        "insecure_transport": "Traffic can be intercepted or altered by anyone on the network path.",
    }.get(cls, "This weakness may be exploitable; review the dataflow.")
