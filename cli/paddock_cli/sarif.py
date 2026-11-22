"""SARIF 2.1.0 output via the orchestrator's own writer (``standards.sarif_log``).

Findings are mapped to the same "hit" shape the orchestrator's
``GET /v1/export/sarif`` builds, so a file from the CLI and an export from a
Paddock server are interchangeable in GitHub code scanning.
"""
from __future__ import annotations

import hashlib
from typing import Any

from . import engines
from .model import Finding, ScanResult


def _hits(f: Finding) -> list[dict[str, Any]]:
    if f.kind == "dependency":
        eco, name, ver = f.data["ecosystem"], f.data["package"], f.data["version"]
        out = []
        for adv in f.data.get("advisories") or []:
            vid = adv.get("cve") or adv["id"]
            msg = f"{name}@{ver} ({eco}) is affected by {vid}"
            if adv.get("summary"):
                msg += f": {adv['summary']}"
            if f.data.get("fixed_version"):
                msg += f". Fixed in {f.data['fixed_version']}."
            out.append({
                "kind": "sca", "rule_id": str(adv["id"]), "rule_name": str(vid),
                "title": f"{vid} in {name}", "message": msg,
                "description": adv.get("summary") or f"Known vulnerability {vid}",
                "help": f.fix or "See the advisory for remediation.",
                "help_uri": f"https://osv.dev/vulnerability/{adv['id']}",
                "severity": adv.get("severity") or f.severity, "cvss": None,
                "file": f.file, "start_line": f.line, "tags": ["dependency", "sca", eco],
                "properties": {"fixedVersion": f.data.get("fixed_version"),
                               "direct": f.data.get("direct")},
                "fingerprint": hashlib.sha256(
                    f"sca|{adv['id']}|{eco}|{name}|{ver}|{f.file}".encode()).hexdigest(),
            })
        return out
    tags = {"secret": ["secret"], "config": ["config"], "malicious": ["dependency", "malware"],
            "typosquat": ["dependency", "supply-chain"], "code": ["sast"]}[f.kind]
    return [{
        "kind": "sast", "rule_id": f.rule_id, "rule_name": f.rule_id.rsplit(":", 1)[-1],
        "title": f.title, "message": f.message or f.title, "description": f.why,
        "help": f.fix or f.why, "severity": f.severity, "file": f.file, "start_line": f.line,
        "end_line": f.end_line, "cwe": f.cwe, "dataflow": f.data.get("dataflow"),
        "tags": tags, "properties": {"paddockFindingId": f.id},
        "fingerprint": hashlib.sha256(f"{f.kind}|{f.id}".encode()).hexdigest(),
    }]


def to_sarif(res: ScanResult, project: str) -> dict[str, Any]:
    hits = [h for f in res.findings for h in _hits(f)]
    return engines.standards().sarif_log(hits, automation_id=f"paddock-cli/{project}/")
