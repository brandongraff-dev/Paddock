"""Optional: send scan results to a Paddock server (``paddock login`` / ``paddock upload``).

Uses the orchestrator's existing ingest API, ``POST /v1/findings/bulk`` (the same
endpoint the SCA and codeanalysis services post to), authenticated with an API key
read from ``PADDOCK_API_KEY``. The key is never written to disk. Uploading only ever
happens when the user runs ``paddock upload``; ``scan`` and ``fix`` never call a server.

Secret values are never uploaded: secret findings carry only the redacted preview.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__, engines
from .model import Finding, ScanResult

CHUNK = 500


class UploadError(RuntimeError):
    pass


def config_path() -> Path:
    base = os.environ.get("PADDOCK_CONFIG_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"),
        "paddock")
    return Path(base) / "config.json"


def load_config() -> dict[str, Any]:
    try:
        return json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict[str, Any]) -> Path:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return p


def resolve_server(flag: str | None) -> str:
    server = flag or os.environ.get("PADDOCK_SERVER") or load_config().get("server")
    if not server:
        raise UploadError("no server: pass --server URL, set PADDOCK_SERVER, or run `paddock login`")
    return normalize_server(server)


def normalize_server(url: str) -> str:
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise UploadError(f"not a valid server URL: {url!r}")
    local = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme == "http" and not local:
        raise UploadError("refusing to send an API key over plain http; use https")
    return url.strip().rstrip("/")


def api_key() -> str:
    key = os.environ.get("PADDOCK_API_KEY", "").strip()
    if not key:
        raise UploadError("PADDOCK_API_KEY is not set (create a key in the Paddock console)")
    return key


def _request(method: str, url: str, key: str | None, body: Any = None, timeout: float = 30) -> Any:
    headers = {"Accept": "application/json", "User-Agent": f"paddock-cli/{__version__}"}
    if key:
        headers["X-API-Key"] = key
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise UploadError(f"server answered HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise UploadError(f"cannot reach {url}: {exc}") from exc


def check_server(server: str, key: str | None) -> dict[str, Any]:
    """Health check, plus who the key belongs to when one is provided."""
    _request("GET", f"{server}/healthz", None)
    if key:
        return _request("GET", f"{server}/v1/auth/me", key) or {}
    return {}


def to_item(f: Finding, project: str) -> dict[str, Any]:
    """Map a CLI finding onto a ``POST /v1/findings/bulk`` item, reusing the engines' builders."""
    proj = {"name": project}
    d = f.data
    if f.kind == "dependency":
        comp = {"ecosystem": d["ecosystem"], "name": d["package"], "version": d["version"],
                "direct": d.get("direct"), "depth": d.get("depth"), "paths": []}
        vulns = [{"osv_id": a["id"], "cve_id": a.get("cve"), "severity": a.get("severity") or "medium",
                  "fixed_version": a.get("fixed"), "refs": [], "cvss": None}
                 for a in d.get("advisories") or []] or [{"osv_id": None, "severity": f.severity}]
        item = engines.sca_findings().build_sca_finding(component=comp, vulns=vulns, project=proj)
        item["evidence"]["manifest"] = f.file
        return item
    if f.kind == "code":
        hit = {"rule": f.rule_id.removeprefix("sast:"), "rule_class": d.get("rule_class"),
               "message": f.message, "severity": f.severity, "file": f.file, "start_line": f.line,
               "end_line": f.end_line, "source": d.get("source"), "sink": d.get("sink"),
               "dataflow": d.get("dataflow") or [], "cwe": f.cwe, "engine": d.get("engine"),
               "language": d.get("language")}
        return engines.sast_normalize().build_sast_finding(hit, proj)
    source = {"secret": "secret_scan", "config": "policy"}.get(f.kind, "sca")
    return {
        "rule_id": f.rule_id, "rule_source": source, "severity": f.severity, "title": f.title[:500],
        "description": f.message or f.title, "impact": f.why, "remediation": f.fix,
        "evidence": {"file": f.file, "line": f.line, "redacted": d.get("redacted"),
                     "rule": d.get("rule"), "package": d.get("package"),
                     "ecosystem": d.get("ecosystem"), "version": d.get("version")},
        "references": f.refs, "metadata": {"source": "paddock-cli", "project": project},
        "asset_value": project, "asset_kind": "repository",
    }


def upload(res: ScanResult, server: str, key: str, project: str) -> dict[str, int]:
    items = [to_item(f, project) for f in res.findings]
    sent = 0
    for i in range(0, len(items), CHUNK):
        chunk = items[i:i + CHUNK]
        _request("POST", f"{server}/v1/findings/bulk", key, {"items": chunk}, timeout=120)
        sent += len(chunk)
    return {"uploaded": sent, "findings": len(items)}
