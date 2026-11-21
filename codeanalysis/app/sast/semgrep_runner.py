"""Run Semgrep over the provided source when the binary is installed.

The provided files are untrusted DATA. They are written to a throwaway temp
directory purely so the external ``semgrep`` process can READ them, scanned,
and then deleted. We NEVER import, execute, or evaluate them, and Semgrep is
always invoked WITHOUT ``--autofix`` (we analyse, we do not modify source).

``--config auto`` may fetch rule packs from the Semgrep registry; when offline
that fetch fails and Semgrep is treated as unavailable -- the caller falls back
to the bundled taint scanner. No finding is fabricated.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404 - used only to run the read-only scanner, never source
import tempfile
from typing import Any, Optional

log = logging.getLogger("codeanalysis.semgrep")

ENGINE = "semgrep"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL_BYTES = 64 * 1024 * 1024

# severities Semgrep emits -> our scale
_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

_TEXT_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go",
    ".java", ".rb", ".php", ".c", ".h", ".cpp", ".cs", ".rs", ".scala",
    ".kt", ".swift", ".sh", ".bash", ".html", ".sql", ".json", ".yaml", ".yml",
}


def is_available(binary: str = "semgrep") -> bool:
    return shutil.which(binary) is not None


def _safe_rel(path: str) -> Optional[str]:
    """Return a sanitized relative path confined under the temp dir, or None."""
    p = path.replace("\\", "/").lstrip("/")
    parts = [seg for seg in p.split("/") if seg not in ("", ".", "..")]
    if not parts:
        return None
    _, ext = os.path.splitext(parts[-1])
    if ext.lower() not in _TEXT_EXTS:
        return None
    return os.path.join(*parts)


def _materialize(files: dict[str, str], base: str) -> list[str]:
    written: list[str] = []
    total = 0
    for path, content in files.items():
        if len(written) >= MAX_FILES:
            break
        if not isinstance(content, str):
            continue
        rel = _safe_rel(path)
        if rel is None:
            continue
        data = content.encode("utf-8", "replace")
        if len(data) > MAX_FILE_BYTES:
            continue
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            break
        full = os.path.join(base, rel)
        real = os.path.realpath(full)
        if not real.startswith(os.path.realpath(base) + os.sep):
            continue  # defence-in-depth against traversal
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
        written.append(rel)
    return written


def run(files: dict[str, str], *, binary: str = "semgrep", config: str = "auto",
        timeout_s: int = 300) -> dict[str, Any]:
    """Scan ``files`` with Semgrep. Returns ``{available, hits, error?, note}``.

    Never raises for an absent/failed tool -- returns ``available=False``.
    """
    if not is_available(binary):
        return {"available": False, "hits": [], "note": "semgrep binary not found"}

    tmp = tempfile.mkdtemp(prefix="codeanalysis-semgrep-")
    try:
        written = _materialize(files, tmp)
        if not written:
            return {"available": True, "hits": [], "note": "no scannable source files"}
        cmd = [
            binary, "--json", "--quiet",
            "--config", config,
            "--disable-version-check", "--metrics", "off",
            "--timeout", str(max(5, timeout_s // 2)),
            tmp,
        ]
        # Invariant: analysis only. --autofix / --replacement MUST NOT appear.
        assert "--autofix" not in cmd and "-a" not in cmd
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, scans temp dir
                cmd, capture_output=True, text=True, timeout=timeout_s,
                cwd=tmp, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {"available": True, "hits": [], "error": str(exc),
                    "note": "semgrep run failed"}
        if not proc.stdout.strip():
            return {"available": True, "hits": [],
                    "error": (proc.stderr or "")[:500] or "empty output",
                    "note": "semgrep produced no JSON (offline rule fetch?)"}
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return {"available": True, "hits": [], "error": str(exc),
                    "note": "semgrep JSON parse failed"}
        hits = parse_results(payload, base=tmp)
        return {"available": True, "hits": hits, "note": f"semgrep scanned {len(written)} files"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def parse_results(payload: dict[str, Any], *, base: str = "") -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for r in (payload or {}).get("results", []) or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        start = (r.get("start") or {}).get("line")
        end = (r.get("end") or {}).get("line")
        rule_id = str(r.get("check_id") or "semgrep.rule")
        path = str(r.get("path") or "")
        if base and path.startswith(base):
            path = os.path.relpath(path, base)
        sev = _SEV.get(str(extra.get("severity") or "").upper(), "medium")
        cwe = _first_cwe(meta.get("cwe"))
        src, sink, flow = _dataflow(extra.get("dataflow_trace") or {}, base)
        hits.append({
            "engine": ENGINE,
            "language": (meta.get("language") or _lang_from_path(path)),
            "rule": rule_id,
            "rule_class": _class_from_cwe(cwe) or rule_id.split(".")[-1],
            "message": str(extra.get("message") or meta.get("message") or rule_id),
            "severity": sev,
            "file": path,
            "start_line": start,
            "end_line": end,
            "source": src,
            "sink": sink,
            "dataflow": flow,
            "cwe": cwe,
        })
    return hits


def _first_cwe(cwe: Any) -> Optional[str]:
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None


def _class_from_cwe(cwe: Optional[str]) -> Optional[str]:
    if not cwe:
        return None
    mapping = {
        "CWE-89": "sql_injection", "CWE-78": "command_injection",
        "CWE-22": "path_traversal", "CWE-502": "insecure_deserialization",
        "CWE-918": "ssrf", "CWE-327": "weak_crypto", "CWE-798": "hardcoded_secret",
    }
    for key, val in mapping.items():
        if cwe.startswith(key):
            return val
    return None


def _dataflow(trace: dict[str, Any], base: str) -> tuple[Optional[str], Optional[str], list[dict[str, Any]]]:
    flow: list[dict[str, Any]] = []
    src = sink = None
    ts = trace.get("taint_source")
    tk = trace.get("taint_sink")
    if isinstance(ts, list) and ts:
        src = "source"
        flow.append({"step": "source", "label": "taint source",
                     "line": _loc_line(ts)})
    for inter in (trace.get("intermediate_vars") or []):
        loc = (inter or {}).get("location") or {}
        flow.append({"step": "propagator", "label": inter.get("content") or "var",
                     "line": loc.get("line")})
    if isinstance(tk, list) and tk:
        sink = "sink"
        flow.append({"step": "sink", "label": "taint sink", "line": _loc_line(tk)})
    return src, sink, flow


def _loc_line(entry: Any) -> Optional[int]:
    try:
        node = entry[0] if isinstance(entry, list) else entry
        loc = node.get("location") or node.get("start") or {}
        return loc.get("line")
    except Exception:
        return None


def _lang_from_path(path: str) -> Optional[str]:
    from .taint_fallback import language_for
    return language_for(path)
