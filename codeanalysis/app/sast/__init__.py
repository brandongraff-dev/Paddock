"""SAST: Semgrep when installed, else a bundled source->sink taint scanner.

``run_sast`` picks the engine, returning a uniform result:
``{engine, available, hits, note, error?}``. Source files are DATA -- parsed
read-only (Python AST) or written to a temp dir for the external Semgrep
process; they are never imported, executed, or evaluated.
"""
from __future__ import annotations

from typing import Any

from . import normalize, semgrep_runner, taint_fallback

__all__ = ["normalize", "semgrep_runner", "taint_fallback", "run_sast"]


def run_sast(files: dict[str, str], *, enable_semgrep: bool = True,
             semgrep_bin: str = "semgrep", semgrep_config: str = "auto",
             semgrep_timeout_s: int = 300) -> dict[str, Any]:
    """Run SAST over ``files`` with the best available engine.

    Prefers Semgrep; falls back to the bundled taint scanner when the binary is
    absent or Semgrep could not produce results (e.g. offline rule fetch).
    """
    if enable_semgrep and semgrep_runner.is_available(semgrep_bin):
        res = semgrep_runner.run(files, binary=semgrep_bin, config=semgrep_config,
                                 timeout_s=semgrep_timeout_s)
        if res.get("available") and not res.get("error"):
            return {"engine": "semgrep", "available": True,
                    "hits": res.get("hits", []), "note": res.get("note")}
        # Semgrep present but failed (offline rules / crash) -> fall back.
        fb = taint_fallback.scan_files(files)
        return {"engine": "taint_fallback", "available": True, "hits": fb,
                "note": "semgrep unavailable (%s); used bundled taint scanner"
                        % (res.get("note") or res.get("error") or "unknown")}

    hits = taint_fallback.scan_files(files)
    return {"engine": "taint_fallback", "available": True, "hits": hits,
            "note": "semgrep binary not found; used bundled taint scanner"}
