"""Universal ingest: auto-detect a scanner's output and normalise it.

``parse_payload(raw, hint, hints)`` is the single entry point (pure, no I/O).
Supported: SARIF 2.1, CycloneDX, SPDX, OCSF, Trivy JSON, Grype JSON, Semgrep
JSON, Nuclei JSONL/JSON, ZAP JSON and CSV with documented columns.

Hostile-input policy: bodies are size-capped before parsing (and gzip bodies
are inflated with a hard output cap), XML is refused outright (no entity
expansion is ever attempted), JSON nesting depth is bounded, line-oriented
formats (NDJSON, CSV) are consumed one record at a time, and the number of
findings / components is capped.
"""
from __future__ import annotations

import json
import re
import zlib
from typing import Any, Iterator, Optional

from .common import IngestError, ParseResult, clean
from .parsers import (
    CSV_COLUMNS,
    FORMATS,
    Hints,
    csv_looks_like,
    parse_csv,
    parse_grype,
    parse_nuclei,
    parse_ocsf,
    parse_sarif,
    parse_sbom_doc,
    parse_semgrep,
    parse_trivy,
    parse_zap,
)

__all__ = ["FORMATS", "CSV_COLUMNS", "Hints", "IngestError", "ParseResult", "decode_body",
           "detect_format", "parse_payload"]

MAX_JSON_DEPTH = 64


def inflate_limited(raw: bytes, max_out: int) -> bytes:
    """gzip/zlib-inflate with a hard output cap (zip-bomb safe)."""
    d = zlib.decompressobj(wbits=31)            # 31 = gzip container
    try:
        out = d.decompress(raw, max_out + 1)
        if d.unconsumed_tail or len(out) > max_out:
            raise IngestError(f"decompressed body exceeds {max_out} bytes", 413)
        out += d.flush()
    except zlib.error:
        raise IngestError("body is not valid gzip", 400) from None
    if len(out) > max_out:
        raise IngestError(f"decompressed body exceeds {max_out} bytes", 413)
    return out


def decode_body(raw: bytes, *, gzipped: bool, max_bytes: int) -> str:
    if gzipped or raw[:2] == b"\x1f\x8b":
        raw = inflate_limited(raw, max_bytes)
    if len(raw) > max_bytes:
        raise IngestError(f"body exceeds {max_bytes} bytes", 413)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IngestError("body is not valid UTF-8 text", 415) from None
    if "\x00" in text:
        raise IngestError("body contains NUL bytes", 415)
    return text


_BOMB_RE = re.compile(r"(?:[\[{]\s*(?:\"[^\"]{0,64}\"\s*:\s*)?){%d}" % (MAX_JSON_DEPTH + 1))


def _depth_ok(text: str) -> bool:
    """Refuse the classic nested-bracket "JSON bomb" before the recursive
    parser sees it (anything subtler still hits Python's recursion limit,
    which is caught and reported as 422)."""
    return _BOMB_RE.search(text) is None


def _json_lines(text: str, res: ParseResult) -> Iterator[Any]:
    n = 0
    for i, line in enumerate(text.split("\n")):
        line = line.strip()
        if not line:
            continue
        try:
            if len(line) > 200_000 and not _depth_ok(line):
                raise ValueError("nested too deeply")
            yield json.loads(line)
            n += 1
        except (ValueError, RecursionError) as exc:
            res.error(f"line {i + 1}", f"invalid JSON: {str(exc)[:80]}")
            if res.skipped > 1000 and n == 0:
                raise IngestError("not JSON lines: too many unparseable lines", 400) from None


def detect_format(doc: Any) -> Optional[str]:
    """Format of an already-parsed JSON document (None if unrecognised)."""
    if isinstance(doc, list):
        first = next((x for x in doc if isinstance(x, dict)), None)
        return detect_format(first) if first is not None else None
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("runs"), list) and (
            "sarif" in str(doc.get("$schema", "")).lower() or str(doc.get("version", "")).startswith("2.")):
        return "sarif"
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if str(doc.get("spdxVersion") or "").startswith("SPDX-2."):
        return "spdx"
    if "SchemaVersion" in doc and ("Results" in doc or "ArtifactName" in doc):
        return "trivy"
    if isinstance(doc.get("matches"), list) and ("descriptor" in doc or "source" in doc or "distro" in doc
                                                 or any(isinstance(m, dict) and "artifact" in m for m in doc["matches"][:3])):
        return "grype"
    if isinstance(doc.get("results"), list) and ("version" in doc or "errors" in doc or "paths" in doc
                                                 or any(isinstance(r, dict) and "check_id" in r for r in doc["results"][:3])):
        return "semgrep"
    if "site" in doc and (isinstance(doc["site"], (list, dict))) and ("@programName" in doc or "@version" in doc
                                                                       or "@generated" in doc or "site" in doc):
        return "zap"
    if "template-id" in doc or "templateID" in doc:
        return "nuclei"
    if isinstance(doc.get("class_uid"), int):
        return "ocsf"
    if isinstance(doc.get("events"), list) and doc["events"] and isinstance(doc["events"][0], dict) \
            and isinstance(doc["events"][0].get("class_uid"), int):
        return "ocsf"
    return None


def _unwrap(doc: Any, fmt: str) -> Any:
    if fmt == "ocsf" and isinstance(doc, dict):
        return doc["events"] if isinstance(doc.get("events"), list) else [doc]
    if fmt == "nuclei" and isinstance(doc, dict):
        return [doc]
    return doc


def parse_payload(raw_text: str, hint: Optional[str] = None, hints: Optional[Hints] = None) -> ParseResult:
    """Detect + parse. Raises :class:`IngestError` (with an HTTP status) when the
    payload is unusable as a whole; per-record problems land in ``result.errors``."""
    h = hints or Hints()
    hint = (hint or "").strip().lower() or None
    if hint == "sbom":
        hint = None
    if hint and hint not in FORMATS:
        raise IngestError(f"unknown format {clean(hint, 30)!r}; supported: {', '.join(FORMATS)}", 422)
    text = raw_text.lstrip()
    if not text:
        raise IngestError("empty body", 400)
    if text[0] == "<":
        raise IngestError("XML is not accepted (it is a classic entity-expansion vector); export the report "
                          "as JSON (SARIF, CycloneDX/SPDX JSON, ZAP JSON, ...)", 415)

    # ---- CSV -------------------------------------------------------------- #
    if text[0] not in "{[":
        if hint not in (None, "csv"):
            raise IngestError(f"body is not JSON, but format={hint} was requested", 422)
        if not csv_looks_like(text) and hint != "csv":
            raise IngestError("unrecognised format: not JSON and not CSV with the documented columns "
                              f"({', '.join(c for c in CSV_COLUMNS if CSV_COLUMNS[c].startswith('REQUIRED'))} "
                              "are required)", 415)
        res = ParseResult(format="csv")
        parse_csv(text, h, res)
        return res

    # ---- JSON / JSONL -------------------------------------------------------- #
    res_lines = ParseResult(format="")
    doc: Any
    try:
        if not _depth_ok(text):
            raise IngestError(f"JSON nests deeper than {MAX_JSON_DEPTH} levels", 422)
        doc = json.loads(text)
        lines_mode = False
    except IngestError:
        raise
    except RecursionError:
        raise IngestError("JSON nested too deeply", 422) from None
    except ValueError as exc:
        # NDJSON ("Extra data" after the first value) is the normal reason.
        if "Extra data" not in str(exc) and "\n" not in text.strip():
            raise IngestError(f"body is not valid JSON: {str(exc)[:100]}", 400) from None
        doc = list(_json_lines(text, res_lines))
        if not doc:
            raise IngestError("body is neither valid JSON nor JSON lines", 400) from None
        lines_mode = True

    fmt = detect_format(doc)
    if fmt is None and lines_mode and doc:
        fmt = detect_format(doc[0])
    if fmt is None:
        fmt = hint
        if fmt is None or fmt in ("sarif", "cyclonedx", "spdx", "trivy", "grype", "semgrep", "zap"):
            raise IngestError("unrecognised JSON document: expected SARIF, CycloneDX, SPDX, OCSF, Trivy, Grype, "
                              "Semgrep, Nuclei or ZAP output (set ?format= to force a format)", 415)
    elif hint and hint != fmt:
        raise IngestError(f"payload looks like {fmt} but format={hint} was requested", 422)

    res = ParseResult(format=fmt)
    res.errors, res.skipped = res_lines.errors, res_lines.skipped
    body = _unwrap(doc, fmt)
    if fmt in ("nuclei", "ocsf"):
        if not isinstance(body, list):
            raise IngestError(f"{fmt} input must be JSON lines or an array of records")
        (parse_nuclei if fmt == "nuclei" else parse_ocsf)(iter(body), h, res)
        return res
    if not isinstance(body, dict):
        raise IngestError(f"{fmt} input must be a JSON object")
    {"sarif": parse_sarif, "trivy": parse_trivy, "grype": parse_grype, "semgrep": parse_semgrep,
     "zap": parse_zap, "cyclonedx": parse_sbom_doc, "spdx": parse_sbom_doc}[fmt](body, h, res)
    return res
