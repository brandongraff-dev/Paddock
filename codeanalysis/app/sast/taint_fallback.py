"""Bundled source->sink taint scanner used when Semgrep is not installed.

Python is analysed with the ``ast`` module (read-only; files are NEVER
imported, executed, compiled or ``eval``/``exec``'d). Other languages are
covered by the regex rules in ``app/data/taint_rules.json``.

Rule classes: SQL injection, OS command injection, path traversal, insecure
deserialization, SSRF, weak crypto, and hardcoded secrets. Output is a list of
normalized "hit" dicts; see ``normalize.py`` for the DB/finding mapping.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
from functools import lru_cache
from typing import Any, Optional

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "taint_rules.json")

ENGINE = "taint_fallback"


@lru_cache(maxsize=1)
def _rules() -> dict[str, Any]:
    try:
        with open(_DATA, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # pragma: no cover - data ships with the package
        # Loud, not silent: a missing rules file once shipped unnoticed and
        # turned the whole JS/TS/Go scanner (and Python sources) into a no-op.
        logging.getLogger(__name__).error(
            "taint_rules_missing: %s unreadable; SAST fallback is DEGRADED", _DATA
        )
        return {"python_sources": [], "regex_rules": []}


_LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
}


def language_for(path: str) -> Optional[str]:
    _, ext = os.path.splitext(path)
    return _LANG_BY_EXT.get(ext.lower())


def scan_files(files: dict[str, str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for path, content in files.items():
        if not isinstance(content, str):
            continue
        lang = language_for(path)
        if lang == "python":
            hits.extend(scan_python(path, content))
        elif lang in ("javascript", "typescript", "go"):
            hits.extend(scan_regex(path, content, lang))
    return hits


# ===========================================================================
# Python AST taint analysis
# ===========================================================================
def scan_python(path: str, content: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    try:
        return _PyTaint(path).analyze(tree)
    except Exception:  # pragma: no cover - never let one file break a scan
        return []


_PY_SOURCE_PREFIXES = None


def _py_sources() -> list[str]:
    return _rules().get("python_sources", [])


# A secret-ish NAME is matched on identifier segments ("db_password", "apiKey"),
# so "queue_passive" or "tokenizer" don't qualify.
_SECRET_NAME = re.compile(
    # case-insensitive keyword, case-SENSITIVE camelCase boundaries
    r"(?:^|_|(?<=[a-z])(?=[A-Z]))(?i:pass(?:word|wd)?|pwd|secret|api_?key|apikey|token|"
    r"private_?key|access_?key|client_?secret|credentials?)(?:$|_|(?=[A-Z]))"
)


def _looks_secret(v: str) -> bool:
    """Literal looks like a credential: >= 8 chars, no spaces, letters AND digits."""
    return (
        len(v) >= 8
        and not any(c.isspace() for c in v)
        and any(c.isdigit() for c in v)
        and any(c.isalpha() for c in v)
    )


def _dotted(node: ast.AST) -> Optional[str]:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(cur, ast.Call):
        inner = _dotted(cur.func)
        if inner:
            parts.append(inner)
            parts.reverse()
            return ".".join(parts)
    return None


class _PyTaint:
    def __init__(self, path: str) -> None:
        self.path = path
        self.hits: list[dict[str, Any]] = []
        self._seen: set[tuple[str, int]] = set()

    def analyze(self, tree: ast.Module) -> list[dict[str, Any]]:
        # module scope, then descend into functions with inherited taint
        self._block(tree.body, tainted={})
        return self.hits

    # -- taint state -----------------------------------------------------
    def _block(self, body: list[ast.stmt], tainted: dict[str, dict[str, Any]]) -> None:
        for stmt in body:
            self._stmt(stmt, tainted)

    def _stmt(self, stmt: ast.stmt, tainted: dict[str, dict[str, Any]]) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._block(stmt.body, dict(tainted))
            return
        if isinstance(stmt, ast.ClassDef):
            self._block(stmt.body, dict(tainted))
            return
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            self._assign(stmt, tainted)
        # scan every call inside the statement for sinks
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                self._check_sink(node, tainted)
        # recurse control-flow bodies so inner assignments keep ordering
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, field, None)
            if isinstance(inner, list) and not isinstance(
                stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                self._block(inner, tainted)
        for handler in getattr(stmt, "handlers", []) or []:
            self._block(handler.body, tainted)

    def _assign(self, stmt: ast.stmt, tainted: dict[str, dict[str, Any]]) -> None:
        value = getattr(stmt, "value", None)
        if value is None:
            return
        # hardcoded secret: NAME = "literal"
        self._check_hardcoded(stmt, value)
        src = self._expr_taint(value, tainted)
        targets: list[ast.expr] = []
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            targets = [stmt.target]  # type: ignore[list-item]
        for tgt in targets:
            for name in self._target_names(tgt):
                if src:
                    tainted[name] = {"source": src, "line": getattr(stmt, "lineno", 0)}
                elif not isinstance(stmt, ast.AugAssign) and name in tainted:
                    tainted.pop(name, None)

    @staticmethod
    def _target_names(tgt: ast.expr) -> list[str]:
        if isinstance(tgt, ast.Name):
            return [tgt.id]
        if isinstance(tgt, (ast.Tuple, ast.List)):
            out: list[str] = []
            for e in tgt.elts:
                if isinstance(e, ast.Name):
                    out.append(e.id)
            return out
        return []

    # -- taint of an expression -----------------------------------------
    def _expr_taint(self, node: ast.expr, tainted: dict[str, dict[str, Any]]) -> Optional[str]:
        """Return a source label if the expression is tainted, else None."""
        src = self._direct_source(node)
        if src:
            return src
        if isinstance(node, ast.Name):
            info = tainted.get(node.id)
            return info["source"] if info else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._expr_taint(node.left, tainted) or self._expr_taint(node.right, tainted)
        if isinstance(node, ast.JoinedStr):  # f-string
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    s = self._expr_taint(v.value, tainted)
                    if s:
                        return s
            return None
        if isinstance(node, ast.Call):
            # str(x), "..".format(x), "..".join([x])
            fname = _dotted(node.func) or ""
            if fname.split(".")[-1] in ("format", "join", "str"):
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    s = self._expr_taint(arg, tainted)
                    if s:
                        return s
            # value.format() where value tainted
            if isinstance(node.func, ast.Attribute):
                s = self._expr_taint(node.func.value, tainted)
                if s:
                    return s
        if isinstance(node, ast.Subscript):
            return self._expr_taint(node.value, tainted)
        return None

    def _direct_source(self, node: ast.expr) -> Optional[str]:
        dotted = _dotted(node)
        if dotted:
            for pref in _py_sources():
                if dotted == pref or dotted.startswith(pref + ".") or dotted.startswith(pref + "["):
                    return pref
        if isinstance(node, ast.Subscript):
            base = _dotted(node.value)
            if base:
                for pref in _py_sources():
                    if base == pref or base.startswith(pref + "."):
                        return pref
        if isinstance(node, ast.Call):
            fname = _dotted(node.func) or ""
            # Environment variables are deliberately NOT sources: they are
            # operator configuration, and treating them as attacker input made
            # every `urlopen(os.environ[...])` health-check an SSRF finding.
            if fname == "input" or fname.endswith(".get_json"):
                return fname
        return None

    @staticmethod
    def _is_built_string(node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return node.func.attr in ("format", "join")
        return False

    # -- sinks -----------------------------------------------------------
    def _check_sink(self, call: ast.Call, tainted: dict[str, dict[str, Any]]) -> None:
        name = _dotted(call.func) or ""
        last = name.split(".")[-1]
        args = list(call.args)
        kwargs = {kw.arg: kw.value for kw in call.keywords if kw.arg}

        def first_tainted() -> Optional[tuple[str, Optional[int]]]:
            for a in args:
                s = self._expr_taint(a, tainted)
                if s:
                    return s, self._origin_line(a, tainted)
            for a in kwargs.values():
                s = self._expr_taint(a, tainted)
                if s:
                    return s, self._origin_line(a, tainted)
            return None

        # insecure deserialization -- dangerous regardless of taint
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
                    "_pickle.loads", "marshal.loads"):
            self._emit(call, "insecure-deserialization", "insecure_deserialization",
                       "Insecure deserialization via %s (arbitrary object construction)" % name,
                       "critical" if "pickle" in name else "high", "CWE-502",
                       source="untrusted bytes", sink=name, origin=None)
            return
        if last == "load" and name.endswith("yaml.load"):
            if not self._yaml_is_safe(call, kwargs):
                self._emit(call, "yaml-unsafe-load", "insecure_deserialization",
                           "yaml.load() without SafeLoader allows arbitrary object "
                           "construction", "high", "CWE-502",
                           source="untrusted YAML", sink="yaml.load", origin=None)
            return

        # weak crypto
        if name in ("hashlib.md5", "hashlib.sha1") or last in ("md5", "sha1"):
            self._emit(call, "weak-hash", "weak_crypto",
                       "Weak hash %s used (unsuitable for passwords/integrity)" % last,
                       "medium", "CWE-327", source="n/a", sink=name or last, origin=None)
            return

        # the remaining sinks require tainted input
        tnt = first_tainted()
        if tnt is None:
            return
        source_label, origin = tnt

        if last in ("execute", "executemany", "executescript", "raw"):
            built = any(self._is_built_string(a) for a in args)
            self._emit(call, "sql-injection", "sql_injection",
                       "Untrusted input reaches %s() in a %s SQL query" % (
                           last, "string-built" if built else "parameterised-bypass"),
                       "high", "CWE-89", source=source_label, sink=last, origin=origin)
        elif name in ("os.system", "os.popen") or (
            last in ("call", "run", "Popen", "check_output", "check_call",
                     "getoutput", "getstatusoutput")
        ):
            self._emit(call, "command-injection", "command_injection",
                       "Untrusted input reaches OS command sink %s()" % (name or last),
                       "critical", "CWE-78", source=source_label, sink=name or last,
                       origin=origin)
        elif last == "open" or name == "open" or last in ("send_file", "send_from_directory"):
            self._emit(call, "path-traversal", "path_traversal",
                       "Untrusted input reaches file path sink %s() (path traversal)" % (
                           name or last),
                       "high", "CWE-22", source=source_label, sink=name or last, origin=origin)
        elif name.startswith("requests.") and last in (
            "get", "post", "put", "delete", "patch", "head", "request"
        ) or last == "urlopen" or name in ("urllib.request.urlopen",) or (
            name.startswith("httpx.") and last in ("get", "post")
        ):
            self._emit(call, "ssrf", "ssrf",
                       "Untrusted input controls the target of %s() (SSRF)" % (name or last),
                       "high", "CWE-918", source=source_label, sink=name or last, origin=origin)

    @staticmethod
    def _yaml_is_safe(call: ast.Call, kwargs: dict[str, ast.expr]) -> bool:
        loader = kwargs.get("Loader")
        candidates = list(call.args[1:]) + ([loader] if loader is not None else [])
        for c in candidates:
            dotted = _dotted(c) or ""
            if "Safe" in dotted:
                return True
        return False

    def _origin_line(self, node: ast.expr, tainted: dict[str, dict[str, Any]]) -> Optional[int]:
        if isinstance(node, ast.Name):
            info = tainted.get(node.id)
            if info:
                return info.get("line")
        return getattr(node, "lineno", None)

    def _check_hardcoded(self, stmt: ast.stmt, value: ast.expr) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        if len(value.value) < 6:
            return
        low = value.value.lower()
        if any(p in low for p in ("example", "changeme", "placeholder", "your_", "xxxx", "<", "test")):
            return
        names: list[str] = []
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                names += self._target_names(t)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            names = [stmt.target.id]
        if not _looks_secret(value.value):
            return
        if any(_SECRET_NAME.search(n) for n in names):
            self._emit(stmt, "hardcoded-secret", "hardcoded_secret",
                       "Hardcoded credential/secret assigned to %s" % (names[0] if names else "var"),
                       "medium", "CWE-798", source="n/a", sink="literal", origin=None)

    def _emit(self, node: ast.AST, rule: str, cls: str, message: str, severity: str,
              cwe: str, *, source: Optional[str], sink: Optional[str],
              origin: Optional[int]) -> None:
        start = getattr(node, "lineno", 0) or 0
        end = getattr(node, "end_lineno", start) or start
        key = (rule, start)
        if key in self._seen:
            return
        self._seen.add(key)
        steps: list[dict[str, Any]] = []
        if source and source != "n/a":
            steps.append({"step": "source", "label": source,
                          "line": origin or start})
        if sink:
            steps.append({"step": "sink", "label": sink, "line": start})
        self.hits.append({
            "engine": ENGINE,
            "language": "python",
            "rule": rule,
            "rule_class": cls,
            "message": message,
            "severity": severity,
            "file": self.path,
            "start_line": start,
            "end_line": end,
            "source": source,
            "sink": sink,
            "dataflow": steps,
            "cwe": cwe,
        })


# ===========================================================================
# Regex scanning for JS/TS/Go
# ===========================================================================
def scan_regex(path: str, content: str, lang: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    rules = [r for r in _rules().get("regex_rules", []) if lang in r.get("languages", [])]
    if not rules:
        return hits
    lines = content.splitlines()
    seen: set[tuple[str, int]] = set()
    for i, line in enumerate(lines):
        # small window to catch args spilling onto the next lines
        window = "\n".join(lines[i:i + 3])
        first_len = len(lines[i])
        for rule in rules:
            try:
                m = re.search(rule["pattern"], window)
                # The window only lets arguments spill onto following lines;
                # a match that STARTS on a later line is that line's finding.
                if not m or m.start() > first_len:
                    continue
                reqs = rule.get("requires_any") or []
                if reqs and not any(re.search(p, window) for p in reqs):
                    continue
                forbid = rule.get("forbid_any") or []
                if forbid and any(re.search(p, window) for p in forbid):
                    continue
            except re.error:  # pragma: no cover - malformed rule
                continue
            key = (rule["id"], i + 1)
            if key in seen:
                continue
            seen.add(key)
            end = i + 1 + min(2, max(0, window.count("\n")))
            hits.append({
                "engine": ENGINE,
                "language": lang,
                "rule": rule["id"],
                "rule_class": rule["class"],
                "message": rule["message"],
                "severity": rule["severity"],
                "file": path,
                "start_line": i + 1,
                "end_line": end,
                "source": rule.get("source"),
                "sink": rule.get("sink"),
                "dataflow": [
                    {"step": "source", "label": rule.get("source") or "input", "line": i + 1},
                    {"step": "sink", "label": rule.get("sink") or rule["class"], "line": i + 1},
                ],
                "cwe": rule.get("cwe"),
            })
    return hits
