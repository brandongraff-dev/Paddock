"""Per-language call-graph construction + dependency-vuln reachability grading.

Supported first-party languages:
  * Python   -- precise, via the ``ast`` module (defs, calls, imports)
  * JS/TS    -- lightweight import+symbol scan
  * Go       -- package/func reference scan

``build_callgraph`` routes each file by extension and merges a single
``CallGraph``. Unparseable files are skipped, never raised.
"""
from __future__ import annotations

from typing import Any

from . import callgraph_go, callgraph_js, callgraph_py
from .grade import (
    CallGraph,
    grade,
    symbol_matches,
    symbols_from_osv,
    symbols_from_row,
)

__all__ = [
    "CallGraph", "grade", "symbol_matches", "symbols_from_osv", "symbols_from_row",
    "build_callgraph", "module_for",
]

_PY_EXTS = (".py", ".pyi")


def build_callgraph(files: dict[str, str]) -> CallGraph:
    py = {k: v for k, v in files.items() if k.endswith(_PY_EXTS)}
    js = {k: v for k, v in files.items() if callgraph_js.supports(k)}
    go = {k: v for k, v in files.items() if callgraph_go.supports(k)}

    cg = CallGraph()
    cg.merge(callgraph_py.build(py))
    cg.merge(callgraph_js.build(js))
    cg.merge(callgraph_go.build(go))
    return cg


# PyPI distribution names whose import module differs from the package name.
_PYPI_IMPORT = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "msgpack-python": "msgpack",
    "attrs": "attr",
}


def module_for(ecosystem: str | None, name: str | None) -> str:
    """Best-effort mapping from an SBOM component to its import module/path."""
    if not name:
        return ""
    if ecosystem == "PyPI":
        key = name.lower().replace("_", "-")
        return _PYPI_IMPORT.get(key, name.replace("-", "_"))
    # npm / Go / others: the package name is (close enough to) the import id
    return name


def grade_vuln(cg: CallGraph, *, ecosystem: str | None, name: str | None,
               symbols: list[str]) -> dict[str, Any]:
    """Grade a single dependency vuln row against the call graph."""
    module = module_for(ecosystem, name)
    return grade(cg, module, symbols)
