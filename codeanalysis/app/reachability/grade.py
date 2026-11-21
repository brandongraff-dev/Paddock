"""Reachability call-graph model + grading.

A ``CallGraph`` is a language-agnostic summary of first-party code:

  * ``imported_modules`` -- modules/packages first-party code imports
  * ``entrypoints``      -- node ids reachable "for free" (module top-level,
    ``main``, route/handler/task functions)
  * ``edges``            -- first-party call edges (caller node -> callee node)
  * ``node_symbols``     -- external dotted symbols each node references,
    e.g. ``requests.get``, ``lodash.merge``, ``os.system``

Grading a dependency vuln against the graph yields one of:
  * ``reachable``   -- a path exists from an entrypoint to the vulnerable symbol
  * ``potential``   -- the package is imported but the symbol is not clearly hit
  * ``unreachable`` -- the package is not imported at all
  * ``unknown``     -- the advisory names no symbol, or there is no source

Everything here is pure and deterministic: no I/O, no code execution.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

# dotted symbol reference points INTO a dependency module. The last component
# is the function/attribute; the rest identify the module.
MODULE_NODE = "<module>"


@dataclass
class CallGraph:
    imported_modules: set[str] = field(default_factory=set)
    entrypoints: set[str] = field(default_factory=set)
    edges: dict[str, set[str]] = field(default_factory=dict)
    node_symbols: dict[str, set[str]] = field(default_factory=dict)
    files_parsed: int = 0
    files_skipped: int = 0

    # -- construction helpers --------------------------------------------
    def add_edge(self, caller: str, callee: str) -> None:
        self.edges.setdefault(caller, set()).add(callee)

    def add_symbol(self, node: str, symbol: str) -> None:
        self.node_symbols.setdefault(node, set()).add(symbol)

    def add_entrypoint(self, node: str) -> None:
        self.entrypoints.add(node)

    def merge(self, other: "CallGraph") -> None:
        self.imported_modules |= other.imported_modules
        self.entrypoints |= other.entrypoints
        for k, v in other.edges.items():
            self.edges.setdefault(k, set()).update(v)
        for k, v in other.node_symbols.items():
            self.node_symbols.setdefault(k, set()).update(v)
        self.files_parsed += other.files_parsed
        self.files_skipped += other.files_skipped

    # -- querying --------------------------------------------------------
    def has_source(self) -> bool:
        return self.files_parsed > 0

    def is_imported(self, module: str) -> bool:
        if not module:
            return False
        m = module.strip()
        for im in self.imported_modules:
            if im == m or im.startswith(m + ".") or im.startswith(m + "/") \
               or m.startswith(im + ".") or m.startswith(im + "/"):
                return True
            # Go import paths: module may be a path suffix (e.g. "yaml.v2")
            if "/" in im and (im.endswith("/" + m) or im.split("/")[-1] == m):
                return True
        return False

    def nodes_referencing(self, module: str, symbols: list[str]) -> list[tuple[str, str]]:
        """First-party nodes that reference one of the vulnerable symbols.

        Returns ``(node_id, matched_symbol)`` pairs.
        """
        hits: list[tuple[str, str]] = []
        for node, refs in self.node_symbols.items():
            for ref in refs:
                m = symbol_matches(ref, module, symbols)
                if m:
                    hits.append((node, m))
                    break
        return hits

    def path_from_entrypoint(self, target: str) -> Optional[list[str]]:
        """Shortest call path from any entrypoint to ``target`` node (BFS)."""
        if target in self.entrypoints:
            return [target]
        # reverse BFS from entrypoints forward along edges
        seen: set[str] = set(self.entrypoints)
        q: deque[list[str]] = deque([ep] for ep in sorted(self.entrypoints))
        while q:
            path = q.popleft()
            last = path[-1]
            for callee in sorted(self.edges.get(last, set())):
                if callee == target:
                    return path + [callee]
                if callee not in seen:
                    seen.add(callee)
                    q.append(path + [callee])
        return None


def symbol_matches(ref: str, module: str, symbols: list[str]) -> Optional[str]:
    """Does external reference ``ref`` hit one of the advisory ``symbols``?

    Matches on the fully-qualified form (``module.symbol``), a dotted suffix
    (``*.symbol`` where the module appears in the reference), or a bare symbol
    name. Returns the matched symbol, or None.
    """
    if not ref or not symbols:
        return None
    ref_last = ref.split(".")[-1]
    mod_base = (module or "").split(".")[-1].split("/")[-1]
    for sym in symbols:
        if not sym:
            continue
        sym_last = sym.split(".")[-1]
        # exact fully-qualified
        if ref == sym or ref == f"{module}.{sym}":
            return sym
        # module-qualified suffix: ref like "mod.sub.Func" and module present
        if ref_last == sym_last:
            if module and (module in ref or mod_base in ref):
                return sym
            # bare symbol match when advisory symbol itself is qualified
            if "." in sym:
                return sym
    return None


def grade(cg: CallGraph, module: str, symbols: list[str]) -> dict[str, Any]:
    """Grade one dependency vuln. Deterministic.

    Returns ``{reachability, reachable_symbol, call_path}``.
    """
    symbols = [s for s in (symbols or []) if s]
    if not cg.has_source() or not symbols:
        return {"reachability": "unknown", "reachable_symbol": None, "call_path": []}

    if not cg.is_imported(module):
        return {"reachability": "unreachable", "reachable_symbol": None, "call_path": []}

    hits = cg.nodes_referencing(module, symbols)
    if not hits:
        # imported, but the vulnerable symbol itself is never referenced
        return {"reachability": "potential", "reachable_symbol": None, "call_path": []}

    # a referencing node reachable from an entrypoint => reachable
    best: Optional[tuple[list[str], str]] = None
    for node, sym in hits:
        path = cg.path_from_entrypoint(node)
        if path is not None:
            if best is None or len(path) < len(best[0]):
                best = (path + [f"{module}.{sym}"], sym)
    if best is not None:
        return {
            "reachability": "reachable",
            "reachable_symbol": best[1],
            "call_path": best[0],
        }
    # referenced but not on any entrypoint path
    return {
        "reachability": "potential",
        "reachable_symbol": hits[0][1],
        "call_path": [],
    }


# ---------------------------------------------------------------------------
# advisory symbol extraction
# ---------------------------------------------------------------------------
def symbols_from_osv(vuln: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Extract (module, [symbols]) pairs from a full OSV advisory detail.

    Uses the govulncheck-style ``affected[].ecosystem_specific.imports[]``
    ({path, symbols}) and any ``database_specific`` symbol hints.
    """
    out: list[tuple[str, list[str]]] = []
    for aff in (vuln.get("affected") or []):
        if not isinstance(aff, dict):
            continue
        es = aff.get("ecosystem_specific") or {}
        for imp in (es.get("imports") or []):
            if not isinstance(imp, dict):
                continue
            path = str(imp.get("path") or "")
            syms = [str(s) for s in (imp.get("symbols") or []) if s]
            if path and syms:
                out.append((path, syms))
        ds = aff.get("database_specific") or {}
        syms = [str(s) for s in (ds.get("symbols") or []) if s]
        if syms:
            pkg = (aff.get("package") or {}).get("name")
            out.append((str(pkg or ""), syms))
    return out


def symbols_from_row(refs: Any, summary: Optional[str], package: str) -> list[str]:
    """Best-effort symbol extraction from a stored ``sbom_component_vulns`` row.

    ``refs`` may carry structured entries ({symbol|symbols|path}); the summary
    is parsed only for clearly dotted/back-ticked identifiers. When nothing is
    confidently found the caller treats the vuln as ``unknown`` (never guesses).
    """
    syms: list[str] = []
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, dict):
                if r.get("symbol"):
                    syms.append(str(r["symbol"]))
                for s in (r.get("symbols") or []):
                    if s:
                        syms.append(str(s))
    syms += _symbols_from_summary(summary or "", package)
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for s in syms:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


_IDENT = "A-Za-z_][A-Za-z0-9_"


def _symbols_from_summary(summary: str, package: str) -> list[str]:
    import re
    out: list[str] = []
    # back-ticked identifiers: `foo.bar` or `Baz`
    for m in re.findall(r"`([" + _IDENT + r".]*)`", summary):
        tok = m.strip().strip(".")
        if tok and not tok.isdigit():
            out.append(tok)
    # package.symbol() or package.Symbol references in prose
    if package:
        esc = re.escape(package.split("/")[-1])
        for m in re.findall(esc + r"\.([" + _IDENT + r"]*)", summary):
            if m:
                out.append(m)
    return out
