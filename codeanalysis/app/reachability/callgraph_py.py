"""Python call-graph builder (read-only ``ast`` parse).

Source files are parsed into an AST and inspected. They are NEVER imported,
executed, compiled to a module, or ``eval``/``exec``'d -- ``ast.parse`` builds
a syntax tree from text only.
"""
from __future__ import annotations

import ast
from typing import Optional

from .grade import MODULE_NODE, CallGraph

# decorator name fragments that mark a top-level function as an entrypoint
_ENTRY_DECOS = (
    "route", "get", "post", "put", "patch", "delete", "websocket",
    "handler", "task", "command", "cli", "endpoint", "schedule", "cron",
    "lambda_handler", "main",
)


def build(files: dict[str, str]) -> CallGraph:
    cg = CallGraph()
    for path, content in files.items():
        if not isinstance(content, str):
            cg.files_skipped += 1
            continue
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            cg.files_skipped += 1
            continue
        try:
            _FileVisitor(path, cg).run(tree)
            cg.files_parsed += 1
        except Exception:  # pragma: no cover - never let one file break a scan
            cg.files_skipped += 1
    return cg


def _attr_chain(node: ast.AST) -> Optional[list[str]]:
    """Return dotted-name parts for a Name/Attribute chain, else None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return None


def _deco_names(fn: ast.AST) -> list[str]:
    out: list[str] = []
    for d in getattr(fn, "decorator_list", []) or []:
        target = d.func if isinstance(d, ast.Call) else d
        chain = _attr_chain(target) if isinstance(target, (ast.Name, ast.Attribute)) else None
        if chain:
            out.append(chain[-1].lower())
            out.append(".".join(chain).lower())
    return out


class _FileVisitor:
    def __init__(self, path: str, cg: CallGraph) -> None:
        self.path = path
        self.cg = cg
        # alias -> {"module": top-level dep module, "fq": fully-qualified base}
        self.imports: dict[str, dict[str, str]] = {}
        # simple function name -> node id (for first-party edge resolution)
        self.func_nodes: dict[str, str] = {}

    def node_id(self, qual: str) -> str:
        return f"{self.path}::{qual}"

    def run(self, tree: ast.Module) -> None:
        self._collect_imports(tree)
        self._collect_func_names(tree)
        module_node = self.node_id(MODULE_NODE)
        self.cg.add_entrypoint(module_node)
        # top-level statements run at import/module scope => the module node
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._visit_function(stmt, parent=MODULE_NODE, top_level=True)
            elif isinstance(stmt, ast.ClassDef):
                self._visit_class(stmt)
            else:
                self._scan_body([stmt], module_node)

    # -- imports ---------------------------------------------------------
    def _collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    asname = alias.asname or alias.name.split(".")[0]
                    self.imports[asname] = {"module": mod, "fq": mod}
                    self.cg.imported_modules.add(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import = first-party, not a dependency
                mod = node.module or ""
                if not mod:
                    continue
                self.cg.imported_modules.add(mod)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    asname = alias.asname or alias.name
                    self.imports[asname] = {
                        "module": mod, "fq": f"{mod}.{alias.name}"
                    }

    def _collect_func_names(self, tree: ast.Module) -> None:
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.func_nodes[stmt.name] = self.node_id(stmt.name)
            elif isinstance(stmt, ast.ClassDef):
                for sub in stmt.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.func_nodes[sub.name] = self.node_id(f"{stmt.name}.{sub.name}")

    # -- functions / classes --------------------------------------------
    def _visit_class(self, cls: ast.ClassDef) -> None:
        for sub in cls.body:
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._visit_function(sub, parent=f"{cls.name}.{sub.name}",
                                     top_level=True, qual=f"{cls.name}.{sub.name}")

    def _visit_function(self, fn: ast.AST, *, parent: str, top_level: bool,
                        qual: Optional[str] = None) -> None:
        name = getattr(fn, "name", "<anon>")
        q = qual or name
        node = self.node_id(q)
        if top_level:
            decos = _deco_names(fn)
            if name == "main" or any(
                frag in d for d in decos for frag in _ENTRY_DECOS
            ):
                self.cg.add_entrypoint(node)
        self._scan_body(getattr(fn, "body", []), node)

    # -- body scan (calls -> edges + external symbols) -------------------
    def _scan_body(self, body: list[ast.stmt], node: str) -> None:
        for stmt in body:
            for sub in ast.walk(stmt):
                # don't descend into nested function defs here; they are their
                # own nodes (collected only when top-level/class). Nested local
                # defs are rare; their calls still attribute to this node which
                # is a safe over-approximation for reachability.
                if isinstance(sub, ast.Call):
                    self._handle_call(sub, node)

    def _handle_call(self, call: ast.Call, node: str) -> None:
        chain = _attr_chain(call.func)
        if not chain:
            return
        base = chain[0]
        rest = chain[1:]
        if base in self.imports:
            imp = self.imports[base]
            fq = imp["fq"]
            if rest:
                fq = fq + "." + ".".join(rest)
            self.cg.add_symbol(node, fq)
        elif not rest and base in self.func_nodes:
            # first-party call edge
            callee = self.func_nodes[base]
            if callee != node:
                self.cg.add_edge(node, callee)
