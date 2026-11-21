"""Lightweight Go package/func reference scan.

Reads ``import`` declarations (single and block form) and records which
imported-package functions are referenced in the file. References are recorded
against the full import path so they match govulncheck-style advisory symbols
(``affected[].ecosystem_specific.imports[] = {path, symbols}``). Source is read
as text only -- never compiled or run.
"""
from __future__ import annotations

import re

from .grade import MODULE_NODE, CallGraph

_IMPORT_BLOCK = re.compile(r"import\s*\((?P<body>.*?)\)", re.DOTALL)
_IMPORT_LINE = re.compile(r'import\s+(?:(?P<alias>[A-Za-z_.][\w]*)\s+)?"(?P<path>[^"]+)"')
_BLOCK_ENTRY = re.compile(r'(?:(?P<alias>[A-Za-z_.][\w]*)\s+)?"(?P<path>[^"]+)"')


def supports(path: str) -> bool:
    return path.endswith(".go")


def build(files: dict[str, str]) -> CallGraph:
    cg = CallGraph()
    for path, content in files.items():
        if not supports(path):
            continue
        if not isinstance(content, str):
            cg.files_skipped += 1
            continue
        try:
            _scan_file(path, content, cg)
            cg.files_parsed += 1
        except Exception:  # pragma: no cover
            cg.files_skipped += 1
    return cg


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def _default_alias(import_path: str) -> str:
    last = import_path.rstrip("/").split("/")[-1]
    # gopkg.in/yaml.v2 -> yaml
    last = re.sub(r"\.v\d+$", "", last)
    return last


def _scan_file(path: str, content: str, cg: CallGraph) -> None:
    node = f"{path}::{MODULE_NODE}"
    cg.add_entrypoint(node)
    code = _strip_comments(content)

    aliases: dict[str, str] = {}  # alias -> full import path

    def add(alias: str | None, import_path: str) -> None:
        if not import_path:
            return
        cg.imported_modules.add(import_path)
        use_alias = alias if alias and alias not in ("_", ".") else _default_alias(import_path)
        aliases[use_alias] = import_path

    for block in _IMPORT_BLOCK.finditer(code):
        for entry in _BLOCK_ENTRY.finditer(block.group("body")):
            add(entry.group("alias"), entry.group("path"))
    # single-line imports (outside blocks)
    for m in _IMPORT_LINE.finditer(code):
        add(m.group("alias"), m.group("path"))

    for alias, import_path in aliases.items():
        esc = re.escape(alias)
        for m in re.finditer(r"\b" + esc + r"\.([A-Za-z_][\w]*)", code):
            cg.add_symbol(node, f"{import_path}.{m.group(1)}")
