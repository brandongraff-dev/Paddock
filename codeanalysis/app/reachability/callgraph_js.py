"""Lightweight JS/TS import + symbol scan.

This is a text scan (not a full parser): it reads ``import`` / ``require``
bindings and records which imported symbols are *used* in the file body. Usage
is attributed to the module entrypoint, so a used symbol grades ``reachable``,
an imported-but-unused symbol grades ``potential``, and a never-imported module
grades ``unreachable``. Conservative by design (favours recall). Source is read
as text only -- never evaluated.
"""
from __future__ import annotations

import re

from .grade import MODULE_NODE, CallGraph

_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

# import {a, b as c} from 'mod';  import def from 'mod';  import * as ns from 'mod'
_IMPORT_FROM = re.compile(
    r"""import\s+(?P<spec>[^;'"]+?)\s+from\s*['"](?P<mod>[^'"]+)['"]""",
    re.MULTILINE,
)
# bare side-effect import:  import 'mod';
_IMPORT_BARE = re.compile(r"""import\s*['"](?P<mod>[^'"]+)['"]""")
# const x = require('mod');  const {a,b} = require('mod')
_REQUIRE = re.compile(
    r"""(?:const|let|var)\s+(?P<bind>\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""",
)


def supports(path: str) -> bool:
    return path.endswith(_EXTS)


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


def _is_bare(mod: str) -> bool:
    return bool(mod) and not mod.startswith((".", "/"))


def _scan_file(path: str, content: str, cg: CallGraph) -> None:
    node = f"{path}::{MODULE_NODE}"
    cg.add_entrypoint(node)
    code = _strip_comments(content)

    # alias -> {"module": spec, "fq": fq-base}
    aliases: dict[str, dict[str, str]] = {}

    def record_import(mod: str) -> None:
        if _is_bare(mod):
            cg.imported_modules.add(mod)

    for m in _IMPORT_FROM.finditer(code):
        mod = m.group("mod")
        record_import(mod)
        if not _is_bare(mod):
            continue
        _parse_es_spec(m.group("spec"), mod, aliases)
    for m in _IMPORT_BARE.finditer(code):
        record_import(m.group("mod"))
    for m in _REQUIRE.finditer(code):
        mod = m.group("mod")
        record_import(mod)
        if not _is_bare(mod):
            continue
        _parse_require_bind(m.group("bind"), mod, aliases)

    for alias, info in aliases.items():
        _record_usages(code, alias, info, node, cg)


def _parse_es_spec(spec: str, mod: str, aliases: dict[str, dict[str, str]]) -> None:
    spec = spec.strip()
    # namespace:  * as ns
    ns = re.match(r"\*\s+as\s+([A-Za-z_$][\w$]*)", spec)
    if ns:
        aliases[ns.group(1)] = {"module": mod, "fq": mod}
        return
    # default + maybe named:  def, {a, b as c}
    brace = re.search(r"\{([^}]*)\}", spec)
    default_part = spec.split("{", 1)[0].strip().rstrip(",").strip()
    if default_part and re.match(r"^[A-Za-z_$][\w$]*$", default_part):
        aliases[default_part] = {"module": mod, "fq": mod}
    if brace:
        for piece in brace.group(1).split(","):
            piece = piece.strip()
            if not piece:
                continue
            parts = re.split(r"\s+as\s+", piece)
            orig = parts[0].strip()
            alias = parts[-1].strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", alias) and re.match(r"^[A-Za-z_$][\w$]*$", orig):
                aliases[alias] = {"module": mod, "fq": f"{mod}.{orig}"}


def _parse_require_bind(bind: str, mod: str, aliases: dict[str, dict[str, str]]) -> None:
    bind = bind.strip()
    if bind.startswith("{"):
        for piece in bind.strip("{}").split(","):
            piece = piece.strip()
            if not piece:
                continue
            parts = re.split(r"\s*:\s*", piece)
            orig = parts[0].strip()
            alias = parts[-1].strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", alias):
                aliases[alias] = {"module": mod, "fq": f"{mod}.{orig}"}
    elif re.match(r"^[A-Za-z_$][\w$]*$", bind):
        aliases[bind] = {"module": mod, "fq": mod}


def _record_usages(code: str, alias: str, info: dict[str, str], node: str, cg: CallGraph) -> None:
    fq = info["fq"]
    esc = re.escape(alias)
    # attribute access: alias.attr
    found_attr = False
    for m in re.finditer(r"\b" + esc + r"\.([A-Za-z_$][\w$]*)", code):
        cg.add_symbol(node, f"{fq}.{m.group(1)}")
        found_attr = True
    # direct use (call / reference) of a named/default binding
    if re.search(r"\b" + esc + r"\s*\(", code) or (
        not found_attr and len(re.findall(r"\b" + esc + r"\b", code)) > 0
    ):
        cg.add_symbol(node, fq)
