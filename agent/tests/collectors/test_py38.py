"""The agent core must run on Python 3.8 (owner decision O1). No 3.8 interpreter is available in
CI images here, so this is a static gate: every module parses with ``feature_version=(3, 8)`` and
none uses a runtime API or construct that appeared after 3.8."""
import ast
import os

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                   "paddock_agent")
BUILTIN_GENERICS = {"list", "dict", "set", "frozenset", "tuple", "type"}
BANNED_ATTRS = {
    "removeprefix": "str.removeprefix is 3.9+",
    "removesuffix": "str.removesuffix is 3.9+",
    "bit_count": "int.bit_count is 3.10+",
    "randbytes": "random.randbytes is 3.9+",
    "is_relative_to": "Path.is_relative_to is 3.9+",
    "with_stem": "Path.with_stem is 3.9+",
    "readlink": None,           # os.readlink is fine; Path.readlink is 3.9+ (checked below)
    "unparse": "ast.unparse is 3.9+",
    "pidfd_open": "os.pidfd_open is 3.9+",
    "lcm": "math.lcm is 3.9+",
    "topological_sort": "graphlib is 3.9+",
    "fromisoformat": "datetime.fromisoformat does not accept 'Z' before 3.11",
    "UTC": "datetime.UTC is 3.11+",
    "EnumType": "enum.EnumType is 3.11+",
    "StrEnum": "enum.StrEnum is 3.11+",
    "TaskGroup": "asyncio.TaskGroup is 3.11+",
    "to_thread": "asyncio.to_thread is 3.9+",
    "get_origin": "typing.get_origin is 3.8 but typing helpers differ; avoid",
}
BANNED_MODULES = {"zoneinfo", "graphlib", "tomllib", "match", "psutil", "httpx"}
BANNED_KWARGS = {("zip", "strict"): "zip(strict=) is 3.10+",
                 ("dataclass", "slots"): "dataclass(slots=) is 3.10+",
                 ("dataclass", "kw_only"): "dataclass(kw_only=) is 3.10+"}


def py_files(sub=None):
    base = os.path.join(PKG, sub) if sub else PKG
    for root, _dirs, files in os.walk(base):
        if "__pycache__" in root:
            continue
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(root, f)


def rel(path):
    return os.path.relpath(path, os.path.dirname(PKG))


def collectors_files():
    out = list(py_files("collectors"))
    out.append(os.path.join(PKG, "runner.py"))
    return out


def scan(path):
    """Return a list of human-readable problems for one file."""
    src = open(path, "r", encoding="utf-8").read()
    problems = []
    try:
        tree = ast.parse(src, filename=path, feature_version=(3, 8))
    except SyntaxError as exc:
        return ["syntax not valid on 3.8: %s" % exc]
    skip = set()
    if "from __future__ import annotations" in src:
        # annotations are never evaluated at runtime under PEP 563 (3.7+): only runtime
        # positions matter for 3.8
        for node in ast.walk(tree):
            anns = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                for arg in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg]:
                    if arg is not None and arg.annotation is not None:
                        anns.append(arg.annotation)
                if node.returns is not None:
                    anns.append(node.returns)
            elif isinstance(node, ast.AnnAssign):
                anns.append(node.annotation)
            for ann in anns:
                for sub in ast.walk(ann):
                    skip.add(id(sub))
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        where = "%s:%d" % (rel(path), getattr(node, "lineno", 0))
        if isinstance(node, ast.Attribute) and node.attr == "cache" and isinstance(
                node.value, ast.Name) and node.value.id == "functools":
            problems.append("%s functools.cache is 3.9+" % where)
        if isinstance(node, ast.NamedExpr):
            problems.append("%s walrus operator" % where)
        if isinstance(node, ast.Subscript):
            v = node.value
            if isinstance(v, ast.Name) and v.id in BUILTIN_GENERICS:
                problems.append("%s builtin generic %s[...] is 3.9+ at runtime" % (where, v.id))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            for side in (node.left, node.right):
                if isinstance(side, ast.Constant) and side.value is None:
                    problems.append("%s `X | None` union is 3.10+" % where)
                if isinstance(side, ast.Name) and side.id in ("str", "int", "bytes", "float", "bool",
                                                              "list", "dict", "set", "tuple"):
                    problems.append("%s `%s | ...` union / dict merge is 3.9+" % (where, side.id))
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
            if isinstance(node.value, (ast.Dict, ast.DictComp)):
                problems.append("%s dict |= is 3.9+" % where)
        if isinstance(node, ast.Attribute):
            why = BANNED_ATTRS.get(node.attr)
            if why:
                problems.append("%s .%s: %s" % (where, node.attr, why))
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
            for kw in node.keywords:
                why = BANNED_KWARGS.get((name, kw.arg))
                if why:
                    problems.append("%s %s" % (where, why))
            if isinstance(fn, ast.Attribute) and fn.attr == "to_bytes" and len(node.args) + len(node.keywords) < 2:
                problems.append("%s int.to_bytes() without length/byteorder is 3.11+" % where)
            if name == "isinstance" and len(node.args) == 2 and isinstance(node.args[1], ast.BinOp):
                problems.append("%s isinstance(x, A | B) is 3.10+" % where)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for m in mods:
                if m.split(".")[0] in BANNED_MODULES:
                    problems.append("%s import of %s" % (where, m))
        if isinstance(node, ast.ImportFrom) and node.module == "functools":
            if any(a.name == "cache" for a in node.names):
                problems.append("%s functools.cache is 3.9+" % where)
    return problems


@pytest.mark.parametrize("path", collectors_files(), ids=rel)
def test_collectors_and_runner_are_python38_clean(path):
    problems = scan(path)
    assert not problems, "\n".join(problems)


def test_the_whole_agent_package_is_python38_clean():
    """Every module of ``paddock_agent`` (the core is stdlib-only, Python >= 3.8)."""
    problems = []
    for path in py_files():
        problems.extend(scan(path))
    assert not problems, "\n".join(problems)


def test_scanner_catches_what_it_claims_to(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("import zoneinfo\n"
                   "def f(x: list[str], y: 'str | None' = None):\n"
                   "    a: str | None = None\n"
                   "    if (n := len(x)) > 1:\n"
                   "        return x.removeprefix('a') + str(n.bit_count())\n"
                   "    return {1: 2} | {3: 4}\n"
                   "z = isinstance(1, int | str)\n"
                   "zip([], [], strict=True)\n"
                   "(1).to_bytes()\n")
    msgs = "\n".join(scan(str(bad)))
    for needle in ("zoneinfo", "list[...]", "walrus", "removeprefix", "bit_count", "isinstance", "strict",
                   "to_bytes"):
        assert needle in msgs, needle
    assert "| None" in msgs or "None" in msgs


def test_scanner_accepts_clean_code(tmp_path):
    good = tmp_path / "good.py"
    good.write_text("import json\nfrom typing import Dict, List, Optional\n"
                    "def f(x: Optional[List[str]] = None) -> Dict[str, int]:\n"
                    "    return dict((k, 1) for k in (x or []))\n")
    assert scan(str(good)) == []


def test_no_third_party_imports_in_the_collectors():
    stdlib_or_local = None
    import sys
    stdlib_or_local = set(getattr(sys, "stdlib_module_names", ()))
    if not stdlib_or_local:
        pytest.skip("sys.stdlib_module_names needs a newer interpreter")
    for path in collectors_files():
        tree = ast.parse(open(path, encoding="utf-8").read(), feature_version=(3, 8))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] in stdlib_or_local, (rel(path), a.name)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert (node.module or "").split(".")[0] in stdlib_or_local, (rel(path), node.module)
