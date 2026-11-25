"""Owner decision O1: the agent runs on Python >= 3.8 with the standard library only.

There is no 3.8 interpreter in this repo's CI image, so this is a static gate over EVERY module of
``paddock_agent`` (core and collectors): the syntax must parse with ``feature_version=(3, 8)``, nothing may
use a runtime API or construct newer than 3.8, and nothing outside the standard library may be imported
(``cryptography`` is the single permitted optional import, only inside ``signing.py``)."""
import ast
import os
import re
import sys

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paddock_agent")
ROOT = os.path.dirname(PKG)

GENERICS = {"list", "dict", "set", "frozenset", "tuple", "type"}
BANNED_ATTRS = {
    "removeprefix": "str.removeprefix is 3.9+", "removesuffix": "str.removesuffix is 3.9+",
    "bit_count": "int.bit_count is 3.10+", "randbytes": "random.randbytes is 3.9+",
    "is_relative_to": "Path.is_relative_to is 3.9+", "with_stem": "Path.with_stem is 3.9+",
    "unparse": "ast.unparse is 3.9+", "lcm": "math.lcm is 3.9+", "to_thread": "asyncio.to_thread is 3.9+",
    "fromisoformat": "datetime.fromisoformat does not accept 'Z' before 3.11",
    "UTC": "datetime.UTC is 3.11+", "StrEnum": "enum.StrEnum is 3.11+", "TaskGroup": "asyncio.TaskGroup is 3.11+",
    "waitstatus_to_exitcode": "os.waitstatus_to_exitcode is 3.9+", "file_digest": "hashlib.file_digest is 3.11+",
    "pidfd_open": "os.pidfd_open is 3.9+", "stdlib_module_names": "sys.stdlib_module_names is 3.10+",
    "TypeAlias": "typing.TypeAlias is 3.10+", "ParamSpec": "typing.ParamSpec is 3.10+",
    "Self": "typing.Self is 3.11+", "Annotated": "typing.Annotated is 3.9+",
    "get_origin": "typing.get_origin: avoid",
}
BANNED_MODULES = {"zoneinfo", "graphlib", "tomllib", "psutil", "httpx", "requests", "yaml", "six"}
BANNED_KWARGS = {("zip", "strict"): "zip(strict=) is 3.10+", ("dataclass", "slots"): "dataclass(slots=) is 3.10+",
                 ("dataclass", "kw_only"): "dataclass(kw_only=) is 3.10+"}


def package_files():
    for root, _dirs, files in os.walk(PKG):
        if "__pycache__" in root:
            continue
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(root, f)


def rel(path):
    return os.path.relpath(path, ROOT)


def scan(path, src=None):
    src = open(path, encoding="utf-8").read() if src is None else src
    try:
        tree = ast.parse(src, filename=path, feature_version=(3, 8))
    except SyntaxError as exc:
        return ["not valid Python 3.8 syntax: %s" % exc]
    future_ann = "from __future__ import annotations" in src
    skip = set()
    if future_ann:      # annotations are strings under PEP 563 (3.7+): not evaluated at runtime
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
    problems = []
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        where = "%s:%d" % (rel(path), getattr(node, "lineno", 0))
        if isinstance(node, ast.NamedExpr):
            problems.append("%s walrus operator" % where)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in GENERICS:
            problems.append("%s builtin generic %s[...] at runtime is 3.9+" % (where, node.value.id))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            for side in (node.left, node.right):
                if isinstance(side, ast.Constant) and side.value is None:
                    problems.append("%s `X | None` is 3.10+" % where)
                if isinstance(side, ast.Name) and side.id in GENERICS | {"str", "int", "bytes", "float", "bool"}:
                    problems.append("%s `%s | ...` is 3.9+/3.10+" % (where, side.id))
                if isinstance(side, ast.Dict):
                    problems.append("%s dict | dict is 3.9+" % where)
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr) and isinstance(node.value, ast.Dict):
            problems.append("%s dict |= is 3.9+" % where)
        if isinstance(node, ast.Attribute):
            why = BANNED_ATTRS.get(node.attr)
            if why:
                problems.append("%s .%s: %s" % (where, node.attr, why))
            if node.attr == "cache" and isinstance(node.value, ast.Name) and node.value.id == "functools":
                problems.append("%s functools.cache is 3.9+" % where)
            if node.attr == "readlink" and isinstance(node.value, ast.Call) and getattr(
                    node.value.func, "id", getattr(node.value.func, "attr", "")) == "Path":
                problems.append("%s Path.readlink is 3.9+" % where)
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
            for kw in node.keywords:
                why = BANNED_KWARGS.get((name, kw.arg))
                if why:
                    problems.append("%s %s" % (where, why))
            if isinstance(fn, ast.Attribute) and fn.attr in ("to_bytes", "from_bytes"):
                if len(node.args) + len(node.keywords) < 2:
                    problems.append("%s int.%s() without byteorder is 3.11+" % (where, fn.attr))
            if name == "isinstance" and len(node.args) == 2 and isinstance(node.args[1], ast.BinOp):
                problems.append("%s isinstance(x, A | B) is 3.10+" % where)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for m in mods:
                if m.split(".")[0] in BANNED_MODULES:
                    problems.append("%s import of %s" % (where, m))
        if isinstance(node, ast.ImportFrom) and node.module == "functools" and any(
                a.name == "cache" for a in node.names):
            problems.append("%s functools.cache is 3.9+" % where)
    return problems


@pytest.mark.parametrize("path", list(package_files()), ids=rel)
def test_module_is_python38_clean(path):
    problems = scan(path)
    assert not problems, "\n".join(problems)


def test_only_the_standard_library_is_imported_apart_from_optional_cryptography():
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    if not stdlib:
        pytest.skip("sys.stdlib_module_names needs a newer interpreter")
    for path in package_files():
        tree = ast.parse(open(path, encoding="utf-8").read(), feature_version=(3, 8))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods = [node.module or ""]
            for m in mods:
                top = m.split(".")[0]
                if top == "cryptography":
                    assert os.path.basename(path) == "signing.py", "%s may not import cryptography" % rel(path)
                    continue
                assert top in stdlib or top == "paddock_agent", "%s imports non-stdlib %s" % (rel(path), m)


def test_cryptography_is_imported_lazily_so_a_broken_wheel_cannot_break_the_agent():
    tree = ast.parse(open(os.path.join(PKG, "signing.py"), encoding="utf-8").read())
    for node in tree.body:       # module level: no cryptography import
        assert not (isinstance(node, (ast.Import, ast.ImportFrom)) and "cryptography" in ast.dump(node))


def test_the_package_declares_python38_and_no_dependencies():
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert re.search(r'requires-python\s*=\s*">=3\.8"', text)
    assert not re.search(r"httpx|psutil", text)
    m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
    assert m is None or not m.group(1).strip()


def test_scanner_catches_what_it_claims_to(tmp_path):
    bad = "\n".join([
        "import zoneinfo, psutil",
        "def f(x: list[str]):",                        # runtime annotation (no __future__): flagged below
        "    a = list[int]",
        "    if (n := len(x)) > 1:",
        "        return x.removeprefix('a') + str(n.bit_count())",
        "    b = {1: 2} | {3: 4}",
        "    c = int | None",
        "    return isinstance(1, int | str), zip([], [], strict=True), (1).to_bytes(), int.from_bytes(b'x'),",
        "import datetime; datetime.datetime.fromisoformat('2020-01-01T00:00:00Z')",
        "match = 1",
    ])
    msgs = "\n".join(scan("bad.py", bad))
    for needle in ("zoneinfo", "psutil", "walrus", "removeprefix", "bit_count", "dict | dict", "isinstance",
                   "strict", "to_bytes", "from_bytes", "fromisoformat", "builtin generic"):
        assert needle in msgs, needle
    assert scan("syn.py", "match x:\n    case 1:\n        pass\n")       # 3.10 syntax does not parse as 3.8


def test_scanner_accepts_clean_code():
    good = ("from __future__ import annotations\nimport json\nfrom typing import Dict, List, Optional\n"
            "def f(x: Optional[List[str]] = None, y: dict[str, int] = None) -> Dict[str, int]:\n"
            "    return dict((k, 1) for k in (x or []))\n")
    assert scan("good.py", good) == []
