# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard stays a movable, stdlib-only subpackage (contract D4, D31, 3.11 H1, 10.1; acceptance 9, 10, 13)."""
from __future__ import annotations

import ast
import os
import subprocess
import shutil
import sys
from pathlib import Path


GUARD_DIR = Path(__file__).resolve().parents[2] / "paddock_cli" / "guard"
SUPPORT_DIR = Path(__file__).resolve().parent
PKG = "paddock_cli.guard"
SPDX = "# SPDX-License-Identifier: AGPL-3.0-or-later"
STDLIB = set(sys.stdlib_module_names)
DYNAMIC_IMPORT_OK = {"registry.py", "cli.py"}
WRITE_OK = {"files.py"}

_WRITE_OS = {"open", "replace", "rename", "remove", "unlink", "mkdir", "makedirs", "rmdir", "write", "truncate",
             "symlink", "link", "chmod", "chown", "mkfifo", "removedirs", "renames", "fchmod", "ftruncate"}
_WRITE_ATTRS = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to", "mkdir", "unlink", "rmdir"}
_WRITE_MODULES = {"shutil", "tempfile"}
_BANNED_MODULES = {"pickle", "marshal", "shelve", "dill", "cPickle", "ctypes"}


def guard_files():
    return sorted(p for p in GUARD_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def package_of(path: Path) -> str:
    rel = path.relative_to(GUARD_DIR.parent.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        return ".".join(parts[:-1])
    return ".".join(parts[:-1])


def resolve_from(path: Path, node: ast.ImportFrom) -> str:
    """Absolute module of a ``from`` import (level plus module, resolved against the file's package)."""
    if node.level == 0:
        return node.module or ""
    pkg = package_of(path).split(".")
    base = pkg[: len(pkg) - (node.level - 1)] if node.level - 1 <= len(pkg) else []
    return ".".join(base + ([node.module] if node.module else []))


def _ok_module(name: str) -> bool:
    if name == PKG or name.startswith(PKG + "."):
        return True
    return name.split(".")[0] in STDLIB


def test_every_import_resolves_to_stdlib_or_the_guard_package():
    bad = []
    for path in guard_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if not _ok_module(a.name):
                        bad.append("%s imports %s" % (path.name, a.name))
            elif isinstance(node, ast.ImportFrom):
                mod = resolve_from(path, node)
                if not _ok_module(mod):
                    bad.append("%s imports from %s" % (path.name, mod))
    assert bad == []


def test_the_resolver_flags_a_relative_import_that_climbs_out(tmp_path):
    f = GUARD_DIR / "checks" / "x.py"
    assert resolve_from(f, ast.parse("from .. import ui").body[0]) == PKG
    assert resolve_from(f, ast.parse("from ... import ui").body[0]) == "paddock_cli"
    assert resolve_from(f, ast.parse("from ...model import Finding").body[0]) == "paddock_cli.model"
    assert not _ok_module("paddock_cli.model") and not _ok_module("paddock_cli") and not _ok_module("yaml")
    assert resolve_from(GUARD_DIR / "cli.py", ast.parse("from . import model").body[0]) == PKG
    assert resolve_from(GUARD_DIR / "cli.py", ast.parse("from .. import ui").body[0]) == "paddock_cli"
    assert _ok_module("paddock_cli.guard.model") and _ok_module("os.path") and _ok_module("__future__")


def test_banned_dynamic_import_exec_shell_and_pickle():
    bad = []
    for path in guard_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else None
                if name in ("__import__", "eval", "exec"):
                    bad.append("%s calls %s" % (path.name, name))
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                    if f.value.id == "os" and (f.attr in ("system", "popen") or f.attr.startswith(("exec", "spawn", "posix_spawn"))):
                        bad.append("%s calls os.%s" % (path.name, f.attr))
                    if f.value.id == "importlib" and path.name not in DYNAMIC_IMPORT_OK:
                        bad.append("%s uses importlib.%s" % (path.name, f.attr))
                for kw in node.keywords:
                    if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                        bad.append("%s passes shell=%s" % (path.name, ast.dump(kw.value)))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for n in names:
                    top = n.split(".")[0]
                    if top in _BANNED_MODULES:
                        bad.append("%s imports %s" % (path.name, n))
                    if top == "importlib" and path.name not in DYNAMIC_IMPORT_OK:
                        bad.append("%s imports importlib" % path.name)
            elif isinstance(node, ast.Name) and node.id in ("pickle", "marshal"):
                bad.append("%s mentions %s" % (path.name, node.id))
    assert bad == []


def test_dynamic_imports_name_only_guard_modules():
    """importlib is allowed in registry.py and cli.py only; every dotted module string there is a guard module."""
    import re

    for name in DYNAMIC_IMPORT_OK:
        tree = ast.parse((GUARD_DIR / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(r"paddock_cli(\.[A-Za-z_][A-Za-z0-9_]*)+", node.value):
                assert node.value.startswith(PKG + "."), (name, node.value)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in ("paddock_cli.",):
                raise AssertionError("bare paddock_cli. prefix in " + name)


def _open_mode(call: ast.Call):
    if len(call.args) >= 2:
        return call.args[1]
    for kw in call.keywords:
        if kw.arg == "mode":
            return kw.value
    return None


def test_no_file_writes_outside_files_py():
    bad = []
    for path in guard_files():
        if path.name in WRITE_OK and path.parent == GUARD_DIR:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Name) and f.id == "open":
                mode = _open_mode(node)
                if mode is None:
                    continue
                if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)) or set(mode.value) & set("wax+"):
                    bad.append("%s: open() with a write or unknown mode" % path.name)
            elif isinstance(f, ast.Attribute):
                if isinstance(f.value, ast.Name):
                    if f.value.id == "os" and f.attr in _WRITE_OS:
                        bad.append("%s: os.%s" % (path.name, f.attr))
                    if f.value.id in _WRITE_MODULES:
                        bad.append("%s: %s.%s" % (path.name, f.value.id, f.attr))
                if f.attr in _WRITE_ATTRS:
                    bad.append("%s: .%s()" % (path.name, f.attr))
    assert bad == []


def test_write_detector_catches_a_planted_violation(tmp_path):
    src = "import os\nfrom pathlib import Path\nopen('x', 'w')\nos.replace('a', 'b')\nPath('p').write_text('x')\n"
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert any(isinstance(c.func, ast.Name) and c.func.id == "open" and "w" in _open_mode(c).value for c in calls)
    assert any(isinstance(c.func, ast.Attribute) and c.func.attr == "replace" for c in calls)
    assert any(isinstance(c.func, ast.Attribute) and c.func.attr in _WRITE_ATTRS for c in calls)


def test_every_python_file_has_the_spdx_header_and_future_import():
    missing = []
    for path in guard_files() + sorted(p for p in SUPPORT_DIR.rglob("*.py") if "fixtures" not in p.relative_to(SUPPORT_DIR).parts):
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or lines[0] != SPDX:
            missing.append("%s: header" % path.name)
        if "from __future__ import annotations" not in path.read_text(encoding="utf-8"):
            missing.append("%s: future import" % path.name)
    assert missing == []


def test_provenance_exists_and_names_the_clean_room_rule():
    text = (GUARD_DIR / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "clean-room" in text.lower() and "Semgrep" in text and "TruffleHog" in text


def test_guard_imports_standalone_with_only_a_stub_parent(tmp_path):
    """Move the subpackage under a stub parent: it imports, lists checks and loads no other paddock_cli module."""
    parent = tmp_path / "moved" / "paddock_cli"
    parent.mkdir(parents=True)
    (parent / "__init__.py").write_text("")
    shutil.copytree(GUARD_DIR, parent / "guard", ignore=shutil.ignore_patterns("__pycache__"))
    script = (
        "import importlib, pkgutil, sys\n"
        "import paddock_cli.guard as g\n"
        "for m in pkgutil.walk_packages(g.__path__, 'paddock_cli.guard.'):\n"
        "    if m.name.endswith('__main__'): continue\n"
        "    importlib.import_module(m.name)\n"
        "from paddock_cli.guard import cli\n"
        "rc = cli.main(['list'])\n"
        "std = set(sys.stdlib_module_names)\n"
        "other = sorted({n.split('.')[0] for n in sys.modules if n.split('.')[0] not in std and not n.startswith('_') and n != 'sitecustomize'})\n"
        "foreign = sorted(n for n in sys.modules if n.startswith('paddock_cli.') and not n.startswith('paddock_cli.guard'))\n"
        "print('RC', rc, 'OTHER', other, 'FOREIGN', foreign)\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(tmp_path / "moved"), script)],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=120)
    assert r.returncode == 0, r.stderr[-1500:]
    last = [ln for ln in r.stdout.splitlines() if ln.startswith("RC ")][-1]
    assert last.startswith("RC 0") and "OTHER ['paddock_cli']" in last and "FOREIGN []" in last, last
