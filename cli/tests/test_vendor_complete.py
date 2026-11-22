"""The wheel's engine bundle must be self-contained.

A built wheel carries copies of the engines (``paddock_cli/_vendor``, made by
``vendor.vendor_all``). If an engine module gains a relative import of a
sibling that isn't in ``vendor.ENGINES``, the source checkout still works but
the installed CLI breaks. This builds the bundle and checks that every
relative import inside it resolves to a bundled module.
"""
from __future__ import annotations

import ast
from pathlib import Path

from paddock_cli import vendor

REPO = Path(__file__).resolve().parents[2]


def _resolves(pkg_dir: Path, module_file: Path, level: int, name: str | None) -> bool:
    base = module_file.parent
    for _ in range(level - 1):
        base = base.parent
    if not base.is_relative_to(pkg_dir):
        return False  # would climb out of the bundled package
    if not name:
        return True
    target = base.joinpath(*name.split("."))
    return target.with_suffix(".py").is_file() or (target / "__init__.py").is_file()


# Imports the loader (paddock_cli/engines.py) satisfies itself instead of the bundle:
# wargame's safety.py does ``from ..policy import ...`` (the correlation service's module, which
# needs yaml/pydantic); engines.py installs a stdlib-only stand-in under that name.
LOADER_PROVIDED = {("wargame/safety.py", "..policy")}


def test_every_relative_import_in_the_bundle_resolves(tmp_path):
    dest = tmp_path / "_vendor"
    assert vendor.vendor_all(REPO, dest)
    missing = []
    for alias in vendor.ENGINES:
        pkg = dest / alias
        for f in pkg.rglob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level == 0:
                    continue
                if node.module is not None:
                    ok = _resolves(pkg, f, node.level, node.module)
                    spelled = "." * node.level + node.module
                    if not ok and (str(f.relative_to(dest)), spelled) in LOADER_PROVIDED:
                        continue
                    if not ok:
                        missing.append(f"{f.relative_to(dest)}: from {'.' * node.level}{node.module}")
                else:  # from . import a, b -> each name is a sibling module or a package attr
                    for alias_ in node.names:
                        if _resolves(pkg, f, node.level, alias_.name):
                            continue
                        init = f.parent / "__init__.py"
                        defined = init.is_file() and alias_.name in init.read_text(encoding="utf-8")
                        if not defined:
                            missing.append(f"{f.relative_to(dest)}: from {'.' * node.level} import {alias_.name}")
    assert not missing, "add these to vendor.ENGINES:\n" + "\n".join(missing)
