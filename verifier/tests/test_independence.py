# SPDX-License-Identifier: Apache-2.0
"""The verifier and the vector generators stay independent of the rest of the repo (contract 8.1, 9.1)."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "verifier" / "paddock_verify"
SPEC = ROOT / "docs" / "spec" / "containment-attestation-v1"

FORBIDDEN_IN_VERIFIER = {"app", "orchestrator", "paddock_assurance", "paddock_agent", "paddock_cli", "shared",
                         "pydantic", "yaml", "dns"}
FORBIDDEN_IN_GENERATORS = {"paddock_verify", "verifier", "app", "orchestrator", "paddock_assurance", "paddock_agent",
                           "paddock_cli", "shared"}
ALLOWED_THIRD_PARTY = {"cryptography", "paddock_verify"}
STDLIB = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None


def absolute_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(a.name.split(".")[0], node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.append((node.module.split(".")[0], node.lineno))
        elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__" and node.args \
                and isinstance(node.args[0], ast.Constant):
            out.append((str(node.args[0].value).split(".")[0], node.lineno))
    return out


def py_files(base):
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def test_verifier_imports_nothing_forbidden():
    files = py_files(PKG)
    assert files
    for f in files:
        for mod, line in absolute_imports(f):
            assert mod not in FORBIDDEN_IN_VERIFIER, "%s:%d imports %s" % (f.relative_to(ROOT), line, mod)


@pytest.mark.skipif(STDLIB is None, reason="needs sys.stdlib_module_names (3.10+)")
def test_verifier_runtime_dependencies_are_stdlib_plus_cryptography():
    for f in py_files(PKG):
        for mod, line in absolute_imports(f):
            assert mod in STDLIB or mod in ALLOWED_THIRD_PARTY, "%s:%d imports %s" % (f.relative_to(ROOT), line, mod)


def test_generators_and_runner_import_nothing_from_the_repo():
    gens = [p for p in (SPEC / "tools").glob("*.py")] + [p for p in (SPEC / "conformance").glob("*.py")]
    assert any(p.name == "gen_vectors.py" for p in gens)
    for f in gens:
        for mod, line in absolute_imports(f):
            assert mod not in FORBIDDEN_IN_GENERATORS, "%s:%d imports %s" % (f.relative_to(ROOT), line, mod)


@pytest.mark.skipif(STDLIB is None, reason="needs sys.stdlib_module_names (3.10+)")
def test_conformance_runner_is_stdlib_only():
    for f in (SPEC / "conformance").glob("*.py"):
        for mod, line in absolute_imports(f):
            assert mod in STDLIB, "%s:%d imports %s" % (f.relative_to(ROOT), line, mod)


def test_generators_never_touch_the_verifier_by_path_either():
    for f in list((SPEC / "tools").glob("*.py")):
        src = f.read_text(encoding="utf-8")
        for needle in ("verifier/", "paddock_verify", "orchestrator/", "sys.path"):
            assert needle not in src.replace("imports nothing from verifier/ or orchestrator/", ""), (f.name, needle)


def test_pyproject_runtime_dependencies_are_exactly_cryptography():
    text = (ROOT / "verifier" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = ["cryptography>=41"]' in text
    assert 'requires-python = ">=3.9"' in text
    assert "Apache-2.0" in text


def test_python39_syntax_and_no_newer_api():
    for f in py_files(PKG):
        src = f.read_text(encoding="utf-8")
        ast.parse(src, filename=str(f), feature_version=(3, 9))
        assert "datetime.UTC" not in src and "from datetime import UTC" not in src, f
        assert "int.bit_count" not in src and ".bit_count()" not in src, f
        assert "removeprefix" not in src or sys.version_info >= (3, 9)


def test_spdx_header_on_every_source_file():
    files = list(py_files(PKG)) + list((ROOT / "verifier" / "tests").glob("*.py"))
    files += list((SPEC / "tools").glob("*.py")) + list((SPEC / "conformance").glob("*.py"))
    files += list((SPEC / "spec").glob("*.md")) + [SPEC / "README.md", SPEC / "CHANGELOG.md", SPEC / "conformance" / "README.md",
                                                   ROOT / "verifier" / "README.md", ROOT / "verifier" / "pyproject.toml"]
    for f in files:
        head = "\n".join(f.read_text(encoding="utf-8").splitlines()[:3])
        assert "SPDX-License-Identifier: Apache-2.0" in head, f.relative_to(ROOT)


def test_license_files_are_apache_and_separate():
    for d in (ROOT / "verifier", SPEC):
        lic = (d / "LICENSE").read_text(encoding="utf-8")
        assert "Apache License" in lic and "Version 2.0, January 2004" in lic
        assert (d / "NOTICE").exists()
    assert (SPEC / "LICENSE").read_bytes() == (ROOT / "verifier" / "LICENSE").read_bytes()


def test_no_conformance_key_is_in_trust_roots():
    """Release-pipeline check (contract 9.2): the public test seeds never become trust roots."""
    import base64
    import json
    roots = PKG / "data" / "trust_roots.json"
    if not roots.exists():
        pytest.skip("trust_roots.json is P3.4's file")
    prim = json.loads((SPEC / "vectors" / "primitives" / "kid.json").read_text(encoding="ascii"))
    test_pubs = {c["pub_b64"] for c in prim["cases"]}
    for r in json.loads(roots.read_text(encoding="ascii")):
        assert base64.b64encode(base64.b64decode(r["public_key"])).decode() not in test_pubs
