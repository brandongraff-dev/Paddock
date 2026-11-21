from __future__ import annotations

import pathlib

import app

APP_ROOT = pathlib.Path(app.__file__).parent


def _py_files():
    return sorted(APP_ROOT.rglob("*.py"))


def test_package_safety_invariant_documented():
    doc = (app.__doc__ or "").lower()
    assert "defensive" in doc and "detection-only" in doc
    assert "must not" in doc
    # the hard prohibitions are spelled out
    assert "execute" in doc and "eval" in doc and "import" in doc


def test_no_exec_eval_of_scanned_content():
    # Analysis code must never execute/eval/compile the source it scans.
    for py in _py_files():
        src = py.read_text()
        assert "eval(" not in src, f"eval() in {py}"
        assert "exec(" not in src, f"exec() in {py}"
        assert "__import__(" not in src, f"__import__ in {py}"
        # the builtin compile() must not be used (re.compile is fine)
        assert "compile(" not in src.replace("re.compile(", ""), f"compile() in {py}"


def test_subprocess_only_in_semgrep_runner():
    # Only the Semgrep wrapper may spawn a process, and it runs semgrep over a
    # temp dir -- it never runs the scanned files themselves.
    offenders = [p for p in _py_files()
                 if "subprocess" in p.read_text() and p.name != "semgrep_runner.py"]
    assert offenders == [], f"unexpected subprocess use: {offenders}"


def test_semgrep_invoked_without_autofix():
    src = (APP_ROOT / "sast" / "semgrep_runner.py").read_text()
    assert 'assert "--autofix" not in cmd' in src
    assert '"--autofix",' not in src


def test_taint_fallback_parses_read_only():
    src = (APP_ROOT / "sast" / "taint_fallback.py").read_text()
    assert "ast.parse(" in src  # AST, not execution


def test_reachability_does_not_import_scanned_modules():
    for name in ("callgraph_py.py", "callgraph_js.py", "callgraph_go.py", "grade.py"):
        src = (APP_ROOT / "reachability" / name).read_text()
        assert "importlib" not in src
        assert "subprocess" not in src
