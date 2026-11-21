from __future__ import annotations

from app.sast import semgrep_runner as sr


def test_is_available_false_for_bogus_binary():
    assert sr.is_available("definitely-not-a-real-binary-xyz") is False


def test_run_returns_unavailable_without_binary():
    res = sr.run({"a.py": "x = 1\n"}, binary="definitely-not-a-real-binary-xyz")
    assert res["available"] is False
    assert res["hits"] == []


def test_safe_rel_blocks_traversal_and_binaries():
    assert sr._safe_rel("../../etc/passwd") is None
    assert sr._safe_rel("/abs/secret.py") == "abs/secret.py"
    assert sr._safe_rel("src/app.py") == "src/app.py"
    assert sr._safe_rel("image.png") is None  # not a text/source ext


def test_parse_results_maps_cwe_and_severity():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "/tmp/x/app.py",
                "start": {"line": 10}, "end": {"line": 11},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL injection",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "language": "python"},
                    "dataflow_trace": {
                        "taint_source": [{"location": {"line": 5}}],
                        "taint_sink": [{"location": {"line": 10}}],
                    },
                },
            }
        ]
    }
    hits = sr.parse_results(payload, base="/tmp/x")
    assert len(hits) == 1
    h = hits[0]
    assert h["severity"] == "high"
    assert h["rule_class"] == "sql_injection"
    assert h["file"] == "app.py"
    steps = {s["step"] for s in h["dataflow"]}
    assert "source" in steps and "sink" in steps


def test_runner_never_uses_autofix():
    # the module must never pass --autofix (analysis only) and must guard it
    src = open(sr.__file__).read()
    assert "--autofix" in src  # only inside the guard assertion
    assert 'assert "--autofix" not in cmd' in src
    # the flag only appears in the guard, never as a command argument
    assert '"--autofix",' not in src
