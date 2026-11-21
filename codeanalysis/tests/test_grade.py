from __future__ import annotations

import app.reachability.grade as g
from app.reachability.grade import symbol_matches, symbols_from_osv, symbols_from_row

g.symbol_matches = symbol_matches
g.symbols_from_osv = symbols_from_osv
g.symbols_from_row = symbols_from_row


def test_symbol_matches_fully_qualified():
    assert g.symbol_matches("requests.get", "requests", ["get"]) == "get"


def test_symbol_matches_module_qualified_path():
    assert g.symbol_matches("gopkg.in/yaml.v2.Unmarshal", "gopkg.in/yaml.v2",
                            ["Unmarshal"]) == "Unmarshal"


def test_symbol_matches_rejects_wrong_symbol():
    assert g.symbol_matches("requests.post", "requests", ["get"]) is None


def test_symbol_matches_rejects_unrelated_module():
    # same last name but a different module should not match
    assert g.symbol_matches("other.get", "requests", ["get"]) is None


def test_symbols_from_osv_imports_and_database_specific():
    vuln = {
        "affected": [
            {"package": {"name": "a"},
             "ecosystem_specific": {"imports": [{"path": "mod/a", "symbols": ["F"]}]}},
            {"package": {"name": "b"},
             "database_specific": {"symbols": ["G"]}},
        ]
    }
    pairs = g.symbols_from_osv(vuln)
    assert ("mod/a", ["F"]) in pairs
    assert ("b", ["G"]) in pairs


def test_symbols_from_row_backticked_summary():
    syms = g.symbols_from_row([], "Prototype pollution in `merge` and `set`", "lodash")
    assert "merge" in syms and "set" in syms


def test_symbols_from_row_structured_refs():
    refs = [{"symbol": "loads"}, {"symbols": ["load"]}, "https://x/y"]
    syms = g.symbols_from_row(refs, None, "pyyaml")
    assert "loads" in syms and "load" in syms


def test_symbols_from_row_empty_when_no_signal():
    assert g.symbols_from_row(["https://x"], "Denial of service", "demo") == []


def test_grade_is_deterministic():
    from app import reachability as reach
    src = {"app.py": "import requests\n\ndef main():\n    requests.get('x')\n"}
    cg = reach.build_callgraph(src)
    r1 = reach.grade(cg, "requests", ["get"])
    r2 = reach.grade(cg, "requests", ["get"])
    assert r1 == r2
