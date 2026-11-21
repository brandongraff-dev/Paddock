from __future__ import annotations

from app import reachability as reach

_SRC_REACHABLE = '''
import requests

def fetch(url):
    return requests.get(url)

def main():
    return fetch("http://example.com")
'''

_SRC_POTENTIAL = '''
import requests

def never_called(url):
    return requests.get(url)
'''

_SRC_WRONG_SYMBOL = '''
import requests

def main():
    return requests.post("http://example.com")
'''

_SRC_MODULE_LEVEL = '''
import yaml
CONFIG = yaml.load(open("c.yml").read())
'''

_BROKEN = "def oops(:\n   this is not python"


def _cg(src, path="app.py"):
    return reach.build_callgraph({path: src})


def test_python_reachable_via_call_chain():
    cg = _cg(_SRC_REACHABLE)
    res = reach.grade(cg, "requests", ["get"])
    assert res["reachability"] == "reachable"
    assert res["reachable_symbol"] == "get"
    assert res["call_path"][-1] == "requests.get"
    # path runs from the main entrypoint through fetch
    assert any("fetch" in step for step in res["call_path"])


def test_python_potential_when_symbol_not_reached():
    cg = _cg(_SRC_POTENTIAL)
    res = reach.grade(cg, "requests", ["get"])
    assert res["reachability"] == "potential"
    assert res["call_path"] == []


def test_python_potential_when_symbol_absent():
    cg = _cg(_SRC_WRONG_SYMBOL)
    res = reach.grade(cg, "requests", ["get"])
    # requests imported but .get is never referenced
    assert res["reachability"] == "potential"


def test_python_unreachable_when_not_imported():
    cg = _cg(_SRC_REACHABLE)
    res = reach.grade(cg, "lodash", ["merge"])
    assert res["reachability"] == "unreachable"


def test_python_unknown_without_symbol():
    cg = _cg(_SRC_REACHABLE)
    res = reach.grade(cg, "requests", [])
    assert res["reachability"] == "unknown"


def test_python_unknown_without_source():
    cg = reach.build_callgraph({})
    res = reach.grade(cg, "requests", ["get"])
    assert res["reachability"] == "unknown"


def test_python_module_level_is_reachable():
    cg = _cg(_SRC_MODULE_LEVEL)
    res = reach.grade(cg, "yaml", ["load"])
    assert res["reachability"] == "reachable"


def test_unparseable_file_is_skipped_not_raised():
    cg = reach.build_callgraph({"bad.py": _BROKEN, "ok.py": _SRC_REACHABLE})
    assert cg.files_skipped == 1
    assert cg.files_parsed == 1


def test_pypi_import_name_mapping():
    assert reach.module_for("PyPI", "PyYAML") == "yaml"
    assert reach.module_for("PyPI", "beautifulsoup4") == "bs4"
    assert reach.module_for("npm", "lodash") == "lodash"
