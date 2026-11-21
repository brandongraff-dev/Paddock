from __future__ import annotations

from app import reachability as reach
from tests.conftest import load_json_fixture

_SRC_SINGLE = '''
package main

import "gopkg.in/yaml.v2"

func main() {
    var v map[string]interface{}
    yaml.Unmarshal([]byte("a: 1"), &v)
}
'''

_SRC_BLOCK = '''
package main

import (
    "fmt"
    yaml "gopkg.in/yaml.v2"
)

func main() {
    fmt.Println(yaml.Marshal("x"))
}
'''

_SRC_OTHER = '''
package main

import "fmt"

func main() { fmt.Println("hi") }
'''


def _cg(src, path="main.go"):
    return reach.build_callgraph({path: src})


def test_go_reachable_symbol_from_fixture_advisory():
    vuln = load_json_fixture("osv_vuln_symbol.json")
    pairs = reach.symbols_from_osv(vuln)
    assert pairs
    module, symbols = pairs[0]
    assert module == "gopkg.in/yaml.v2"
    assert "Unmarshal" in symbols

    cg = _cg(_SRC_SINGLE)
    res = reach.grade(cg, module, symbols)
    assert res["reachability"] == "reachable"
    assert res["reachable_symbol"] == "Unmarshal"


def test_go_unreachable_when_symbol_not_the_vulnerable_one():
    vuln = load_json_fixture("osv_vuln_symbol.json")
    module, symbols = reach.symbols_from_osv(vuln)[0]
    # this file imports yaml but only calls Marshal, not Unmarshal
    cg = _cg(_SRC_BLOCK)
    res = reach.grade(cg, module, symbols)
    assert res["reachability"] == "potential"


def test_go_unreachable_when_package_absent():
    vuln = load_json_fixture("osv_vuln_symbol.json")
    module, symbols = reach.symbols_from_osv(vuln)[0]
    cg = _cg(_SRC_OTHER)
    res = reach.grade(cg, module, symbols)
    assert res["reachability"] == "unreachable"


def test_go_block_import_alias_detected():
    cg = _cg(_SRC_BLOCK)
    assert cg.is_imported("gopkg.in/yaml.v2")
