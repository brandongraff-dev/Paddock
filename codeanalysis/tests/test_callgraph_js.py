from __future__ import annotations

from app import reachability as reach

_ES_IMPORT = '''
import { merge } from 'lodash';
export function handler(req) {
  return merge({}, req.body);
}
'''

_REQUIRE = '''
const _ = require('lodash');
function run(req) { return _.merge({}, req.query); }
'''

_UNUSED = '''
import { merge } from 'lodash';
export function handler() { return 1; }
'''

_RELATIVE_ONLY = '''
import helper from './helper';
export function handler() { return helper(); }
'''


def _cg(src, path="index.js"):
    return reach.build_callgraph({path: src})


def test_js_named_import_symbol_reachable():
    cg = _cg(_ES_IMPORT)
    res = reach.grade(cg, "lodash", ["merge"])
    assert res["reachability"] == "reachable"
    assert res["reachable_symbol"] == "merge"


def test_js_require_member_access_reachable():
    cg = _cg(_REQUIRE)
    res = reach.grade(cg, "lodash", ["merge"])
    assert res["reachability"] == "reachable"


def test_js_imported_symbol_unused_is_potential():
    cg = _cg(_UNUSED)
    res = reach.grade(cg, "lodash", ["defaultsDeep"])
    assert res["reachability"] == "potential"


def test_js_relative_import_is_not_a_dependency():
    cg = _cg(_RELATIVE_ONLY)
    res = reach.grade(cg, "lodash", ["merge"])
    assert res["reachability"] == "unreachable"


def test_ts_extension_supported():
    cg = reach.build_callgraph({"a.ts": _ES_IMPORT})
    assert cg.files_parsed == 1
