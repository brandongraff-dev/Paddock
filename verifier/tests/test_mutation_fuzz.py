# SPDX-License-Identifier: Apache-2.0
"""Mutation and fuzz properties (contract 9.6): no damaged copy of a valid bundle is ever accepted.

For the compact valid bundle (envelope, keys.json, revoked.json) every bit of the small file and a seeded sample of
3000 bits of each large file is flipped, each file is truncated at every 7th byte, and each key of the predicate is
deleted (the statement is then re-signed, so only the schema can object). The exit code must never be 0. An exit 0
is a spec bug or a field that is signed by nobody and read by nobody.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import random
import sys
import time
from pathlib import Path

import pytest

from paddock_verify import canon, checks, fetch, jsonstrict, keys as keys_mod, limits, model, schema
from paddock_verify.dns import resolver as dns_resolver

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, str(SPEC / "tools" / (name + ".py")))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GC = _load("gen_cases")
ROOTS = keys_mod.parse_roots((SPEC / "vectors" / "test-roots.json").read_bytes(), custom=True)
REG = model.load_default_registry()
NOW = "2026-12-01T12:00:00Z"
RESOLVERS = dns_resolver.ResolverSet([dns_resolver.FakeResolver({"_paddock-attest.example.com": dns_resolver.DnsAnswer(
    "ok", [GC.WORKED["dns_txt"]], None, "f")}, name="f")], 1)


def exit_of(files, now=NOW):
    bundle = model.Bundle(fetch.MemorySource(files), "attestation/latest.json", label="mem")
    return checks.verify(bundle, None, now=now, resolver=RESOLVERS, roots=ROOTS, registry=REG).exit


def valid_files():
    return GC.Bk().build()


FILES = valid_files()
ENV, KEYS, REVOKED = "attestation/latest.json", "keys.json", "revoked.json"


def test_the_unmutated_bundle_is_accepted():
    assert exit_of(dict(FILES)) == 0


def _flip(files, name, bit):
    data = bytearray(files[name])
    data[bit // 8] ^= 1 << (bit % 8)
    out = dict(files)
    out[name] = bytes(data)
    return out


def test_every_bit_of_the_revocation_list_matters():
    n = len(FILES[REVOKED]) * 8
    assert n < 6000
    survivors = [b for b in range(n) if exit_of(_flip(FILES, REVOKED, b)) == 0]
    assert survivors == []


@pytest.mark.parametrize("name", [ENV, KEYS])
def test_a_sample_of_bit_flips_of_the_large_files_never_gives_exit_zero(name):
    rnd = random.Random(20261201)
    n = len(FILES[name]) * 8
    sample = sorted(rnd.sample(range(n), 3000))
    survivors = [b for b in sample if exit_of(_flip(FILES, name, b)) == 0]
    assert survivors == [], [(b // 8, b % 8) for b in survivors[:5]]


@pytest.mark.parametrize("name", [ENV, KEYS, REVOKED])
def test_truncation_at_every_seventh_byte_never_gives_exit_zero(name):
    full = FILES[name]
    for cut in range(0, len(full), 7):
        files = dict(FILES)
        files[name] = full[:cut]
        assert exit_of(files) != 0, (name, cut)


def test_whitespace_in_the_unsigned_outer_files_is_the_documented_exception():
    """Pretty-printing keys.json changes no signed byte: it is accepted, which is why the property excludes it."""
    files = dict(FILES)
    files[KEYS] = json.dumps(json.loads(FILES[KEYS]), indent=2).encode("ascii")
    assert exit_of(files) == 0


def test_deleting_any_key_of_the_predicate_or_a_result_is_never_accepted():
    """Each required key is deleted in turn and the statement re-signed, so only the schema can object."""
    optional = {("predicate", "audit_anchor"), ("predicate", "prev")}
    base = GC.base_statement()
    paths = [("predicate", k) for k in base["predicate"]]
    for i in range(len(base["predicate"]["results"])):
        paths += [("predicate", "results", i, k) for k in base["predicate"]["results"][i]]
    for sub in ("snapshot", "scope", "policy", "disclosure", "engine", "limits", "audit_anchor"):
        paths += [("predicate", sub, k) for k in base["predicate"][sub]]
    paths += [(k,) for k in base]
    n = 0
    for path in paths:
        if path in optional:
            continue
        stmt = copy.deepcopy(base)
        node = stmt
        for p in path[:-1]:
            node = node[p]
        del node[path[-1]]
        b = GC.Bk()
        b.stmt = stmt
        n += 1
        assert exit_of(b.build()) != 0, path
    assert n > 60
    # the two optional keys really are optional: removing them leaves a valid statement
    b = GC.Bk()
    del b.stmt["predicate"]["audit_anchor"]
    assert exit_of(b.build()) == 0
    b = GC.Bk()
    del b.stmt["predicate"]["results"][0]["selected"]["from"]
    assert exit_of(b.build()) == 0


def test_deleting_each_key_of_keys_json_and_the_revocation_payload_is_never_accepted():
    doc = GC.default_keys_doc()
    for key in list(doc):
        d = copy.deepcopy(doc)
        del d[key]
        files = dict(FILES)
        files[KEYS] = GC.compact(d)
        assert exit_of(files) != 0, key
    for i in range(2):
        for key in list(doc["keys"][i]):
            d = copy.deepcopy(doc)
            del d["keys"][i][key]
            files = dict(FILES)
            files[KEYS] = GC.compact(d)
            assert exit_of(files) != 0, (i, key)
    payload = GC.revoked_payload()
    for key in list(payload):
        p = dict(payload)
        del p[key]
        files = dict(FILES)
        files[REVOKED] = GC.compact(GC.revoked_env(p))
        assert exit_of(files) != 0, key


# ------------------------------------------------------------------------------- the strict reader
def test_strict_reader_fuzz_never_raises_anything_but_json_errors():
    rnd = random.Random(7)
    seeds = [b'{"a":{"b":[1,2,{"c":true}]}}', b'[1,2,3]', b'"x"', b'{"a":1,"a":2}', b'{"a":1.5}', b'\xef\xbb\xbf{}', b'{"a":NaN}', b'[1,2,]',
             b'{"a":"\\ud800"}', b'{"a":"\xff"}', b'', b'  ', b'{"a":-0}', b'{"a":01}', b'1e2', b'null', b'tru', b'{"a":"\\u0041"}']
    for _ in range(4000):
        data = bytearray(rnd.choice(seeds))
        for _i in range(rnd.randint(0, 3)):
            if data and rnd.random() < 0.7:
                data[rnd.randrange(len(data))] = rnd.choice(b'{}[]",:\\-+.eE0123456789ntfu \n\x00\xff')
            else:
                data.insert(rnd.randrange(len(data) + 1), rnd.choice(b'{}[]",:\\-+.eE09ntfu '))
        try:
            canon.roundtrip(bytes(data))
        except jsonstrict.JsonError as e:
            assert e.code.startswith(("input.", "schema.payload_not_canonical"))
        except RecursionError:
            pytest.fail("recursion in the strict reader")


def test_duplicate_keys_at_every_depth_are_found():
    for depth in range(1, 9):
        inner = '"k":1,"k":2'
        text = ('{"x":' * (depth - 1)) + "{" + inner + "}" + "}" * (depth - 1)
        with pytest.raises(jsonstrict.JsonError) as ei:
            jsonstrict.parse(text.encode("ascii"))
        assert ei.value.code == "input.duplicate_key", depth


def test_depth_bombs_and_huge_numbers_are_input_errors_without_recursion():
    for payload, code in ((b"[" * 100000 + b"]" * 100000, "input.depth_exceeded"), (b'{"a":' * 5000 + b"1" + b"}" * 5000, "input.depth_exceeded"),
                          (b"[" + b"9" * 5000 + b"]", "input.number_invalid"), (b"[" + b"9" * 17 + b"]", "input.number_invalid"),
                          (b'{"a":NaN}', "input.number_invalid"), (b'[Infinity]', "input.number_invalid")):
        with pytest.raises(jsonstrict.JsonError) as ei:
            jsonstrict.parse(payload, max_depth=16)
        assert ei.value.code == code, payload[:20]


def test_the_reader_is_linear_on_half_a_mebibyte_of_awkward_input():
    shapes = [b"[" + b",".join([b'{"a":[1,2,3],"b":"xxxxxxxx"}'] * 17000)[:520000] + b"]",
              b'["' + b"a" * 520000 + b'"]', b"[" + b",".join([b"1"] * 260000) + b"]", b"{" + b",".join(b'"k%d":1' % i for i in range(40000)) + b"}"]
    for data in shapes:
        data = data[:limits.MAX_PCJ_BYTES]
        t = time.time()
        try:
            jsonstrict.parse(data, max_depth=16)
        except jsonstrict.JsonError:
            pass
        assert time.time() - t < 3.0


def test_statement_validation_is_total_over_arbitrary_json_shapes():
    rnd = random.Random(11)
    base = GC.base_statement()

    def mutate(v, depth=0):
        r = rnd.random()
        if r < 0.15:
            return rnd.choice([None, True, False, 0, -1, 2 ** 60, "", "x" * 600, [], {}, [1], {"a": 1}, 1.5])
        if isinstance(v, dict) and depth < 6:
            return dict((k, mutate(x, depth + 1) if rnd.random() < 0.4 else x) for k, x in v.items() if rnd.random() > 0.05)
        if isinstance(v, list) and depth < 6:
            return [mutate(x, depth + 1) if rnd.random() < 0.4 else x for x in v]
        return v

    for _ in range(1500):
        m = mutate(copy.deepcopy(base))
        issues, _unsupported = schema.validate_statement(m)
        for i in issues:
            assert i.code in __import__("paddock_verify.codes", fromlist=["x"]).CODES
            assert isinstance(i.path, str) and len(i.path) < 80
