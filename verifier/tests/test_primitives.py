# SPDX-License-Identifier: Apache-2.0
"""Primitive-level tests: every module of the byte layer against the primitive vectors.

The vectors (docs/spec/containment-attestation-v1/vectors/primitives/*.json) are written by
tools/gen_vectors.py, an independent implementation that imports nothing from this package.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest

from paddock_verify import b64, canon, codes, dsse, ed25519, jsonstrict, limits, merkle, timefmt, wording

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"
PRIM = SPEC / "vectors" / "primitives"


def vec(name):
    return json.loads((PRIM / name).read_text(encoding="ascii"))


def unhex(s):
    return bytes.fromhex(s)


def materialise(case):
    """A vector input is either input_b64 or a recipe that the test expands (huge inputs)."""
    if "input_b64" in case:
        return base64.b64decode(case["input_b64"], validate=True)
    r = case["recipe"]
    head, tail = r["head"].encode("ascii"), r["tail"].encode("ascii")
    fill = r["fill"].encode("ascii")
    n = r["length"] - len(head) - len(tail)
    assert n >= 0 and len(fill) == 1
    return head + fill * n + tail


# --------------------------------------------------------------------------------------------- PAE
@pytest.mark.parametrize("case", vec("pae.json")["cases"], ids=lambda c: c["id"])
def test_pae_vectors(case):
    payload = base64.b64decode(case["payload_b64"])
    assert len(payload) == case["payload_len"]
    assert dsse.pae(case["payload_type"], payload) == base64.b64decode(case["pae_b64"])


def test_pae_shape_and_types():
    assert dsse.pae("application/vnd.in-toto+json", b"") == b"DSSEv1 28 application/vnd.in-toto+json 0 "
    assert dsse.pae(b"x", b"yz") == b"DSSEv1 1 x 2 yz"
    with pytest.raises(TypeError):
        dsse.pae("x", "not bytes")
    with pytest.raises(ValueError):
        dsse.pae("caf\u00e9", b"")           # the payload type is ASCII by contract


def test_pae_constants():
    assert dsse.PAYLOAD_TYPE_STATEMENT == "application/vnd.in-toto+json"
    assert dsse.PAYLOAD_TYPE_KEY_CERT == "application/vnd.paddock.key-cert+json"
    assert dsse.PAYLOAD_TYPE_REVOCATION == "application/vnd.paddock.revocation-list+json"


# ----------------------------------------------------------------------------------------- base64
@pytest.mark.parametrize("case", vec("b64.json")["decode"], ids=lambda c: c["id"])
def test_b64_decode_vectors(case):
    if case["valid"]:
        assert b64.strict_decode(case["input"]) == unhex(case["decoded_hex"])
    else:
        with pytest.raises(b64.B64Error) as ei:
            b64.strict_decode(case["input"])
        assert ei.value.code == case["code"] == "schema.base64_invalid"


@pytest.mark.parametrize("case", vec("b64.json")["encode"], ids=lambda c: c["data_hex"][:16] or "empty")
def test_b64_encode_vectors(case):
    assert b64.encode(unhex(case["data_hex"])) == case["b64"]


def test_b64_accepts_ascii_bytes_and_rejects_non_text():
    assert b64.strict_decode(b"Zm9v") == b"foo"
    with pytest.raises(b64.B64Error):
        b64.strict_decode(b"Zm9v\n")
    with pytest.raises(b64.B64Error):
        b64.strict_decode(None)
    with pytest.raises(b64.B64Error):
        b64.strict_decode(12)


# ------------------------------------------------------------------------------------------ PCJ
@pytest.mark.parametrize("case", vec("pcj.json")["encode"], ids=lambda c: c["id"])
def test_pcj_encode_vectors(case):
    if "error" in case:
        with pytest.raises(canon.CanonError):
            canon.dumps(case["value"])
    else:
        assert canon.dumps(case["value"]) == base64.b64decode(case["pcj_b64"])


@pytest.mark.parametrize("case", vec("pcj.json")["parse"], ids=lambda c: c["id"])
def test_pcj_parse_vectors(case):
    data = materialise(case)
    if case["result"] == "accept":
        value = canon.roundtrip(data)
        if "value" in case:
            assert value == case["value"]
        assert canon.dumps(value) == data
        return
    if case["stage"] == "loads":
        with pytest.raises(canon.CanonError) as ei:
            canon.loads(data)
        assert ei.value.code == case["code"]
        # roundtrip is a superset of loads: the same input fails the same way
        with pytest.raises(canon.CanonError) as ei2:
            canon.roundtrip(data)
        assert ei2.value.code == case["code"]
    else:
        assert case["stage"] == "roundtrip"
        canon.loads(data)                        # parses fine, only the canonical form is wrong
        with pytest.raises(canon.CanonError) as ei:
            canon.roundtrip(data)
        assert ei.value.code == case["code"] == "schema.payload_not_canonical"


def test_pcj_vectors_cover_the_whole_edge_table():
    """Section 2.1 lists the edge table the vectors MUST cover."""
    ids = {c["id"] for c in vec("pcj.json")["parse"]}
    need = {"neg-zero", "float-1.0", "float-1e2", "float-1E2", "nan", "infinity", "null", "int-2^53",
            "int-5000-digits", "non-ascii-e-acute", "lone-surrogate-escape", "escape-u0041",
            "escape-solidus", "escape-newline", "bom", "leading-whitespace", "trailing-whitespace",
            "trailing-newline", "dup-keys-depth-1", "dup-keys-depth-5", "unsorted-keys", "empty-key",
            "depth-17", "size-1mib-plus-1", "trailing-comma", "leading-zero", "empty-input",
            "trailing-garbage", "true-as-number"}
    assert need <= ids, sorted(need - ids)


def test_pcj_exception_hierarchy_catch_order():
    """CanonError must be a ValueError (so catch order matters) and carry a stable code."""
    assert issubclass(canon.CanonError, ValueError)
    assert issubclass(jsonstrict.JsonError, ValueError)
    try:
        canon.loads(b"[1.5]")
    except canon.CanonError as e:
        assert e.code == "input.number_invalid"
    # a producer-side failure raises the same class
    with pytest.raises(canon.CanonError):
        canon.dumps({"a": 1.5})


def test_pcj_dumps_rules():
    assert canon.dumps({"b": 1, "a": [True, False, "x"]}) == b'{"a":[true,false,"x"],"b":1}'
    assert canon.dumps(2 ** 53 - 1) == b"9007199254740991"
    for bad in (2 ** 53, -1, 1.0, None, "a\"b", "a\\b", "é", "\x7f", "tab\t", {"": 1}, {1: 2}, (1,), {"a": {1, 2}}):
        with pytest.raises(canon.CanonError):
            canon.dumps(bad)
    deep = 1
    for _ in range(17):
        deep = [deep]
    with pytest.raises(canon.CanonError):
        canon.dumps(deep)
    ok = 1
    for _ in range(16):
        ok = [ok]
    canon.dumps(ok)


def test_pcj_matches_json_dumps_for_conforming_values():
    v = {"z": [1, 2, {"b": "x", "a": True}], "a": "hello world", "m": {"k": 0}}
    assert canon.dumps(v) == json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                       allow_nan=False).encode("ascii")


def test_pcj_key_order_is_byte_order_not_locale_or_length():
    assert canon.dumps({"b": 1, "B": 2, "a": 3, "_": 4, "aa": 5}) == b'{"B":2,"_":4,"a":3,"aa":5,"b":1}'


def test_jsonstrict_linear_time_and_no_recursion_error():
    import time
    big = b"[" + b",".join([b'{"a":"%d","b":[1,2,3]}' % i for i in range(18000)]) + b"]"
    assert 400_000 < len(big) < 520_000
    t0 = time.time()
    v = jsonstrict.parse(big, max_depth=16, max_bytes=1 << 20)
    assert len(v) == 18000
    assert time.time() - t0 < 5
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse(b"[" * 200000)
    assert ei.value.code == "input.depth_exceeded"
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse(b'{"a":' * 100000)
    assert ei.value.code == "input.depth_exceeded"


def test_jsonstrict_depth_parameter():
    jsonstrict.parse(b"[[[[[[[[1]]]]]]]]", max_depth=8)                    # depth 8
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse(b"[[[[[[[[[1]]]]]]]]]", max_depth=8)               # depth 9
    assert ei.value.code == "input.depth_exceeded"


def test_jsonstrict_accepts_plain_whitespace_and_escapes_for_unsigned_files():
    assert jsonstrict.parse(b' {\n "a" : [ 1 , 2 ],\t"b":"x\\ny" }\r\n') == {"a": [1, 2], "b": "x\ny"}
    assert jsonstrict.parse(b'"\\ud83d\\ude00"') == "\U0001F600"           # a valid surrogate pair


@pytest.mark.parametrize("data,code", [
    (b'{"a":1,"a":2}', "input.duplicate_key"),
    (b'{"a":{"b":1,"b":2}}', "input.duplicate_key"),
    (b'[1,2,]', "input.not_json"), (b"[1 2]", "input.not_json"), (b"{'a':1}", "input.not_json"),
    (b"[tru]", "input.not_json"), (b'"abc', "input.not_json"), (b'"\\x41"', "input.not_json"),
    (b'"\\ud800"', "input.not_json"), (b'"\\udc00"', "input.not_json"), (b'"a\tb"', "input.not_json"),
    (b"// c\n1", "input.not_json"), (b"", "input.not_json"), (b"   ", "input.not_json"),
    (b"1 2", "input.not_json"), (b"{} x", "input.not_json"), (b"[null]", "input.not_json"),
    (b"[01]", "input.number_invalid"), (b"[-1]", "input.number_invalid"), (b"[+1]", "input.number_invalid"),
    (b"[1.5]", "input.number_invalid"), (b"[1e3]", "input.number_invalid"), (b"[NaN]", "input.number_invalid"),
    (b"[Infinity]", "input.number_invalid"), (b"[-Infinity]", "input.number_invalid"),
    (b"[9007199254740992]", "input.number_invalid"), (b"[.5]", "input.number_invalid"),
    (b"[1.]", "input.number_invalid"), (b"[0x10]", "input.number_invalid"),
    (b"\xef\xbb\xbf[1]", "input.not_ascii"), (b'["\xc3\xa9"]', "input.not_ascii"), (b"[1]\x7f", "input.not_ascii"),
])
def test_jsonstrict_rejections(data, code):
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse(data)
    assert ei.value.code == code


def test_jsonstrict_too_large_is_checked_first():
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse(b"\xff" * 20, max_bytes=10)
    assert ei.value.code == "input.too_large"
    with pytest.raises(jsonstrict.JsonError) as ei:
        jsonstrict.parse("not bytes")
    assert ei.value.code == "input.unreadable"


def test_jsonstrict_returns_plain_types_and_bool_is_not_int_confusable():
    v = jsonstrict.parse(b'{"seq":true,"n":1}')
    assert v["seq"] is True and type(v["n"]) is int


# ---------------------------------------------------------------------------------------- time
TV = vec("time.json")


@pytest.mark.parametrize("case", TV["parse"], ids=lambda c: c["id"])
def test_time_parse_vectors(case):
    if case["valid"]:
        assert timefmt.parse(case["input"]) == case["epoch"]
        assert timefmt.format(case["epoch"]) == case["input"]
    else:
        with pytest.raises(timefmt.TimeError) as ei:
            timefmt.parse(case["input"])
        assert ei.value.code == "schema.time_format"


@pytest.mark.parametrize("case", TV["format"], ids=lambda c: str(c["epoch"]))
def test_time_format_vectors(case):
    assert timefmt.format(case["epoch"]) == case["text"]


@pytest.mark.parametrize("case", TV["durations"], ids=lambda c: c["input"] or "empty")
def test_duration_vectors(case):
    if case["valid"]:
        assert timefmt.parse_duration(case["input"]) == case["seconds"]
    else:
        with pytest.raises(timefmt.TimeError):
            timefmt.parse_duration(case["input"])


@pytest.mark.parametrize("case", TV["windows"], ids=lambda c: c["id"])
def test_time_window_vectors(case):
    assert timefmt.window_state(case["now"], case["issued_at"], case["valid_until"]) == case["state"]


def test_time_parse_rejects_non_str_and_unicode_digits():
    for bad in (None, 5, b"2026-12-01T09:00:00Z", "2026-12-01T09:00:00Z\n", " 2026-12-01T09:00:00Z"):
        with pytest.raises(timefmt.TimeError):
            timefmt.parse(bad)
    with pytest.raises(timefmt.TimeError):
        timefmt.parse("２０２６-12-01T09:00:00Z")          # full-width digits


def test_time_format_range():
    with pytest.raises(timefmt.TimeError):
        timefmt.format(-1)
    with pytest.raises(timefmt.TimeError):
        timefmt.format(timefmt.parse("9999-12-31T23:59:59Z") + 1)
    with pytest.raises(timefmt.TimeError):
        timefmt.format(True)


# ---------------------------------------------------------------------------------------- ed25519
@pytest.mark.parametrize("case", vec("ed25519.json")["cases"], ids=lambda c: c["id"])
def test_ed25519_vectors(case):
    pub, msg, sig = unhex(case["pub_hex"]), unhex(case["msg_hex"]), unhex(case["sig_hex"])
    expect = case["expect"]
    got = ed25519.verify_code(pub, msg, sig)
    if expect == "valid":
        assert got is None
        assert ed25519.verify(pub, msg, sig) is True
    else:
        assert got == expect
        assert ed25519.verify(pub, msg, sig) is False


def test_ed25519_vectors_include_the_rfc_and_the_hostile_cases():
    ids = {c["id"] for c in vec("ed25519.json")["cases"]}
    need = {"rfc8032-test1", "rfc8032-test2", "rfc8032-test3", "s-plus-l", "identity-key-identity-sig",
            "two-torsion-key", "order4-key", "order8-key", "noncanonical-y-key", "not-on-curve-key",
            "sig-63-bytes", "sig-65-bytes", "pub-31-bytes", "message-tampered", "r-bit-flipped",
            "weak-key-and-s-ge-l"}
    assert need <= ids, sorted(need - ids)


def test_ed25519_small_order_set_is_exactly_eight_points():
    enc = ed25519.small_order_encodings()
    assert len(enc) == 8 and len(set(enc)) == 8
    for e in enc:
        assert ed25519.precheck_public_key(e) == "sig.weak_key"


@pytest.mark.parametrize("case", vec("kid.json")["cases"], ids=lambda c: c["name"])
def test_kid_vectors(case):
    pub = unhex(case["pub_hex"])
    assert base64.b64encode(pub).decode() == case["pub_b64"]
    assert ed25519.fingerprint(pub) == case["fp"] == "sha256:" + hashlib.sha256(pub).hexdigest()
    assert ed25519.kid_of(pub) == case["kid"] == hashlib.sha256(pub).hexdigest()[:32]


def test_kid_of_requires_32_bytes():
    with pytest.raises(ValueError):
        ed25519.kid_of(b"\x00" * 31)


def test_ed25519_roundtrip_with_library_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test").digest())
    pub = sk.public_key().public_bytes_raw()
    sig = sk.sign(b"hello")
    assert ed25519.verify(pub, b"hello", sig)
    assert not ed25519.verify(pub, b"hellp", sig)
    assert ed25519.verify_code(pub, b"hellp", sig) == "sig.invalid"
    with pytest.raises(TypeError):
        ed25519.verify(pub, "hello", sig)


# ----------------------------------------------------------------------------------------- merkle
MV = vec("merkle.json")


def test_merkle_empty_root():
    assert merkle.EMPTY_ROOT == hashlib.sha256(b"").digest() == unhex(MV["empty_root_hex"])
    assert merkle.root([]) == merkle.EMPTY_ROOT
    assert merkle.root_str([]) == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("case", MV["leaf_hashes"], ids=lambda c: c["id"])
def test_merkle_leaf_hash_vectors(case):
    assert merkle.leaf_hash(unhex(case["nonce_hex"]), case["leaf_json"].encode("ascii")).hex() == case["leaf_hash_hex"]


@pytest.mark.parametrize("case", MV["node_hashes"], ids=lambda c: c["left_hex"][:8])
def test_merkle_node_hash_vectors(case):
    assert merkle.node_hash(unhex(case["left_hex"]), unhex(case["right_hex"])).hex() == case["node_hash_hex"]


@pytest.mark.parametrize("case", MV["trees"], ids=lambda c: "n%d" % c["size"])
def test_merkle_tree_vectors(case):
    ck = unhex(MV["commit_key_hex"])
    t = merkle.build_tree("graph", case["records"], ck)
    assert t.size == case["size"] == len(case["records"])
    assert [leaf.leaf_hash.hex() for leaf in t.leaves] == case["sorted_leaf_hashes"]
    assert t.root.hex() == case["root_hex"]
    assert t.root_str == "sha256:" + case["root_hex"]
    assert merkle.root([unhex(h) for h in case["sorted_leaf_hashes"]]).hex() == case["root_hex"]


def test_merkle_set_commitment_and_duplicate_collapse():
    sc = MV["set_commitment"]
    ck = unhex(MV["commit_key_hex"])
    a = merkle.build_tree("policy", sc["records_a"], ck)
    b = merkle.build_tree("policy", sc["records_b"], ck)         # permuted and with duplicates
    assert a.size == b.size == sc["size"]
    assert a.root.hex() == b.root.hex() == sc["root_hex"]


@pytest.mark.parametrize("case", MV["inclusion"], ids=lambda c: "n%d-i%d" % (c["size"], c["index"]))
def test_merkle_inclusion_vectors(case):
    lh, root = unhex(case["leaf_hash_hex"]), unhex(case["root_hex"])
    path = [unhex(x) for x in case["path_hex"]]
    assert merkle.verify_inclusion(lh, case["index"], case["size"], path, root) is True


def test_merkle_inclusion_path_generation_matches_vectors_and_verifies_everywhere():
    for n in range(1, 40):
        hashes = [hashlib.sha256(b"leaf%d" % i).digest() for i in range(n)]
        root = merkle.root(hashes)
        for i in range(n):
            path = merkle.inclusion_path(hashes, i)
            assert merkle.verify_inclusion(hashes[i], i, n, path, root), (n, i)
    for case in MV["inclusion"]:
        hs = [unhex(x) for x in case["all_leaf_hashes_hex"]]
        assert [p.hex() for p in merkle.inclusion_path(hs, case["index"])] == case["path_hex"]


@pytest.mark.parametrize("case", MV["bad_inclusion"], ids=lambda c: c["id"])
def test_merkle_bad_inclusion_vectors(case):
    path = [unhex(x) for x in case["path_hex"]]
    assert merkle.verify_inclusion(unhex(case["leaf_hash_hex"]), case["index"], case["size"], path,
                                   unhex(case["root_hex"])) is False


def test_merkle_recursive_reference_equals_iterative_root():
    def mth(hs):
        n = len(hs)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return hs[0]
        k = 1 << ((n - 1).bit_length() - 1)
        return hashlib.sha256(b"\x01" + mth(hs[:k]) + mth(hs[k:])).digest()
    for n in range(0, 70):
        hs = [hashlib.sha256(b"x%d" % i).digest() for i in range(n)]
        assert merkle.root(hs) == mth(hs), n


def test_merkle_rejects_malformed_inputs():
    h = hashlib.sha256(b"x").digest()
    assert merkle.verify_inclusion(h, 0, 1, [], h) is True
    assert merkle.verify_inclusion(h, 1, 1, [], h) is False
    assert merkle.verify_inclusion(h, 0, 0, [], h) is False
    assert merkle.verify_inclusion(h, -1, 1, [], h) is False
    assert merkle.verify_inclusion(h, 0, 1, [], b"\x00" * 31) is False
    assert merkle.verify_inclusion(h[:31], 0, 1, [], h) is False
    assert merkle.verify_inclusion(h, 0, 2, [b"short"], h) is False
    with pytest.raises(ValueError):
        merkle.inclusion_path([h], 1)
    with pytest.raises(ValueError):
        merkle.build_tree("bogus", [{"a": 1}], b"\x01" * 32)
    with pytest.raises(ValueError):
        merkle.build_tree("graph", [{"tree": "graph"}], b"\x01" * 32)
    with pytest.raises(ValueError):
        merkle.build_tree("graph", [{"a": 1}], b"\x01" * 31)


@pytest.mark.parametrize("case", MV["proof_files"], ids=lambda c: c["id"])
def test_merkle_proof_file_vectors(case):
    if case["valid"]:
        merkle.verify_proof(case["proof"], case["root"], expected_tree=case.get("tree"))
    else:
        with pytest.raises(merkle.MerkleError) as ei:
            merkle.verify_proof(case["proof"], case["root"], expected_tree=case.get("tree"))
        assert ei.value.code == "merkle.proof_invalid"


def test_merkle_tree_builds_verifiable_proof_files():
    ck = b"\x01" * 32
    recs = [{"id": "std:a", "digest": "sha256:" + "0" * 64, "enabled": True, "source": "std"},
            {"id": "std:b", "digest": "sha256:" + "1" * 64, "enabled": False, "source": "std"},
            {"id": "acme:c", "digest": "sha256:" + "2" * 64, "enabled": True, "source": "custom"}]
    t = merkle.build_tree("policy", recs, ck)
    for i in range(t.size):
        p = t.proof(i)
        assert p["v"] == 1 and p["tree"] == "policy" and p["size"] == 3 and p["index"] == i
        assert "tree" not in p["record"]
        merkle.verify_proof(p, t.root_str, expected_tree="policy")
        with pytest.raises(merkle.MerkleError):
            merkle.verify_proof(p, t.root_str, expected_tree="graph")


# -------------------------------------------------------------------------- commit nonce / leaves
CV = vec("commit-nonce.json")


@pytest.mark.parametrize("case", CV["leaves"], ids=lambda c: c["id"])
def test_commit_nonce_vectors(case):
    ck = unhex(CV["commit_key_hex"])
    rec = dict(case["record"], tree=case["tree"])
    lj = canon.dumps(rec)
    assert lj.decode("ascii") == case["leaf_json"]
    assert hashlib.sha256(lj).hexdigest() == case["leaf_json_sha256"]
    nonce = merkle.leaf_nonce(ck, lj)
    assert nonce.hex() == case["nonce_hex"]
    assert merkle.leaf_hash(nonce, lj).hex() == case["leaf_hash_hex"]


@pytest.mark.parametrize("case", CV["trees"], ids=lambda c: c["id"])
def test_commit_tree_vectors(case):
    t = merkle.build_tree(case["tree"], case["records"], unhex(CV["commit_key_hex"]))
    assert t.root_str == case["root"]
    assert t.size == case["size"]
    assert [leaf.leaf_hash.hex() for leaf in t.leaves] == case["sorted_leaf_hashes"]


# -------------------------------------------------------------------------------- coverage maths
KV = vec("coverage.json")


@pytest.mark.parametrize("case", KV["meets"], ids=lambda c: "%d-of-%d-vs-%d" % (c["covered"], c["universe"], c["required_bp"]))
def test_coverage_meets_vectors(case):
    assert limits.coverage_meets(case["covered"], case["universe"], case["required_bp"]) is case["ok"]


@pytest.mark.parametrize("case", KV["percent"], ids=lambda c: "%d-of-%d" % (c["covered"], c["universe"]))
def test_percent_floor_vectors(case):
    assert wording.percent_floor(case["covered"], case["universe"]) == case["pct_floor"]


@pytest.mark.parametrize("case", KV["required_bp"], ids=lambda c: c["float_repr"])
def test_required_bp_from_float_vectors(case):
    assert limits.required_bp_from_float(float(case["float_repr"])) == case["bp"]


@pytest.mark.parametrize("case", KV["threshold"], ids=lambda c: c["input"] or "empty")
def test_threshold_bp_vectors(case):
    if case["valid"]:
        assert limits.threshold_bp(case["input"]) == case["bp"]
    else:
        with pytest.raises(ValueError):
            limits.threshold_bp(case["input"])


def test_coverage_never_rounds_up_past_a_threshold():
    assert limits.coverage_meets(19, 20, 9500) is True
    assert limits.coverage_meets(18, 20, 9500) is False
    assert limits.coverage_meets(41, 42, 9800) is False          # 97.6 %
    assert wording.percent_floor(41, 42) == 97                   # never 98 or 100
    assert limits.coverage_meets(0, 0, 0) is False               # empty universe is never covered
    assert limits.coverage_meets(1, 1, 10001) is False


# ------------------------------------------------------------------------------------ reason map
RV = vec("reason-map.json")


def test_reason_enum_matches_contract():
    assert set(RV["enum"]) == set(codes.UNKNOWN_REASON_CODES)
    assert RV["enum"] == sorted(RV["enum"])


@pytest.mark.parametrize("case", RV["cases"], ids=lambda c: c["reason"] or "empty")
def test_reason_map_vectors(case):
    assert codes.map_engine_reason(case["reason"]) == case["code"]
    assert case["code"] in codes.UNKNOWN_REASON_CODES


def test_reason_map_unknown_strings_are_other_not_errors():
    for odd in ("", ":", "no_counterexample", "witness_found", "x" * 1000, "é", ":coverage_below_required"):
        assert codes.map_engine_reason(odd) == "other"


def test_map_reasons_is_sorted_unique_and_nonempty():
    assert codes.map_reasons(["zone_unknown:3", "coverage_below_required", "zone_unknown:9"]) == [
        "coverage_below_required", "zone_unknown"]
    assert codes.map_reasons([]) == ["other"]                    # UNKNOWN always carries at least one code


# ------------------------------------------------------------------- worked example (section 13)
WX = vec("worked-example.json")


def test_worked_example_reproduces_the_contract_bytes():
    payload = base64.b64decode(WX["payload_b64"])
    assert len(payload) == 2536
    assert hashlib.sha256(payload).hexdigest() == "ccd9d6bcfa3d9ef1b18bd5cfb1f864d13d50f0239eb055d40f28e9ea5e6278db"
    stmt = canon.roundtrip(payload)
    assert stmt["predicate"]["kid"] == "2ceb61e24df5fde7c0ab24b2a2774fa4"
    env = dsse.parse_envelope(WX["envelope"].encode("ascii"), expected_type=dsse.PAYLOAD_TYPE_STATEMENT)
    assert env.payload == payload and env.keyid == stmt["predicate"]["kid"]
    pub = base64.b64decode(WX["tenant_public_key_b64"])
    assert ed25519.kid_of(pub) == env.keyid
    assert ed25519.verify_code(pub, dsse.pae(env.payload_type, env.payload), env.sig) is None
    assert base64.b64encode(env.sig).decode() == (
        "c5fOB7whPuYeD9wONEz/Ppl+zY5l3x5FxBz4qogxnjF8P4mg2ZzqMyunTj+XrkQF3WoGE12Ri6/6btdiBYyqBg==")
    assert len(WX["envelope"]) == 3608
    # a one-bit change anywhere in the payload breaks the signature
    bad = bytearray(payload)
    bad[100] ^= 1
    assert ed25519.verify_code(pub, dsse.pae(env.payload_type, bytes(bad)), env.sig) == "sig.invalid"


def test_worked_example_pins_from_the_contract():
    assert WX["pins"]["policy_root"] == "sha256:1ceecb33a4ca1bf921a3336c237c60c55068826cf4fe6bc83c6de172c061551d"
    assert WX["pins"]["scope_digest"] == "sha256:be3fe528ef2b63fbb572c9bf47918ef6eacb45d7233231581fbb06c193044b7c"
    assert WX["pins"]["subject_digest"] == hashlib.sha256(b"dns:example.com").hexdigest()
    assert WX["pins"]["limits_digest"] == "sha256:330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f"
    assert WX["pins"]["anchor_digest"] == "sha256:5f06ee2d93da06240f8c46c6d40844b0f8364a8142d2ee91bc3e83d7ba9ac0b8"
    anchor = base64.b64decode(WX["anchor_doc_b64"])
    assert "sha256:" + hashlib.sha256(anchor).hexdigest() == WX["pins"]["anchor_digest"]
    doc = canon.roundtrip(anchor)
    sig = base64.b64decode(doc.pop("sig"))
    apub = base64.b64decode(WX["anchor_public_key_b64"])
    assert ed25519.kid_of(apub) == doc["kid"] == "9aef608fe4565a8f55947deec61af518"
    assert ed25519.verify_code(apub, b"paddock-anchor/v2\n" + canon.dumps(doc), sig) is None
    # an anchor signature is not a statement signature (context separation)
    assert ed25519.verify_code(apub, dsse.pae(dsse.PAYLOAD_TYPE_STATEMENT, canon.dumps(doc)), sig) == "sig.invalid"


# --------------------------------------------------------------------------------- dsse envelope
def _env(payload=b'{"a":1}', ptype="application/vnd.in-toto+json", keyid="0" * 32, sig=b"\x00" * 64, **over):
    d = {"payloadType": ptype, "payload": base64.b64encode(payload).decode(),
         "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}]}
    d.update(over)
    return json.dumps(d).encode()


@pytest.mark.parametrize("data,code", [
    (b"[]", "schema.envelope_invalid"),
    (b'"x"', "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": [], "extra": 1}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": ""}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": 1, "payload": "", "signatures": []}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": []}).encode(), "sig.count_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": [{"keyid": "0" * 32, "sig": "AA=="}] * 2}).encode(),
     "sig.count_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": "x"}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": [1]}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": [{"keyid": "0" * 32}]}).encode(), "schema.envelope_invalid"),
    (json.dumps({"payloadType": "t", "payload": "", "signatures": [{"keyid": "0" * 32, "sig": "A", "x": 1}]}).encode(),
     "schema.envelope_invalid"),
    (_env(payload=b"x").replace(b'"eA=="', b'"eA"'), "schema.base64_invalid"),
    (_env(keyid="ABC"), "schema.digest_format"),
    (_env(keyid="0" * 31), "schema.digest_format"),
    (_env(sig=b"\x00" * 63), "sig.malformed"),
    (_env(sig=b"\x00" * 65), "sig.malformed"),
    (b'{"payloadType":"t","payloadType":"t","payload":"","signatures":[]}', "input.duplicate_key"),
    (b"\xef\xbb\xbf" + _env(), "input.not_ascii"),
])
def test_envelope_rejections(data, code):
    with pytest.raises(dsse.DsseError) as ei:
        dsse.parse_envelope(data)
    assert ei.value.code == code


def test_envelope_expected_type_and_limits():
    e = dsse.parse_envelope(_env(), expected_type="application/vnd.in-toto+json")
    assert e.payload == b'{"a":1}' and e.keyid == "0" * 32 and e.sig == b"\x00" * 64
    with pytest.raises(dsse.DsseError) as ei:
        dsse.parse_envelope(_env(), expected_type="application/vnd.paddock.key-cert+json")
    assert ei.value.code == "schema.payload_type"
    with pytest.raises(dsse.DsseError) as ei:
        dsse.parse_envelope(b" " * (limits.MAX_ENVELOPE_BYTES + 1))
    assert ei.value.code == "input.too_large"
    with pytest.raises(dsse.DsseError) as ei:
        dsse.parse_envelope(_env(payload=b"a" * (limits.MAX_PAYLOAD_BYTES + 1)))
    assert ei.value.code == "schema.limit_exceeded"
    dsse.parse_envelope(_env(payload=b"a" * limits.MAX_PAYLOAD_BYTES))


def test_envelope_pretty_printed_and_build_roundtrip():
    pretty = json.dumps(json.loads(_env()), indent=2).encode() + b"\n"
    assert dsse.parse_envelope(pretty).payload == b'{"a":1}'
    built = dsse.build_envelope("application/vnd.in-toto+json", b'{"a":1}', "0" * 32, b"\x01" * 64)
    e = dsse.parse_envelope(built)
    assert e.sig == b"\x01" * 64
    assert built == dsse.build_envelope("application/vnd.in-toto+json", b'{"a":1}', "0" * 32, b"\x01" * 64)
    assert built.startswith(b'{"payload":')                      # sorted keys, compact


# ------------------------------------------------------------------------ limits and constants
def test_limits_constants_follow_the_contract():
    assert limits.MAX_INT == 2 ** 53 - 1
    assert limits.MAX_PCJ_BYTES == 1 << 20 and limits.MAX_PCJ_DEPTH == 16 and limits.MAX_STATEMENT_DEPTH == 8
    assert limits.MAX_PAYLOAD_BYTES == 256 * 1024 and limits.MAX_ENVELOPE_BYTES == 512 * 1024
    assert limits.MAX_AUX_FILE_BYTES == 256 * 1024 and limits.MAX_RUN_BYTES == 8 * 1024 * 1024
    assert limits.MAX_RESULTS == 256 and limits.MAX_STRING_BYTES == 512
    assert limits.MAX_TTL_SECONDS == 7 * 86400 and limits.SKEW_SECONDS == 300 and limits.SNAPSHOT_MAX_GAP_SECONDS == 900
    assert limits.REVOCATION_STALE_GRACE_SECONDS == 48 * 3600
    assert limits.MAX_DNS_RECORDS == 8 and limits.MAX_DNS_BYTES == 4096


def test_limits_text_is_pinned_by_digest():
    text = limits.limits_text("paddock-limits/1")
    assert text is not None and text.encode("ascii").endswith(b"\n") and b"\r" not in text.encode("ascii")
    assert len(text.encode("ascii")) == 1636
    assert limits.limits_digest("paddock-limits/1") == (
        "sha256:330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f")
    assert limits.limits_text("paddock-limits/2") is None
    assert limits.limits_digest("nope") is None


def test_data_files_are_identical_to_the_spec_registry():
    data = Path(limits.__file__).resolve().parent / "data"
    reg = SPEC / "registry"
    for src, dst in (("advisories.json", "advisories.json"), ("wording-v1.json", "wording-v1.json"),
                     ("limits-v1.txt", "limits-v1.txt"), ("std-registry.json", "std_registry.json")):
        assert (reg / src).read_bytes() == (data / dst).read_bytes(), src


# --------------------------------------------------------------------------------------- wording
def test_wording_holds_line_is_exact():
    s = wording.render("W-HOLDS", name="No internet path reaches a data store", tier_phrase=wording.tier_phrase("configured"),
                       covered=41, universe=42, pct=wording.percent_floor(41, 42), valid_until="2026-12-02T08:40:00Z")
    assert s == ('No counterexample found for "No internet path reaches a data store", based on configuration read from '
                 'the systems (not tested from outside). 41 of 42 relevant assets had live evidence (97%). '
                 'Evidence current until 2026-12-02T08:40:00Z.')


def test_wording_footer_and_every_template_is_clean():
    f = wording.render("W-FOOTER")
    assert f == ("A passing result means: no counterexample was found under this evidence, at this coverage, at this "
                 "time. It is not a statement that the organisation is secure.")
    for tid in wording.template_ids():
        text = wording.raw_template(tid)
        assert wording.forbidden_hits(text, remove=[f]) == [], tid
    for t, p in wording.TIER_PHRASES.items():
        assert wording.forbidden_hits(p) == [], t
    for c in codes.UNKNOWN_REASON_CODES:
        assert wording.forbidden_hits(wording.reason_phrase(c)) == [], c
    assert wording.forbidden_hits("This is SECURE and Safe, passed. A clean, proven, breach-proof system", remove=[]) == [
        "breach-proof", "clean", "passed", "proven", "safe", "secure"]
    # whole words: unsafe / insecure / security are not listed, a hyphenated compound still contains the word
    assert wording.forbidden_hits("secure-looking, unsafe, insecure, security, secured.") == ["secure", "secured"]


def test_wording_forbidden_scan_removal_is_exact_text_only():
    hostile = "acme:fully-secure"
    out = wording.render("W-CUSTOM-NAME", id=hostile)
    assert hostile in out and "`" + hostile + "`" in out
    assert wording.forbidden_hits(out, remove=[hostile]) == []
    assert wording.forbidden_hits("it is secure", remove=[hostile]) == ["secure"]


def test_wording_slot_validation_rejects_attacker_text():
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x\nfake line", tier_phrase="t", covered=1, universe=1, pct=100, valid_until="2026-12-02T08:40:00Z")
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x", tier_phrase="t", covered="1; rm", universe=1, pct=100, valid_until="2026-12-02T08:40:00Z")
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x", tier_phrase="t", covered=True, universe=1, pct=100, valid_until="2026-12-02T08:40:00Z")
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x", tier_phrase="t", covered=1, universe=1, pct=100, valid_until="tomorrow")
    with pytest.raises(wording.WordingError):
        wording.render("W-CUSTOM-NAME", id="bad id with spaces")
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x")                       # missing slots
    with pytest.raises(wording.WordingError):
        wording.render("W-FOOTER", extra=1)                       # unexpected slot
    with pytest.raises(wording.WordingError):
        wording.render("W-NOPE")


def test_wording_other_templates_and_headlines():
    assert wording.render("W-HOLDS-EXPIRED", name="N", valid_until="2026-12-02T08:40:00Z") == (
        'EXPIRED: the result for "N" was current until 2026-12-02T08:40:00Z. It says nothing about now.')
    assert wording.render("W-VIOLATED", name="N", violations=2) == 'A counterexample exists for "N" (2 found).'
    assert wording.render("W-UNKNOWN", name="N", reason_phrase=wording.reason_phrase("stale_or_missing_evidence")) == (
        'Undetermined for "N": evidence is stale or missing. This is not a pass.')
    assert wording.render("W-EXC", n=3) == "3 declared exception(s) apply."
    assert wording.render("W-STD-MISSING", n=1) == "Standard invariants enabled but not disclosed: 1."
    assert wording.headline("baseline") == "VALID under baseline profile"
    assert wording.headline("accepted", name="acme-policy") == "ACCEPTED under policy acme-policy"
    assert wording.headline("rejected", message="Signature does not match") == "REJECTED: Signature does not match"
    assert wording.headline("unverifiable", message="DNS lookup failed.") == "UNVERIFIABLE: DNS lookup failed."
    assert wording.profile_line() == ("profile: baseline (no acceptance policy given; nothing requires specific invariants)")
    assert "disabled" in wording.render("W-POLICY", disclosed=2, enabled=3, disabled=0, k=1)
    for tid in ("W-SUPERSEDED", "W-ROLLBACK", "W-CHAIN-BROKEN", "W-DNS-UNBOUND", "W-KEY-REVOKED", "W-ENGINE-ADVISORY",
                "W-POLICY-SHRANK", "W-DIGEST-CHANGED", "W-STD-UNRECOGNISED"):
        assert wording.render(tid)
    assert wording.percent_floor(0, 5) == 0 and wording.percent_floor(5, 5) == 100
    with pytest.raises(ValueError):
        wording.percent_floor(1, 0)


def test_wording_file_is_ascii_and_versioned():
    raw = (SPEC / "registry" / "wording-v1.json").read_bytes()
    raw.decode("ascii")
    d = json.loads(raw)
    assert d["wording_version"] == 1
    assert set(d["forbidden_words"]) == {"secure", "secured", "safe", "safely", "protected", "compliant", "certified",
                                         "guarantee", "guaranteed", "unhackable", "breach-proof", "passed", "clean", "proven"}
    assert re.fullmatch(r"[a-z-]+", " ".join(d["forbidden_words"]).replace(" ", ""))


# ------------------------------------------------------------------------------ conformance runner
def _load_runner():
    import importlib.util
    spec = importlib.util.spec_from_file_location("conformance_run", SPEC / "conformance" / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _adapter():
    import types
    a = types.SimpleNamespace()
    a.pae = dsse.pae
    a.b64_decode = b64.strict_decode
    a.pcj_parse = canon.roundtrip
    a.pcj_dumps = canon.dumps
    a.time_parse = timefmt.parse
    a.merkle_root = merkle.root
    a.merkle_verify = merkle.verify_inclusion
    a.ed25519_verify = ed25519.verify
    return a


def test_runner_level_b_passes_for_this_implementation():
    run = _load_runner()
    res = run.run_level_b(_adapter(), str(PRIM))
    assert len(res) > 250
    assert [r for r in res if not r[2]] == []
    assert {r[0] for r in res} == {"pae.json", "b64.json", "pcj.json", "time.json", "merkle.json", "ed25519.json"}


def test_runner_level_b_catches_broken_implementations():
    run = _load_runner()

    def broken(**over):
        a = _adapter()
        for k, v in over.items():
            setattr(a, k, v)
        return [r for r in run.run_level_b(a, str(PRIM)) if not r[2]]
    assert broken(pae=lambda t, p: dsse.pae(t, p) + b"\n")
    assert broken(b64_decode=lambda s: __import__("base64").b64decode(s))                  # lenient decoder
    assert broken(pcj_parse=canon.loads)                                                    # forgot the round trip
    assert broken(time_parse=lambda s: timefmt.parse(s.replace(":60", ":59")))
    assert broken(merkle_verify=lambda leaf, i, n, p, r: True)
    assert broken(ed25519_verify=lambda pub, m, s: __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"]).Ed25519PublicKey.from_public_bytes(pub).verify(s, m) is None)


def _write_case(root, cid, expect, now="2026-12-01T12:00:00Z", files=None, **extra):
    d = root / "cases" / cid
    (d / "bundle").mkdir(parents=True)
    for name, data in (files or {"a.json": b"{}"}).items():
        (d / "bundle" / name).write_bytes(data)
    case = {"id": cid, "now": now, "target": {"kind": "dir", "path": "."}, "args": [], "tags": ["t"], "expect": expect}
    case.update(extra)
    (d / "case.json").write_text(json.dumps(case))


def test_runner_level_a_against_a_stub_implementation(tmp_path, monkeypatch, capsys):
    import sys
    run = _load_runner()
    stub = tmp_path / "stub.py"
    stub.write_text(
        "import json, sys\n"
        "a = sys.argv[1:]\n"
        "assert '--json' in a and '--offline' in a and a[a.index('--now') + 1] == '2026-12-01T12:00:00Z'\n"
        "assert '--no-state' in a and '--roots' in a\n"
        "mode = open(a[-1] + '/a.json').read()\n"
        "if mode.startswith('{\"bad'):\n"
        "    rep = {'decision': 'accepted', 'primary': None, 'profile': 'baseline', 'reasons': [], 'warnings': [], 'human': ['this system is secure']}\n"
        "    print(json.dumps(rep)); sys.exit(0)\n"
        "if mode.startswith('{\"rej'):\n"
        "    rep = {'decision': 'rejected', 'primary': 'sig.invalid', 'profile': 'baseline', 'reasons': [\n"
        "      {'code': 'sig.invalid', 'class': 'R'}, {'code': 'time.expired', 'class': 'R'}], 'warnings': [{'code': 'dns.record_ignored'}], 'human': []}\n"
        "    print(json.dumps(rep)); sys.exit(1)\n"
        "rep = {'decision': 'accepted', 'primary': None, 'profile': 'baseline', 'reasons': [], 'warnings': [], 'human': ['No counterexample found.']}\n"
        "print(json.dumps(rep))\n")
    monkeypatch.setattr(run, "VECTORS", str(tmp_path))
    (tmp_path / "test-roots.json").write_text("[]")
    _write_case(tmp_path, "ok", {"exit": 0, "decision": "accepted", "codes": [], "warnings": [], "primary": None, "profile": "baseline",
                                 "forbidden_terms": True})
    _write_case(tmp_path, "rejected", {"exit": 1, "decision": "rejected", "codes": ["sig.invalid", "time.expired"],
                                       "warnings": ["dns.record_ignored"], "primary": "sig.invalid"}, files={"a.json": b'{"rej":1}'})
    _write_case(tmp_path, "wrong-order", {"exit": 1, "decision": "rejected", "codes": ["time.expired", "sig.invalid"]},
                files={"a.json": b'{"rej":1}'})
    _write_case(tmp_path, "wrong-exit", {"exit": 2, "decision": "accepted"})
    _write_case(tmp_path, "forbidden-word", {"exit": 0, "decision": "accepted", "forbidden_terms": True}, files={"a.json": b'{"bad":1}'})
    _write_case(tmp_path, "forbidden-word-from-input-is-removed", {"exit": 0, "decision": "accepted", "forbidden_terms": True},
                files={"a.json": b'{"bad":1,"x":"acme:fully-secure"}'})
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "ok"]) == 0
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "rejected"]) == 0
    capsys.readouterr()
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "wrong-order"]) == 1
    assert "codes ['sig.invalid', 'time.expired'], expected ['time.expired', 'sig.invalid']" in capsys.readouterr().out
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "wrong-exit"]) == 1
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "forbidden-word"]) == 1
    assert "forbidden words in the output: secure" in capsys.readouterr().out
    # the hostile id is removed from the scan, but the bare word elsewhere in the output is not: still a failure
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--case", "forbidden-word-from-input-is-removed"]) == 1
    assert run.main(["--impl", "%s %s" % (sys.executable, stub), "--filter", "t"]) == 1
    assert run.main(["--list"]) == 0
    assert run.main(["--impl", "no-such-command-xyz", "--case", "ok"]) == 1
    assert run.main(["--impl", "x", "--case", "nope"]) == 2


def test_runner_recipes_and_command_assembly(tmp_path):
    run = _load_runner()
    d = tmp_path / "c"
    (d / "bundle" / ".well-known").mkdir(parents=True)
    (d / "bundle" / ".well-known" / "e.json").write_bytes(b"{}")
    case = {"id": "x", "now": "2026-12-01T12:00:00Z", "target": {"kind": "dir", "path": ".well-known"}, "args": ["--max-age", "24h"],
            "policy": {"policy_version": 1}, "dns": {"resolvers": [{"a": 1}, {"b": 2}]}, "state": {"hw": 3}, "anchor": ".well-known/e.json",
            "registry": "default", "roots": "test",
            "recipes": [{"op": "pad_file", "file": ".well-known/e.json", "bytes": 600000}, {"op": "write_file", "file": "big.bin", "bytes": 1000, "head": "[", "tail": "]", "fill": " "}]}
    work = tmp_path / "w"
    work.mkdir()
    root = run.materialise(str(d), case, str(work))
    assert (Path(root) / ".well-known" / "e.json").stat().st_size == 600000
    assert (Path(root) / "big.bin").stat().st_size == 1000
    cmd = run.build_command("paddock-verify --x", str(d), case, root, str(work), "/roots.json")
    assert cmd[:2] == ["paddock-verify", "--x"] and cmd[2:4] == ["--json", "--offline"]
    assert cmd.count("--dns-resolver") == 2 and "--policy" in cmd and "--state-file" in cmd and "--no-state" not in cmd
    assert cmd[cmd.index("--roots") + 1] == "/roots.json"
    assert cmd[-1].endswith(".well-known") and cmd[cmd.index("--anchor-file") + 1].endswith(".well-known/e.json")
    assert cmd[cmd.index("--max-age") + 1] == "24h"
    with pytest.raises(ValueError):
        run.materialise(str(d), dict(case, recipes=[{"op": "pad_file", "file": ".well-known/e.json", "bytes": 1}]), str(tmp_path / "w2"))
    with pytest.raises(ValueError):
        run.materialise(str(d), dict(case, recipes=[{"op": "unknown", "file": "x"}]), str(tmp_path / "w3"))


def test_runner_forbidden_scan_matches_the_verifier_scan():
    run = _load_runner()
    words = json.loads((SPEC / "registry" / "wording-v1.json").read_text())["forbidden_words"]
    for text in ("This is SECURE and Safe, passed. A clean, proven, breach-proof system", "secure-looking, unsafe, insecure, security, secured.",
                 "nothing here", "A passing result is not a statement that anything is protected."):
        assert run.forbidden_hits(text, [], words) == wording.forbidden_hits(text)
    assert run.harvest_inputs(str(PRIM / ".."))                         # finds ids in the vector files


# ----------------------------------------------------------------------------------- JSON schemas
SCHEMAS = ["statement", "predicate", "dsse-envelope", "keys", "keycert", "revoked", "anchor", "inclusion-proof", "bundle-index",
           "acceptance-policy", "verifier-report", "vector-case"]


def _schema(name):
    return json.loads((SPEC / "schema" / (name + ".schema.json")).read_text(encoding="ascii"))


@pytest.mark.parametrize("name", SCHEMAS)
def test_schema_files_are_wellformed(name):
    s = _schema(name)
    assert s["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert s["$id"] == "https://paddock.dev/spec/containment-attestation/v1/%s.schema.json" % name
    assert s["title"] and s["description"]
    names = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "properties":
                    names.extend(v)
                if k in ("enum", "const"):
                    names.extend(e for e in (v if isinstance(v, list) else [v]) if isinstance(e, str))
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(s)
    assert wording.forbidden_hits(" ".join(names)) == []


def test_worked_example_validates_against_the_schemas():
    jsonschema = pytest.importorskip("jsonschema")
    store = {s["$id"]: s for s in (_schema(n) for n in SCHEMAS)}
    from referencing import Registry, Resource
    reg = Registry().with_resources([(k, Resource.from_contents(v)) for k, v in store.items()])
    stmt_schema = _schema("statement")
    v = jsonschema.Draft202012Validator(stmt_schema, registry=reg)
    stmt = WX["statement"]
    assert list(v.iter_errors(stmt)) == []
    env = jsonschema.Draft202012Validator(_schema("dsse-envelope"), registry=reg)
    assert list(env.iter_errors(json.loads(WX["envelope"]))) == []
    anchor = jsonschema.Draft202012Validator(_schema("anchor"), registry=reg)
    assert list(anchor.iter_errors(WX["anchor_doc"])) == []

    def bad(mutate):
        d = json.loads(json.dumps(stmt))
        mutate(d)
        return [e.message for e in v.iter_errors(d)]
    assert bad(lambda d: d["predicate"].__setitem__("extra", 1))                                   # strict: unknown key
    assert bad(lambda d: d["predicate"]["results"][0].__setitem__("verdict", "EXPIRED"))           # never issued
    assert bad(lambda d: d["predicate"]["results"][0].__setitem__("tier", "declared"))             # never on a HOLDS
    assert bad(lambda d: d["predicate"]["results"][0].pop("tier"))
    assert bad(lambda d: d["predicate"]["results"][0].__setitem__("violations", 1))                # HOLDS has no violations field
    assert bad(lambda d: d["predicate"].__setitem__("issued_at", "2026-12-01T09:00:00+00:00"))
    assert bad(lambda d: d["predicate"].__setitem__("seq", 2))                                     # prev required iff seq > 1
    assert bad(lambda d: d["predicate"]["results"][0]["coverage"].__setitem__("required_bp", 10001))
    assert bad(lambda d: d["predicate"]["results"][0].__setitem__("invariant", "BAD ID"))
    assert bad(lambda d: d.__setitem__("subject", []))
    assert bad(lambda d: d["predicate"]["results"].append(d["predicate"]["results"][0]) or d["predicate"].__setitem__("results", d["predicate"]["results"] * 300))
    ok_violated = json.loads(json.dumps(stmt))
    r = ok_violated["predicate"]["results"][0]
    for k in ("tier", "valid_until"):
        r.pop(k)
    r.update({"verdict": "VIOLATED", "violations": 2})
    assert list(v.iter_errors(ok_violated)) == []
    r.pop("violations")
    assert list(v.iter_errors(ok_violated)) != []
    r.update({"verdict": "UNKNOWN", "reason_codes": ["stale_or_missing_evidence", "zone_unknown"]})
    assert list(v.iter_errors(ok_violated)) == []
    r["reason_codes"] = ["zone_unknown", "stale_or_missing_evidence"]   # unsorted: sortedness is checked by the verifier, not the schema
    r["reason_codes"] = ["not_a_code"]
    assert list(v.iter_errors(ok_violated)) != []


# ------------------------------------------------------------------- generators, registry, package
def _load_generator():
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_vectors", SPEC / "tools" / "gen_vectors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_primitive_vectors_are_up_to_date():
    gen = _load_generator()
    assert gen.main(["--check"]) == 0
    files = gen.generate()
    assert set(files) == {p.name for p in PRIM.glob("*.json")}
    assert gen.generate() == files                     # deterministic: two runs, identical bytes


def test_generator_reference_agrees_with_the_verifier_on_small_order_points():
    gen = _load_generator()
    assert [bytes.fromhex(h) for h in vec("ed25519.json")["small_order_encodings"]] == gen.small_order_points()
    assert gen.small_order_points() == sorted(ed25519.small_order_encodings())


def test_policy_parse_vectors_agree_with_a_full_yaml_library_on_accepted_cases():
    yaml = pytest.importorskip("yaml")
    from decimal import Decimal

    def norm(v):
        if isinstance(v, float):
            return {"$decimal": str(Decimal(repr(v)))}
        if isinstance(v, dict):
            return {k: norm(x) for k, x in v.items()}
        if isinstance(v, list):
            return [norm(x) for x in v]
        return v
    cases = [c for c in vec("policy-parse.json")["cases"] if c["accept"]]
    assert len(cases) >= 20
    for c in cases:
        got = norm(yaml.safe_load(c["yaml"])) if c["yaml"].strip() else {}
        assert (got or {}) == c["value"], c["id"]
    rejected = [c for c in vec("policy-parse.json")["cases"] if not c["accept"]]
    assert len(rejected) >= 40 and all(c["code"] == "config.policy_invalid" and c["line"] >= 1 for c in rejected)


def test_dns_txt_vectors_are_internally_consistent():
    d = vec("dns-txt-parse.json")
    assert len(d["cases"]) >= 55
    ids = [c["id"] for c in d["cases"]]
    assert len(ids) == len(set(ids))
    for c in d["cases"]:
        for r in c["expect"]["records"]:
            assert r["status"] in d["statuses"]
            if r["status"] == "ok":
                assert re.fullmatch(r"[0-9a-f]{32}", r["kid"]) and r["fp"] == "sha256:" + r["kid"] + r["fp"][39:]
    assert any(c["expect"]["too_many"] for c in d["cases"])


def test_scope_digest_vectors_digest_matches_their_own_document():
    for c in vec("scope-digest.json")["cases"]:
        e = c["expect"]
        assert canon.dumps(e["doc"]).decode() == e["doc_pcj"]
        assert e["digest"] == "sha256:" + hashlib.sha256(e["doc_pcj"].encode()).hexdigest()
        assert e["entries"] == len(e["doc"]["entries"])
        assert [(x["kind"], x["value"]) for x in e["doc"]["entries"]] == sorted((x["kind"], x["value"]) for x in e["doc"]["entries"])


def test_reason_prefix_map_equals_the_vector_table():
    assert vec("reason-map.json")["prefix_map"] == codes.REASON_PREFIX_MAP


def test_package_exports_and_lazy_pipeline_entry_points():
    import paddock_verify
    assert paddock_verify.NAME == "paddock-verify" and paddock_verify.SPEC_VERSION == "1.0" and paddock_verify.__version__
    with pytest.raises(AttributeError):
        paddock_verify.nonexistent
    # verify / verify_envelope live in paddock_verify.checks (P3.4); until then they are simply not there
    try:
        import paddock_verify.checks  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError):
            paddock_verify.verify


def test_std_registry_is_current_against_the_shipped_library():
    pytest.importorskip("pydantic")
    pytest.importorskip("yaml")
    import subprocess
    import sys
    script = Path(__file__).resolve().parents[2] / "scripts" / "export_std_registry.py"
    p = subprocess.run([sys.executable, str(script), "--check"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    assert p.returncode == 0, p.stderr.decode()


def test_std_registry_content_follows_the_contract():
    reg = json.loads((SPEC / "registry" / "std-registry.json").read_text())
    assert reg["registry_version"] == 1
    rs = reg["rulesets"]["sha256:b13ad8f0f157b2a037ce106ae96b692b09785be865259702dc45adf3fb15a299"]
    assert rs["engine"] == "0.3.0" and len(rs["std"]) == 6
    rows = [{"digest": e["digest"], "id": i} for i, e in sorted(rs["std"].items())]
    ruleset = "sha256:" + hashlib.sha256(canon.dumps({"std": rows, "v": 1})).hexdigest()
    assert ruleset in reg["rulesets"]
    for i, e in rs["std"].items():
        assert i.startswith("std:") and e["status"] == "current"
        assert e["assertion"] in ("unreachable", "exposes-only", "covered", "host-config")
        assert wording.forbidden_hits(e["name"]) == [] and "hardened" not in e["name"].lower()
    adv = json.loads((SPEC / "registry" / "advisories.json").read_text())
    assert adv["advisories_version"] == 1 and adv["items"] == []


# ------------------------------------------------------------------------ graph leaf value encoding
@pytest.mark.parametrize("case", CV["leaf_encoding"], ids=lambda c: c["id"])
def test_leaf_encoding_vectors(case):
    out = merkle.encode_leaf_value(case["input"])
    assert canon.dumps(dict(out, tree="graph")).decode("ascii") == case["leaf_json"]


@pytest.mark.parametrize("case", CV["unencodable_fail_closed"], ids=lambda c: c["id"])
def test_unencodable_leaf_values_fail_closed(case):
    with pytest.raises(merkle.LeafEncodingError):
        merkle.encode_leaf_value(case["input"])


def test_leaf_encoding_rules():
    h = "sha256:" + hashlib.sha256("caf\u00e9".encode("utf-8")).hexdigest()
    assert merkle.encode_leaf_value({"a": None, "b": "caf\u00e9", "c": [1, "x"], "d": {"e": None}}) == {
        "b": {"$h": h}, "c": [1, "x"], "d": {}}
    assert merkle.encode_leaf_value("plain") == "plain"
    assert merkle.encode_leaf_value(True) is True
    assert merkle.encode_leaf_value(0) == 0
    for bad in (1.5, -1, 2 ** 53, {1: 2}, {"": 1}, (1, 2), b"x", {"k": {"n": -3}}, [1, None], {'k"': 1}, "\ud800", [[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]):
        with pytest.raises(merkle.LeafEncodingError):
            merkle.encode_leaf_value(bad)
    assert issubclass(merkle.LeafEncodingError, ValueError)


# ================================================================================= review round 2
def test_wording_every_enum_phrase_and_rendered_key_line_is_clean():
    """The key line is printed for every valid baseline case, so it must pass the forbidden-vocabulary scan for
    every combination of the enumerations (a phrase such as 'certified by the vendor root' would fail Level A)."""
    import itertools
    enums = json.loads((SPEC / "registry" / "wording-v1.json").read_text())["enums"]
    for kind, table in enums.items():
        for token, phrase in table.items():
            assert wording.forbidden_hits(phrase) == [], (kind, token, phrase)
    names = ["cert", "custody", "dns", "dnssec"]
    n = 0
    for combo in itertools.product(*[sorted(enums[k]) for k in names]):
        line = wording.render("W-KEY", **dict(zip(names, combo)))
        assert wording.forbidden_hits(line, remove=[wording.render("W-FOOTER")]) == [], line
        n += 1
    assert n == 2 * 3 * 3 * 3


def test_wording_scan_covers_every_message_phrase_and_headline():
    footer = wording.render("W-FOOTER")
    for c, entry in codes.CODES.items():
        assert wording.forbidden_hits(entry.message) == [], c
        assert wording.forbidden_hits(wording.headline("rejected", message=entry.message)) == [], c
    for kind in ("baseline", "accepted", "rejected", "unverifiable"):
        slots = {"accepted": {"name": "p"}, "rejected": {"message": "m"}, "unverifiable": {"message": "m"}}.get(kind, {})
        assert wording.forbidden_hits(wording.headline(kind, **slots)) == []
    assert wording.forbidden_hits(wording.profile_line()) == []
    assert wording.forbidden_hits(footer, remove=[footer]) == []


def test_spec_wording_table_matches_the_shipped_enums():
    """spec/09 prints the enumeration phrases; they must be the registry's, and clean."""
    text = (SPEC / "spec" / "09-human-wording.md").read_text(encoding="utf-8")
    enums = json.loads((SPEC / "registry" / "wording-v1.json").read_text())["enums"]
    for kind, table in enums.items():
        for token, phrase in table.items():
            assert "| `%s` | `%s` | %s |" % (kind, token, phrase) in text, (kind, token)


ANCHORED = [
    (b64, "_SHAPE", "AAAA"), (dsse, "_KID", "a" * 32), (jsonstrict, "_PLAIN_INT", "10"), (jsonstrict, "_HEX4", "00e9"),
    (limits, "_THRESHOLD", "0.95"), (merkle, "_HEX64", "a" * 64), (merkle, "_ROOT", "sha256:" + "a" * 64),
    (timefmt, "_T", "2026-12-01T12:00:00Z"), (timefmt, "_DUR", "24h"), (wording, "_INVID", "std:a-b"),
    (wording, "_SUBJECT", "dns:example.com"), (wording, "_TOKEN", "acme-policy"), (wording, "_NAME", "A name"),
    (wording, "_PHRASE", "a phrase"),
]


@pytest.mark.parametrize("mod,attr,good", ANCHORED, ids=lambda x: x if isinstance(x, str) else getattr(x, "__name__", "")[-6:])
def test_end_anchors_reject_a_trailing_newline(mod, attr, good):
    """`$` would accept 'value\\n'; every shape check must use \\Z (or a full match)."""
    rx = getattr(mod, attr)
    assert rx.match(good), (mod.__name__, attr)
    for tail in ("\n", "\n\n", "\r\n"):
        assert rx.match(good + tail) is None, (mod.__name__, attr, tail)


def test_trailing_newline_is_rejected_through_the_public_entry_points():
    with pytest.raises(wording.WordingError):
        wording.render("W-CUSTOM-NAME", id="std:a\n")
    with pytest.raises(wording.WordingError):
        wording.render("W-HOLDS", name="x\n", tier_phrase="t", covered=1, universe=1, pct=100, valid_until="2026-12-02T08:40:00Z")
    with pytest.raises(wording.WordingError):
        wording.headline("accepted", name="policy\n")
    with pytest.raises(b64.B64Error):
        b64.strict_decode("AAAA\n")
    with pytest.raises(timefmt.TimeError):
        timefmt.parse("2026-12-01T12:00:00Z\n")
    with pytest.raises(timefmt.TimeError):
        timefmt.parse_duration("24h\n")
    ck = b"\x01" * 32
    t = merkle.build_tree("graph", [{"a": 1}], ck)
    p = t.proof(0)
    for bad in (dict(p, nonce=p["nonce"] + "\n"), dict(p, path=[x + "\n" for x in p["path"]] or ["a" * 64 + "\n"])):
        with pytest.raises(merkle.MerkleError):
            merkle.verify_proof(bad, t.root_str)
    with pytest.raises(merkle.MerkleError):
        merkle.verify_proof(p, t.root_str + "\n")


def test_merkle_expected_size_binds_the_proof_size():
    """Only the right-most leaf's path commits to the tree size; a consumer that knows the size passes it."""
    ck = b"\x02" * 32
    t = merkle.build_tree("graph", [{"n": i} for i in range(3)], ck)
    for i in range(3):
        p = t.proof(i)
        merkle.verify_proof(p, t.root_str, expected_tree="graph", expected_size=3)
        merkle.verify_proof(p, t.root_str)
        for wrong in (1, 2, 4, 5):
            with pytest.raises(merkle.MerkleError):
                merkle.verify_proof(p, t.root_str, expected_tree="graph", expected_size=wrong)
    p0 = dict(t.proof(0), size=4)                      # still verifies by path alone: this is why the argument exists
    merkle.verify_proof(p0, t.root_str)
    with pytest.raises(merkle.MerkleError):
        merkle.verify_proof(p0, t.root_str, expected_size=3)
    for bad in (True, 3.0, "3", -1):
        with pytest.raises(merkle.MerkleError):
            merkle.verify_proof(t.proof(0), t.root_str, expected_size=bad)


def test_merkle_proof_version_must_be_an_integer_one():
    ck = b"\x02" * 32
    t = merkle.build_tree("graph", [{"n": 1}], ck)
    p = t.proof(0)
    merkle.verify_proof(p, t.root_str)
    for bad in (1.0, True, "1", 2, 0):
        with pytest.raises(merkle.MerkleError):
            merkle.verify_proof(dict(p, v=bad), t.root_str)


def test_spec_conventions_keep_their_escape_examples():
    """The unicode-escape examples in 01-conventions were once interpreted away ('such as "a" and "a"')."""
    text = (SPEC / "spec" / "01-conventions.md").read_text(encoding="utf-8")
    assert "\\u0061" in text and "\\u0041" in text and "\\/" in text
    for f in sorted((SPEC / "spec").glob("*.md")) + [SPEC / "README.md", SPEC / "CHANGELOG.md"]:
        t = f.read_text(encoding="utf-8")
        assert '"a" and "a"' not in t, f.name
        assert "including `A`" not in t, f.name


def test_json_schemas_carry_an_spdx_comment():
    for f in sorted((SPEC / "schema").glob("*.schema.json")):
        d = json.loads(f.read_text(encoding="ascii"))
        assert "SPDX-License-Identifier: Apache-2.0" in d.get("$comment", ""), f.name


def test_runner_level_a_is_robust_to_hostile_reports_and_incomplete_cases(tmp_path, monkeypatch, capsys):
    import sys
    run = _load_runner()
    stub = tmp_path / "stub2.py"
    stub.write_text("import sys\n"
                    "mode = open(sys.argv[-1] + '/a.json').read()\n"
                    "print('[]' if mode.startswith('{\"list') else '\"x\"' if mode.startswith('{\"str') else '{\"decision\":\"accepted\",\"warnings\":7,\"reasons\":3}')\n")
    monkeypatch.setattr(run, "VECTORS", str(tmp_path))
    (tmp_path / "test-roots.json").write_text("[]")
    full = {"exit": 0, "decision": "accepted", "codes": [], "warnings": [], "primary": None}
    _write_case(tmp_path, "list-report", full, files={"a.json": b'{"list":1}'})
    _write_case(tmp_path, "str-report", full, files={"a.json": b'{"str":1}'})
    _write_case(tmp_path, "weird-fields", full, files={"a.json": b'{"w":1}'})
    _write_case(tmp_path, "no-codes", {"exit": 0, "decision": "accepted", "warnings": [], "primary": None}, files={"a.json": b'{"w":1}'})
    impl = "%s %s" % (sys.executable, stub)
    for cid in ("list-report", "str-report", "weird-fields"):
        assert run.main(["--impl", impl, "--case", cid]) == 1, cid        # a clean failure, not a traceback
        out = capsys.readouterr().out
        assert "Traceback" not in out, cid
    assert run.main(["--impl", impl, "--case", "no-codes"]) == 1
    assert "expect" in capsys.readouterr().out
