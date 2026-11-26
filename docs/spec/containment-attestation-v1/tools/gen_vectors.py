#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Primitive test-vector generator for the containment attestation spec (v1).

This file is a third, independent implementation written from the spec text (spec/01 to spec/09). It uses
only the standard library and `cryptography` and imports nothing from the verifier or the orchestrator
(an AST test enforces that), so a bug in either of those cannot be baked into the vectors.

    python gen_vectors.py             write vectors/primitives/*.json
    python gen_vectors.py --check     regenerate in memory and fail on any difference (CI)
    python gen_vectors.py --out DIR   write somewhere else

Everything is deterministic: no clock, no randomness. Keys derive from public test seeds.
Committed JSON: sorted keys, 2-space indent, ASCII, one trailing newline.
"""
from __future__ import annotations

import argparse
import base64
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_DIR = os.path.dirname(HERE)
DEFAULT_OUT = os.path.join(SPEC_DIR, "vectors", "primitives")
SPEC_VERSION = "1.0"
MAX_INT = 2 ** 53 - 1
P_TYPE_STATEMENT = "application/vnd.in-toto+json"
P_TYPE_CERT = "application/vnd.paddock.key-cert+json"
P_TYPE_REVOKED = "application/vnd.paddock.revocation-list+json"


# ======================================================================================== utilities
def sha(b):
    return hashlib.sha256(b).hexdigest()


def b64(b):
    return base64.b64encode(b).decode("ascii")


def unb64(s):
    return base64.b64decode(s, validate=True)


def hx(b):
    return b.hex()


def pcj(v, _depth=0):
    """Reference PCJ encoder (spec 2.1). Raises ValueError for anything a conforming document cannot hold."""
    if _depth > 16:
        raise ValueError("depth")
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if isinstance(v, int):
        if not 0 <= v <= MAX_INT:
            raise ValueError("int range")
        return str(v).encode("ascii")
    if isinstance(v, str):
        _ascii_check(v)
        return b'"' + v.encode("ascii") + b'"'
    if isinstance(v, list):
        return b"[" + b",".join(pcj(x, _depth + 1) for x in v) + b"]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str) or not k:
                raise ValueError("key")
            _ascii_check(k)
        return b"{" + b",".join(pcj(k, _depth + 1) + b":" + pcj(v[k], _depth + 1)
                                for k in sorted(v, key=lambda s: s.encode("ascii"))) + b"}"
    raise ValueError("type")


def _ascii_check(s):
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o > 0x7E or ch in '"\\':
            raise ValueError("charset")


def seed_for(name):
    return hashlib.sha256(b"paddock-conformance-seed/v1/" + name.encode("ascii")).digest()


def key_for(name):
    return Ed25519PrivateKey.from_private_bytes(seed_for(name))


def pub_of(sk):
    return sk.public_key().public_bytes_raw()


def kid_of(pub):
    return sha(pub)[:32]


def pae(ptype, payload):
    t = ptype.encode("ascii")
    return b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" " + str(len(payload)).encode("ascii") + b" " + payload


def det_bytes(n, salt=7):
    return bytes((i * 31 + salt) & 0xFF for i in range(n))


# ============================================================================== reference Ed25519
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)


def _decompress(enc):
    """Return the affine (x, y) of a 32-byte encoding, or a string naming why it is not a canonical point."""
    if len(enc) != 32:
        return "length"
    n = int.from_bytes(enc, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        return "noncanonical-y"
    u = (y * y - 1) % P
    v = (CURVE_D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return "not-on-curve"
    if x == 0 and sign == 1:
        return "noncanonical-sign"
    if (x & 1) != sign:
        x = P - x
    return (x, y)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * CURVE_D % P
    D2 = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, D2 - C, D2 + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(k, pt):
    r = IDENT
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _ext(xy):
    return (xy[0], xy[1], 1, xy[0] * xy[1] % P)


def _is_ident(pt):
    return pt[0] % P == 0 and (pt[1] - pt[2]) % P == 0


def _encode(pt):
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def small_order_points():
    """The eight points of order dividing 8, found by multiplying curve points by L (L = 5 mod 8)."""
    found = {}
    y = 2
    while len(found) < 8 and y < 400:
        r = _decompress(y.to_bytes(32, "little"))
        if isinstance(r, tuple):
            q = _mul(L, _ext(r))
            found[_encode(q)] = q
        y += 1
    assert len(found) == 8, len(found)
    for enc, pt in found.items():
        assert _is_ident(_mul(8, pt)), "not small order"
    return sorted(found)


def ref_precheck(pub, sig):
    """The 2.5 rules, written independently. Returns None or the reason code."""
    if len(sig) != 64:
        return "sig.malformed"
    if len(pub) != 32:
        return "sig.weak_key"
    r = _decompress(pub)
    if not isinstance(r, tuple):
        return "sig.weak_key"
    if _is_ident(_mul(8, _ext(r))):
        return "sig.weak_key"
    if int.from_bytes(sig[32:], "little") >= L:
        return "sig.noncanonical_s"
    return None


# ================================================================================ reference Merkle
EMPTY = hashlib.sha256(b"").digest()
NONCE_CTX = b"paddock/leaf-nonce/v1\x00"


def m_leaf(nonce, lj):
    return hashlib.sha256(b"\x00" + nonce + lj).digest()


def m_node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def m_root(hs):
    n = len(hs)
    if n == 0:
        return EMPTY
    if n == 1:
        return hs[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return m_node(m_root(hs[:k]), m_root(hs[k:]))


def m_path(hs, m):
    n = len(hs)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return m_path(hs[:k], m) + [m_root(hs[k:])]
    return m_path(hs[k:], m - k) + [m_root(hs[:k])]


def m_verify(leaf, index, size, path, root):
    """RFC 9162 2.1.3.2, exactly the algorithm printed in spec/04-merkle.md."""
    if index >= size or index < 0:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = m_node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = m_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def m_nonce(ck, lj):
    return hmac.new(ck, NONCE_CTX + hashlib.sha256(lj).digest(), hashlib.sha256).digest()


def m_tree(label, records, ck):
    """Return the sorted, de-duplicated leaves as (leaf_hash, nonce, leaf_json, record)."""
    seen = {}
    for rec in records:
        r = dict(rec)
        assert "tree" not in r
        r["tree"] = label
        lj = pcj(r)
        n = m_nonce(ck, lj)
        seen[lj] = (m_leaf(n, lj), n, lj, rec)
    leaves = sorted(seen.values(), key=lambda t: t[0])
    return leaves, m_root([t[0] for t in leaves])


COMMIT_KEY = bytes([1]) * 32


# ==================================================================================== file builders
def build_pae():
    cases = []
    for n in (0, 9, 10, 99, 100, 127, 128, 255, 256, 1000):
        payload = det_bytes(n)
        cases.append({"id": "payload-%d" % n, "payload_type": P_TYPE_STATEMENT, "payload_len": n,
                      "payload_b64": b64(payload), "pae_b64": b64(pae(P_TYPE_STATEMENT, payload))})
    for t in (P_TYPE_CERT, P_TYPE_REVOKED):
        payload = det_bytes(33)
        cases.append({"id": "type-" + t.split("/")[1].split("+")[0], "payload_type": t, "payload_len": 33,
                      "payload_b64": b64(payload), "pae_b64": b64(pae(t, payload))})
    for n in (1, 9, 10, 99, 100):
        t = "t" * n
        payload = b"x"
        cases.append({"id": "typelen-%d" % n, "payload_type": t, "payload_len": 1,
                      "payload_b64": b64(payload), "pae_b64": b64(pae(t, payload))})
    return {"kind": "pae", "spec": "spec/01-conventions.md 2.4", "cases": cases}


def build_b64():
    dec = []

    def ok(i, s, raw):
        dec.append({"id": i, "input": s, "valid": True, "decoded_hex": hx(raw)})

    def bad(i, s, why):
        dec.append({"id": i, "input": s, "valid": False, "code": "schema.base64_invalid", "why": why})
    for i, raw in (("empty", b""), ("one-byte", b"\x00"), ("two-bytes", b"\x00\x00"), ("three-bytes", b"\x00\x00\x00"),
                   ("foo", b"foo"), ("foob", b"foob"), ("fooba", b"fooba"), ("foobar", b"foobar"),
                   ("plus-slash", b"\xfb\xff\xbf"), ("slash-pad", b"\xff"), ("all-ones", b"\xff\xff\xff")):
        ok(i, b64(raw), raw)
    bad("no-padding", "Zm9vYg", "padding is required")
    bad("no-padding-2", "Zm9vYmE", "padding is required")
    bad("short-padding", "Zm9vYg=", "wrong amount of padding")
    bad("extra-padding", "Zg===", "too much padding")
    bad("padding-only", "====", "padding only")
    bad("leading-padding", "=Zg=", "padding in front")
    bad("padding-in-middle", "Zg==Zg==", "concatenated groups")
    bad("urlsafe-minus", "-_8=", "URL-safe alphabet")
    bad("urlsafe-underscore", "Zm9_", "URL-safe alphabet")
    bad("trailing-newline", "Zm9v\n", "whitespace")
    bad("leading-space", " Zm9v", "whitespace")
    bad("inner-space", "Zm 9v", "whitespace")
    bad("inner-newline", "Zm9v\nYmFy", "line break")
    bad("tab", "Zm9v\t", "whitespace")
    bad("nonzero-trailing-bits-2", "Zh==", "non-zero trailing bits (canonical form is Zg==)")
    bad("nonzero-trailing-bits-3", "Zm9=", "non-zero trailing bits (canonical form is Zm8=)")
    bad("length-1", "Z", "impossible length")
    bad("length-5", "ZZZZZ", "length is not a multiple of 4")
    bad("non-ascii", "Zm9\u00e9", "outside the alphabet")
    bad("full-width", "\uff3a\uff4d\uff39\uff56", "outside the alphabet")
    bad("nul-byte", "Zm9v\u0000", "outside the alphabet")
    bad("dot", "Zm9.", "outside the alphabet")
    bad("equals-then-data", "Zm=v", "padding inside a group")
    enc = [{"data_hex": hx(r), "b64": b64(r)} for r in (b"", b"\x00", b"\xff", b"\x00\x01", b"foo", b"foobar", b"\xfb\xff\xbf",
                                                           det_bytes(64))]
    return {"kind": "b64", "spec": "spec/01-conventions.md 2.2", "decode": dec, "encode": enc}


def _R(head, fill, tail, length):
    return {"head": head, "fill": fill, "tail": tail, "length": length}


def build_pcj():
    parse = []

    def add(i, data, result, **kw):
        c = {"id": i, "result": result}
        if isinstance(data, dict):
            c["recipe"] = data
        else:
            if isinstance(data, str):
                data = data.encode("latin-1")
            c["input_b64"] = b64(data)
            try:
                c["input_text"] = data.decode("ascii")
            except UnicodeDecodeError:
                pass
        c.update(kw)
        parse.append(c)

    def acc(i, data, value, **kw):
        add(i, data, "accept", value=value, **kw)

    def rej(i, data, code, stage="loads", **kw):
        add(i, data, "reject", code=code, stage=stage, **kw)

    nested16 = "[" * 16 + "1" + "]" * 16
    deep16 = json.loads(nested16)
    acc("empty-object", "{}", {})
    acc("empty-array", "[]", [])
    acc("scalar-zero", "0", 0)
    acc("scalar-true", "true", True)
    acc("simple-object", '{"a":1,"b":[true,false,"x y"]}', {"a": 1, "b": [True, False, "x y"]})
    acc("nested-sorted", '{"a":{"b":{"c":[]}},"z":0}', {"a": {"b": {"c": []}}, "z": 0})
    acc("max-int", "[9007199254740991]", [MAX_INT])
    acc("printable-ascii", '["!#$%&\'()*+,-./0123456789:;<=>?@AZ[]^_`az{|}~ "]', ["!#$%&'()*+,-./0123456789:;<=>?@AZ[]^_`az{|}~ "])
    acc("true-as-number", '{"seq":true}', {"seq": True},
        note="valid PCJ; the schema layer must still reject a boolean where an integer is required")
    acc("depth-16", nested16, deep16)
    add("large-string-512k", _R('{"a":"', "a", '"}', 524288), "accept",
        note="the value is not stored: a mapping with key a and a string of 524280 letters a")
    acc("sorted-by-byte", '{"B":1,"_":2,"a":3,"aa":4,"b":5}', {"B": 1, "_": 2, "a": 3, "aa": 4, "b": 5})
    # --- rejected while parsing (stage loads)
    rej("neg-zero", "[-0]", "input.number_invalid")
    rej("neg-one", "[-1]", "input.number_invalid")
    rej("plus-one", "[+1]", "input.number_invalid")
    rej("float-1.0", "[1.0]", "input.number_invalid")
    rej("float-1e2", "[1e2]", "input.number_invalid")
    rej("float-1E2", "[1E2]", "input.number_invalid")
    rej("float-fraction", "[0.5]", "input.number_invalid")
    rej("leading-zero", "[01]", "input.number_invalid")
    rej("nan", "[NaN]", "input.number_invalid")
    rej("infinity", "[Infinity]", "input.number_invalid")
    rej("neg-infinity", "[-Infinity]", "input.number_invalid")
    rej("int-2^53", "[9007199254740992]", "input.number_invalid")
    rej("int-5000-digits", _R("[", "9", "]", 5002), "input.number_invalid")
    rej("null", "[null]", "input.not_json")
    rej("null-in-object", '{"a":null}', "input.not_json")
    rej("non-ascii-e-acute", '["\u00e9"]'.encode("utf-8"), "input.not_ascii")
    rej("bom", b"\xef\xbb\xbf{}", "input.not_ascii")
    rej("del-byte", b'["a\x7fb"]', "input.not_ascii")
    rej("lone-surrogate-escape", '["\\ud800"]', "input.not_json")
    rej("lone-low-surrogate-escape", '["\\udc00"]', "input.not_json")
    rej("bad-escape", '["\\x41"]', "input.not_json")
    rej("raw-tab-in-string", '["a\tb"]', "input.not_json")
    rej("raw-newline-in-string", '["a\nb"]', "input.not_json")
    rej("dup-keys-depth-1", '{"a":1,"a":2}', "input.duplicate_key")
    rej("dup-keys-depth-5", '{"a":{"b":{"c":{"d":{"e":1,"e":2}}}}}', "input.duplicate_key")
    rej("dup-keys-via-escape", '{"a":1,"\\u0061":2}', "input.duplicate_key")
    rej("dup-keys-in-array-object", '[{"k":1,"k":1}]', "input.duplicate_key")
    rej("depth-17", "[" * 17 + "1" + "]" * 17, "input.depth_exceeded")
    rej("depth-bomb", _R("[", "[", "", 100000), "input.depth_exceeded")
    rej("size-1mib-plus-1", _R("[", " ", "]", 1048577), "input.too_large")
    rej("trailing-comma", "[1,2,]", "input.not_json")
    rej("missing-comma", "[1 2]", "input.not_json")
    rej("single-quotes", "{'a':1}", "input.not_json")
    rej("unterminated-string", '["abc', "input.not_json")
    rej("unterminated-array", "[1,2", "input.not_json")
    rej("empty-input", b"", "input.not_json")
    rej("whitespace-only", b"  ", "input.not_json")
    rej("trailing-garbage", "{} x", "input.not_json")
    rej("two-documents", "{}{}", "input.not_json")
    rej("comment", "[1] // x", "input.not_json")
    rej("bare-word", "[tru]", "input.not_json")
    # --- parse, but not canonical (stage roundtrip)
    rej("escape-u0041", '["\\u0041"]', "schema.payload_not_canonical", "roundtrip", value=["A"])
    rej("escape-solidus", '["\\/"]', "schema.payload_not_canonical", "roundtrip", value=["/"])
    rej("escape-newline", '["\\n"]', "schema.payload_not_canonical", "roundtrip", value=["\n"])
    rej("escape-quote", '["\\""]', "schema.payload_not_canonical", "roundtrip", value=['"'])
    rej("escape-backslash", '["\\\\"]', "schema.payload_not_canonical", "roundtrip", value=["\\"])
    rej("escape-e-acute", '["\\u00e9"]', "schema.payload_not_canonical", "roundtrip", value=["\u00e9"])
    rej("escape-surrogate-pair", '["\\ud83d\\ude00"]', "schema.payload_not_canonical", "roundtrip", value=["\U0001f600"])
    rej("escape-del", '["\\u007f"]', "schema.payload_not_canonical", "roundtrip", value=["\x7f"])
    rej("leading-whitespace", " {}", "schema.payload_not_canonical", "roundtrip", value={})
    rej("trailing-whitespace", "{} ", "schema.payload_not_canonical", "roundtrip", value={})
    rej("trailing-newline", "{}\n", "schema.payload_not_canonical", "roundtrip", value={})
    rej("whitespace-after-colon", '{"a": 1}', "schema.payload_not_canonical", "roundtrip", value={"a": 1})
    rej("whitespace-after-comma", "[1, 2]", "schema.payload_not_canonical", "roundtrip", value=[1, 2])
    rej("unsorted-keys", '{"b":1,"a":2}', "schema.payload_not_canonical", "roundtrip", value={"a": 2, "b": 1})
    rej("unsorted-keys-case", '{"a":1,"B":2}', "schema.payload_not_canonical", "roundtrip", value={"B": 2, "a": 1})
    rej("empty-key", '{"":1}', "schema.payload_not_canonical", "roundtrip", value={"": 1})
    # --- encode
    encode = []

    def enc_ok(i, v):
        encode.append({"id": i, "value": v, "pcj_b64": b64(pcj(v))})

    def enc_bad(i, v):
        encode.append({"id": i, "value": v, "error": "not_encodable"})
    enc_ok("empty-object", {})
    enc_ok("unsorted-input", {"b": 1, "a": [True, False, "x"]})
    enc_ok("byte-order-keys", {"b": 1, "B": 2, "a": 3, "_": 4, "aa": 5})
    enc_ok("max-int", MAX_INT)
    enc_ok("zero", 0)
    enc_ok("all-printable", "!#$%&'()*+,-./09:;<=>?@AZ[]^_`az{|}~ ")
    enc_ok("nested", {"x": [[], {}, [1, [2]]]})
    enc_bad("int-2^53", MAX_INT + 1)
    enc_bad("negative", -1)
    enc_bad("float", 1.5)
    enc_bad("float-integral", 1.0)
    enc_bad("null", None)
    enc_bad("string-with-quote", 'a"b')
    enc_bad("string-with-backslash", "a\\b")
    enc_bad("string-non-ascii", "\u00e9")
    enc_bad("string-control", "a\tb")
    enc_bad("string-del", "\x7f")
    enc_bad("empty-key", {"": 1})
    enc_bad("key-with-quote", {'a"': 1})
    deep = 1
    for _ in range(17):
        deep = [deep]
    enc_bad("depth-17", deep)
    for c in encode:
        if "error" in c:
            try:
                pcj(c["value"])
            except ValueError:
                continue
            raise AssertionError("reference encoder accepted " + c["id"])
    return {"kind": "pcj", "spec": "spec/01-conventions.md 2.1", "parse": parse, "encode": encode,
            "recipe_note": "input = head + fill * (length - len(head) - len(tail)) + tail"}


# -------------------------------------------------------------------------------------------- time
def _p_epoch(y, mo, d, h, mi, s):
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))


def _fmt_epoch(e):
    import time as _t
    return _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(e))


def build_time():
    parse = []
    valid = ["2026-12-01T09:00:00Z", "2000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "2028-02-29T12:00:00Z",
             "2000-02-29T00:00:00Z", "2026-02-28T23:59:59Z", "2026-12-31T23:59:59Z", "2026-01-01T00:00:00Z",
             "2400-02-29T00:00:00Z", "2026-06-30T23:59:59Z", "2026-04-30T00:00:00Z"]
    for t in valid:
        y, mo, d = int(t[0:4]), int(t[5:7]), int(t[8:10])
        h, mi, s = int(t[11:13]), int(t[14:16]), int(t[17:19])
        e = _p_epoch(y, mo, d, h, mi, s)
        assert _fmt_epoch(e) == t
        parse.append({"id": "ok-" + t, "input": t, "valid": True, "epoch": e})
    invalid = [
        ("offset-plus", "2026-12-01T09:00:00+00:00"), ("offset-minus", "2026-12-01T09:00:00-05:00"),
        ("fraction", "2026-12-01T09:00:00.5Z"), ("lowercase-z", "2026-12-01T09:00:00z"),
        ("lowercase-t", "2026-12-01t09:00:00Z"), ("space-separator", "2026-12-01 09:00:00Z"),
        ("no-z", "2026-12-01T09:00:00"), ("leap-second", "2026-12-31T23:59:60Z"),
        ("feb-30", "2026-02-30T00:00:00Z"), ("feb-29-non-leap", "2026-02-29T00:00:00Z"),
        ("feb-29-century-non-leap", "2100-02-29T00:00:00Z"), ("month-13", "2026-13-01T00:00:00Z"),
        ("month-00", "2026-00-01T00:00:00Z"), ("day-00", "2026-12-00T00:00:00Z"), ("day-32", "2026-12-32T00:00:00Z"),
        ("apr-31", "2026-04-31T00:00:00Z"), ("hour-24", "2026-12-01T24:00:00Z"), ("minute-60", "2026-12-01T09:60:00Z"),
        ("year-1999", "1999-12-31T23:59:59Z"), ("year-10000", "10000-01-01T00:00:00Z"), ("year-0000", "0000-01-01T00:00:00Z"),
        ("leading-space", " 2026-12-01T09:00:00Z"), ("trailing-space", "2026-12-01T09:00:00Z "),
        ("trailing-newline", "2026-12-01T09:00:00Z\n"), ("empty", ""), ("date-only", "2026-12-01"),
        ("short-year", "26-12-01T09:00:00Z"), ("single-digit-month", "2026-1-01T09:00:00Z"),
        ("full-width-digits", "\uff12\uff10\uff12\uff16-12-01T09:00:00Z"), ("arabic-indic-digit", "2026-12-0\u0661T09:00:00Z"),
        ("basic-format", "20261201T090000Z"), ("week-date", "2026-W49-1T09:00:00Z"), ("epoch-number", "1796115600"),
        ("minus-year", "-2026-12-01T09:00:00Z"), ("double-z", "2026-12-01T09:00:00ZZ"),
    ]
    for i, t in invalid:
        parse.append({"id": "bad-" + i, "input": t, "valid": False, "code": "schema.time_format"})
    fmt = [{"epoch": e, "text": _fmt_epoch(e)} for e in (946684800, 1796115600, 1796202000, 253402300799, 1000000000, 951782400)]
    dur = []
    for t, s in (("30s", 30), ("5m", 300), ("24h", 86400), ("7d", 604800), ("0s", 0), ("48h", 172800), ("72h", 259200),
                 ("1d", 86400), ("90m", 5400)):
        dur.append({"input": t, "valid": True, "seconds": s})
    for t in ("", "24", "h", "1.5h", "-1h", "+1h", "01h", "1H", "1 h", "1w", "1hh", " 1h", "1h ", "1h\n", "9007199254740992s",
              "999999999999d", "\uff11h", "0x10s", "1e2s", "PT1H", "24 hours"):
        dur.append({"input": t, "valid": False})
    base = _p_epoch(2026, 12, 1, 9, 0, 0)
    vu = base + 86400
    win = []
    for i, now, st in (("at-issue", base, "ok"), ("one-before-expiry", vu - 1, "ok"), ("at-expiry", vu, "expired"),
                       ("after-expiry", vu + 1, "expired"), ("skew-edge", base - 300, "ok"),
                       ("beyond-skew", base - 301, "not_yet_valid"), ("one-before-issue", base - 1, "ok"),
                       ("far-future", vu + 10 ** 7, "expired"), ("far-past", 0, "not_yet_valid"),
                       ("expired-wins-over-skew", vu + 5, "expired")):
        win.append({"id": i, "now": now, "issued_at": base, "valid_until": vu, "state": st})
    return {"kind": "time", "spec": "spec/01-conventions.md 2.6", "parse": parse, "format": fmt, "durations": dur,
            "windows": win, "window_rule": "ok iff issued_at - 300 <= now < valid_until; now >= valid_until is expired first"}


# ---------------------------------------------------------------------------------------- ed25519
def build_ed25519():
    cases = []

    def add(i, pub, msg, sig, expect, desc):
        cases.append({"id": i, "pub_hex": hx(pub), "msg_hex": hx(msg), "sig_hex": hx(sig), "expect": expect, "desc": desc})
    # RFC 8032 section 7.1, tests 1 to 3: secret keys and messages from the RFC; the answers are checked
    rfc = [("rfc8032-test1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
           ("rfc8032-test2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
           ("rfc8032-test3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
            None,
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]
    for i, sec, msg, pub_expected, sig_expected in rfc:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec))
        pub, m = pub_of(sk), bytes.fromhex(msg)
        sig = sk.sign(m)
        assert hx(sig) == sig_expected, i
        if pub_expected is not None:
            assert hx(pub) == pub_expected, i
        add(i, pub, m, sig, "valid", "RFC 8032 section 7.1 " + i[-5:])
    ta, tb = key_for("tenant-a"), key_for("tenant-b")
    pub_a, pub_b = pub_of(ta), pub_of(tb)
    msg = b"paddock conformance message"
    sig = ta.sign(msg)
    add("valid-tenant-a", pub_a, msg, sig, "valid", "an ordinary signature by the public test key tenant-a")
    s = int.from_bytes(sig[32:], "little")
    assert s < L
    add("s-plus-l", pub_a, msg, sig[:32] + (s + L).to_bytes(32, "little"), "sig.noncanonical_s",
        "the malleable twin S + L of a valid signature: some libraries accept it")
    add("s-equal-l", pub_a, msg, sig[:32] + L.to_bytes(32, "little"), "sig.noncanonical_s", "S == L")
    add("s-all-ones", pub_a, msg, sig[:32] + b"\xff" * 32, "sig.noncanonical_s", "S = 2^256 - 1")
    add("s-minus-one-of-l", pub_a, msg, sig[:32] + (L - 1).to_bytes(32, "little"), "sig.invalid",
        "S = L - 1 is reduced, so only the equation fails")
    add("message-tampered", pub_a, msg + b"!", sig, "sig.invalid", "valid signature, different message")
    flipped = bytearray(sig)
    flipped[0] ^= 1
    add("r-bit-flipped", pub_a, msg, bytes(flipped), "sig.invalid", "one bit of R changed")
    flipped = bytearray(sig)
    flipped[32] ^= 1
    add("s-bit-flipped", pub_a, msg, bytes(flipped), "sig.invalid", "one bit of S changed")
    add("wrong-key", pub_b, msg, sig, "sig.invalid", "valid under tenant-a, offered with the tenant-b key")
    add("sig-63-bytes", pub_a, msg, sig[:63], "sig.malformed", "signature one byte short")
    add("sig-65-bytes", pub_a, msg, sig + b"\x00", "sig.malformed", "signature one byte long")
    add("sig-empty", pub_a, msg, b"", "sig.malformed", "empty signature")
    add("pub-31-bytes", pub_a[:31], msg, sig, "sig.weak_key", "public key one byte short")
    add("pub-33-bytes", pub_a + b"\x00", msg, sig, "sig.weak_key", "public key one byte long")
    ident = bytes([1]) + bytes(31)
    add("identity-key-identity-sig", ident, msg, ident + bytes(32), "sig.weak_key",
        "identity public key with R = identity, S = 0: accepted by some libraries for ANY message")
    add("identity-key-identity-sig-empty-msg", ident, b"", ident + bytes(32), "sig.weak_key", "same, empty message")
    so = small_order_points()
    named = {hx(ident): "identity", "ec" + "ff" * 30 + "7f": "two-torsion"}
    for e in so:
        k = hx(e)
        label = named.get(k)
        if label is None:
            label = "order4-key" if _is_ident(_mul(4, _ext(_decompress(e)))) else "order8-key"
        else:
            label = {"identity": "identity-key", "two-torsion": "two-torsion-key"}[label]
        add(label + "-" + k[:8] + k[-4:], e, msg, ident + bytes(32), "sig.weak_key", "small-order point (%s)" % label)
    # the contract names these ids; keep one stable alias each
    alias = {"two-torsion-key": "ec" + "ff" * 30 + "7f", "order4-key": "00" * 32,
             "order8-key": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"}
    for i, k in alias.items():
        assert bytes.fromhex(k) in so, i
        add(i, bytes.fromhex(k), msg, ident + bytes(32), "sig.weak_key", "small-order public key")
    add("noncanonical-y-key", bytes.fromhex("ee" + "ff" * 30 + "7f"), msg, ident + bytes(32), "sig.weak_key",
        "y = p + 1 encodes the identity non-canonically")
    add("noncanonical-y-order4-key", bytes.fromhex("ed" + "ff" * 30 + "7f"), msg, ident + bytes(32), "sig.weak_key",
        "y = p encodes an order-4 point non-canonically")
    y = 2
    while not isinstance(_decompress(y.to_bytes(32, "little")), tuple) or y < 3:
        y += 1
    assert y < 19 and ref_precheck((y + P).to_bytes(32, "little"), bytes(64)) == "sig.weak_key"
    add("noncanonical-y-regular-point-key", (y + P).to_bytes(32, "little"), msg, ident + bytes(32), "sig.weak_key",
        "y = %d + p: a non-canonical encoding of an ordinary curve point (not small order), rejected for its encoding alone" % y)
    add("noncanonical-sign-key", bytes([1]) + bytes(30) + b"\x80", msg, ident + bytes(32), "sig.weak_key",
        "x = 0 with the sign bit set")
    y = 2
    while isinstance(_decompress(y.to_bytes(32, "little")), tuple):
        y += 1
    add("not-on-curve-key", y.to_bytes(32, "little"), msg, sig, "sig.weak_key", "y = %d has no x on the curve" % y)
    add("weak-key-and-s-ge-l", ident, msg, ident + L.to_bytes(32, "little"), "sig.weak_key",
        "both rules apply: the weak key is reported first")
    add("sig-wrong-length-and-weak-key", ident, msg, sig[:10], "sig.malformed", "length is checked before the key")
    for c in cases:
        pub, m, sg = bytes.fromhex(c["pub_hex"]), bytes.fromhex(c["msg_hex"]), bytes.fromhex(c["sig_hex"])
        pre = ref_precheck(pub, sg)
        if c["expect"] == "valid":
            assert pre is None
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(pub).verify(sg, m)
        elif c["expect"] in ("sig.malformed", "sig.weak_key", "sig.noncanonical_s"):
            assert pre == c["expect"], (c["id"], pre)
        else:
            assert pre is None, c["id"]
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(sg, m)
            except InvalidSignature:
                pass
            else:
                raise AssertionError("library accepted " + c["id"])
    return {"kind": "ed25519", "spec": "spec/01-conventions.md 2.5",
            "check_order": ["sig length 64 (sig.malformed)", "public key 32 bytes, canonical, not small order (sig.weak_key)",
                            "S < L (sig.noncanonical_s)", "verify (sig.invalid)"],
            "small_order_encodings": [hx(e) for e in so], "cases": cases}


def build_kid():
    cases = []
    for n in ("root-1", "root-2", "issuer-1", "revoker-1", "tenant-a", "tenant-b", "anchor-a", "attacker"):
        sk = key_for(n)
        pub = pub_of(sk)
        cases.append({"name": n, "seed_hex": hx(seed_for(n)), "pub_hex": hx(pub), "pub_b64": b64(pub),
                      "kid": kid_of(pub), "fp": "sha256:" + sha(pub)})
    assert cases[4]["kid"] == "2ceb61e24df5fde7c0ab24b2a2774fa4"
    assert cases[4]["pub_b64"] == "SSJYp+SRzsje7AY/OPHucOc6+STVMppqHDvdYR9OLmk="
    assert cases[6]["kid"] == "9aef608fe4565a8f55947deec61af518"
    return {"kind": "kid", "spec": "spec/05-keys-certs-revocation-dns.md",
            "seed_rule": "seed = sha256(b\"paddock-conformance-seed/v1/\" + name); kid = first 32 hex of sha256(raw public key)",
            "warning": "public test keys: never a trust root", "cases": cases}


# --------------------------------------------------------------------------------------- merkle
def _rec(i):
    return {"i": i}


def build_merkle():
    ck = COMMIT_KEY
    leaf_cases = []
    for i, nonce, lj in (("empty-json-zero-nonce", bytes(32), b""), ("object-zero-nonce", bytes(32), b'{"tree":"graph"}'),
                         ("policy-leaf", bytes.fromhex("39befbe29dfecdf1e956037ec2f8097fc19f12be1000d0e1d0ccde873641b9e8"),
                          pcj({"digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1", "enabled": True,
                               "id": "std:server-ssh-hardened", "source": "std", "tree": "policy"})),
                         ("ff-nonce", b"\xff" * 32, b'{"t":"node","tree":"graph"}')):
        leaf_cases.append({"id": i, "nonce_hex": hx(nonce), "leaf_json": lj.decode("ascii"), "leaf_hash_hex": hx(m_leaf(nonce, lj))})
    node_cases = []
    for a, b in ((bytes(32), bytes(32)), (b"\x01" * 32, b"\x02" * 32), (b"\x02" * 32, b"\x01" * 32), (EMPTY, EMPTY)):
        node_cases.append({"left_hex": hx(a), "right_hex": hx(b), "node_hash_hex": hx(m_node(a, b))})
    trees = []
    for n in range(0, 18):
        recs = [_rec(i) for i in range(n)]
        leaves, root = m_tree("graph", recs, ck)
        trees.append({"size": n, "records": recs, "sorted_leaf_hashes": [hx(t[0]) for t in leaves], "root_hex": hx(root)})
    inclusion, bad = [], []
    for n in (1, 2, 3, 5, 7, 8, 9, 17):
        recs = [_rec(i) for i in range(n)]
        leaves, root = m_tree("graph", recs, ck)
        hs = [t[0] for t in leaves]
        for idx in range(n):
            path = m_path(hs, idx)
            assert m_verify(hs[idx], idx, n, path, root)
            inclusion.append({"size": n, "index": idx, "leaf_hash_hex": hx(hs[idx]), "path_hex": [hx(p) for p in path],
                              "root_hex": hx(root), "all_leaf_hashes_hex": [hx(h) for h in hs]})
    n, idx = 7, 3
    leaves, root = m_tree("graph", [_rec(i) for i in range(n)], ck)
    hs = [t[0] for t in leaves]
    path = m_path(hs, idx)

    def addbad(i, desc, leaf=None, index=idx, size=n, p=None, r=None):
        leaf = hs[idx] if leaf is None else leaf
        p = path if p is None else p
        r = root if r is None else r
        assert not m_verify(leaf, index, size, p, r), i
        bad.append({"id": i, "desc": desc, "size": size, "index": index, "leaf_hash_hex": hx(leaf),
                    "path_hex": [hx(x) for x in p], "root_hex": hx(r)})
    flip = lambda b: bytes([b[0] ^ 1]) + b[1:]  # noqa: E731
    addbad("wrong-index", "index + 1 with the path of index", index=idx + 1)
    addbad("wrong-index-low", "index - 1", index=idx - 1)
    addbad("index-equals-size", "index == size", index=n)
    addbad("index-negative", "negative index", index=-1)
    # the size is bound by the root only through the path shape: a left-half leaf verifies for several sizes,
    # so the size vectors use the right-most leaf, whose path changes with the size
    edge = dict(leaf=hs[n - 1], index=n - 1, p=m_path(hs, n - 1))
    addbad("wrong-size-plus", "size + 1 for the right-most leaf", size=n + 1, **edge)
    addbad("wrong-size-minus", "size - 1: the index is now out of range", size=n - 1, **edge)
    addbad("wrong-size-double", "size 14 for the right-most leaf", size=14, **edge)
    addbad("size-zero", "size 0", size=0)
    addbad("truncated-path", "last element dropped", p=path[:-1])
    addbad("extra-path-element", "an element appended", p=path + [hs[0]])
    addbad("empty-path", "no path for a tree with seven leaves", p=[])
    addbad("flipped-path-bit", "one bit of one path element", p=[flip(path[0])] + path[1:])
    addbad("swapped-path-order", "elements in the wrong order", p=list(reversed(path)))
    addbad("flipped-leaf-bit", "one bit of the leaf hash", leaf=flip(hs[idx]))
    addbad("wrong-root", "root of another tree", r=m_root(hs[:-1]))
    addbad("leaf-as-node", "an inner node offered as a leaf", leaf=m_node(hs[0], hs[1]), index=0, p=[m_root(hs[2:])], size=n, r=root)
    # an inner node offered as a leaf with a path that is too short: only the final "path consumed" check rejects it
    l4, r4 = m_tree("graph", [_rec(i) for i in range(4)], ck)
    h4 = [t[0] for t in l4]
    addbad("inner-node-as-leaf-short-path", "node(h0,h1) offered as a leaf of a four-leaf tree with a one-element path",
           leaf=m_node(h4[0], h4[1]), index=0, size=4, p=[m_node(h4[2], h4[3])], r=r4)
    l1, r1 = m_tree("graph", [_rec(0)], ck)
    addbad("nonempty-path-for-single-leaf", "a one-leaf tree has an empty path", leaf=l1[0][0], index=0, size=1, p=[hs[0]], r=r1)
    # proof files (spec 2.3), the section 13 policy tree
    pol_recs = [
        {"id": "std:no-internet-to-datastore", "digest": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6", "enabled": True, "source": "std"},
        {"id": "std:server-ssh-hardened", "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1", "enabled": True, "source": "std"},
        {"id": "std:guest-cannot-reach-pos", "digest": "sha256:e261c80c93ca592db7f8eb4c08a42e66d1748eab61038722b958bc33bb69fc1c", "enabled": True, "source": "std"}]
    pl, proot = m_tree("policy", pol_recs, ck)
    assert "sha256:" + hx(proot) == "sha256:1ceecb33a4ca1bf921a3336c237c60c55068826cf4fe6bc83c6de172c061551d"
    phs = [t[0] for t in pl]
    root_s = "sha256:" + hx(proot)

    def proof_of(i, leaves=pl, hashes=phs):
        lh, nonce, lj, rec = leaves[i]
        return {"v": 1, "tree": "policy", "size": len(leaves), "index": i, "nonce": hx(nonce), "record": dict(rec),
                "path": [hx(x) for x in m_path(hashes, i)]}
    pf = []
    p0 = proof_of(0)
    assert p0["record"]["id"] == "std:server-ssh-hardened" and p0["nonce"] == "39befbe29dfecdf1e956037ec2f8097fc19f12be1000d0e1d0ccde873641b9e8"
    assert p0["path"][0].startswith("23333591") and p0["path"][1].startswith("afda932d")
    for i in range(3):
        pf.append({"id": "valid-index-%d" % i, "proof": proof_of(i), "root": root_s, "tree": "policy", "valid": True})

    def mut(i, fn, tree="policy", root=root_s):
        p = json.loads(json.dumps(p0))
        fn(p)
        pf.append({"id": i, "proof": p, "root": root, "tree": tree, "valid": False, "code": "merkle.proof_invalid"})
    mut("record-changed", lambda p: p["record"].__setitem__("enabled", False))
    mut("record-extra-key", lambda p: p["record"].__setitem__("note", "x"))
    mut("record-contains-tree-key", lambda p: p["record"].__setitem__("tree", "policy"))
    mut("nonce-bit-flipped", lambda p: p.__setitem__("nonce", "38" + p["nonce"][2:]))
    mut("nonce-short", lambda p: p.__setitem__("nonce", p["nonce"][:-2]))
    mut("nonce-uppercase", lambda p: p.__setitem__("nonce", p["nonce"].upper()))
    mut("wrong-index", lambda p: p.__setitem__("index", 1))
    mut("index-out-of-range", lambda p: p.__setitem__("index", 3))
    mut("index-negative", lambda p: p.__setitem__("index", -1))
    # a left-half leaf verifies for several sizes (the size is bound through the root only), so use the right-most leaf
    p2 = proof_of(2)
    pf.append({"id": "wrong-size-right-most-leaf", "proof": dict(p2, size=4), "root": root_s, "tree": "policy", "valid": False,
               "code": "merkle.proof_invalid"})
    mut("size-zero", lambda p: p.__setitem__("size", 0))
    mut("path-truncated", lambda p: p.__setitem__("path", p["path"][:1]))
    mut("path-extra", lambda p: p["path"].append("00" * 32))
    mut("path-element-not-hex", lambda p: p["path"].__setitem__(0, "zz" * 32))
    mut("path-element-uppercase", lambda p: p["path"].__setitem__(0, p["path"][0].upper()))
    mut("path-element-short", lambda p: p["path"].__setitem__(0, p["path"][0][:-2]))
    mut("version-2", lambda p: p.__setitem__("v", 2))
    mut("version-missing", lambda p: p.pop("v"))
    mut("unknown-top-key", lambda p: p.__setitem__("extra", 1))
    mut("tree-label-graph", lambda p: p.__setitem__("tree", "graph"))
    mut("tree-label-unknown", lambda p: p.__setitem__("tree", "other"))
    mut("tree-label-confusion-expected-graph", lambda p: None, tree="graph")
    mut("wrong-root", lambda p: None, root="sha256:" + "00" * 32)
    mut("root-without-prefix", lambda p: None, root=hx(proot))
    # a graph leaf offered to the policy tree root: it fails through the tree label inside the hashed leaf
    gl, groot = m_tree("graph", [{"t": "node", "id": "internet", "kind": "internet", "tags": []}, {"t": "node", "id": "x", "kind": "y", "tags": []}], ck)
    gp = {"v": 1, "tree": "policy", "size": 2, "index": 0, "nonce": hx(gl[0][1]), "record": dict(gl[0][3]),
          "path": [hx(m_path([t[0] for t in gl], 0)[0])]}
    pf.append({"id": "graph-leaf-offered-to-policy-tree", "proof": gp, "root": "sha256:" + hx(groot), "tree": "policy", "valid": False,
               "code": "merkle.proof_invalid"})
    gp2 = dict(gp, tree="graph")
    pf.append({"id": "graph-leaf-valid-in-graph-tree", "proof": gp2, "root": "sha256:" + hx(groot), "tree": "graph", "valid": True})
    # single-leaf and empty
    sl, sroot = m_tree("blind", [{"inv": "std:a", "node": "asset:x", "direction": "in", "reason": "stale", "relevant": True}], ck)
    pf.append({"id": "single-leaf-blind", "proof": {"v": 1, "tree": "blind", "size": 1, "index": 0, "nonce": hx(sl[0][1]),
                                                      "record": dict(sl[0][3]), "path": []}, "root": "sha256:" + hx(sroot),
               "tree": "blind", "valid": True})
    # set commitment
    a = [{"id": "x:%s" % c, "digest": "sha256:" + c * 64, "enabled": True, "source": "std"} for c in "abc"]
    b = [a[2], a[0], a[1], a[0], a[2]]
    la, ra = m_tree("policy", a, ck)
    lb, rb = m_tree("policy", b, ck)
    assert ra == rb and len(la) == len(lb) == 3
    return {"kind": "merkle", "spec": "spec/04-merkle.md", "commit_key_hex": hx(ck), "empty_root_hex": hx(EMPTY),
            "leaf_hashes": leaf_cases, "node_hashes": node_cases, "trees": trees, "inclusion": inclusion,
            "bad_inclusion": bad, "proof_files": pf,
            "set_commitment": {"records_a": a, "records_b": b, "size": 3, "root_hex": hx(ra)}}


# ------------------------------------------------------------------------------ commit nonce, leaves
def build_commit_nonce():
    ck = COMMIT_KEY
    leaves = []
    samples = [
        ("policy-ssh", "policy", {"id": "std:server-ssh-hardened", "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1", "enabled": True, "source": "std"}),
        ("policy-disabled-custom", "policy", {"id": "acme:no-telnet", "digest": "sha256:" + "ab" * 32, "enabled": False, "source": "custom"}),
        ("graph-node", "graph", {"t": "node", "id": "internet", "kind": "internet", "tags": []}),
        ("graph-edge", "graph", {"t": "edge", "src": "internet", "dst": "asset:22222222-2222-4222-8222-222222222222", "proto": "tcp", "ports": "443", "basis": "configured", "source": "aws_sg"}),
        ("graph-fact", "graph", {"t": "fact", "node": "agent:33333333-3333-4333-8333-333333333333", "name": "sshd", "d": "sha256:" + "cd" * 32}),
        ("blind-spot", "blind", {"inv": "std:no-internet-to-datastore", "node": "asset:33333333-3333-4333-8333-333333333333", "direction": "in", "reason": "stale", "relevant": True}),
        ("blind-spot-collector", "blind", {"inv": "std:server-ssh-hardened", "node": "agent:44444444-4444-4444-8444-444444444444", "direction": "host", "reason": "no_value", "relevant": False, "collector": "sshd"}),
    ]
    for i, tree, rec in samples:
        lj = pcj(dict(rec, tree=tree))
        n = m_nonce(ck, lj)
        leaves.append({"id": i, "tree": tree, "record": rec, "leaf_json": lj.decode("ascii"), "leaf_json_sha256": sha(lj),
                       "nonce_hex": hx(n), "leaf_hash_hex": hx(m_leaf(n, lj))})
    assert leaves[0]["nonce_hex"] == "39befbe29dfecdf1e956037ec2f8097fc19f12be1000d0e1d0ccde873641b9e8"
    trees = []

    def add_tree(i, tree, recs, order_key):
        lv, root = m_tree(tree, recs, ck)
        trees.append({"id": i, "tree": tree, "records": recs, "size": len(lv), "root": "sha256:" + hx(root),
                      "sorted_leaf_hashes": [hx(t[0]) for t in lv], "leaf_order": [t[3].get(order_key) for t in lv]})
    pol = [{"id": "std:no-internet-to-datastore", "digest": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6", "enabled": True, "source": "std"},
           {"id": "std:server-ssh-hardened", "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1", "enabled": True, "source": "std"},
           {"id": "std:guest-cannot-reach-pos", "digest": "sha256:e261c80c93ca592db7f8eb4c08a42e66d1748eab61038722b958bc33bb69fc1c", "enabled": True, "source": "std"}]
    add_tree("section-13-policy", "policy", pol, "id")
    assert trees[-1]["root"] == "sha256:1ceecb33a4ca1bf921a3336c237c60c55068826cf4fe6bc83c6de172c061551d"
    assert trees[-1]["leaf_order"] == ["std:server-ssh-hardened", "std:no-internet-to-datastore", "std:guest-cannot-reach-pos"]
    graph = [{"t": "node", "id": "internet", "kind": "internet", "tags": []},
             {"t": "node", "id": "asset:11111111-1111-4111-8111-111111111111", "kind": "cloud_db", "class": "datastore", "tags": []},
             {"t": "edge", "src": "internet", "dst": "asset:22222222-2222-4222-8222-222222222222", "proto": "tcp", "ports": "443", "basis": "configured", "source": "aws_sg"}]
    add_tree("section-13-graph", "graph", graph, "t")
    assert trees[-1]["root"] == "sha256:7b5165627f159516c5e6f40f4875c238fe2d607d816be24d320a9ad5da9580e7"
    blind = [{"inv": "std:no-internet-to-datastore", "node": "asset:33333333-3333-4333-8333-333333333333", "direction": "in", "reason": "stale", "relevant": True}]
    add_tree("section-13-blind", "blind", blind, "inv")
    assert trees[-1]["root"] == "sha256:ed05f1c6aa2391a9bd2ae7ab2aa47f239e20ab3741915a4cf8632c9a306dd8c0"
    add_tree("empty-policy", "policy", [], "id")
    # leaf value encoding (spec 04, graph tree): None omitted, out-of-charset string replaced by its digest, anything else fails closed
    enc_cases = []

    def encode_value(v):
        if isinstance(v, str):
            try:
                _ascii_check(v)
                return v
            except ValueError:
                return {"$h": "sha256:" + sha(v.encode("utf-8"))}
        if isinstance(v, dict):
            return {k: encode_value(x) for k, x in v.items() if x is not None}
        if isinstance(v, list):
            return [encode_value(x) for x in v]
        return v
    for i, rec in (("none-omitted", {"t": "node", "id": "n1", "zone": None, "kind": "host"}),
                   ("non-ascii-label", {"t": "node", "id": "n2", "label": "caf\u00e9"}),
                   ("quote-in-string", {"t": "node", "id": "n3", "label": 'say "hi"'}),
                   ("backslash-in-string", {"t": "node", "id": "n4", "label": "a\\b"}),
                   ("control-char", {"t": "node", "id": "n5", "label": "a\tb"}),
                   ("nested-list", {"t": "node", "id": "n6", "tags": ["a", "\u00e9", "b"]})):
        out = encode_value(rec)
        enc_cases.append({"id": i, "input": rec, "leaf_json": pcj(dict(out, tree="graph")).decode("ascii")})
    unenc = [{"id": "float", "input": {"t": "meta", "k": "x", "v": 1.5}}, {"id": "negative-int", "input": {"t": "meta", "k": "x", "v": -1}},
             {"id": "int-over-2^53", "input": {"t": "meta", "k": "x", "v": MAX_INT + 1}},
             {"id": "float-integral", "input": {"t": "meta", "k": "x", "v": 1.0}}]
    return {"kind": "commit-nonce", "spec": "spec/04-merkle.md", "commit_key_hex": hx(ck),
            "nonce_rule": "HMAC-SHA256(commit_key, b\"paddock/leaf-nonce/v1\\x00\" || SHA256(leaf_json))",
            "leaves": leaves, "trees": trees, "leaf_encoding": enc_cases, "unencodable_fail_closed": unenc}


# ---------------------------------------------------------------------------------------- coverage
def build_coverage():
    from decimal import Decimal, ROUND_FLOOR
    meets = []
    for cov, uni, bp, note in ((19, 20, 9500, "19 of 20 at 0.95"), (18, 20, 9500, "18 of 20 at 0.95"), (41, 42, 9800, "97.6 percent against 98"),
                               (41, 42, 9761, "just under 41/42"), (41, 42, 9762, "just over 41/42"), (1, 3, 3333, ""), (1, 3, 3334, "1/3 vs 0.3334"),
                               (2, 3, 6666, ""), (2, 3, 6667, ""), (0, 0, 0, "an empty universe is never covered"),
                               (0, 0, 9500, "empty universe"), (0, 1, 0, "floor zero"), (1, 1, 10000, ""), (3, 3, 10000, ""),
                               (1, 1, 10001, "floor above 100 percent"), (21, 20, 5000, "covered above universe is inconsistent"),
                               (MAX_INT, MAX_INT, 10000, "large"), (MAX_INT - 1, MAX_INT, 10000, "large, one short"),
                               (95, 100, 9500, ""), (94, 100, 9500, ""), (995, 1000, 9950, ""), (994, 1000, 9950, "")):
        ok = uni >= 1 and cov <= uni and cov * 10000 >= bp * uni
        meets.append({"covered": cov, "universe": uni, "required_bp": bp, "ok": ok, "note": note})
    pct = []
    for cov, uni in ((41, 42), (0, 5), (5, 5), (1, 3), (2, 3), (19, 20), (199, 200), (1, 1000), (999, 1000), (1, 1), (97, 100), (9999, 10000)):
        pct.append({"covered": cov, "universe": uni, "pct_floor": cov * 100 // uni})
    rb = []
    for s in ("0.95", "0.995", "1.0", "0.3334", "0.3", "0.30000000000000004", "0.99999", "0.0", "0.00001", "0.9999999999999999",
              "0.1", "0.57", "0.58", "0.29", "0.07", "0.5", "0.9999", "0.0001"):
        bp = int((Decimal(repr(float(s))) * 10000).to_integral_value(rounding=ROUND_FLOOR))
        rb.append({"float_repr": s, "bp": bp})
    assert {c["float_repr"]: c["bp"] for c in rb}["0.57"] == 5700
    th = []
    for s, bp in (("0.95", 9500), ("1", 10000), ("1.0", 10000), ("0", 0), ("0.0", 0), ("0.9501", 9501), ("0.5", 5000), ("1.0000", 10000),
                  ("0.0001", 1), ("0.3334", 3334), ("0.57", 5700), ("0.9999", 9999)):
        th.append({"input": s, "valid": True, "bp": bp})
    for s in ("", "0.95001", "1.0001", "1.1", "2", "-0.1", "-0", ".5", "5.", "95%", "0.95 ", " 0.95", "1e0", "NaN", "Infinity", "0x1",
              "1,5", "\uff11", "01", "00.5", "0.95\n", "+0.5", "0.", "1.00001"):
        th.append({"input": s, "valid": False})
    return {"kind": "coverage", "spec": "spec/03-verdicts-tiers-coverage-freshness.md",
            "rule": "a result is covered enough iff universe >= 1 and covered <= universe and covered * 10000 >= required_bp * universe",
            "meets": meets, "percent": pct, "required_bp": rb, "threshold": th}


# ----------------------------------------------------------------------------------------- reason map
REASON_PREFIX = {
    "coverage_below_required": "coverage_below_required", "possible_via_unknown_edges": "possible_via_unknown_edges",
    "possible_via_zone_unknown": "zone_unknown", "zone_unknown": "zone_unknown",
    "overlapping_selectors_too_large": "selection_too_large",
    "hosts_unknown": "host_evidence_unusable", "no_agent": "host_evidence_unusable", "agent_revoked": "host_evidence_unusable",
    "no_value": "host_evidence_unusable",
    "stale": "stale_or_missing_evidence", "future_timestamp": "stale_or_missing_evidence", "tier_below_min": "stale_or_missing_evidence",
    "no_sensor": "stale_or_missing_evidence",
    "empty_selector": "empty_selector", "graph_incomplete": "graph_incomplete", "graph_unavailable": "graph_incomplete",
    "invalid_definition": "invalid_definition", "evaluation_error": "evaluation_error",
}


def build_reason_map():
    enum = sorted(set(REASON_PREFIX.values()) | {"other"})
    cases = []
    for r in ("coverage_below_required", "possible_via_unknown_edges", "possible_via_zone_unknown", "zone_unknown:3", "zone_unknown",
              "overlapping_selectors_too_large", "hosts_unknown:2", "no_agent", "agent_revoked", "no_value", "stale", "future_timestamp",
              "tier_below_min", "no_sensor", "empty_selector:to", "empty_selector:from", "empty_selector:no_distinct_pair",
              "graph_incomplete:cidr_expansion_overflow", "graph_incomplete", "graph_unavailable", "invalid_definition", "evaluation_error",
              "evaluation_error:TimeoutError", "no_counterexample", "witness_found", "std_unrecognised", "brand_new_reason:7", "", ":",
              ":coverage_below_required", "Coverage_Below_Required", "coverage_below_required ", "x" * 300, "zone_unknown:1:2"):
        pre = r.split(":", 1)[0]
        cases.append({"reason": r, "code": REASON_PREFIX.get(pre, "other")})
    return {"kind": "reason-map", "spec": "spec/02-statement-predicate.md",
            "rule": "the public code is looked up by the part of the engine reason before the first colon; anything else is other",
            "enum": enum, "prefix_map": REASON_PREFIX, "cases": cases}


# ------------------------------------------------------------------------------------- DNS TXT parse
KID_A = kid_of(pub_of(key_for("tenant-a")))
FP_A = "sha256:" + sha(pub_of(key_for("tenant-a")))
KID_B = kid_of(pub_of(key_for("tenant-b")))
FP_B = "sha256:" + sha(pub_of(key_for("tenant-b")))
HEX = "0123456789abcdef"
VERSION_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"


def ref_parse_txt(strings):
    """Reference parser written from spec/05. Returns {"status", ...}."""
    rec = "".join(strings)
    if len(rec.encode("utf-8", "replace")) > 1024:
        return {"status": "malformed"}
    try:
        rec.encode("ascii")
    except UnicodeEncodeError:
        return {"status": "malformed"}
    body = rec
    # version pre-scan: a record that says v=<anything but 1> exactly once is ignored without further parsing
    vs = []
    for f in body.split(";"):
        f = f[1:] if f.startswith(" ") else f
        if f.startswith("v="):
            vs.append(f[2:])
    if len(vs) == 1 and vs[0] != "1" and 1 <= len(vs[0]) <= 16 and all(c in VERSION_CHARS for c in vs[0]):
        return {"status": "ignored"}
    if body.endswith(";"):
        body = body[:-1]
    if body == "":
        return {"status": "malformed"}
    parts = body.split(";")
    pairs = []
    for i, f in enumerate(parts):
        if i > 0 and f.startswith(" "):
            f = f[1:]
        if f == "" or f != f.strip(" ") or "\t" in f or " " in f:
            return {"status": "malformed"}
        if "=" not in f:
            return {"status": "malformed"}
        k, v = f.split("=", 1)
        if not k or k[0] not in "abcdefghijklmnopqrstuvwxyz" or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in k):
            pairs.append(None)
            continue
        if v == "" or any(not (0x21 <= ord(c) <= 0x7E) for c in v):
            return {"status": "malformed"}
        pairs.append((k, v))
    if any(p is None for p in pairs):
        return {"status": "malformed"}
    keys = [p[0] for p in pairs]
    if len(set(keys)) != len(keys):
        return {"status": "malformed"}
    d = dict(pairs)
    if d.get("v") != "1":
        return {"status": "malformed"}
    kid, fp = d.get("kid"), d.get("fp")
    if kid is None or fp is None:
        return {"status": "malformed"}
    if len(kid) != 32 or any(c not in HEX for c in kid):
        return {"status": "malformed"}
    if not fp.startswith("sha256:") or len(fp) != 71 or any(c not in HEX for c in fp[7:]):
        return {"status": "malformed"}
    if fp[7:39] != kid:
        return {"status": "malformed"}
    keys_url = d.get("keys")
    if keys_url is not None and (not keys_url.startswith("https://") or len(keys_url) <= len("https://") or len(keys_url) > 300):
        return {"status": "malformed"}
    return {"status": "ok", "kid": kid, "fp": fp, "keys": keys_url}


def build_dns_txt():
    cases = []
    rec_min = "v=1; kid=%s; fp=%s" % (KID_A, FP_A)
    url = "https://example.com/.well-known/paddock/keys.json"
    rec_full = rec_min + "; keys=" + url

    def add(i, strings, expect, desc):
        got = ref_parse_txt(strings)
        want = dict(expect)
        want_status = want["status"]
        assert got["status"] == want_status, (i, got, want)
        if want_status == "ok":
            assert got == {"status": "ok", "kid": want["kid"], "fp": want["fp"], "keys": want.get("keys")}, i
        cases.append({"id": i, "desc": desc, "records": [strings], "expect": {"too_many": False, "records": [
            {"status": want_status, "kid": want.get("kid"), "fp": want.get("fp"), "keys": want.get("keys")} if want_status == "ok"
            else {"status": want_status}]}})
    okA = {"status": "ok", "kid": KID_A, "fp": FP_A}
    add("minimal", [rec_min], okA, "three required tags")
    add("with-keys", [rec_full], dict(okA, keys=url), "optional keys hint")
    add("no-spaces", ["v=1;kid=%s;fp=%s" % (KID_A, FP_A)], okA, "the space after the semicolon is optional")
    add("trailing-semicolon", [rec_min + ";"], okA, "one trailing semicolon is allowed")
    add("trailing-semicolon-space", [rec_min + "; "], {"status": "malformed"}, "a trailing space is not")
    add("chunked-3", [rec_full[:20], rec_full[20:61], rec_full[61:]], dict(okA, keys=url), "chunks are concatenated with no separator")
    add("chunked-mid-token", [rec_min[:30], rec_min[30:]], okA, "a chunk boundary can fall inside a value")
    add("chunked-255", [rec_full[:255], rec_full[255:]] if len(rec_full) > 255 else [rec_full], dict(okA, keys=url), "255-byte chunks")
    add("keys-with-query", [rec_min + "; keys=https://h.example/k.json?a=b&c=d"], dict(okA, keys="https://h.example/k.json?a=b&c=d"), "'=' inside a value")
    add("unknown-tag-ignored", [rec_min + "; x=1; future-tag=abc"], okA, "unknown tags are ignored")
    add("tag-order-free", ["fp=%s; v=1; kid=%s" % (FP_A, KID_A)], okA, "order of tags is free")
    add("version-2-ignored", ["v=2; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "ignored"}, "forward compatibility: ignored silently")
    add("version-2-with-garbage", ["v=2; ~~~ nonsense ;;"], {"status": "ignored"}, "an unknown version is not parsed further")
    add("version-0", ["v=0; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "ignored"}, "any v other than 1 is ignored")
    add("version-01", ["v=01; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "ignored"}, "the version is compared as text")
    add("duplicate-kid", [rec_min + "; kid=%s" % KID_A], {"status": "malformed"}, "a duplicate tag makes the record malformed")
    add("duplicate-unknown-tag", [rec_min + "; x=1; x=2"], {"status": "malformed"}, "duplicates count for unknown tags too")
    add("duplicate-v", ["v=1; " + rec_min], {"status": "malformed"}, "two v tags")
    add("uppercase-key", ["V=1; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "tags are lowercase: V is an unknown tag, v is missing")
    add("uppercase-kid-tag", ["v=1; KID=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "KID is unknown, kid is missing")
    add("uppercase-hex", ["v=1; kid=%s; fp=%s" % (KID_A.upper(), FP_A)], {"status": "malformed"}, "hex is lowercase")
    add("uppercase-fp-hex", ["v=1; kid=%s; fp=sha256:%s" % (KID_A, FP_A[7:].upper())], {"status": "malformed"}, "hex is lowercase")
    add("kid-not-prefix-of-fp", ["v=1; kid=%s; fp=%s" % (KID_B, FP_A)], {"status": "malformed"}, "kid must be the first 32 hex of fp")
    add("kid-short", ["v=1; kid=%s; fp=%s" % (KID_A[:30], FP_A)], {"status": "malformed"}, "kid is exactly 32 hex")
    add("fp-missing-prefix", ["v=1; kid=%s; fp=%s" % (KID_A, FP_A[7:])], {"status": "malformed"}, "fp starts with sha256:")
    add("fp-short", ["v=1; kid=%s; fp=%s" % (KID_A, FP_A[:-2])], {"status": "malformed"}, "fp is 64 hex")
    add("fp-other-alg", ["v=1; kid=%s; fp=sha512:%s" % (KID_A, FP_A[7:])], {"status": "malformed"}, "only sha256")
    add("missing-fp", ["v=1; kid=%s" % KID_A], {"status": "malformed"}, "fp is required")
    add("missing-kid", ["v=1; fp=%s" % FP_A], {"status": "malformed"}, "kid is required")
    add("missing-v", ["kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "v is required")
    add("keys-http", [rec_min + "; keys=http://example.com/k.json"], {"status": "malformed"}, "keys must be https")
    add("keys-ftp", [rec_min + "; keys=ftp://example.com/k.json"], {"status": "malformed"}, "keys must be https")
    add("keys-empty-host", [rec_min + "; keys=https://"], {"status": "malformed"}, "https:// alone is not a location")
    add("keys-empty-value", [rec_min + "; keys="], {"status": "malformed"}, "empty value")
    add("empty-record", [""], {"status": "malformed"}, "nothing")
    add("empty-record-no-chunks", [], {"status": "malformed"}, "a TXT record with no strings")
    add("only-semicolon", [";"], {"status": "malformed"}, "")
    add("whitespace-only", ["   "], {"status": "malformed"}, "")
    add("field-without-equals", [rec_min + "; junk"], {"status": "malformed"}, "")
    add("double-semicolon", [rec_min + ";; x=1"], {"status": "malformed"}, "an empty field")
    add("space-around-equals", ["v = 1; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "no spaces around =")
    add("two-spaces-after-semicolon", ["v=1;  kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "at most one space")
    add("space-before-semicolon", ["v=1 ; kid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "no space before a semicolon")
    add("tab-separator", ["v=1;\tkid=%s; fp=%s" % (KID_A, FP_A)], {"status": "malformed"}, "")
    add("leading-space", [" " + rec_min], {"status": "malformed"}, "")
    add("non-ascii", [rec_min + "; x=caf\u00e9"], {"status": "malformed"}, "")
    add("other-txt-purpose", ["google-site-verification=abc123"], {"status": "malformed"}, "a foreign TXT string under the label")
    add("spf-like", ["v=spf1 include:_spf.example.com ~all"], {"status": "malformed"}, "the version token is not a plain token, so the record is parsed and rejected")
    add("version-token-with-letters", ["v=beta2; kid=x"], {"status": "ignored"}, "any plain version token other than 1 is ignored")
    add("too-long-record", ["v=1; kid=%s; fp=%s; x=%s" % (KID_A, FP_A, "a" * 1000)], {"status": "malformed"}, "over 1024 bytes")
    add("max-length-record", ["v=1; kid=%s; fp=%s; x=%s" % (KID_A, FP_A, "a" * (1024 - len(rec_min) - 6))], okA, "exactly 1024 bytes")
    # set level
    rec_b = "v=1; kid=%s; fp=%s" % (KID_B, FP_B)

    def add_set(i, recs, too_many, desc):
        out = []
        total = sum(len("".join(r)) for r in recs)
        tm = len(recs) > 8 or total > 4096
        assert tm == too_many, (i, tm)
        for r in recs:
            g = ref_parse_txt(r)
            out.append({"status": g["status"], **({"kid": g["kid"], "fp": g["fp"], "keys": g["keys"]} if g["status"] == "ok" else {})})
        cases.append({"id": i, "desc": desc, "records": recs,
                      "expect": {"too_many": too_many, "records": [] if too_many else out}})
    add_set("two-records-rotation", [[rec_min], [rec_b]], False, "two kids at once (rotation)")
    add_set("eight-records", [[rec_min]] * 8, False, "eight records are allowed")
    add_set("nine-records", [[rec_min]] * 9, True, "more than eight is dns.too_many_records")
    big = ["v=1; kid=%s; fp=%s; x=%s" % (KID_A, FP_A, "a" * 800)]
    add_set("over-4096-bytes-total", [big] * 5, True, "five records of about 900 bytes exceed 4 KiB in total")
    add_set("under-4096-bytes-total", [big] * 4, False, "four records of about 900 bytes are fine")
    add_set("mixed-ok-ignored-malformed", [[rec_min], ["v=2; x"], ["garbage"]], False, "per record statuses")
    add_set("same-kid-two-fps", [[rec_min], ["v=1; kid=%s; fp=sha256:%s%s" % (KID_A, KID_A, "0" * 32)]], False,
            "both parse; the conflict is a verification-time rule (dns.record_conflict)")
    return {"kind": "dns-txt-parse", "spec": "spec/05-keys-certs-revocation-dns.md",
            "statuses": {"ok": "usable", "ignored": "v is not 1: ignored silently", "malformed": "ignored with warning dns.record_ignored"},
            "limits": {"record_max_bytes": 1024, "max_records": 8, "max_total_bytes": 4096}, "cases": cases}


# --------------------------------------------------------------------------------------- policy parse
def D(s):
    return {"$decimal": s}


def build_policy_parse():
    cases = []

    def acc(i, text, value, desc=""):
        cases.append({"id": i, "desc": desc, "yaml": text, "accept": True, "value": value})

    def rej(i, text, line, desc=""):
        cases.append({"id": i, "desc": desc, "yaml": text, "accept": False, "line": line, "code": "config.policy_invalid"})
    mvp = ("require:\n"
           "  - { invariant: std:no-internet-to-datastore, verdict: HOLDS, min_tier: observed }\n"
           "  - { invariant: std:server-ssh-hardened,       verdict: HOLDS }\n"
           "max_age: 48h\n"
           "min_coverage: 0.95\n")
    acc("mvp-doc-example", mvp, {"require": [{"invariant": "std:no-internet-to-datastore", "verdict": "HOLDS", "min_tier": "observed"},
                                            {"invariant": "std:server-ssh-hardened", "verdict": "HOLDS"}],
                                 "max_age": "48h", "min_coverage": D("0.95")}, "the MVP document's example parses unchanged")
    acc("empty-document", "", {}, "no content is an empty mapping")
    acc("comments-only", "# nothing here\n\n   # indented comment\n", {}, "")
    acc("comments-and-blank-lines", "# a comment\npolicy_version: 1  # trailing comment\n\nmax_age: 24h\n", {"policy_version": 1, "max_age": "24h"}, "")
    acc("nested-mapping", "trust:\n  vendor_cert: required\n  dns_binding: required\n  revocation_max_age: 72h\n",
        {"trust": {"vendor_cert": "required", "dns_binding": "required", "revocation_max_age": "72h"}}, "")
    acc("block-sequence-scalars", "ids:\n  - std:a\n  - std:b\n", {"ids": ["std:a", "std:b"]}, "")
    acc("block-sequence-of-mappings", "require:\n  - invariant: std:x\n    verdict: HOLDS\n  - invariant: std:y\n    min_tier: configured\n",
        {"require": [{"invariant": "std:x", "verdict": "HOLDS"}, {"invariant": "std:y", "min_tier": "configured"}]}, "")
    acc("flow-sequence", "ids: [a, b, c]\n", {"ids": ["a", "b", "c"]}, "")
    acc("flow-sequence-empty", "ids: []\n", {"ids": []}, "")
    acc("flow-mapping-empty-item", "require:\n  - {}\n", {"require": [{}]}, "")
    acc("double-quoted", 'name: "a: b # c"\n', {"name": "a: b # c"}, "")
    acc("double-quoted-escapes", 'name: "say \\"x\\" \\\\ y"\n', {"name": 'say "x" \\ y'}, "")
    acc("quoted-keyword-off", 'anchor: "off"\ndnssec: "off"\n', {"anchor": "off", "dnssec": "off"}, "off must be quoted to be a string")
    acc("quoted-keyword-null", 'a: "null"\nb: "yes"\nc: "~"\n', {"a": "null", "b": "yes", "c": "~"}, "")
    acc("integers", "policy_version: 1\nmax_exceptions: 0\nhistory_depth: 12\n", {"policy_version": 1, "max_exceptions": 0, "history_depth": 12}, "")
    acc("decimals", "min_coverage: 0.95\nx: 1.0\ny: 0.9999\n", {"min_coverage": D("0.95"), "x": D("1.0"), "y": D("0.9999")}, "decimals stay exact")
    acc("booleans", "require_latest: true\nflag: false\n", {"require_latest": True, "flag": False}, "")
    acc("bare-strings", "a: std:no-internet-to-datastore\nb: 48h\nc: sha256:ab12\nd: 95%\ne: a/b.c+d_e-f\n",
        {"a": "std:no-internet-to-datastore", "b": "48h", "c": "sha256:ab12", "d": "95%", "e": "a/b.c+d_e-f"}, "")
    acc("flow-mapping-in-item", "require:\n  - { invariant: std:x, verdict: HOLDS, max_age: 6h, min_coverage: 0.9 }\n",
        {"require": [{"invariant": "std:x", "verdict": "HOLDS", "max_age": "6h", "min_coverage": D("0.9")}]}, "")
    acc("flow-sequence-in-flow-mapping-not-needed", "a:\n  - [x, y]\n", {"a": [["x", "y"]]}, "a flow sequence is a valid sequence item")
    acc("depth-6", "a:\n  b:\n    c:\n      d:\n        e:\n          f: 1\n", {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}, "six levels of nesting")
    acc("key-order-preserved-by-value", "b: 1\na: 2\n", {"b": 1, "a": 2}, "")
    acc("no-final-newline", "a: 1", {"a": 1}, "")
    rej("bare-hash-in-value", "a: b#c\n", 1, "'#' is outside the bare-string charset")
    rej("anchor", "a: &x 1\n", 1, "anchors")
    rej("alias", "a: *x\n", 1, "aliases")
    rej("tag", "a: !!str 1\n", 1, "tags")
    rej("block-scalar-literal", "a: |\n  text\n", 1, "block scalars")
    rej("block-scalar-folded", "a: >\n  text\n", 1, "block scalars")
    rej("document-start", "---\na: 1\n", 1, "multi-document syntax")
    rej("document-end", "a: 1\n...\n", 2, "")
    rej("second-document", "a: 1\n---\nb: 2\n", 2, "")
    rej("merge-key", "a: 1\n<<: b\n", 2, "")
    rej("yes", "a: yes\n", 1, "YAML 1.1 booleans are not scalars here")
    rej("no", "a: no\n", 1, "")
    rej("on", "a: on\n", 1, "")
    rej("off", "a: off\n", 1, "off must be quoted")
    rej("tilde", "a: ~\n", 1, "")
    rej("null", "a: null\n", 1, "")
    rej("Null", "a: Null\n", 1, "")
    rej("NULL", "a: NULL\n", 1, "")
    rej("Yes-capitalised", "a: Yes\n", 1, "")
    rej("True-capitalised", "a: True\n", 1, "only lowercase true and false")
    rej("empty-value", "a:\n", 1, "a key with no value and no children")
    rej("duplicate-key", "a: 1\nb: 2\na: 3\n", 3, "")
    rej("duplicate-key-nested", "m:\n  x: 1\n  x: 2\n", 3, "")
    rej("duplicate-key-in-flow", "r:\n  - { a: 1, a: 2 }\n", 2, "")
    rej("depth-7", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g: 1\n", 7, "more than six levels")
    rej("tab-indent", "a:\n\tb: 1\n", 2, "")
    rej("tab-anywhere", "a:\t1\n", 1, "")
    rej("odd-indent", "a:\n   b: 1\n", 2, "indentation is two spaces per level")
    rej("indent-4", "a:\n    b: 1\n", 2, "")
    rej("non-ascii-value", "a: caf\u00e9\n", 1, "")
    rej("non-ascii-comment", "a: 1 # caf\u00e9\n", 1, "the whole file is ASCII")
    rej("cr-line-ending", "a: 1\r\nb: 2\r\n", 1, "LF only")
    rej("single-quoted", "a: 'x'\n", 1, "")
    rej("unterminated-quote", 'a: "x\n', 1, "")
    rej("bad-escape", 'a: "\\n"\n', 1, "only \\\" and \\\\ are escapes")
    rej("bare-with-space", "a: hello world\n", 1, "")
    rej("bare-with-comma", "a: x,y\n", 1, "")
    rej("nested-flow-mapping", "r:\n  - { a: { b: 1 } }\n", 2, "")
    rej("nested-flow-sequence", "a: [x, [y]]\n", 1, "")
    rej("unclosed-flow-sequence", "a: [x, y\n", 1, "")
    rej("unclosed-flow-mapping", "r:\n  - { a: 1\n", 2, "")
    rej("flow-mapping-as-value", "a: { b: 1 }\n", 1, "a flow mapping is only allowed as a sequence item")
    rej("line-without-colon", "a: 1\nnonsense\n", 2, "")
    rej("complex-key", "? a\n: b\n", 1, "")
    rej("sequence-of-sequences", "a:\n  - - x\n", 2, "")
    rej("top-level-sequence", "- a\n- b\n", 1, "the document is a mapping")
    rej("top-level-scalar", "hello\n", 1, "")
    rej("key-with-space", "a b: 1\n", 1, "")
    rej("quoted-key", '"a": 1\n', 1, "")
    rej("decimal-leading-dot", "a: .5\n", 1, "")
    rej("mixed-sequence-and-mapping", "a:\n  - x\n  b: 1\n", 3, "")
    rej("sequence-indent-jump", "a:\n  - x\n      - y\n", 3, "")
    big = "# " + "x" * 65536 + "\n"
    cases.append({"id": "file-over-64kib", "desc": "more than 65536 bytes", "yaml_recipe": {"text": "# ", "fill": "x", "newline": True, "length": 65537},
                  "accept": False, "line": 1, "code": "config.policy_invalid"})
    assert len(big) > 65536
    return {"kind": "policy-parse", "spec": "spec/08-acceptance-policy.md",
            "value_encoding": "{\"$decimal\": \"0.95\"} stands for an exact decimal; everything else is plain JSON",
            "limits": {"max_bytes": 65536, "max_depth": 6}, "cases": cases}


# ---------------------------------------------------------------------------------------- scope digest
PRIVATE_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
              "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
PRIVATE_V6 = ["::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"]


def _is_private_net(net):
    for r in (PRIVATE_V4 if net.version == 4 else PRIVATE_V6):
        rn = ipaddress.ip_network(r)
        if net.version == rn.version and net.subnet_of(rn):
            return True
    return False


def _norm(kind, value):
    v = value.strip()
    if kind in ("domain", "subdomain_wildcard"):
        v = v.lower().rstrip(".")
        wild = v.startswith("*.")
        host = v[2:] if wild else v
        host = ".".join(lbl.encode("idna").decode("ascii") if not lbl.isascii() else lbl for lbl in host.split("."))
        return ("*." if wild else "") + host
    if kind in ("ipv4_cidr", "ipv6_cidr"):
        return str(ipaddress.ip_network(v, strict=False))
    if kind == "asn":
        n = v.upper()
        n = n[2:] if n.startswith("AS") else n
        return "AS%d" % int(n)
    raise ValueError(kind)


def ref_scope(entries):
    doc, unproven, private = [], 0, 0
    for e in entries:
        if not e["active"] or e.get("expired"):
            continue
        if e["proof"] not in ("verified", "attested"):
            unproven += 1
            continue
        v = _norm(e["kind"], e["value"])
        if e["kind"] in ("ipv4_cidr", "ipv6_cidr") and _is_private_net(ipaddress.ip_network(v)):
            private += 1
            continue
        doc.append({"kind": e["kind"], "value": v})
    doc = sorted({(d["kind"], d["value"]) for d in doc})
    body = {"entries": [{"kind": k, "value": v} for k, v in doc], "v": 1}
    raw = pcj(body)
    return {"doc": body, "doc_pcj": raw.decode("ascii"), "digest": "sha256:" + sha(raw), "entries": len(doc),
            "unproven": unproven, "private": private}


def build_scope_digest():
    cases = []

    def add(i, entries, desc=""):
        cases.append({"id": i, "desc": desc, "entries": entries, "expect": ref_scope(entries)})

    def E(kind, value, proof="verified", active=True, expired=False):
        return {"kind": kind, "value": value, "proof": proof, "active": active, "expired": expired}
    add("one-domain", [E("domain", "example.com")], "the section 13 example")
    assert cases[-1]["expect"]["digest"] == "sha256:be3fe528ef2b63fbb572c9bf47918ef6eacb45d7233231581fbb06c193044b7c"
    add("empty", [], "no entries: the digest of an empty document")
    add("domain-case-and-dot", [E("domain", "Example.COM.")], "lowercase, no trailing dot")
    add("idn-domain", [E("domain", "b\u00fccher.example")], "A-label (punycode)")
    add("wildcard-kept", [E("subdomain_wildcard", "*.Example.com")], "the *. prefix is kept")
    add("sorted-by-kind-then-value", [E("domain", "b.example"), E("asn", "64500"), E("domain", "a.example"), E("ipv4_cidr", "8.8.8.0/24")], "")
    add("duplicates-collapse", [E("domain", "a.example"), E("domain", "A.example")], "")
    add("cidr-canonical", [E("ipv4_cidr", "8.8.8.8/24")], "strict=False: host bits cleared")
    add("ipv6-canonical", [E("ipv6_cidr", "2606:4700:0:0::/32")], "compressed canonical text")
    add("asn-forms", [E("asn", "as64500"), E("asn", "AS64501"), E("asn", "64502")], "AS<n>")
    add("private-cidrs-excluded", [E("ipv4_cidr", "10.1.0.0/16"), E("ipv4_cidr", "192.168.1.0/24"), E("ipv4_cidr", "8.8.8.0/24"),
                                   E("ipv6_cidr", "fd00::/8"), E("ipv4_cidr", "100.64.0.0/10")], "non-global ranges are counted, not listed")
    add("whole-internet-cidr-is-not-private", [E("ipv4_cidr", "0.0.0.0/0")], "a /0 is not inside any single special-purpose range")
    add("unproven-excluded", [E("domain", "a.example", proof="pending"), E("domain", "b.example", proof="attested"),
                              E("domain", "c.example", proof="expired")], "pending and expired proofs are counted as unproven")
    add("inactive-and-expired-skipped", [E("domain", "a.example", active=False), E("domain", "b.example", expired=True),
                                         E("domain", "c.example")], "neither counted nor listed")
    add("attested-cidr", [E("ipv4_cidr", "203.0.114.0/24", proof="attested")], "attested entries count")
    return {"kind": "scope-digest", "spec": "spec/02-statement-predicate.md (scope) and spec/06-bundle.md (scope.json)",
            "private_ranges": PRIVATE_V4 + PRIVATE_V6,
            "rule": "scope.digest = sha256(PCJ({\"entries\":[{kind,value}...sorted by (kind,value)],\"v\":1})); informative for issuers",
            "cases": cases}


# ------------------------------------------------------------------------------------ worked example
def build_worked_example():
    reg = os.path.join(SPEC_DIR, "registry", "limits-v1.txt")
    with open(reg, "rb") as fh:
        limits = fh.read()
    assert sha(limits) == "330258fa3556e0417b000fa9cae4a2cd1853d4402a17762c5b030b1652d7c37f"
    sk, ask = key_for("tenant-a"), key_for("anchor-a")
    pub, apub = pub_of(sk), pub_of(ask)
    kid, akid = kid_of(pub), kid_of(apub)
    estate = "e_3fq7m2xk5h6cnj4d2v5yb7wzta"
    ck = COMMIT_KEY
    scope = pcj({"v": 1, "entries": [{"kind": "domain", "value": "example.com"}]})
    pol = [{"id": "std:no-internet-to-datastore", "digest": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6", "enabled": True, "source": "std"},
           {"id": "std:server-ssh-hardened", "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1", "enabled": True, "source": "std"},
           {"id": "std:guest-cannot-reach-pos", "digest": "sha256:e261c80c93ca592db7f8eb4c08a42e66d1748eab61038722b958bc33bb69fc1c", "enabled": True, "source": "std"}]
    _, proot = m_tree("policy", pol, ck)
    graph = [{"t": "node", "id": "internet", "kind": "internet", "tags": []},
             {"t": "node", "id": "asset:11111111-1111-4111-8111-111111111111", "kind": "cloud_db", "class": "datastore", "tags": []},
             {"t": "edge", "src": "internet", "dst": "asset:22222222-2222-4222-8222-222222222222", "proto": "tcp", "ports": "443", "basis": "configured", "source": "aws_sg"}]
    _, groot = m_tree("graph", graph, ck)
    _, blroot = m_tree("blind", [{"inv": "std:no-internet-to-datastore", "node": "asset:33333333-3333-4333-8333-333333333333", "direction": "in", "reason": "stale", "relevant": True}], ck)
    head = sha(b"example chain head")
    adoc = {"alg": "ed25519", "at": "2026-12-01T08:59:40Z", "estate": estate, "hash_alg": "hmac-sha256", "head": head, "kid": akid, "max_id": 99120, "v": 2}
    asig = ask.sign(b"paddock-anchor/v2\n" + pcj(adoc))
    adoc_full = dict(adoc, sig=b64(asig))
    anchor_bytes = pcj(adoc_full)
    adigest = "sha256:" + sha(anchor_bytes)
    empty = "sha256:" + hx(EMPTY)
    stmt = {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "dns:example.com", "digest": {"sha256": sha(b"dns:example.com")}}],
            "predicateType": "https://paddock.dev/attestation/containment/v1",
            "predicate": {
                "estate": estate, "seq": 1, "issued_at": "2026-12-01T09:00:00Z", "valid_until": "2026-12-02T09:00:00Z", "kid": kid,
                "snapshot": {"at": "2026-12-01T08:57:12Z", "graph": {"root": "sha256:" + hx(groot), "size": 3}},
                "scope": {"digest": "sha256:" + sha(scope), "entries": 1, "unproven": 0, "private": 0},
                "policy": {"commitment": "sha256:" + hx(proot), "total": 3, "enabled_std": 3, "enabled_custom": 0, "disclosed": 2, "versions": 3},
                "disclosure": {"verdicts": "holds_only", "custom": False},
                "results": [
                    {"invariant": "std:no-internet-to-datastore", "digest": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6",
                     "assertion": "unreachable", "verdict": "HOLDS", "tier": "configured", "min_tier": "configured", "max_age_s": 86400,
                     "coverage": {"universe": 42, "covered": 41, "required_bp": 9500, "estate_universe": 120, "estate_covered": 118},
                     "blind_spots": {"root": "sha256:" + hx(blroot), "size": 1, "truncated": False},
                     "selected": {"from": 1, "to": 4, "stop_at": 3}, "exceptions": 0, "valid_until": "2026-12-02T08:40:00Z"},
                    {"invariant": "std:server-ssh-hardened", "digest": "sha256:e118308d1eb364979bffb1609cb40171c11006d38d4b6087b73cafdd5b2bb0f1",
                     "assertion": "host-config", "verdict": "HOLDS", "tier": "configured", "min_tier": "configured", "max_age_s": 21600,
                     "coverage": {"universe": 3, "covered": 3, "required_bp": 10000, "estate_universe": 120, "estate_covered": 118},
                     "blind_spots": {"root": empty, "size": 0, "truncated": False},
                     "selected": {"to": 3}, "exceptions": 0, "valid_until": "2026-12-01T14:50:00Z"}],
                "engine": {"name": "paddock-assurance", "version": "0.3.0",
                           "ruleset": "sha256:b13ad8f0f157b2a037ce106ae96b692b09785be865259702dc45adf3fb15a299"},
                "audit_anchor": {"max_id": 99120, "head": head, "hash_alg": "hmac-sha256", "at": "2026-12-01T08:59:40Z", "kid": akid, "digest": adigest},
                "limits": {"id": "paddock-limits/1", "digest": "sha256:" + sha(limits)}}}
    payload = pcj(stmt)
    sig = sk.sign(pae(P_TYPE_STATEMENT, payload))
    env = {"payload": b64(payload), "payloadType": P_TYPE_STATEMENT, "signatures": [{"keyid": kid, "sig": b64(sig)}]}
    env_text = json.dumps(env)
    assert len(payload) == 2536 and sha(payload) == "ccd9d6bcfa3d9ef1b18bd5cfb1f864d13d50f0239eb055d40f28e9ea5e6278db"
    assert b64(sig) == "c5fOB7whPuYeD9wONEz/Ppl+zY5l3x5FxBz4qogxnjF8P4mg2ZzqMyunTj+XrkQF3WoGE12Ri6/6btdiBYyqBg=="
    assert len(env_text) == 3608
    assert adigest == "sha256:5f06ee2d93da06240f8c46c6d40844b0f8364a8142d2ee91bc3e83d7ba9ac0b8"
    return {"kind": "worked-example", "spec": "spec/C-worked-example.md",
            "dns_txt": "v=1; kid=%s; fp=sha256:%s; keys=https://example.com/.well-known/paddock/keys.json" % (kid, sha(pub)),
            "tenant_public_key_b64": b64(pub), "anchor_public_key_b64": b64(apub), "estate": estate,
            "statement": stmt, "payload_b64": b64(payload), "payload_len": len(payload), "payload_sha256": sha(payload),
            "pae_head": pae(P_TYPE_STATEMENT, payload)[:40].decode("ascii"), "signature_b64": b64(sig), "envelope": env_text,
            "anchor_doc_b64": b64(anchor_bytes), "anchor_doc": adoc_full,
            "pins": {"policy_root": "sha256:" + hx(proot), "graph_root": "sha256:" + hx(groot), "blind_root": "sha256:" + hx(blroot),
                     "scope_digest": "sha256:" + sha(scope), "scope_document": scope.decode("ascii"), "subject_digest": sha(b"dns:example.com"),
                     "limits_digest": "sha256:" + sha(limits), "anchor_digest": adigest,
                     "empty_root": empty}}


# ============================================================================================== main
BUILDERS = [("pae.json", build_pae), ("b64.json", build_b64), ("pcj.json", build_pcj), ("time.json", build_time),
            ("ed25519.json", build_ed25519), ("kid.json", build_kid), ("merkle.json", build_merkle),
            ("commit-nonce.json", build_commit_nonce), ("coverage.json", build_coverage), ("reason-map.json", build_reason_map),
            ("dns-txt-parse.json", build_dns_txt), ("policy-parse.json", build_policy_parse),
            ("scope-digest.json", build_scope_digest), ("worked-example.json", build_worked_example)]


def render(obj):
    obj = dict(obj)
    obj["generator"] = "tools/gen_vectors.py"
    obj["spec_version"] = SPEC_VERSION
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def generate():
    return {name: render(fn()) for name, fn in BUILDERS}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="compare with the committed files, write nothing")
    args = ap.parse_args(argv)
    files = generate()
    if args.check:
        bad = []
        for name, data in files.items():
            p = os.path.join(args.out, name)
            if not os.path.exists(p):
                bad.append("missing " + name)
            elif open(p, "rb").read() != data:
                bad.append("differs " + name)
        if os.path.isdir(args.out):
            extra = sorted(set(os.listdir(args.out)) - set(files))
            bad += ["unexpected " + e for e in extra]
        if bad:
            sys.stderr.write("vectors are stale: %s\n" % ", ".join(bad))
            return 1
        print("primitive vectors are up to date (%d files)" % len(files))
        return 0
    os.makedirs(args.out, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(data)
    print("wrote %d files to %s" % (len(files), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
