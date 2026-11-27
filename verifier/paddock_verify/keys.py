# SPDX-License-Identifier: Apache-2.0
"""Trust roots, ``keys.json`` and certificate chains (spec/05-keys-certs-revocation-dns.md sections 1 to 3).

A key is trusted only through a certificate chain to a pinned root. ``check_chain`` returns every defect it finds in
the order of the reason-code table (fingerprint, missing, invalid, subject mismatch, unknown root, key window,
issuer window) so a caller can report them in step order. The algorithm of a key comes from its certificate: any
value other than ``ed25519`` is unverifiable, never a fallback.
"""
from __future__ import annotations

import functools
import json
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from . import b64, canon, dsse, ed25519, jsonstrict, limits, schema, timefmt
from .jsonstrict import JsonError

ALG = "ed25519"


class KeysError(Exception):
    """``keys.json`` is not usable: ``code`` is ``keys.invalid`` or an ``input.*`` parse code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__("%s%s" % (code, (": " + detail) if detail else ""))
        self.code = code
        self.detail = detail


class ConfigError(ValueError):
    """A trust-roots file that cannot be used (a configuration error, exit 64)."""


# ---------------------------------------------------------------------------------------------- roots
class Root(NamedTuple):
    kid: str
    public_key: bytes
    usage: str                 # root | issue-cert
    not_before: int
    not_after: int


class TrustRoots(object):
    """Pinned roots plus the issuers that the release itself revokes."""

    def __init__(self, roots: Optional[List[Root]] = None, revoked_issuers: Optional[List[str]] = None, custom: bool = False) -> None:
        self.roots = list(roots or [])
        self.revoked_issuers = set(revoked_issuers or [])
        self.custom = custom

    def __bool__(self) -> bool:
        return bool(self.roots)

    def find(self, kid: str, usage: str) -> Optional[Root]:
        for r in self.roots:
            if r.kid == kid and r.usage == usage:
                return r
        return None

    def merged(self, other: "TrustRoots") -> "TrustRoots":
        return TrustRoots(self.roots + other.roots, sorted(self.revoked_issuers | other.revoked_issuers), custom=True)


def parse_roots(data: Any, custom: bool = False) -> TrustRoots:
    """A trust-roots file: ``[{"kid","public_key"(base64),"usage":"root"|"issue-cert","not_before","not_after"}]``.

    An additive entry ``{"kid", "usage": "issuer-revoked"}`` names an issuer that this release revokes
    (``issuer.revoked``): the roots data ships with the verifier, so it needs no signature of its own.
    """
    try:
        doc = jsonstrict.parse(data if isinstance(data, (bytes, bytearray)) else bytes(data, "ascii"), max_depth=limits.MAX_PCJ_DEPTH,
                               max_bytes=limits.MAX_AUX_FILE_BYTES)
    except (JsonError, UnicodeEncodeError) as e:
        raise ConfigError("trust roots are not valid strict JSON: %s" % e) from None
    if not isinstance(doc, list) or len(doc) > 64:
        raise ConfigError("trust roots are a list of at most 64 entries")
    roots, revoked = [], []  # type: List[Root], List[str]
    for i, e in enumerate(doc):
        if not isinstance(e, dict) or not isinstance(e.get("kid"), str) or len(e["kid"]) != 32 or not _is_hex(e["kid"]):
            raise ConfigError("trust root %d needs a kid of 32 lowercase hex characters" % i)
        if e.get("usage") == "issuer-revoked":
            if set(e) != {"kid", "usage"}:
                raise ConfigError("trust root %d: an issuer-revoked entry has exactly kid and usage" % i)
            revoked.append(e["kid"])
            continue
        if set(e) != {"kid", "public_key", "usage", "not_before", "not_after"} or e["usage"] not in ("root", "issue-cert"):
            raise ConfigError("trust root %d has exactly kid, public_key, usage (root or issue-cert), not_before and not_after" % i)
        try:
            pub = b64.strict_decode(e["public_key"])
            nb, na = timefmt.parse(e["not_before"]), timefmt.parse(e["not_after"])
        except (JsonError, TypeError):
            raise ConfigError("trust root %d: public_key must be canonical base64 and the times YYYY-MM-DDTHH:MM:SSZ" % i) from None
        if len(pub) != 32 or ed25519.kid_of(pub) != e["kid"]:
            raise ConfigError("trust root %d: kid does not match the public key" % i)
        roots.append(Root(e["kid"], pub, e["usage"], nb, na))
    return TrustRoots(roots, revoked, custom)


def load_default_roots() -> TrustRoots:
    return parse_roots(limits.read_data("trust_roots.json"))


def _is_hex(s: str) -> bool:
    return all(c in "0123456789abcdef" for c in s)


# ----------------------------------------------------------------------------------------- keys.json
class Entry(NamedTuple):
    kid: str
    usage: str
    alg: str
    public_key_b64: str
    public_key: bytes
    custody: str
    not_before: str
    not_after: str
    cert: Optional[Dict[str, Any]]


class KeysDoc(NamedTuple):
    estate: str
    issuers: List[Dict[str, Any]]
    revoker: Dict[str, Any]
    entries: Dict[str, Entry]


def _env_shape(e: Any) -> bool:
    return isinstance(e, dict) and set(e) == {"payloadType", "payload", "signatures"}


def parse_keys(data: bytes) -> KeysDoc:
    if len(data) > limits.MAX_AUX_FILE_BYTES:
        raise KeysError("input.too_large", "keys.json")
    try:
        doc = jsonstrict.parse(data, max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_AUX_FILE_BYTES)
    except JsonError as e:
        raise KeysError(e.code, "keys.json") from None
    bad = KeysError("keys.invalid")
    if not isinstance(doc, dict) or set(doc) != {"spec", "estate", "issuers", "revoker", "keys"} or doc["spec"] != "paddock-keys/v1":
        raise bad
    if not isinstance(doc["estate"], str) or not schema._ESTATE.match(doc["estate"]):
        raise bad
    issuers, revoker, keys = doc["issuers"], doc["revoker"], doc["keys"]
    if not isinstance(issuers, list) or not 1 <= len(issuers) <= 4 or not all(_env_shape(e) for e in issuers) or not _env_shape(revoker):
        raise bad
    if not isinstance(keys, list) or len(keys) > 16:
        raise bad
    entries = {}  # type: Dict[str, Entry]
    for k in keys:
        if not isinstance(k, dict) or not {"kid", "usage", "alg", "public_key", "custody", "not_before", "not_after"} <= set(k) \
                or set(k) - {"kid", "usage", "alg", "public_key", "custody", "not_before", "not_after", "cert"}:
            raise bad
        if not isinstance(k["kid"], str) or not schema._KID.match(k["kid"]) or k["usage"] not in ("attest", "anchor") \
                or not isinstance(k["alg"], str) or not 1 <= len(k["alg"]) <= 32 or k["custody"] not in ("hosted", "byok-kms", "byok-hsm"):
            raise bad
        try:
            pub = b64.strict_decode(k["public_key"])
            timefmt.parse(k["not_before"])
            timefmt.parse(k["not_after"])
        except (JsonError, TypeError):
            raise bad from None
        if len(pub) != 32 or k["kid"] in entries or ("cert" in k and not _env_shape(k["cert"])):
            raise bad
        entries[k["kid"]] = Entry(k["kid"], k["usage"], k["alg"], k["public_key"], pub, k["custody"], k["not_before"], k["not_after"],
                                  k.get("cert"))
    return KeysDoc(doc["estate"], issuers, revoker, entries)


# ----------------------------------------------------------------------------------------- certificates
class Cert(NamedTuple):
    payload: Dict[str, Any]
    kid: str
    issuer_kid: str
    usage: str
    public_key: bytes
    not_before: int
    not_after: int
    estate: Optional[str]
    signed_by: str              # the envelope keyid
    signature: bytes
    pae: bytes


@functools.lru_cache(maxsize=512)
def _verify_cached(pub: bytes, message: bytes, sig: bytes) -> bool:
    return ed25519.verify(pub, message, sig)


def verify_sig(pub: bytes, message: bytes, sig: bytes) -> bool:
    """``ed25519.verify`` with a bounded memo: a pure function, and one run checks the same certificate several times."""
    return _verify_cached(bytes(pub), bytes(message), bytes(sig))


def parse_cert(env_obj: Dict[str, Any]) -> Cert:
    """Parse and canonically validate a certificate envelope; ``ValueError`` when it is not acceptable."""
    try:
        text = json.dumps(env_obj, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ValueError("shape") from None
    return _parse_cert_text(text)


@functools.lru_cache(maxsize=256)
def _parse_cert_text(text: str) -> Cert:
    raw = text.encode("ascii", "replace")
    try:
        env = dsse.parse_envelope(raw, expected_type=dsse.PAYLOAD_TYPE_KEY_CERT)
        payload = canon.roundtrip(env.payload)
    except JsonError as e:
        raise ValueError(e.code) from None
    if schema.cert_issues(payload):
        raise ValueError("schema")
    try:
        pub = b64.strict_decode(payload["public_key"])
        nb, na = timefmt.parse(payload["not_before"]), timefmt.parse(payload["not_after"])
    except JsonError:
        raise ValueError("schema") from None
    if len(pub) != 32 or env.keyid != payload["issuer_kid"] or nb >= na:
        raise ValueError("shape")
    return Cert(payload, payload["kid"], payload["issuer_kid"], payload["usage"], pub, nb, na, payload.get("estate"), env.keyid, env.sig,
                dsse.pae(dsse.PAYLOAD_TYPE_KEY_CERT, env.payload))


class ChainResult(NamedTuple):
    codes: List[str]                     # defects in table order (empty means the chain is good)
    cert: Optional[Cert]                 # the leaf certificate when it parsed
    issuer: Optional[Cert]               # the issuer certificate when the chain used one
    chain_ok: bool                       # the signatures and the pinned root were established (windows aside)


def _in_window(t: int, nb: int, na: int) -> bool:
    return nb <= t < na


def check_chain(env_obj: Optional[Dict[str, Any]], keys: KeysDoc, roots: TrustRoots, t_start: int, t_end: Optional[int],
                expect_usage: str, expect_estate: Optional[str], entry: Optional[Entry] = None,
                check_fingerprint: bool = True, force_subject_mismatch: bool = False) -> ChainResult:
    """Check one leaf certificate (an estate key, an anchor key, the revoker or an issuer) at ``t_start``.

    ``t_end`` additionally requires the leaf window to reach that instant (a statement's ``valid_until``).
    ``entry`` is the unsigned ``keys[]`` entry that must agree with the certificate.
    """
    fingerprint = invalid = unknown_root = key_window = issuer_window = False
    subject = force_subject_mismatch
    if entry is not None and check_fingerprint and ed25519.kid_of(entry.public_key) != entry.kid:
        fingerprint = True
    if env_obj is None:
        return ChainResult(_order(fingerprint, True, False, False, False, False, False), None, None, False)
    try:
        leaf = parse_cert(env_obj)
    except ValueError:
        return ChainResult(_order(fingerprint, False, True, False, False, False, False), None, None, False)
    if ed25519.kid_of(leaf.public_key) != leaf.kid:
        fingerprint = True
    if leaf.usage != expect_usage:
        subject = True
    if expect_estate is not None and leaf.estate != expect_estate:
        subject = True
    if leaf.estate is not None and keys.estate != leaf.estate:
        subject = True
    if entry is not None:
        p = leaf.payload
        if (entry.kid, entry.usage, entry.alg, entry.public_key_b64, entry.custody, entry.not_before, entry.not_after) != \
                (p["kid"], p["usage"], p["alg"], p["public_key"], p["custody"], p["not_before"], p["not_after"]):
            subject = True
    if not _in_window(t_start, leaf.not_before, leaf.not_after) or (t_end is not None and t_end > leaf.not_after):
        key_window = True
    # who certified the leaf
    issuer_pub = None  # type: Optional[bytes]
    issuer = None      # type: Optional[Cert]
    if expect_usage == "issue-cert":
        root = roots.find(leaf.issuer_kid, "root")           # an issuer is certified directly by a pinned root
        if root is None:
            unknown_root = True
        else:
            issuer_pub = root.public_key
            if not _in_window(t_start, root.not_before, root.not_after):
                unknown_root = True
    else:
        pinned = roots.find(leaf.issuer_kid, "issue-cert")  # a self-hoster pins its own issuer: chain length 1
        if pinned is not None:
            issuer_pub = pinned.public_key
            if not _in_window(t_start, pinned.not_before, pinned.not_after):
                issuer_window = True
        else:
            issuer = _find_issuer(keys, leaf.issuer_kid)
            if issuer is None:
                unknown_root = True
            else:
                if issuer.usage != "issue-cert" or issuer.payload["alg"] != ALG:
                    invalid = True
                root = roots.find(issuer.issuer_kid, "root")
                if root is None:
                    unknown_root = True
                else:
                    if issuer.signed_by != root.kid or not verify_sig(root.public_key, issuer.pae, issuer.signature):
                        invalid = True
                    if not _in_window(t_start, root.not_before, root.not_after):
                        unknown_root = True
                if not _in_window(t_start, issuer.not_before, issuer.not_after):
                    issuer_window = True
                issuer_pub = issuer.public_key
    if issuer_pub is not None and not verify_sig(issuer_pub, leaf.pae, leaf.signature):
        invalid = True
    ok = not (invalid or unknown_root)
    return ChainResult(_order(fingerprint, False, invalid, subject, unknown_root, key_window, issuer_window), leaf, issuer, ok)


def _order(fingerprint: bool, missing: bool, invalid: bool, subject: bool, root: bool, key_window: bool, issuer_window: bool) -> List[str]:
    out = []
    for flag, code in ((fingerprint, "key.fingerprint_mismatch"), (missing, "key.cert_missing"), (invalid, "key.cert_invalid"),
                       (subject, "key.cert_subject_mismatch"), (root, "key.root_unknown"), (key_window, "key.outside_validity"),
                       (issuer_window, "issuer.outside_validity")):
        if flag:
            out.append(code)
    return out


def _find_issuer(keys: KeysDoc, kid: str) -> Optional[Cert]:
    for env in keys.issuers:
        try:
            c = parse_cert(env)
        except ValueError:
            continue
        if c.kid == kid:
            return c
    return None


def issuer_kids(keys: KeysDoc) -> List[str]:
    out = []
    for env in keys.issuers:
        try:
            out.append(parse_cert(env).kid)
        except ValueError:
            continue
    return out


def integrity(keys: KeysDoc, roots: TrustRoots, skip_kid: Optional[str] = None) -> List[str]:
    """Defects in the parts of ``keys.json`` that this statement does not rely on (no trust decision is made here).

    Every certificate in the file must parse canonically; every ``keys[]`` entry must agree with its certificate and
    its key id with its key; and a certificate whose issuer is listed (or pinned) must carry a valid signature by it.
    Windows and the chain to a root are *not* judged: a retired key may legitimately outlive an issuer. The point is
    that a bundle whose unsigned wrapper was damaged is never accepted just because the damage is in a part the
    decision happened not to read.
    """
    out = []  # type: List[str]
    issuer_pub = {}  # type: Dict[str, bytes]
    for r in roots.roots:
        if r.usage == "issue-cert":
            issuer_pub[r.kid] = r.public_key
    for env in keys.issuers:
        try:
            c = parse_cert(env)
        except ValueError:
            out.append("key.cert_invalid")
            continue
        issuer_pub.setdefault(c.kid, c.public_key)
        root = roots.find(c.issuer_kid, "root")
        if root is not None and (c.signed_by != root.kid or not verify_sig(root.public_key, c.pae, c.signature)):
            out.append("key.cert_invalid")
    try:
        rev = parse_cert(keys.revoker)
        parent = issuer_pub.get(rev.issuer_kid)
        if parent is not None and not verify_sig(parent, rev.pae, rev.signature):
            out.append("key.cert_invalid")
    except ValueError:
        out.append("key.cert_invalid")
    for kid, e in keys.entries.items():
        if kid == skip_kid:
            continue
        if ed25519.kid_of(e.public_key) != e.kid:
            out.append("key.fingerprint_mismatch")
        if e.cert is None:
            out.append("key.cert_missing")
            continue
        try:
            c = parse_cert(e.cert)
        except ValueError:
            out.append("key.cert_invalid")
            continue
        p = c.payload
        if (e.kid, e.usage, e.alg, e.public_key_b64, e.custody, e.not_before, e.not_after) != \
                (p["kid"], p["usage"], p["alg"], p["public_key"], p["custody"], p["not_before"], p["not_after"]) \
                or (c.estate is not None and c.estate != keys.estate):
            out.append("key.cert_subject_mismatch")
        parent = issuer_pub.get(c.issuer_kid)
        if parent is not None and not verify_sig(parent, c.pae, c.signature):
            out.append("key.cert_invalid")
    return out
