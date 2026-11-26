"""Key certificates, trust roots, chain verification and ``keys.json`` (docs/ASSURANCE_P3.md 3.1, 3.2, D16).

A certificate is a DSSE envelope (``payloadType`` ``application/vnd.paddock.key-cert+json``) with exactly one signature
by the parent key over the PAE, whose payload is PCJ::

    {"_type":"https://paddock.dev/key-cert/v1","alg":"ed25519","custody":"hosted","estate":"e_...","issuer_kid":"..",
     "kid":"..","not_after":"..","not_before":"..","public_key":"<b64>","serial":17,"usage":"attest"}

Everything byte-level (strict JSON, PCJ, base64, DSSE, Ed25519 pre-checks, time) comes from the open verifier's
primitives (``paddock_verify``), so this module cannot disagree with the verifier about what a byte string means.
Production here and the independent builder in ``tests/attest_fakes.py`` are checked against each other.

Chain rules (fixed length: two below the root, or one below a pinned issuer):

=================  ====================================================================================
certificate usage  must be signed by
=================  ====================================================================================
``attest``/        an ``issue-cert`` key: an issuer certificate that chains to a pinned ``root``, or a pinned
``anchor``         root entry whose own ``usage`` is ``issue-cert`` (a self-hoster's issuer, chain length 1)
``issue-cert``/    a pinned root entry with usage ``root``
``revoke``
=================  ====================================================================================

A root never signs an estate key directly and a revoker never certifies anything. Every certificate in the chain must
be valid at the time the caller asks about (a statement's ``issued_at``, never "now"); windows are end-exclusive.

Failures raise :class:`CertError` whose ``code`` is a stable reason code of the spec (``key.cert_invalid``,
``key.root_unknown``, ``key.outside_validity``, ``issuer.outside_validity``, ``issuer.revoked``,
``key.cert_subject_mismatch``, ``key.fingerprint_mismatch``, ``sig.alg_unsupported``, ``sig.weak_key``,
``keys.invalid``, ``key.cert_missing``, ``config.no_trust_roots``, ``input.too_large``). Nothing here returns a
partial success: a certificate is either fully verified or an error.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from paddock_verify import b64, canon, dsse, ed25519, limits, timefmt
from paddock_verify.jsonstrict import JsonError
from paddock_verify import jsonstrict

CERT_TYPE = "https://paddock.dev/key-cert/v1"
PAYLOAD_TYPE = dsse.PAYLOAD_TYPE_KEY_CERT
KEYS_SPEC = "paddock-keys/v1"

USAGES = ("attest", "anchor", "issue-cert", "revoke")
ESTATE_USAGES = ("attest", "anchor")
CUSTODIES = ("hosted", "byok-kms", "byok-hsm")
ALG = "ed25519"
ROOT_USAGES = ("root", "issue-cert")

_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_ESTATE = re.compile(r"e_[a-z2-7]{26}\Z", re.ASCII)
_CERT_KEYS = {"_type", "alg", "custody", "issuer_kid", "kid", "not_after", "not_before", "public_key", "serial", "usage"}
_ENTRY_KEYS = {"kid", "usage", "alg", "public_key", "custody", "not_before", "not_after", "cert"}
_ROOT_KEYS = {"kid", "public_key", "usage", "not_before", "not_after"}


class CertError(ValueError):
    """A certificate, root list or keys file is not acceptable. ``code`` is a spec reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def epoch_of(value: Any) -> int:
    """Whole seconds since the epoch for an int, an aware/naive-UTC ``datetime`` or ``None`` (the host clock)."""
    if value is None:
        return int(time.time())
    if isinstance(value, bool):
        raise TypeError("a time is an int or a datetime")
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        return int(value.timestamp()) if value.tzinfo else int(value.replace(tzinfo=_utc()).timestamp())
    raise TypeError("a time is an int or a datetime")


def _utc():
    from datetime import timezone

    return timezone.utc


# --------------------------------------------------------------------------- #
# Values
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Cert:
    """A parsed certificate. Parsing checks structure and the key fingerprint, **not** the signature or the window
    (``verify_chain`` does)."""

    kid: str
    usage: str
    alg: str
    custody: str
    estate: Optional[str]
    issuer_kid: str
    public_key: bytes = field(repr=False)
    not_before: int
    not_after: int
    serial: int
    payload: bytes = field(repr=False)
    envelope: bytes = field(repr=False)
    sig: bytes = field(repr=False)

    def window_contains(self, t: int) -> bool:
        """End-exclusive: ``not_before <= t < not_after``."""
        return self.not_before <= t < self.not_after


@dataclass(frozen=True)
class Root:
    """One pinned trust anchor: a ``root`` (certifies issuers and revokers) or a self-hoster's ``issue-cert``."""

    kid: str
    public_key: bytes = field(repr=False)
    usage: str
    not_before: int
    not_after: int

    def window_contains(self, t: int) -> bool:
        return self.not_before <= t < self.not_after


@dataclass(frozen=True)
class ChainResult:
    cert: Cert
    issuer: Optional[Cert]
    root: Root
    depth: int
    window: tuple


@dataclass(frozen=True)
class VerifiedKeys:
    estate: str
    issuers: list
    issuers_envelopes: list
    revoker: Cert
    keys: dict


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _as_bytes(value: Any) -> bytes:
    if isinstance(value, Cert):
        return value.envelope
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError:
            raise CertError("key.cert_invalid", "the certificate is not ASCII") from None
    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError):
            raise CertError("key.cert_invalid", "the certificate object is not JSON") from None
    raise CertError("key.cert_invalid", "a certificate envelope is required")


def _time(value: Any, what: str) -> int:
    try:
        return timefmt.parse(value)
    except JsonError:
        raise CertError("key.cert_invalid", f"{what} is not a YYYY-MM-DDTHH:MM:SSZ instant") from None


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_doc(doc: Any) -> tuple:
    """Check a certificate payload (already canonical JSON). Returns the parsed field tuple."""
    if not isinstance(doc, dict):
        raise CertError("key.cert_invalid", "the payload is not an object")
    usage = doc.get("usage")
    expected = set(_CERT_KEYS) | ({"estate"} if usage in ESTATE_USAGES else set())
    if set(doc) != expected:
        raise CertError("key.cert_invalid", "unexpected or missing certificate fields")
    if doc["_type"] != CERT_TYPE:
        raise CertError("key.cert_invalid", "unknown certificate type")
    for name in ("alg", "custody", "issuer_kid", "kid", "not_after", "not_before", "public_key", "usage"):
        if not isinstance(doc[name], str):
            raise CertError("key.cert_invalid", f"{name} is not a string")
    if usage not in USAGES:
        raise CertError("key.cert_invalid", "unknown usage")
    if doc["custody"] not in CUSTODIES:
        raise CertError("key.cert_invalid", "unknown custody")
    if not _is_int(doc["serial"]) or not 1 <= doc["serial"] <= limits.MAX_INT:
        raise CertError("key.cert_invalid", "serial is a positive integer")
    if not _KID.match(doc["issuer_kid"]) or not _KID.match(doc["kid"]):
        raise CertError("key.cert_invalid", "a key id is 32 lowercase hex characters")
    if usage in ESTATE_USAGES and not _ESTATE.match(doc["estate"]):
        raise CertError("key.cert_invalid", "estate is not an estate id")
    try:
        public_key = b64.strict_decode(doc["public_key"])
    except JsonError:
        raise CertError("key.cert_invalid", "public_key is not canonical base64") from None
    if len(public_key) != 32:
        raise CertError("key.cert_invalid", "an Ed25519 public key is 32 bytes")
    not_before, not_after = _time(doc["not_before"], "not_before"), _time(doc["not_after"], "not_after")
    if not not_before < not_after:
        raise CertError("key.cert_invalid", "the validity window is empty")
    if doc["alg"] != ALG:
        raise CertError("sig.alg_unsupported", "only ed25519 is defined in spec v1")
    if hashlib.sha256(public_key).hexdigest()[:32] != doc["kid"]:
        raise CertError("key.fingerprint_mismatch", "kid is not the fingerprint of the public key")
    weak = ed25519.precheck_public_key(public_key)
    if weak:
        raise CertError(weak, "the certified public key is of small order or not canonical")
    return (doc["kid"], usage, doc["alg"], doc["custody"], doc.get("estate"), doc["issuer_kid"], public_key,
            not_before, not_after, doc["serial"])


def parse_cert(envelope: Any) -> Cert:
    """Parse a certificate envelope strictly (envelope, canonical payload, schema, fingerprint). The signature and the
    window are NOT checked here."""
    data = _as_bytes(envelope)
    try:
        env = dsse.parse_envelope(data, expected_type=PAYLOAD_TYPE)
        doc = canon.roundtrip(env.payload)
    except JsonError as exc:
        raise CertError("key.cert_invalid", f"{exc.code}") from None
    fields = _validate_doc(doc)
    if env.keyid != fields[5]:
        raise CertError("key.cert_invalid", "the envelope key id is not the certificate's issuer_kid")
    return Cert(*fields, payload=env.payload, envelope=data, sig=env.sig)


def build_payload(*, usage: str, public_key: bytes, issuer_kid: str, not_before: int, not_after: int, serial: int,
                  estate: Optional[str] = None, custody: str = "hosted", alg: str = ALG) -> bytes:
    """The PCJ payload of a certificate; the same validator as ``parse_cert`` judges it first."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise CertError("key.cert_invalid", "public_key is bytes")
    doc: dict = {
        "_type": CERT_TYPE, "alg": alg, "custody": custody, "issuer_kid": issuer_kid,
        "kid": hashlib.sha256(bytes(public_key)).hexdigest()[:32],
        "not_after": _fmt(not_after), "not_before": _fmt(not_before),
        "public_key": b64.encode(bytes(public_key)), "serial": serial, "usage": usage,
    }
    if estate is not None:
        doc["estate"] = estate
    _validate_doc(doc)
    try:
        return canon.dumps(doc)
    except JsonError:
        raise CertError("key.cert_invalid", "the certificate is not PCJ-encodable") from None


def _fmt(epoch: int) -> str:
    try:
        return timefmt.format(epoch)
    except JsonError:
        raise CertError("key.cert_invalid", "a time is outside the supported years") from None


# --------------------------------------------------------------------------- #
# Roots
# --------------------------------------------------------------------------- #

def parse_roots(data: Any) -> list:
    """Parse the trust-roots list: ``[{"kid","public_key"(b64),"usage":"root"|"issue-cert","not_before","not_after"}]``.
    Strict: an invalid entry makes the whole list unusable (``config.no_trust_roots``), never a partial trust set."""
    if isinstance(data, (bytes, bytearray, str)):
        try:
            raw = data if isinstance(data, (bytes, bytearray)) else data.encode("ascii")
            data = jsonstrict.parse(bytes(raw), max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_AUX_FILE_BYTES)
        except (JsonError, UnicodeEncodeError):
            raise CertError("config.no_trust_roots", "the trust roots file is not strict JSON") from None
    if not isinstance(data, list):
        raise CertError("config.no_trust_roots", "the trust roots are a list")
    out: list = []
    seen: set = set()
    for item in data:
        if not isinstance(item, dict) or set(item) != _ROOT_KEYS:
            raise CertError("config.no_trust_roots", "a trust root has exactly kid, public_key, usage, not_before, not_after")
        if item["usage"] not in ROOT_USAGES:
            raise CertError("config.no_trust_roots", "a trust root's usage is root or issue-cert")
        if not isinstance(item["kid"], str) or not isinstance(item["public_key"], str):
            raise CertError("config.no_trust_roots", "a trust root's kid and public_key are strings")
        try:
            pub = b64.strict_decode(item["public_key"])
            nb, na = timefmt.parse(item["not_before"]), timefmt.parse(item["not_after"])
        except JsonError:
            raise CertError("config.no_trust_roots", "a trust root has a malformed key or time") from None
        if len(pub) != 32 or hashlib.sha256(pub).hexdigest()[:32] != item["kid"] or ed25519.precheck_public_key(pub):
            raise CertError("config.no_trust_roots", "a trust root's kid is not its key's fingerprint, or the key is weak")
        if not nb < na:
            raise CertError("config.no_trust_roots", "a trust root's window is empty")
        if item["kid"] in seen:
            raise CertError("config.no_trust_roots", "duplicate trust root")
        seen.add(item["kid"])
        out.append(Root(item["kid"], pub, item["usage"], nb, na))
    return out


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #

def issue_cert(issuer: Any, *, usage: str, public_key: bytes, not_before: int, not_after: int, serial: int,
               estate: Optional[str] = None, custody: str = "hosted", alg: str = ALG) -> Cert:
    """Certify an estate key (usage ``attest`` or ``anchor``) with the platform issuer. ``issuer`` is a
    ``platform_keys.PlatformKey`` (``kid``, ``usage``, ``cert``, ``sign``). The window is clamped to the issuer
    certificate's; an empty result is refused. Offline-root certificates (issuer, revoker) are the ceremony's."""
    if usage in ("issue-cert", "revoke"):
        raise CertError("key.cert_subject_mismatch", "the online issuer certifies estate keys only")
    if getattr(issuer, "usage", None) != "issue-cert":
        raise CertError("key.cert_subject_mismatch", "only an issue-cert key may issue estate certificates")
    # validate everything before clamping, so an invalid request is never "fixed" by the clamp
    build_payload(usage=usage, public_key=public_key, issuer_kid=issuer.kid, not_before=not_before,
                  not_after=not_after, serial=serial, estate=estate, custody=custody, alg=alg)
    nb = max(not_before, issuer.cert.not_before)
    na = min(not_after, issuer.cert.not_after)
    if not nb < na:
        raise CertError("key.outside_validity", "the issuer certificate does not cover the requested window")
    payload = build_payload(usage=usage, public_key=public_key, issuer_kid=issuer.kid, not_before=nb, not_after=na,
                            serial=serial, estate=estate, custody=custody, alg=alg)
    sig = issuer.sign(dsse.pae(PAYLOAD_TYPE, payload))
    cert = parse_cert(dsse.build_envelope(PAYLOAD_TYPE, payload, issuer.kid, sig))
    if not ed25519.verify(issuer.public_key, dsse.pae(PAYLOAD_TYPE, payload), cert.sig):
        raise CertError("key.cert_invalid", "the issuer's signature does not verify under its own public key")
    return cert


# --------------------------------------------------------------------------- #
# Chain verification
# --------------------------------------------------------------------------- #

def _check_signature(child: Cert, parent_pub: bytes) -> None:
    code = ed25519.verify_code(parent_pub, dsse.pae(PAYLOAD_TYPE, child.payload), child.sig)
    if code is not None:
        raise CertError("key.cert_invalid", f"the signature does not verify ({code})")


def verify_chain(cert: Any, *, issuers: Iterable = (), roots: Iterable, at: Optional[int],
                 valid_until: Optional[int] = None, expect_usage: Optional[str] = None,
                 expect_estate: Optional[str] = None, revoked_issuers: Iterable = ()) -> ChainResult:
    """Verify ``cert`` up to a pinned root. ``at`` is the instant every certificate must be valid at (a statement's
    ``issued_at``); ``None`` checks structure and signatures only (``keys.json`` history). ``valid_until`` (when given)
    must lie within the leaf's window. ``issuers`` are issuer certificate envelopes that may be needed on the way."""
    leaf = cert if isinstance(cert, Cert) else parse_cert(cert)
    root_list = list(roots)
    if not root_list:
        raise CertError("config.no_trust_roots", "no trust roots are configured")
    if expect_usage is not None and leaf.usage != expect_usage:
        raise CertError("key.cert_subject_mismatch", "the certificate's usage is not the one required")
    if expect_estate is not None and leaf.estate != expect_estate:
        raise CertError("key.cert_subject_mismatch", "the certificate belongs to another estate")
    revoked = set(revoked_issuers)
    candidates: dict = {}
    for item in issuers:
        try:
            c = item if isinstance(item, Cert) else parse_cert(item)
        except CertError:
            continue                              # an unusable extra certificate is simply not a candidate
        candidates.setdefault(c.kid, []).append(c)
    roots_by_kid = {r.kid: r for r in root_list}

    issuer_cert, root = _resolve(leaf, candidates, roots_by_kid, revoked)
    _check_signature(leaf, (issuer_cert.public_key if issuer_cert is not None else root.public_key)
                     if leaf.usage in ESTATE_USAGES else root.public_key)
    if issuer_cert is not None:
        _check_signature(issuer_cert, root.public_key)
    depth = 2 if issuer_cert is not None else 1

    nbs = [leaf.not_before] + ([issuer_cert.not_before] if issuer_cert is not None else []) + [root.not_before]
    nas = [leaf.not_after] + ([issuer_cert.not_after] if issuer_cert is not None else []) + [root.not_after]
    if at is not None:
        if not leaf.window_contains(at):
            raise CertError("issuer.outside_validity" if leaf.usage not in ESTATE_USAGES else "key.outside_validity",
                            "the certificate was not valid at that time")
        if issuer_cert is not None and not issuer_cert.window_contains(at):
            raise CertError("issuer.outside_validity", "the issuer certificate was not valid at that time")
        if not root.window_contains(at):
            raise CertError("issuer.outside_validity", "the trust root was not valid at that time")
    if valid_until is not None and valid_until > leaf.not_after:
        raise CertError("key.outside_validity", "the key's window ends before the statement's valid_until")
    return ChainResult(cert=leaf, issuer=issuer_cert, root=root, depth=depth, window=(max(nbs), min(nas)))


def _resolve(leaf: Cert, candidates: dict, roots_by_kid: dict, revoked: set) -> tuple:
    """Find the signer chain for ``leaf``: returns ``(issuer certificate or None, root)``. Encodes the usage table
    of the module doc; nothing here looks at signatures or windows."""
    if leaf.usage in ("issue-cert", "revoke"):
        signer = roots_by_kid.get(leaf.issuer_kid)
        if signer is None:
            if leaf.issuer_kid in candidates:
                raise CertError("key.root_unknown", "an issuer certificate must be signed by a pinned root")
            raise CertError("key.root_unknown", "the certificate does not chain to a trusted root")
        if signer.usage != "root":
            raise CertError("key.cert_subject_mismatch", "only a root certifies issuers and revokers")
        return None, signer
    # an estate key
    pinned = roots_by_kid.get(leaf.issuer_kid)
    if pinned is not None:
        if pinned.usage != "issue-cert":
            raise CertError("key.cert_subject_mismatch", "a root does not certify estate keys directly")
        if pinned.kid in revoked:
            raise CertError("issuer.revoked", "the issuer is revoked")
        return None, pinned
    tried: Optional[CertError] = None
    for issuer_cert in candidates.get(leaf.issuer_kid, []):
        if issuer_cert.usage != "issue-cert":
            tried = CertError("key.cert_subject_mismatch", "the signing certificate is not an issue-cert certificate")
            continue
        if issuer_cert.kid in revoked:
            raise CertError("issuer.revoked", "the issuer is revoked")
        try:
            _, root = _resolve(issuer_cert, candidates, roots_by_kid, revoked)
        except CertError as exc:
            tried = exc
            continue
        return issuer_cert, root
    if tried is not None:
        raise tried
    raise CertError("key.root_unknown", "the issuing certificate is unknown")


# --------------------------------------------------------------------------- #
# keys.json
# --------------------------------------------------------------------------- #

def _object(envelope: Any) -> dict:
    try:
        return json.loads(_as_bytes(envelope))
    except ValueError:
        raise CertError("key.cert_invalid", "the certificate is not JSON") from None


def build_keys_json(estate: str, *, issuers: Iterable, revoker: Any, certs_: Iterable) -> bytes:
    """``keys.json`` (3.2): the public, unsigned wrapper. Every entry field is derived from the (signed) certificate
    payload, so the file cannot disagree with its certificates. Deterministic bytes; at most 64 KiB."""
    if not isinstance(estate, str) or not _ESTATE.match(estate):
        raise CertError("keys.invalid", "estate is not an estate id")
    entries = []
    seen: set = set()
    for c in certs_:
        c = c if isinstance(c, Cert) else parse_cert(c)
        if c.usage not in ESTATE_USAGES or c.estate != estate:
            raise CertError("key.cert_subject_mismatch", "an entry's certificate is not an estate key of this estate")
        if c.kid in seen:
            raise CertError("keys.invalid", "duplicate kid")
        seen.add(c.kid)
        entries.append({
            "kid": c.kid, "usage": c.usage, "alg": c.alg, "public_key": b64.encode(c.public_key), "custody": c.custody,
            "not_before": _fmt(c.not_before), "not_after": _fmt(c.not_after), "cert": _object(c.envelope),
        })
    entries.sort(key=lambda e: (e["usage"], e["not_before"], e["kid"]))
    doc = {"spec": KEYS_SPEC, "estate": estate, "issuers": [_object(i) for i in issuers], "revoker": _object(revoker),
           "keys": entries}
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(data) > limits.MAX_KEYS_FILE_BYTES:
        raise CertError("input.too_large", f"keys.json would be {len(data)} bytes (limit {limits.MAX_KEYS_FILE_BYTES})")
    return data


def verify_keys_json(data: bytes, *, roots: Iterable, at: Optional[int] = None,
                     revoked_issuers: Iterable = ()) -> VerifiedKeys:
    """Verify ``keys.json``: structure, duplicate kids, every certificate's signature chain to a pinned root, and that
    each unsigned entry field equals its certificate. Entry windows are NOT judged here (retired keys stay listed so
    history verifies; ``verify_chain`` judges a key at the statement's own ``issued_at``). With ``at``, the issuers
    and the revoker must be valid at it."""
    root_list = list(roots)
    if len(data) > limits.MAX_KEYS_FILE_BYTES:
        raise CertError("input.too_large", "keys.json is over the size limit")
    try:
        doc = jsonstrict.parse(data, max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_KEYS_FILE_BYTES)
    except JsonError:
        raise CertError("keys.invalid", "keys.json is not strict JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"spec", "estate", "issuers", "revoker", "keys"} \
            or doc["spec"] != KEYS_SPEC or not isinstance(doc["estate"], str) or not _ESTATE.match(doc["estate"]) \
            or not isinstance(doc["issuers"], list) or not isinstance(doc["revoker"], dict) \
            or not isinstance(doc["keys"], list):
        raise CertError("keys.invalid", "keys.json has the wrong shape")
    estate = doc["estate"]
    kids = [e.get("kid") if isinstance(e, dict) else None for e in doc["keys"]]
    if len(set(kids)) != len(kids):
        raise CertError("keys.invalid", "duplicate kid")
    for e in doc["keys"]:
        if not isinstance(e, dict) or (set(e) - _ENTRY_KEYS):
            raise CertError("keys.invalid", "an entry has unexpected fields")
        if "cert" not in e:
            raise CertError("key.cert_missing", "an entry has no certificate")
        if set(e) != _ENTRY_KEYS:
            raise CertError("keys.invalid", "an entry is missing fields")

    issuer_envs = [_as_bytes(i) for i in doc["issuers"]]
    issuer_certs = []
    for env in issuer_envs:
        c = parse_cert(env)
        verify_chain(c, issuers=[], roots=root_list, at=at, expect_usage="issue-cert", revoked_issuers=revoked_issuers)
        issuer_certs.append(c)
    revoker = parse_cert(doc["revoker"])
    verify_chain(revoker, issuers=[], roots=root_list, at=at, expect_usage="revoke")

    keys: dict = {}
    for e in doc["keys"]:
        c = parse_cert(e["cert"])
        verify_chain(c, issuers=issuer_envs, roots=root_list, at=None, expect_estate=estate,
                     revoked_issuers=revoked_issuers)
        want = {"kid": c.kid, "usage": c.usage, "alg": c.alg, "public_key": b64.encode(c.public_key),
                "custody": c.custody, "not_before": _fmt(c.not_before), "not_after": _fmt(c.not_after)}
        if any(e[k] != v for k, v in want.items()):
            raise CertError("key.cert_subject_mismatch", "an entry differs from its certificate")
        keys[c.kid] = c
    return VerifiedKeys(estate=estate, issuers=issuer_certs, issuers_envelopes=issuer_envs, revoker=revoker, keys=keys)


# --------------------------------------------------------------------------- #
# Renewal (the database part lives in keys.py)
# --------------------------------------------------------------------------- #

async def renew_due(conn: Any, platform: Any = None, *, now: Any = None) -> list:
    """Renew the certificates of this tenant's live keys that are due (same key, a new serial). See
    ``keys.renew_certs``; returns the kids renewed."""
    from . import keys

    return await keys.renew_certs(conn, platform, now=now)
