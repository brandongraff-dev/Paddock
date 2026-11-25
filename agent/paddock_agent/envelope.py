"""Signed evidence envelope v1 (docs/ASSURANCE_P2.md section 2) and the enrollment / rotation proofs.

An envelope proves "enrolled key K sent exactly these payload bytes, once, in order, at about
``issued_at``". It does not prove the host is honest. Layout::

    {"v":1,"alg":"ed25519","kid":"<hex(sha256(pub32))[:32]>","agent_id":"<uuid>","tenant_id":"<uuid>",
     "kind":"posture|heartbeat|rotate","seq":<int>=1>,"issued_at":"YYYY-MM-DDTHH:MM:SSZ",
     "nonce":"<b64url 16B>","payload_type":"...","payload_sha256":"<hex>","payload_len":<int>,
     "collectors":{...},"payload_b64":"<b64url of the exact payload bytes>","sig":"<b64url 64B>"}

Signing input = ``b"paddock-agent-envelope/v1\\n" + canon(header)`` where ``header`` is every field
except ``payload_b64`` and ``sig``. ``canon`` is the stdlib form (sorted keys, compact, UTF-8). It equals RFC 8785 only for the inputs this
module lets through: **no floats anywhere**, ``seq`` and ``payload_len`` at most 2^53-1 (the largest integer an
IEEE double prints exactly), and ``collectors`` keys restricted to ``[a-z0-9_.-]{1,64}`` (ASCII, so code-point
and UTF-16 key order agree). The payload is bound by ``payload_sha256`` over the decoded bytes; the
server never re-serialises it, and neither does this module (it signs the bytes it is handed).

Encoding conventions: every base64 field is URL-safe and unpadded (the server accepts both).
"""
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import time
import uuid

from . import signing

VERSION = 1
ALG = "ed25519"
SIGNING_PREFIX = b"paddock-agent-envelope/v1\n"
ENROLL_PROOF_DOMAIN = b"paddock-enroll/v1\n"
ROTATE_PROOF_DOMAIN = b"paddock-rotate/v1\n"

KIND_POSTURE = "posture"
KIND_HEARTBEAT = "heartbeat"
KIND_ROTATE = "rotate"
KINDS = (KIND_POSTURE, KIND_HEARTBEAT, KIND_ROTATE)

PAYLOAD_TYPE_POSTURE = "paddock.host.posture/v2"
PAYLOAD_TYPE_HEARTBEAT = "paddock.host.heartbeat/v1"
PAYLOAD_TYPE_ROTATE = "paddock.agent.key-rotate/v1"

# Server limits (section 2, step 1). The agent refuses to build or send anything larger.
MAX_HEADER_BYTES = 2048
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_BODY_INFLATED_BYTES = 4 * 1024 * 1024
MAX_BODY_GZIP_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16
GZIP_THRESHOLD = 4096
MAX_SEQ = 2 ** 53 - 1          # RFC 8785 prints numbers as IEEE doubles: above this an int is not exact

_HEADER_FIELDS = ("v", "alg", "kid", "agent_id", "tenant_id", "kind", "seq", "issued_at", "nonce",
                  "payload_type", "payload_sha256", "payload_len", "collectors")
_TOKEN_RE = re.compile(r"^fet_([0-9a-f]{12})_[A-Za-z0-9_-]{20,128}$")
_ISSUED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COLLECTOR_KEY_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")


class EnvelopeError(ValueError):
    """Something cannot be put in an envelope (or an envelope is malformed)."""


# --------------------------------------------------------------------------- #
# encoding helpers
# --------------------------------------------------------------------------- #

def b64u(data):
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    """Strict inverse of :func:`b64u` (padding optional; anything outside the alphabet is an error)."""
    if not isinstance(text, str):
        raise EnvelopeError("base64 field must be a string")
    if not re.match(r"^[A-Za-z0-9_-]*$", text):
        raise EnvelopeError("bad base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError("bad base64url") from exc


def _check_canonical(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise EnvelopeError("JSON nesting too deep")
    if value is None:
        raise EnvelopeError("null is not allowed in a signed header")
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, str):
        return
    if isinstance(value, float):
        raise EnvelopeError("floats are not allowed in signed data")
    if isinstance(value, list):
        for item in value:
            _check_canonical(item, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise EnvelopeError("object keys must be strings")
            _check_canonical(v, depth + 1)
        return
    raise EnvelopeError("unsupported type %s in signed data" % type(value).__name__)


def canon(value):
    """The canonical encoding signed by the agent: sorted keys, compact, UTF-8, no NaN, no floats."""
    _check_canonical(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def issued_at_iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))


def new_nonce(rand=None):
    raw = rand(16) if rand else os.urandom(16)
    if len(raw) != 16:
        raise EnvelopeError("nonce must be 16 bytes")
    return b64u(raw)


def _uuid_str(value, what):
    try:
        out = str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise EnvelopeError("%s must be a UUID" % what)
    return out


# --------------------------------------------------------------------------- #
# the envelope
# --------------------------------------------------------------------------- #

def build_header(*, kid, agent_id, tenant_id, kind, seq, issued_at, nonce, payload_type, payload,
                 collectors):
    """The signed header dict for ``payload`` (bytes). ``issued_at`` is an int epoch or the ISO string."""
    if kind not in KINDS:
        raise EnvelopeError("unknown kind %r" % (kind,))
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 or seq > MAX_SEQ:
        raise EnvelopeError("seq must be an integer in 1..%d" % MAX_SEQ)
    if not isinstance(payload, (bytes, bytearray)):
        raise EnvelopeError("payload must be bytes")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise EnvelopeError("payload larger than %d bytes" % MAX_PAYLOAD_BYTES)
    if isinstance(issued_at, str):
        if not _ISSUED_RE.match(issued_at):
            raise EnvelopeError("issued_at must be YYYY-MM-DDTHH:MM:SSZ")
        issued = issued_at
    else:
        issued = issued_at_iso(issued_at)
    if not isinstance(collectors, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in collectors.items()):
        raise EnvelopeError("collectors must map str to str")
    for key in collectors:
        if not _COLLECTOR_KEY_RE.fullmatch(key):
            raise EnvelopeError("collectors key %r must match [a-z0-9_.-]{1,64}" % (key[:40],))
    header = {
        "v": VERSION,
        "alg": ALG,
        "kid": str(kid),
        "agent_id": _uuid_str(agent_id, "agent_id"),
        "tenant_id": _uuid_str(tenant_id, "tenant_id"),
        "kind": kind,
        "seq": int(seq),
        "issued_at": issued,
        "nonce": nonce,
        "payload_type": str(payload_type),
        "payload_sha256": hashlib.sha256(bytes(payload)).hexdigest(),
        "payload_len": len(payload),
        "collectors": dict(collectors),
    }
    if len(canon(header)) > MAX_HEADER_BYTES:
        raise EnvelopeError("header larger than %d bytes" % MAX_HEADER_BYTES)
    return header


def signing_input(header):
    """``SIGNING_PREFIX + canon(header)``; ``header`` must not carry ``payload_b64`` or ``sig``."""
    if "payload_b64" in header or "sig" in header:
        raise EnvelopeError("the signed header excludes payload_b64 and sig")
    return SIGNING_PREFIX + canon(header)


def build_envelope(seed, *, agent_id, tenant_id, kind, seq, issued_at, payload, payload_type,
                   collectors, nonce=None):
    """Sign ``payload`` (the exact bytes) and return the envelope dict ready to be JSON-encoded."""
    pub = signing.public_key(seed)
    header = build_header(
        kid=signing.key_id(pub), agent_id=agent_id, tenant_id=tenant_id, kind=kind, seq=seq,
        issued_at=issued_at, nonce=nonce or new_nonce(), payload_type=payload_type,
        payload=payload, collectors=collectors)
    sig = signing.sign(seed, signing_input(header))
    env = dict(header)
    env["payload_b64"] = b64u(payload)
    env["sig"] = b64u(sig)
    return env


def split_envelope(env):
    """``(header, payload_bytes, signature)`` of an envelope dict; raises :class:`EnvelopeError`."""
    if not isinstance(env, dict):
        raise EnvelopeError("envelope must be an object")
    extra = set(env) - set(_HEADER_FIELDS) - {"payload_b64", "sig"}
    missing = (set(_HEADER_FIELDS) | {"payload_b64", "sig"}) - set(env)
    if extra or missing:
        raise EnvelopeError("envelope fields differ from the contract (extra=%s missing=%s)"
                            % (sorted(extra), sorted(missing)))
    header = dict((k, env[k]) for k in _HEADER_FIELDS)
    return header, b64u_decode(env["payload_b64"]), b64u_decode(env["sig"])


def verify_envelope(env, public_key):
    """Reference verifier (the agent never needs it; tests and server vectors do).

    True only if the payload length and sha256 match the header AND the signature verifies.
    """
    try:
        header, payload, sig = split_envelope(env)
        if header["payload_len"] != len(payload):
            return False
        if header["payload_sha256"] != hashlib.sha256(payload).hexdigest():
            return False
        if header["kid"] != signing.key_id(public_key):
            return False
        return signing.verify(public_key, signing_input(header), sig)
    except (EnvelopeError, KeyError, TypeError, ValueError):
        return False


def encode_body(env, *, gzip_threshold=GZIP_THRESHOLD):
    """``(body_bytes, content_encoding)``: JSON, gzipped when large. Refuses what the server would 413."""
    raw = json.dumps(env, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    if len(raw) > MAX_BODY_INFLATED_BYTES:
        raise EnvelopeError("envelope larger than %d bytes inflated" % MAX_BODY_INFLATED_BYTES)
    if len(raw) >= gzip_threshold:
        packed = gzip.compress(raw, 6, mtime=0)   # mtime=0 (3.8+) keeps the bytes deterministic
        if len(packed) > MAX_BODY_GZIP_BYTES:
            raise EnvelopeError("envelope larger than %d bytes gzipped" % MAX_BODY_GZIP_BYTES)
        return packed, "gzip"
    if len(raw) > MAX_BODY_GZIP_BYTES:
        raise EnvelopeError("envelope larger than %d bytes" % MAX_BODY_GZIP_BYTES)
    return raw, None


# --------------------------------------------------------------------------- #
# enrollment and rotation proofs
# --------------------------------------------------------------------------- #

def token_prefix(token):
    """The 12-hex prefix of ``fet_<prefix>_<secret>``. Raises :class:`EnvelopeError` for anything else."""
    m = _TOKEN_RE.match((token or "").strip())
    if not m:
        raise EnvelopeError("that is not an enrollment token (expected fet_<12 hex>_<secret>)")
    return m.group(1)


def enroll_proof_message(prefix, hostname):
    """``b"paddock-enroll/v1\\n" + token_prefix + "\\n" + hostname`` (UTF-8)."""
    return ENROLL_PROOF_DOMAIN + prefix.encode("ascii") + b"\n" + hostname.encode("utf-8")


def enroll_proof(seed, prefix, hostname):
    """Proof of possession of the new key: its signature over :func:`enroll_proof_message` (b64url)."""
    return b64u(signing.sign(seed, enroll_proof_message(prefix, hostname)))


def rotate_proof_message(agent_id, old_kid, new_kid):
    """What the NEW key signs to prove possession: ``paddock-rotate/v1\\n<agent_id>\\n<old_kid>\\n<new_kid>``."""
    return (ROTATE_PROOF_DOMAIN + _uuid_str(agent_id, "agent_id").encode("ascii") + b"\n"
            + str(old_kid).encode("ascii") + b"\n" + str(new_kid).encode("ascii"))


def rotate_payload(new_seed, agent_id, old_kid):
    """The canonical payload of a rotate envelope (the envelope itself is signed by the OLD key)."""
    new_pub = signing.public_key(new_seed)
    new_kid = signing.key_id(new_pub)
    proof = signing.sign(new_seed, rotate_proof_message(agent_id, old_kid, new_kid))
    return canon({
        "new_key_id": new_kid,
        "new_public_key_b64": b64u(new_pub),
        "proof_b64": b64u(proof),
    })
