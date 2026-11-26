# SPDX-License-Identifier: Apache-2.0
"""DSSE envelope parsing and the pre-authentication encoding (spec/01-conventions.md 2.4, spec/02 section 1.1)."""
from __future__ import annotations

import json
import re
from typing import Any, NamedTuple, Optional, Union

from . import b64, jsonstrict, limits
from .jsonstrict import JsonError

PAYLOAD_TYPE_STATEMENT = "application/vnd.in-toto+json"
PAYLOAD_TYPE_KEY_CERT = "application/vnd.paddock.key-cert+json"
PAYLOAD_TYPE_REVOCATION = "application/vnd.paddock.revocation-list+json"
PAYLOAD_TYPES = (PAYLOAD_TYPE_STATEMENT, PAYLOAD_TYPE_KEY_CERT, PAYLOAD_TYPE_REVOCATION)

_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


class DsseError(JsonError):
    """The envelope is not acceptable; ``code`` is a reason code from codes.py."""


class Envelope(NamedTuple):
    payload_type: str
    payload: bytes           # decoded payload bytes (what is signed and hashed)
    payload_b64: str
    keyid: str
    sig: bytes               # exactly 64 bytes


def pae(payload_type: Union[str, bytes], payload: bytes) -> bytes:
    """``DSSEv1 <len(type)> <type> <len(payload)> <payload>``, lengths in ASCII decimal bytes."""
    if isinstance(payload_type, str):
        try:
            t = payload_type.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("the payload type is ASCII") from None
    elif isinstance(payload_type, (bytes, bytearray)):
        t = bytes(payload_type)
    else:
        raise TypeError("payload_type must be str or bytes")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    return b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" " + str(len(payload)).encode("ascii") + b" " + bytes(payload)


def parse_envelope(data: Any, expected_type: Optional[str] = None) -> Envelope:
    """Parse an envelope strictly. The envelope is plain JSON (it need not be canonical); everything signed is
    reached only through the decoded payload bytes."""
    if isinstance(data, (bytes, bytearray)) and len(data) > limits.MAX_ENVELOPE_BYTES:
        raise DsseError("input.too_large", "envelope over %d bytes" % limits.MAX_ENVELOPE_BYTES)
    try:
        doc = jsonstrict.parse(data, max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_ENVELOPE_BYTES)
    except JsonError as e:
        raise DsseError(e.code, e.detail, e.pos) from None
    if not isinstance(doc, dict) or set(doc) != {"payloadType", "payload", "signatures"}:
        raise DsseError("schema.envelope_invalid", "exactly payloadType, payload and signatures")
    ptype, payload_b64, sigs = doc["payloadType"], doc["payload"], doc["signatures"]
    if not isinstance(ptype, str) or not isinstance(payload_b64, str) or not isinstance(sigs, list):
        raise DsseError("schema.envelope_invalid", "wrong types")
    if expected_type is not None and ptype != expected_type:
        raise DsseError("schema.payload_type", "unexpected payload type")
    if len(sigs) != 1:
        raise DsseError("sig.count_invalid", "version 1 requires exactly one signature")
    entry = sigs[0]
    if not isinstance(entry, dict) or set(entry) != {"keyid", "sig"} or not isinstance(entry["keyid"], str) \
            or not isinstance(entry["sig"], str):
        raise DsseError("schema.envelope_invalid", "a signature has exactly keyid and sig")
    try:
        payload = b64.strict_decode(payload_b64)
        sig = b64.strict_decode(entry["sig"])
    except b64.B64Error:
        raise DsseError(b64.CODE, "payload or signature") from None
    if len(sig) != 64:
        raise DsseError("sig.malformed", "a signature is 64 bytes")
    if not _KID.match(entry["keyid"]):
        raise DsseError("schema.digest_format", "keyid is 32 lowercase hex")
    if len(payload) > limits.MAX_PAYLOAD_BYTES:
        raise DsseError("schema.limit_exceeded", "payload over %d bytes" % limits.MAX_PAYLOAD_BYTES)
    return Envelope(ptype, payload, payload_b64, entry["keyid"], sig)


def build_envelope(payload_type: str, payload: bytes, keyid: str, sig: bytes) -> bytes:
    """Compact envelope bytes with sorted keys (deterministic). Producers sign ``pae(payload_type, payload)``."""
    doc = {"payload": b64.encode(payload), "payloadType": payload_type,
           "signatures": [{"keyid": keyid, "sig": b64.encode(sig)}]}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")
