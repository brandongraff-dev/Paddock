# SPDX-License-Identifier: Apache-2.0
"""Ed25519 verification with the specification's own pre-checks (spec/01-conventions.md 2.5).

Libraries disagree about hostile inputs (the identity public key with an identity signature is accepted by
OpenSSL for any message; WebCrypto engines differ on ``S >= L``). The checks below run first, in pure Python,
so every implementation reaches the same answer:

1. the signature is 64 bytes                                   -> ``sig.malformed``
2. the public key is 32 bytes, a canonical point encoding,
   and not one of the eight small-order points                 -> ``sig.weak_key``
3. ``S < L`` (little-endian bytes 32..63)                      -> ``sig.noncanonical_s``
4. the library verifies                                        -> ``sig.invalid`` otherwise

``R`` is not pre-checked: the residual cofactor ambiguity needs a malicious signer, and a signer here is a
certified key.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_Point = Tuple[int, int, int, int]
_IDENT = (0, 1, 1, 0)  # type: _Point


def _decompress(enc: bytes) -> Optional[Tuple[int, int]]:
    """Affine (x, y) for a canonical encoding on the curve, else ``None``."""
    n = int.from_bytes(enc, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= _P:
        return None                                   # non-canonical y
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None                                   # not on the curve
    if x == 0 and sign == 1:
        return None                                   # "negative zero"
    if (x & 1) != sign:
        x = _P - x
    return (x, y)


def _add(a: _Point, b: _Point) -> _Point:
    aa = (a[1] - a[0]) * (b[1] - b[0]) % _P
    bb = (a[1] + a[0]) * (b[1] + b[0]) % _P
    cc = 2 * a[3] * b[3] * _D % _P
    dd = 2 * a[2] * b[2] % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _times8(xy: Tuple[int, int]) -> _Point:
    p = (xy[0], xy[1], 1, xy[0] * xy[1] % _P)  # type: _Point
    for _ in range(3):
        p = _add(p, p)
    return p


def _is_identity(p: _Point) -> bool:
    return p[0] % _P == 0 and (p[1] - p[2]) % _P == 0


def _encode(p: _Point) -> bytes:
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _mul(k: int, p: _Point) -> _Point:
    r = _IDENT
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


_SMALL_ORDER = None  # type: Optional[List[bytes]]


def small_order_encodings() -> List[bytes]:
    """The eight canonical encodings of the points whose order divides 8 (computed once, not hard-coded)."""
    global _SMALL_ORDER
    if _SMALL_ORDER is None:
        found = set()
        y = 2
        while len(found) < 8 and y < 1000:
            xy = _decompress(y.to_bytes(32, "little"))
            if xy is not None:
                found.add(_encode(_mul(_L, (xy[0], xy[1], 1, xy[0] * xy[1] % _P))))
            y += 1
        if len(found) != 8:
            raise RuntimeError("small-order enumeration failed")
        _SMALL_ORDER = sorted(found)
    return list(_SMALL_ORDER)


def precheck_public_key(pub: bytes) -> Optional[str]:
    """``sig.weak_key`` for a key that is not 32 bytes, not a canonical on-curve encoding, or of small order."""
    if len(pub) != 32:
        return "sig.weak_key"
    xy = _decompress(bytes(pub))
    if xy is None:
        return "sig.weak_key"
    if _is_identity(_times8(xy)):
        return "sig.weak_key"
    return None


def precheck_signature(sig: bytes) -> Optional[str]:
    if len(sig) != 64:
        return "sig.malformed"
    return None


def verify_code(pub: bytes, message: bytes, sig: bytes) -> Optional[str]:
    """``None`` when the signature is valid, else the reason code (see the module doc for the order)."""
    for name, v in (("pub", pub), ("message", message), ("sig", sig)):
        if not isinstance(v, (bytes, bytearray)):
            raise TypeError("%s must be bytes" % name)
    pub, message, sig = bytes(pub), bytes(message), bytes(sig)
    code = precheck_signature(sig)
    if code:
        return code
    code = precheck_public_key(pub)
    if code:
        return code
    if int.from_bytes(sig[32:], "little") >= _L:
        return "sig.noncanonical_s"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
    except InvalidSignature:
        return "sig.invalid"
    except Exception:                                 # an unexpected library failure is never a pass
        return "sig.invalid"
    return None


def verify(pub: bytes, message: bytes, sig: bytes) -> bool:
    return verify_code(pub, message, sig) is None


def fingerprint(pub: bytes) -> str:
    """``sha256:<hex>`` of the raw 32-byte public key (the ``fp`` of a DNS record)."""
    if len(pub) != 32:
        raise ValueError("a raw Ed25519 public key is 32 bytes")
    return "sha256:" + hashlib.sha256(bytes(pub)).hexdigest()


def kid_of(pub: bytes) -> str:
    """The key id: the first 32 hex characters of the fingerprint."""
    return fingerprint(pub)[7:39]
