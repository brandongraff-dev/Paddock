"""Pure-Python Ed25519 (RFC 8032, section 5.1), standard library only.

Used as the fallback signer when the ``cryptography`` package is not importable (owner decision O1:
the agent core is stdlib-only and must run on Python >= 3.8). It is validated against the RFC 8032
test vectors and, in the test-suite, byte-for-byte against ``cryptography`` (OpenSSL).

Honest limits (docs/ASSURANCE_P2.md section 11): this implementation is **not constant-time**
(Python big-int arithmetic and a double-and-add ladder leak timing). The signing key lives on a host
the agent already runs as root on, and the only party that can time it is a local process on that same
host, so the risk is accepted and documented, not hidden. Verification never handles secrets.

Public API (all operate on ``bytes``):

* ``public_key(seed32) -> bytes(32)``
* ``sign(seed32, message) -> bytes(64)``
* ``verify(public_key32, message, signature64) -> bool`` (never raises, strict on ``S < L``)
"""
import hashlib

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493  # group order L


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    """x for a given y and sign bit, or None when y is not on the curve."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, _BX * _BY % _P)   # extended homogeneous coordinates (X, Y, Z, T)
_IDENTITY = (0, 1, 1, 0)


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _P
    c = 2 * p1[3] * p2[3] * _D % _P
    d = 2 * p1[2] * p2[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, point):
    result = _IDENTITY
    addend = point
    while s > 0:
        if s & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        s >>= 1
    return result


def _equal(p1, p2):
    if (p1[0] * p2[2] - p2[0] * p1[2]) % _P != 0:
        return False
    return (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0


def _compress(point):
    zinv = _inv(point[2])
    x = point[0] * zinv % _P
    y = point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512(data):
    return hashlib.sha512(data).digest()


def _expand(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("an Ed25519 seed is exactly 32 bytes")
    h = _sha512(bytes(seed))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    """The 32-byte public key for a 32-byte seed."""
    a, _prefix = _expand(seed)
    return _compress(_mul(a, _B))


def sign(seed, message):
    """The 64-byte deterministic signature of ``message`` under ``seed``."""
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _B))
    message = bytes(message)
    r = int.from_bytes(_sha512(prefix + message), "little") % _Q
    r_enc = _compress(_mul(r, _B))
    k = int.from_bytes(_sha512(r_enc + pub + message), "little") % _Q
    s = (r + k * a) % _Q
    return r_enc + int.to_bytes(s, 32, "little")


def verify(pub, message, signature):
    """True only for a valid signature. Never raises; rejects ``S >= L`` and undecodable points."""
    try:
        if len(pub) != 32 or len(signature) != 64:
            return False
        a_point = _decompress(bytes(pub))
        if a_point is None:
            return False
        r_enc = bytes(signature[:32])
        r_point = _decompress(r_enc)
        if r_point is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= _Q:
            return False
        k = int.from_bytes(_sha512(r_enc + bytes(pub) + bytes(message)), "little") % _Q
        return _equal(_mul(s, _B), _add(r_point, _mul(k, a_point)))
    except Exception:  # noqa: BLE001 - verification fails closed on anything unexpected
        return False
