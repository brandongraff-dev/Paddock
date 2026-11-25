"""Ed25519 signing with two interchangeable backends.

* ``cryptography`` (OpenSSL) when it can be imported,
* otherwise the vendored pure-Python RFC 8032 implementation (:mod:`paddock_agent.ed25519_pure`).

Both are deterministic and produce **byte-identical** keys and signatures (a test proves it over the
RFC vectors and randomised messages). ``PADDOCK_ED25519_BACKEND=pure|cryptography|auto`` forces a
choice (tests, or a host whose ``cryptography`` is broken). A forced backend that is unavailable is an
error, never a silent switch.

A private key here is the 32-byte RFC 8032 *seed*. The key id is ``hex(sha256(pub32))[:32]``.
"""
import hashlib
import os

from . import ed25519_pure

ENV_BACKEND = "PADDOCK_ED25519_BACKEND"


class SigningError(RuntimeError):
    pass


class _PureBackend(object):
    name = "pure"

    @staticmethod
    def public_key(seed):
        return ed25519_pure.public_key(seed)

    @staticmethod
    def sign(seed, message):
        return ed25519_pure.sign(seed, message)

    @staticmethod
    def verify(pub, message, signature):
        return ed25519_pure.verify(pub, message, signature)


class _CryptographyBackend(object):
    name = "cryptography"

    def __init__(self):
        # Raises (ImportError or anything a broken wheel throws) if unusable.
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        self._invalid = InvalidSignature
        self._ser = serialization
        self._ed = ed25519

    def public_key(self, seed):
        key = self._ed.Ed25519PrivateKey.from_private_bytes(_seed(seed))
        return key.public_key().public_bytes(self._ser.Encoding.Raw, self._ser.PublicFormat.Raw)

    def sign(self, seed, message):
        return self._ed.Ed25519PrivateKey.from_private_bytes(_seed(seed)).sign(bytes(message))

    def verify(self, pub, message, signature):
        try:
            if len(pub) != 32 or len(signature) != 64:
                return False
            self._ed.Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(
                bytes(signature), bytes(message))
            return True
        except (self._invalid, ValueError, TypeError):
            return False
        except Exception:  # noqa: BLE001 - fail closed
            return False


def _seed(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise SigningError("an Ed25519 seed is exactly 32 bytes")
    return bytes(seed)


_cache = {}


def get_backend(name=None):
    """Resolve a backend by name (``pure``, ``cryptography``, ``auto``); ``None`` reads the env var."""
    want = (name or os.environ.get(ENV_BACKEND) or "auto").strip().lower()
    if want not in ("auto", "pure", "cryptography"):
        raise SigningError("unknown Ed25519 backend %r" % want)
    if want in _cache:
        return _cache[want]
    if want == "pure":
        backend = _PureBackend()
    elif want == "cryptography":
        try:
            backend = _CryptographyBackend()
        except Exception as exc:  # noqa: BLE001
            raise SigningError("the cryptography backend is not usable: %s" % type(exc).__name__)
    else:
        try:
            backend = _CryptographyBackend()
        except Exception:  # noqa: BLE001 - not importable / broken wheel: use the vendored signer
            backend = _PureBackend()
    _cache[want] = backend
    return backend


def backend_name():
    return get_backend().name


def generate_seed():
    """32 fresh random bytes from the OS CSPRNG."""
    return os.urandom(32)


def public_key(seed):
    return get_backend().public_key(_seed(seed))


def sign(seed, message):
    return get_backend().sign(_seed(seed), message)


def verify(pub, message, signature):
    return get_backend().verify(pub, message, signature)


def key_id(pub):
    """``hex(sha256(pub32))[:32]``: the key id carried in envelopes."""
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise SigningError("a public key is exactly 32 bytes")
    return hashlib.sha256(bytes(pub)).hexdigest()[:32]
