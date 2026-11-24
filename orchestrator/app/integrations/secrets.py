"""Encryption at rest for integration credentials (AES-256-GCM).

Key: ``PADDOCK_SECRET_KEY`` (32 bytes, urlsafe-base64). In enforce mode the
orchestrator must refuse to store secrets without it; in dev a per-process
key is generated (secrets then don't survive a restart -- loudly logged).

Ciphertext format: ``v1:<key_id>:<b64(nonce|ciphertext|tag)>`` so keys can be
rotated: decrypt with any configured key, encrypt with the primary.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from typing import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

_DEV_KEY: bytes | None = None


def _decode_key(raw: str) -> bytes:
    key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(key) != 32:
        raise ValueError("PADDOCK_SECRET_KEY must decode to exactly 32 bytes")
    return key


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def _keys() -> list[bytes]:
    """Primary first, then old keys for rotation (PADDOCK_SECRET_KEY_OLD, comma-separated)."""
    global _DEV_KEY
    primary = os.environ.get("PADDOCK_SECRET_KEY")
    keys: list[bytes] = []
    if primary:
        keys.append(_decode_key(primary))
    else:
        if _DEV_KEY is None:
            _DEV_KEY = AESGCM.generate_key(bit_length=256)
            log.warning("PADDOCK_SECRET_KEY unset: using an ephemeral key; stored "
                        "integration secrets will NOT survive a restart")
        keys.append(_DEV_KEY)
    for old in filter(None, (os.environ.get("PADDOCK_SECRET_KEY_OLD") or "").split(",")):
        keys.append(_decode_key(old.strip()))
    return keys


def has_persistent_key() -> bool:
    return bool(os.environ.get("PADDOCK_SECRET_KEY"))


#: Default additional-authenticated-data. Other features pass their own so a blob
#: encrypted for one purpose cannot be decrypted (or swapped in) as another.
INTEGRATION_AAD = b"paddock-integration"


def encrypt_secrets(values: Mapping[str, str], aad: bytes = INTEGRATION_AAD) -> str:
    key = _keys()[0]
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(dict(values)).encode(), aad)
    return f"v1:{_key_id(key)}:{base64.urlsafe_b64encode(nonce + ct).decode()}"


def decrypt_secrets(blob: str | None, aad: bytes = INTEGRATION_AAD) -> dict[str, str]:
    if not blob:
        return {}
    version, kid, payload = blob.split(":", 2)
    if version != "v1":
        raise ValueError("unsupported secret format")
    raw = base64.urlsafe_b64decode(payload)
    nonce, ct = raw[:12], raw[12:]
    for key in _keys():
        if _key_id(key) == kid:
            return json.loads(AESGCM(key).decrypt(nonce, ct, aad))
    raise ValueError("no configured key can decrypt this secret (rotated away?)")


def redact(values: Mapping[str, str]) -> dict[str, str]:
    """What the API returns for secret fields: presence only, never the value."""
    return {k: ("********" if v else "") for k, v in values.items()}
