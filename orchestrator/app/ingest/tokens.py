"""Per-source ingest tokens.

Format: ``pdi_<tenant:32 hex>_<source:32 hex>_<secret>``. The tenant and source
ids are *not* secret and are *not trusted*: they only tell the handler which
tenant's RLS scope to open the lookup in. The request is authenticated solely
by comparing ``sha256(secret)`` with the stored hash (constant time), so a
forged tenant/source id can never match. The token is shown once at creation;
only the hash is stored. The token grants exactly one thing: ``POST
/v1/ingest`` for its own source -- it is not an API key and carries no
capability anywhere else.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from typing import Optional

TOKEN_PREFIX = "pdi_"
_SECRET_BYTES = 32


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_secret() -> tuple[str, str, str]:
    """(secret, display_prefix, sha256_hex)."""
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    return secret, secret[:6], hash_secret(secret)


def build_token(tenant_id: str, source_id: str, secret: str) -> str:
    return f"{TOKEN_PREFIX}{uuid.UUID(str(tenant_id)).hex}_{uuid.UUID(str(source_id)).hex}_{secret}"


def parse_token(token: Optional[str]) -> Optional[tuple[str, str, str]]:
    """(tenant_id, source_id, secret) or None for anything malformed."""
    if not token or not token.startswith(TOKEN_PREFIX) or len(token) > 256:
        return None
    parts = token[len(TOKEN_PREFIX):].split("_", 2)
    if len(parts) != 3:
        return None
    t, s, secret = parts
    try:
        tid, sid = str(uuid.UUID(hex=t)), str(uuid.UUID(hex=s))
    except ValueError:
        return None
    if len(t) != 32 or len(s) != 32 or len(secret) < 16 or not secret.replace("-", "").replace("_", "").isalnum():
        return None
    return tid, sid, secret


def verify(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret).encode("ascii"), (stored_hash or "").encode("ascii", "ignore"))
