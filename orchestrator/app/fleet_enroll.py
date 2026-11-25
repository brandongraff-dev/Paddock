"""Fleet agent enrollment: per-tenant one-time tokens, proof of possession, key binding (schema 041).

Ported from ``sensors.py`` (docs/ASSURANCE_P2.md section 2, E4). The trust chain, in the order an agent lives it:

1. An admin mints an **enrollment token** (``fet_<12 hex prefix>_<secret>``) for the tenant. Only its sha256 is
   stored; the token is shown once. It is single use by default; ``max_uses`` up to 50 (with a ttl of at most 24 h)
   serves a cloud-init fleet. ``for_agent`` makes it a **re-key** token: it rebinds an existing agent row (its
   history stays) to a new key, which is how a v1 ("legacy") agent, or one that lost its state dir, comes back.
2. ``paddock-agent enroll`` generates an Ed25519 key and sends ``{token, hostname, public_key_b64, proof_b64}``.
   ``proof_b64`` is the key's signature over ``b"paddock-enroll/v1\\n" + token_prefix + "\\n" + hostname``: the
   agent really holds the private key, and the proof is bound to this token and this hostname.
3. :func:`enroll_agent` redeems the token with ONE atomic ``UPDATE ... WHERE revoked_at IS NULL AND
   expires_at > now() AND uses < max_uses RETURNING`` in the same transaction as the agent/key insert: of N
   concurrent redemptions of a single-use token exactly one wins. Every token failure (unknown, malformed, wrong
   secret, expired, revoked, used up, suspended tenant) is the SAME generic 401, so the endpoint is not an oracle.
   A per-client rate limit and a failure lockout (like the sensors') bound guessing.
4. The result carries the agent credential ``fat_<prefix>_<secret>`` (shown once, stored as sha256) and the
   ``key_id``. Authentication of later calls (the agent principal) is ``auth.py``'s job and uses
   :func:`split_agent_token` / :func:`hash_matches` from here.

"Signed is not true": enrolling proves possession of a key, nothing about the host. Evidence from the agent is
tier ``configured`` at best (E2); this module never lifts a tier.

This module is pure logic + SQL; the HTTP surface is ``routers/fleet.py``. It does not write audit rows for
mint/list/revoke (the router does, like ``routers/sensors.py``); enrollment writes its own ``fleet.agent.enroll``
row inside the redeeming transaction, in the token's tenant.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import audit, tenancy
from . import auth as auth_svc
from .netkey import SlidingWindowLimiter, client_key

logger = logging.getLogger(__name__)

TOKEN_SCHEME = "fet"          # fleet enrollment token
AGENT_SCHEME = "fat"          # fleet agent credential (X-Agent-Token)
PREFIX_HEX = 12               # hex chars of a NEW token / credential prefix (48 bits)
ENROLL_PROOF_DOMAIN = b"paddock-enroll/v1\n"

_ENROLL_TOKEN_RE = re.compile(r"^fet_([0-9a-f]{12})_([A-Za-z0-9_-]{20,128})$")
# v1 credentials have an 8 hex prefix; they must still RESOLVE (to a legacy 403), never to "unknown".
_AGENT_TOKEN_RE = re.compile(r"^fat_([0-9a-f]{8}|[0-9a-f]{12})_([A-Za-z0-9_-]{20,128})$")

MAX_USES_LIMIT = 50
MIN_TTL_MINUTES = 1
DEFAULT_TTL_MINUTES = 60
MAX_TTL_MINUTES_SINGLE = 7 * 24 * 60     # single use: a week, like the sensors'
MAX_TTL_MINUTES_MULTI = 24 * 60          # max_uses > 1: a leaked fleet token must die within a day
MAX_LABELS = 20

GENERIC_ENROLL_DETAIL = "invalid, expired or already-used enrollment token"

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:/=-]{1,64}$")
_CAP_RE = re.compile(r"^[a-z_]{1,32}$")
_PLATFORMS = frozenset({"linux", "windows", "macos"})
_NODE_REF_PREFIX = "agent:"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# rate limiting (in-process, like the sensors'; see docs/SENTRY.md for the multi-replica note)
# --------------------------------------------------------------------------- #

# enroll attempts per client address, and *failed* redemptions (lockout).
enroll_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_ENROLL_PER_MIN", 20), window_s=60)
enroll_fail_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_ENROLL_FAILS", 5), window_s=600)


def reset_limiters() -> None:
    enroll_limiter.reset()
    enroll_fail_limiter.reset()


def _limit_key(ip: str | None) -> str:
    """Canonical limiter key. Idempotent on an already-canonical ``x::/64`` key."""
    text = (ip or "").strip()
    if ":" in text and text.endswith("/64"):
        text = text[:-3]
    return client_key(text or None)


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #

class EnrollError(Exception):
    """Redemption failed. ``status`` is the HTTP status the router should return."""

    def __init__(self, status: int, detail: str, *, retry_after: int | None = None,
                 counts_failure: bool = True) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail
        self.retry_after = retry_after
        #: whether this failure feeds the per-client lockout (409s from legitimate token holders do not).
        self.counts_failure = counts_failure


class TokenPolicyError(ValueError):
    """A mint request that violates the token policy. ``code``: ``invalid`` (422) | ``not_found`` (404)."""

    def __init__(self, detail: str, code: str = "invalid") -> None:
        super().__init__(detail)
        self.detail, self.code = detail, code


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #

def _mint(scheme: str) -> tuple[str, str, str]:
    prefix = secrets.token_hex(PREFIX_HEX // 2)
    full = f"{scheme}_{prefix}_{secrets.token_urlsafe(32)}"
    return full, prefix, auth_svc.hash_api_key(full)


def new_enroll_token() -> tuple[str, str, str]:
    """(full, prefix, sha256). The full token is shown once."""
    return _mint(TOKEN_SCHEME)


def new_agent_credential() -> tuple[str, str, str]:
    """(full, prefix, sha256) of a new ``fat_`` agent credential."""
    return _mint(AGENT_SCHEME)


def split_enroll_token(value: str | None) -> str | None:
    """The lookup prefix of a well-formed ``fet_<12 hex>_<secret>``, else None."""
    m = _ENROLL_TOKEN_RE.match((value or "").strip())
    return m.group(1) if m else None


def split_agent_token(value: str | None) -> str | None:
    """The lookup prefix of a well-formed ``fat_<8|12 hex>_<secret>``, else None.

    8-hex prefixes are v1 credentials: they resolve so the caller can answer ``403 re_enroll_required``.
    """
    m = _AGENT_TOKEN_RE.match((value or "").strip())
    return m.group(1) if m else None


def hash_matches(stored: str | None, presented: str) -> bool:
    """Constant-time compare of a stored sha256 against the hash of the presented secret."""
    if not stored:
        return False
    return hmac.compare_digest(stored.encode(), auth_svc.hash_api_key((presented or "").strip()).encode())


# --------------------------------------------------------------------------- #
# Ed25519: key parsing, key id, enrollment proof
# --------------------------------------------------------------------------- #

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decompress(raw: bytes) -> tuple[int, int] | None:
    """The affine point encoded by 32 bytes, or None if it is non-canonical or not on the curve."""
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = (u * pow(v, _P - 2, _P)) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = (x * _SQRT_M1) % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x, y


def _double(pt: tuple[int, int]) -> tuple[int, int]:
    x, y = pt
    t = (_D * x * x % _P) * (y * y % _P) % _P
    x3 = (2 * x * y) % _P * pow(1 + t, _P - 2, _P) % _P
    y3 = (y * y + x * x) % _P * pow((1 - t) % _P, _P - 2, _P) % _P
    return x3, y3


def _is_small_order(pt: tuple[int, int]) -> bool:
    for _ in range(3):          # 8 * P
        pt = _double(pt)
    return pt == (0, 1)


class KeyFormatError(ValueError):
    """A public key / proof that is not acceptable (malformed, wrong length, small order, ...)."""


def b64_decode_strict(text: str, *, max_chars: int = 512) -> bytes:
    """Base64 or base64url, padded or not; anything else raises :class:`KeyFormatError`."""
    t = (text or "").strip()
    if not t or len(t) > max_chars:
        raise KeyFormatError("bad base64 length")
    t = t.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyFormatError("bad base64") from exc


def parse_public_key(raw: bytes) -> bytes:
    """Validate 32 raw bytes as an Ed25519 public key and return them.

    Rejects: wrong length, a non-canonical or off-curve encoding, and any small-order point (a small-order key
    makes the signature check accept forgeries for many messages under non-strict verifiers).
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise KeyFormatError("an Ed25519 public key is 32 bytes")
    pt = _decompress(bytes(raw))
    if pt is None:
        raise KeyFormatError("not a valid Ed25519 point")
    if _is_small_order(pt):
        raise KeyFormatError("small-order Ed25519 public key")
    return bytes(raw)


def parse_public_key_b64(text: str) -> bytes:
    return parse_public_key(b64_decode_strict(text, max_chars=128))


def key_id_for(public_key: bytes) -> str:
    """``hex(sha256(pub32))[:32]``: the key id carried in envelopes (docs/ASSURANCE_P2.md section 2)."""
    return hashlib.sha256(public_key).hexdigest()[:32]


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid signature by a valid key. Never raises."""
    try:
        if len(signature) != 64:
            return False
        parse_public_key(public_key)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, KeyFormatError, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001 -- fail closed on anything unexpected
        logger.exception("ed25519_verify_unexpected")
        return False


def enroll_proof_message(token_prefix: str, hostname: str) -> bytes:
    """``b"paddock-enroll/v1\\n" + token_prefix + "\\n" + hostname`` (UTF-8)."""
    return ENROLL_PROOF_DOMAIN + token_prefix.encode("ascii") + b"\n" + hostname.encode("utf-8")


def verify_enroll_proof(public_key: bytes, token_prefix: str, hostname: str, proof_b64: str) -> bool:
    """Is ``proof_b64`` the key's signature over :func:`enroll_proof_message`? Never raises."""
    try:
        sig = b64_decode_strict(proof_b64, max_chars=256)
        msg = enroll_proof_message(token_prefix, hostname)
    except (KeyFormatError, UnicodeError):
        return False
    return verify_ed25519(public_key, msg, sig)


# --------------------------------------------------------------------------- #
# token views
# --------------------------------------------------------------------------- #

_TOKEN_COLS = ("id, token_prefix, label, labels, max_uses, uses, for_agent, created_by, created_at, "
               "expires_at, revoked_at, revoked_by")   # NEVER token_hash


def token_state(row: Any, now: datetime | None = None) -> str:
    """``revoked`` | ``used`` (all uses spent) | ``expired`` | ``active`` (some uses left) | ``pending``."""
    now = now or datetime.now(timezone.utc)
    if row["revoked_at"] is not None:
        return "revoked"
    if row["uses"] >= row["max_uses"]:
        return "used"
    if row["expires_at"] <= now:
        return "expired"
    return "active" if row["uses"] > 0 else "pending"


def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value


def token_view(row: Any, now: datetime | None = None) -> dict[str, Any]:
    out = {k: row[k] for k in row.keys() if k != "token_hash"}
    out["labels"] = _loads(out.get("labels"), [])
    out["state"] = token_state(row, now)
    return out


def _clean_labels(labels: Any) -> list[str]:
    if labels is None:
        return []
    if not isinstance(labels, (list, tuple)):
        raise TokenPolicyError("labels must be a list of strings")
    out = []
    for item in labels:
        if not isinstance(item, str) or not _LABEL_RE.match(item.strip()):
            raise TokenPolicyError("a label must be 1-64 chars of [A-Za-z0-9_.:/=-]")
        out.append(item.strip())
    out = sorted(set(out))
    if len(out) > MAX_LABELS:
        raise TokenPolicyError(f"at most {MAX_LABELS} labels")
    return out


# --------------------------------------------------------------------------- #
# mint / list / revoke
# --------------------------------------------------------------------------- #

async def mint_token(pool: Any, *, actor: str, label: str | None = None, labels: Any = None,
                     max_uses: int = 1, ttl_minutes: int = DEFAULT_TTL_MINUTES,
                     for_agent: uuid.UUID | str | None = None) -> tuple[str, dict[str, Any]]:
    """Create an enrollment token in the current tenant. Returns ``(full_token, view)``; the full token exists
    only in this return value (shown once). Raises :class:`TokenPolicyError`.

    Policy: ``1 <= max_uses <= 50``; ``1 <= ttl_minutes <= 7 d`` for a single-use token and ``<= 24 h`` when
    ``max_uses > 1``; a ``for_agent`` (re-key) token is single use and must name an agent of this tenant.
    """
    if isinstance(max_uses, bool) or not isinstance(max_uses, int) or not 1 <= max_uses <= MAX_USES_LIMIT:
        raise TokenPolicyError(f"max_uses must be between 1 and {MAX_USES_LIMIT}")
    if isinstance(ttl_minutes, bool) or not isinstance(ttl_minutes, int) or ttl_minutes < MIN_TTL_MINUTES:
        raise TokenPolicyError("ttl_minutes must be a positive integer")
    cap = MAX_TTL_MINUTES_MULTI if max_uses > 1 else MAX_TTL_MINUTES_SINGLE
    if ttl_minutes > cap:
        raise TokenPolicyError(
            f"ttl_minutes must be at most {cap} for a token with max_uses={max_uses}")
    text = (label or "").strip()
    if len(text) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise TokenPolicyError("label must be at most 128 printable characters")
    clean = _clean_labels(labels)
    agent_uuid: uuid.UUID | None = None
    if for_agent is not None:
        try:
            agent_uuid = for_agent if isinstance(for_agent, uuid.UUID) else uuid.UUID(str(for_agent))
        except ValueError as exc:
            raise TokenPolicyError("for_agent must be an agent id") from exc
        if max_uses != 1:
            raise TokenPolicyError("a re-key token (for_agent) is single use")

    async with pool.acquire() as con:
        if agent_uuid is not None:
            if await con.fetchval("SELECT 1 FROM fleet_agents WHERE id = $1", agent_uuid) is None:
                raise TokenPolicyError("no such agent", "not_found")
        for _ in range(5):                       # the prefix is globally unique: retry a (rare) collision
            full, prefix, token_hash = new_enroll_token()
            try:
                row = await con.fetchrow(
                    f"""INSERT INTO fleet_enroll_tokens
                            (token_prefix, token_hash, label, labels, max_uses, for_agent, created_by, expires_at)
                        VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7, NOW() + make_interval(mins => $8))
                        RETURNING {_TOKEN_COLS}""",
                    prefix, token_hash, text, json.dumps(clean), max_uses, agent_uuid, actor, ttl_minutes)
            except asyncpg.UniqueViolationError:
                continue
            return full, token_view(row)
    raise RuntimeError("could not allocate a unique enrollment token prefix")  # pragma: no cover


async def list_tokens(pool: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    """Newest first. Prefix and metadata only: the hash and the secret are never returned."""
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_TOKEN_COLS} FROM fleet_enroll_tokens ORDER BY created_at DESC, id LIMIT $1",
            max(1, min(int(limit), 500)))
    now = datetime.now(timezone.utc)
    return [token_view(r, now) for r in rows]


async def get_token(pool: Any, token_id: uuid.UUID) -> dict[str, Any] | None:
    async with pool.acquire() as con:
        row = await con.fetchrow(f"SELECT {_TOKEN_COLS} FROM fleet_enroll_tokens WHERE id = $1", token_id)
    return token_view(row) if row else None


async def revoke_token(pool: Any, token_id: uuid.UUID, actor: str) -> bool:
    """Revoke a token that still has uses left (including a partly used fleet token). False when it does not
    exist (in this tenant), is already revoked or is fully used."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """UPDATE fleet_enroll_tokens SET revoked_at = NOW(), revoked_by = $2
                WHERE id = $1 AND revoked_at IS NULL AND uses < max_uses RETURNING id""",
            token_id, actor)
    return row is not None


# --------------------------------------------------------------------------- #
# enrollment
# --------------------------------------------------------------------------- #

def _bad() -> EnrollError:
    return EnrollError(401, GENERIC_ENROLL_DETAIL)


def _clean_caps(capabilities: Any) -> list[str]:
    if capabilities is None:
        return ["inventory"]
    if not isinstance(capabilities, (list, tuple)):
        raise EnrollError(400, "capabilities must be a list of strings")
    caps = sorted({c for c in capabilities if c})
    if len(caps) > 16 or any(not isinstance(c, str) or not _CAP_RE.match(c) for c in caps):
        raise EnrollError(400, "invalid capabilities")
    return caps or ["inventory"]


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def enroll_agent(pool: Any, *, token: str, hostname: str, public_key_b64: str, proof_b64: str,
                       agent_version: str | None = None, platform: str = "linux",
                       capabilities: list[str] | None = None,
                       client_ip: str | None = None) -> dict[str, Any]:
    """Redeem an enrollment token: create (or, for a re-key token, rebind) the agent, bind its key, mint its
    credential. Rate limited per client address (``client_ip`` = the trusted-proxy-aware peer address).

    Returns ``{agent_id, agent_token, token_prefix, key_id, tenant_id, hostname, rekey, server_time}``.
    ``agent_token`` is shown ONCE. Raises :class:`EnrollError` (``.status``, ``.detail``, ``.retry_after``):

    * 429 rate limit / lockout; 401 the generic token failure; 400 malformed key / proof / hostname / fields;
    * 409 ``hostname already enrolled`` or ``public key already registered``. A 409 rolls the whole
      transaction back, so it does NOT spend a use of the token.
    """
    key = _limit_key(client_ip)
    if enroll_fail_limiter.blocked(key) or not enroll_limiter.hit(key):
        raise EnrollError(429, "too many enrollment attempts; wait and retry", retry_after=60,
                          counts_failure=False)
    try:
        return await _enroll(pool, token=token, hostname=hostname, public_key_b64=public_key_b64,
                             proof_b64=proof_b64, agent_version=agent_version, platform=platform,
                             capabilities=capabilities, client_ip=client_ip)
    except EnrollError as exc:
        if exc.counts_failure:
            enroll_fail_limiter.hit(key)
        raise


# A hash to compare against when the prefix is unknown, so unknown and wrong-secret take the same path.
_DUMMY_HASH = auth_svc.hash_api_key("fleet-enroll-dummy")


async def _enroll(pool: Any, *, token: str, hostname: str, public_key_b64: str, proof_b64: str,
                  agent_version: str | None, platform: str, capabilities: Any,
                  client_ip: str | None) -> dict[str, Any]:
    prefix = split_enroll_token(token)
    if prefix is None:
        raise _bad()
    # Everything below up to the token lookup depends only on the caller's own input, never on token state,
    # so a failure here is not an oracle for which tokens exist.
    if not isinstance(hostname, str) or not _HOSTNAME_RE.match(hostname):
        raise EnrollError(400, "invalid hostname")
    host = hostname.lower()
    try:
        pub = parse_public_key_b64(public_key_b64)
    except KeyFormatError as exc:
        raise EnrollError(400, f"invalid public key: {exc}") from exc
    if not verify_enroll_proof(pub, prefix, hostname, proof_b64):
        raise EnrollError(400, "invalid proof of possession")
    plat = (platform or "linux").lower().strip()
    if plat not in _PLATFORMS:
        raise EnrollError(400, "platform must be linux|windows|macos")
    version = (agent_version or "").strip()[:64] or None
    if version is not None and any(ord(c) < 32 or ord(c) == 127 for c in version):
        raise EnrollError(400, "invalid agent_version")
    caps = _clean_caps(capabilities)
    key_id = key_id_for(pub)

    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            trow = await con.fetchrow(
                "SELECT id, tenant_id, token_hash FROM fleet_enroll_tokens WHERE token_prefix = $1", prefix)
    if trow is None:
        hash_matches(_DUMMY_HASH, token)
        raise _bad()
    if not hash_matches(trow["token_hash"], token):
        raise _bad()
    tenant_id = str(trow["tenant_id"])

    now = datetime.now(timezone.utc)
    with tenancy.tenant_context(tenant_id):
        async with pool.acquire() as con:
            async with con.transaction():
                tstatus = await con.fetchval("SELECT status FROM tenants WHERE id = $1", trow["tenant_id"])
                if tstatus != "active":
                    raise _bad()
                # THE single-use guarantee: one atomic UPDATE. Of N concurrent redemptions Postgres
                # serialises on the row and re-checks the predicate, so at most max_uses get a row back.
                claimed = await con.fetchrow(
                    """UPDATE fleet_enroll_tokens SET uses = uses + 1
                        WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW() AND uses < max_uses
                    RETURNING id, labels, for_agent, created_by""",
                    trow["id"])
                if claimed is None:
                    raise _bad()
                labels = [str(x) for x in _loads(claimed["labels"], []) if isinstance(x, str)]
                identity = json.dumps({"hostname": host, "basis": "claimed"})
                actor = claimed["created_by"] or "unknown"
                if claimed["for_agent"] is not None:
                    agent_id, retired = await _rekey(
                        con, claimed["for_agent"], host=host, platform=plat, version=version, labels=labels,
                        caps=caps, actor=actor, identity=identity, token_prefix=prefix)
                    cred = retired["cred"]
                    revoked_keys = retired["revoked_keys"]
                else:
                    agent_id, cred = await _insert_agent(
                        con, host=host, platform=plat, version=version, labels=labels, caps=caps,
                        actor=actor, identity=identity)
                    revoked_keys = []
                inserted = await con.fetchrow(
                    """INSERT INTO fleet_agent_keys (agent_id, key_id, public_key)
                       VALUES ($1,$2,$3) ON CONFLICT (tenant_id, key_id) DO NOTHING RETURNING id""",
                    agent_id, key_id, pub)
                if inserted is None:
                    raise EnrollError(409, "public key already registered; generate a new key",
                                      counts_failure=False)
                await audit.record(
                    pool, action="fleet.agent.enroll", actor=f"agent:{host}", actor_role="agent",
                    resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip,
                    details={"hostname": host, "key_id": key_id, "enroll_token_prefix": prefix,
                             "rekey": claimed["for_agent"] is not None, "revoked_keys": revoked_keys,
                             "agent_version": version, "minted_by": actor},
                    con=con, tenant_id=tenant_id)
    full, cred_prefix, _ = cred
    return {"agent_id": str(agent_id), "agent_token": full, "token_prefix": cred_prefix, "key_id": key_id,
            "tenant_id": tenant_id, "hostname": host, "rekey": claimed["for_agent"] is not None,
            "server_time": _iso(now)}


async def _insert_agent(con: Any, *, host: str, platform: str, version: str | None, labels: list[str],
                        caps: list[str], actor: str, identity: str) -> tuple[uuid.UUID, tuple[str, str, str]]:
    """Insert a NEW agent row. An existing hostname is a 409 (never a silent credential replacement)."""
    agent_id = uuid.uuid4()
    for _ in range(3):
        cred = new_agent_credential()
        try:
            async with con.transaction():          # savepoint: a prefix collision must not abort the claim
                row = await con.fetchrow(
                    """INSERT INTO fleet_agents
                           (id, hostname, platform, agent_version, labels, capabilities, status, token_prefix,
                            token_hash, enrolled_by, last_seen, identity, node_ref)
                       VALUES ($1,$2,$3,$4,$5::text[],$6::text[],'enrolled',$7,$8,$9,NOW(),$10::jsonb,$11)
                       ON CONFLICT (tenant_id, hostname) DO NOTHING RETURNING id""",
                    agent_id, host, platform, version, labels, caps, cred[1], cred[2], actor, identity,
                    _NODE_REF_PREFIX + str(agent_id))
        except asyncpg.UniqueViolationError:
            continue                                # token_prefix collision: retry with a new credential
        if row is None:
            raise EnrollError(
                409, "hostname already enrolled; ask an admin for a re-key token (for_agent)",
                counts_failure=False)
        return agent_id, cred
    raise RuntimeError("could not allocate a unique agent credential prefix")  # pragma: no cover


async def _rekey(con: Any, for_agent: uuid.UUID, *, host: str, platform: str, version: str | None,
                 labels: list[str], caps: list[str], actor: str, identity: str,
                 token_prefix: str) -> tuple[uuid.UUID, dict[str, Any]]:
    """Rebind an existing agent (legacy, key lost, or key compromised) to a new key and credential.

    History is kept. Every active key of the agent is revoked with a reason. The identity is reset to
    ``claimed`` and the node to ``agent:<id>`` (a corroboration of the old host says nothing about the new
    one); the posture counters restart with the new key.
    """
    row = await con.fetchrow("SELECT id, labels, capabilities FROM fleet_agents WHERE id = $1 FOR UPDATE",
                             for_agent)
    if row is None:
        raise _bad()                                # the agent was deleted since the token was minted
    revoked = await con.fetch(
        """UPDATE fleet_agent_keys SET status = 'revoked', revoked_at = NOW(),
                  revoke_reason = $2
            WHERE agent_id = $1 AND status = 'active' RETURNING key_id""",
        for_agent, f"re-enrolled with token {token_prefix}")
    for _ in range(3):
        cred = new_agent_credential()
        try:
            async with con.transaction():
                await con.execute(
                    """UPDATE fleet_agents SET
                              hostname = $2, platform = $3, agent_version = $4,
                              labels = CASE WHEN cardinality($5::text[]) > 0 THEN $5::text[] ELSE labels END,
                              capabilities = $6::text[], status = 'enrolled',
                              token_prefix = $7, token_hash = $8, enrolled_by = $9, enrolled_at = NOW(),
                              last_seen = NOW(), legacy = FALSE, revoked_at = NULL, revoked_by = NULL,
                              online = TRUE, offline_since = NULL, identity = $10::jsonb,
                              node_ref = $11, last_posture_seq = 0, last_posture_at = NULL
                        WHERE id = $1""",
                    for_agent, host, platform, version, labels, caps, cred[1], cred[2], actor, identity,
                    _NODE_REF_PREFIX + str(for_agent))
        except asyncpg.UniqueViolationError as exc:
            if "token_prefix" in (exc.constraint_name or ""):
                continue
            raise EnrollError(409, "hostname already enrolled by another agent",
                              counts_failure=False) from exc
        return for_agent, {"cred": cred, "revoked_keys": sorted(r["key_id"] for r in revoked)}
    raise RuntimeError("could not allocate a unique agent credential prefix")  # pragma: no cover
