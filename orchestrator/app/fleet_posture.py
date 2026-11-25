"""Signed host evidence: envelope verification, replay protection, payload schema, persistence (schema 041).

The server side of docs/ASSURANCE_P2.md section 2. What a valid envelope proves: enrolled key ``K`` of tenant
``T`` sent exactly these payload bytes, once, in order, at about ``issued_at``. It does NOT prove the host is
honest (E2: evidence from here is tier ``configured``, never ``observed``; this module never lifts a tier).

The checks run in EXACTLY this order and each fails closed with its own status, ``reason`` and a
``fleet.evidence.rejected`` audit row (reason, key_id, seq) in the agent's tenant chain:

====  =============================================================================================  ======
step  check                                                                                          status
====  =============================================================================================  ======
1     body size: gzip <= 1 MiB, inflated <= 4 MiB, payload <= 2 MiB, header <= 2 KiB, depth <= 16   413
2     strict JSON (no duplicate keys, no floats/NaN), exact field set and types, ``v == 1``           400
3     agent by path id: exists, not revoked, not legacy, header tenant/agent match the row            403/404
4     ``kid`` is an ACTIVE key of this agent and ``alg == "ed25519"``                                 401
5     payload base64, ``payload_len`` and ``payload_sha256`` match the decoded bytes                  400
6     Ed25519 signature over ``b"paddock-agent-envelope/v1\\n" + canon(header)``                      401
7     clock: ``abs(now - issued_at) <= 600 s``                                                        422
8     atomic seq claim ``UPDATE fleet_agent_keys SET last_seq=$s WHERE ... last_seq < $s RETURNING``  409
9     payload schema (Pydantic ``extra=forbid``, per-collector caps)                                  422
10    persist, in ONE transaction with step 8                                                         --
====  =============================================================================================  ======

Everything up to step 7 is read-only: the signature is verified before ANY write, and ``last_seq`` never
advances for a bad signature. A step-9 failure rolls the claim back (the transaction), so a rejected envelope
leaves the previous accepted posture and the seq counter exactly as they were: tampering becomes silence, hence
``UNKNOWN``. An identical retry ``(kid, seq, payload_sha256, kind)`` of the last accepted envelope is an
idempotent 200 (the answer was lost); the same ``(kid, seq)`` with a different digest is **equivocation** (two
payloads signed under one seq: a cloned or stolen key) and is a 409 with its own audit reason.

Locking: every transaction takes the agent row ``FOR UPDATE`` FIRST, then touches the key rows. Enrollment
re-keying and the admin revokes take them in the same order, so there is no lock-order deadlock.

Posture history (E8): the agent row is refreshed on every accepted envelope, but a posture row is stored only
when the content digest changed or at most hourly. The digest ignores timing counters (``ms``, uptime, seq,
payload size, clock skew, key id, package list presence, metadata age).

Not here: the ``reach_node_facts`` write (the ``host_fw`` builder's job) and any evaluation.
"""
import asyncio
import base64
import binascii
import calendar
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import re
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

from . import audit, fleet_enroll, tenancy
from .netkey import SlidingWindowLimiter

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# wire constants (docs/ASSURANCE_P2.md section 2)
# --------------------------------------------------------------------------- #

SIGNING_PREFIX = b"paddock-agent-envelope/v1\n"
ROTATE_PROOF_DOMAIN = b"paddock-rotate/v1\n"
ALG = "ed25519"
PAYLOAD_TYPES = {
    "posture": "paddock.host.posture/v2",
    "heartbeat": "paddock.host.heartbeat/v1",
    "rotate": "paddock.agent.key-rotate/v1",
}
KINDS = tuple(PAYLOAD_TYPES)
MAX_BODY_BYTES = 1024 * 1024            # the request body as sent (gzip or plain)
MAX_INFLATED_BYTES = 4 * 1024 * 1024    # after gunzip
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024     # decoded payload
MAX_HEADER_BYTES = 2048                 # canon(header)
MAX_JSON_DEPTH = 16                     # envelope
CLOCK_WINDOW_S = 600
MAX_SEQ = 2 ** 62
HOURLY_S = 3600

_HEADER_FIELDS = ("v", "alg", "kid", "agent_id", "tenant_id", "kind", "seq", "issued_at", "nonce",
                  "payload_type", "payload_sha256", "payload_len", "collectors")
_ALL_FIELDS = frozenset(_HEADER_FIELDS) | {"payload_b64", "sig"}
_ISSUED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_KID_RE = re.compile(r"^[0-9a-f]{32}$")
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Linear depth scan (no regex backtracking over a whole string: an unterminated string just ends the scan).
_STRUCT_RE = re.compile(rb'["\[\]{}]')
_STR_END_RE = re.compile(rb'[^"\\]*(?:\\.[^"\\]*)*"')


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


# Per-agent request limits (in-process, like the sensors'; with N replicas the effective limit is N times).
heartbeat_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_HEARTBEAT_PER_MIN", 60), window_s=60)
posture_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_POSTURE_PER_MIN", 20), window_s=60)
rotate_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_ROTATE_PER_HOUR", 10), window_s=3600)
inventory_limiter = SlidingWindowLimiter(limit=_env_int("FLEET_INVENTORY_PER_MIN", 6), window_s=60)
_LIMITERS = {"heartbeat": heartbeat_limiter, "posture": posture_limiter, "rotate": rotate_limiter,
             "inventory": inventory_limiter}


def reset_limiters() -> None:
    for lim in _LIMITERS.values():
        lim.reset()


def rate_limited(route: str, agent_id: Any) -> bool:
    """Record a hit for ``agent_id`` on ``route`` and say whether the agent is now OVER its limit."""
    return not _LIMITERS[route].hit(str(agent_id))


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #

class Rejection(Exception):
    """An envelope (or request) refused. ``status``/``reason``/``body`` are the HTTP answer; ``audit`` says
    whether the rejection is recorded as ``fleet.evidence.rejected`` (always, except pure authN failures)."""

    def __init__(self, status: int, reason: str, detail: str | None = None, *,
                 body: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail or reason.replace("_", " ")
        self.body = dict(body or {})
        self.key_id: str | None = None
        self.seq: int | None = None
        self.extra: dict[str, Any] = {}

    def response_body(self) -> dict[str, Any]:
        return {**self.body, "detail": self.detail, "reason": self.reason}


class PayloadError(ValueError):
    """The payload bytes are not an acceptable document of their type (step 9)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason, self.detail = reason, detail


# --------------------------------------------------------------------------- #
# canonical encoding, base64, strict JSON
# --------------------------------------------------------------------------- #

def canon(value: Any) -> bytes:
    """The agent's canonical encoding (stdlib form of RFC 8785 for float-free data)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def b64u_decode(text: Any, *, max_chars: int | None = None) -> bytes:
    """Base64url, padded or not. Anything outside the alphabet (or a bad length) raises ``ValueError``."""
    if not isinstance(text, str) or (max_chars is not None and len(text) > max_chars):
        raise ValueError("bad base64")
    if not _B64U_RE.match(text):
        raise ValueError("bad base64")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("bad base64") from exc


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_depth_exceeds(raw: bytes, limit: int, max_tokens: int = 4096) -> bool:
    """True if brackets nest deeper than ``limit`` outside strings, or if there are more than ``max_tokens``
    structural tokens (a legitimate envelope has a few dozen: its one big field is a single string). Bounded
    work: at most ``max_tokens`` loop iterations, and every regex step is linear."""
    depth = 0
    pos = 0
    for _ in range(max_tokens):
        m = _STRUCT_RE.search(raw, pos)
        if m is None:
            return False
        c = raw[m.start()]
        if c == 0x22:                       # "
            e = _STR_END_RE.match(raw, m.end())
            if e is None:
                return False                # unterminated string: the strict parse rejects it
            pos = e.end()
            continue
        pos = m.end()
        if c in (0x5B, 0x7B):               # [ {
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return True


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _no_float(text: str) -> Any:
    raise ValueError("floats are not allowed")


def _no_constant(text: str) -> Any:
    raise ValueError("NaN/Infinity are not allowed")


def strict_loads(raw: bytes) -> Any:
    """``json.loads`` with duplicate keys, floats and NaN refused. Raises ``ValueError`` (also on bad UTF-8,
    on a BOM, and on nesting deeper than the interpreter allows)."""
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_dupes, parse_float=_no_float,
                          parse_constant=_no_constant)
    except RecursionError as exc:
        raise ValueError("nesting too deep") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("not UTF-8") from exc


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_issued_at(text: str) -> dt.datetime:
    """``YYYY-MM-DDTHH:MM:SSZ`` -> aware UTC datetime. ValueError otherwise."""
    if not isinstance(text, str) or not _ISSUED_RE.match(text):
        raise ValueError("bad timestamp")
    return dt.datetime.fromtimestamp(
        calendar.timegm(dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").timetuple()), dt.timezone.utc)


# --------------------------------------------------------------------------- #
# step 1: body
# --------------------------------------------------------------------------- #

def gunzip_capped(raw: bytes, limit: int = MAX_INFLATED_BYTES) -> bytes:
    """Inflate one gzip member, refusing to produce more than ``limit`` bytes (an inflation bomb is a 413)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(raw, limit + 1)
        if len(out) > limit or d.unconsumed_tail:
            raise Rejection(413, "inflated_too_large", f"the body inflates past {limit} bytes")
        if not d.eof:
            raise Rejection(400, "bad_gzip", "truncated gzip stream")
        if d.unused_data:
            raise Rejection(400, "bad_gzip", "trailing data after the gzip stream")
    except zlib.error as exc:
        raise Rejection(400, "bad_gzip", "invalid gzip stream") from exc
    return out


def inflate_body(body: bytes, content_encoding: str | None) -> bytes:
    """Step 1 for the transport: size caps and (optional) gzip. Raises :class:`Rejection`."""
    enc = (content_encoding or "").strip().lower()
    if enc not in ("", "identity", "gzip"):
        raise Rejection(415, "unsupported_encoding", "Content-Encoding must be gzip or absent")
    if len(body) > MAX_BODY_BYTES:
        raise Rejection(413, "body_too_large", f"the body exceeds {MAX_BODY_BYTES} bytes")
    if enc == "gzip":
        return gunzip_capped(body)
    return body


@dataclass
class Envelope:
    header: dict[str, Any]
    payload_b64: str
    sig_b64: str
    issued: dt.datetime

    @property
    def kid(self) -> str:
        return self.header["kid"]

    @property
    def seq(self) -> int:
        return self.header["seq"]


def parse_envelope(raw: bytes, expected_kind: str) -> Envelope:
    """Steps 1 (depth/header size) and 2: strict JSON, the exact field set, types, ``v == 1``."""
    if json_depth_exceeds(raw, MAX_JSON_DEPTH):
        raise Rejection(413, "json_too_deep", f"JSON nesting deeper than {MAX_JSON_DEPTH}")
    try:
        env = strict_loads(raw)
    except ValueError as exc:
        raise Rejection(400, "bad_json", f"not a strict JSON document: {exc}") from exc
    if not isinstance(env, dict):
        raise Rejection(400, "bad_envelope", "the envelope must be a JSON object")
    keys = set(env)
    if keys != _ALL_FIELDS:
        raise Rejection(400, "bad_envelope",
                        f"envelope fields differ from the contract (missing={sorted(_ALL_FIELDS - keys)}, "
                        f"unexpected={sorted(keys - _ALL_FIELDS)})")

    def _is_int(x: Any) -> bool:
        return isinstance(x, int) and not isinstance(x, bool)

    def _bad(why: str) -> Rejection:
        return Rejection(400, "bad_envelope", why)

    if not _is_int(env["v"]) or env["v"] != 1:
        raise _bad("unsupported envelope version (v must be 1)")
    for name in ("alg", "kid", "agent_id", "tenant_id", "kind", "issued_at", "nonce", "payload_type",
                 "payload_sha256", "payload_b64", "sig"):
        if not isinstance(env[name], str):
            raise _bad(f"{name} must be a string")
    if not _is_int(env["seq"]) or not 1 <= env["seq"] <= MAX_SEQ:
        raise _bad("seq must be an integer >= 1")
    if not _is_int(env["payload_len"]) or env["payload_len"] < 0:
        raise _bad("payload_len must be a non-negative integer")
    coll = env["collectors"]
    if (not isinstance(coll, dict) or len(coll) > 32
            or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 64 or len(v) > 128
                   for k, v in coll.items())):
        raise _bad("collectors must map at most 32 short strings to strings")
    if len(env["kid"]) > 64 or not env["kid"]:
        raise _bad("kid is malformed")
    for name in ("agent_id", "tenant_id"):
        try:
            if str(uuid.UUID(env[name])) != env[name]:
                raise ValueError
        except (ValueError, AttributeError):
            raise _bad(f"{name} must be a canonical UUID") from None
    if env["kind"] not in KINDS:
        raise _bad("kind must be posture, heartbeat or rotate")
    if env["kind"] != expected_kind:
        raise Rejection(400, "kind_route_mismatch",
                        f"a {env['kind']} envelope cannot be posted to the {expected_kind} route")
    if env["payload_type"] != PAYLOAD_TYPES[env["kind"]]:
        raise _bad(f"payload_type for kind {env['kind']} must be {PAYLOAD_TYPES[env['kind']]}")
    if not _HEX64_RE.match(env["payload_sha256"]):
        raise _bad("payload_sha256 must be 64 lower-case hex characters")
    try:
        if len(b64u_decode(env["nonce"], max_chars=64)) != 16:
            raise ValueError
    except ValueError:
        raise _bad("nonce must be 16 bytes of base64url") from None
    try:
        issued = parse_issued_at(env["issued_at"])
    except (ValueError, OverflowError):
        raise _bad("issued_at must be YYYY-MM-DDTHH:MM:SSZ") from None
    header = {k: env[k] for k in _HEADER_FIELDS}
    if len(canon(header)) > MAX_HEADER_BYTES:
        raise Rejection(413, "header_too_large", f"the signed header exceeds {MAX_HEADER_BYTES} bytes")
    if env["payload_len"] > MAX_PAYLOAD_BYTES:
        raise Rejection(413, "payload_too_large", f"the payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    return Envelope(header=header, payload_b64=env["payload_b64"], sig_b64=env["sig"], issued=issued)


def decode_payload(env: Envelope) -> bytes:
    """Step 5: strict base64, then ``payload_len`` and ``payload_sha256`` against the decoded bytes."""
    max_chars = (MAX_PAYLOAD_BYTES * 4) // 3 + 8
    if len(env.payload_b64) > max_chars:
        raise Rejection(413, "payload_too_large", f"the payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    try:
        payload = b64u_decode(env.payload_b64)
    except ValueError:
        raise Rejection(400, "bad_payload_b64", "payload_b64 is not base64url") from None
    if len(payload) != env.header["payload_len"]:
        raise Rejection(400, "payload_len_mismatch", "payload_len does not match the decoded payload")
    if hashlib.sha256(payload).hexdigest() != env.header["payload_sha256"]:
        raise Rejection(400, "payload_sha256_mismatch", "payload_sha256 does not match the decoded payload")
    return payload


def signing_input(header: dict[str, Any]) -> bytes:
    return SIGNING_PREFIX + canon(header)


def verify_signature(public_key: bytes, env: Envelope) -> bool:
    """Step 6. False for anything but a valid 64-byte Ed25519 signature by a valid key."""
    try:
        sig = b64u_decode(env.sig_b64, max_chars=128)
    except ValueError:
        return False
    return fleet_enroll.verify_ed25519(bytes(public_key), signing_input(env.header), sig)


# --------------------------------------------------------------------------- #
# step 9: payload schema (docs/ASSURANCE_P2.md section 4 and agent/PAYLOAD.md). extra=forbid, caps everywhere.
# These models VALIDATE; the stored bytes are never re-serialised from them.
# --------------------------------------------------------------------------- #

def _printable(v: str) -> str:
    if _CTL_RE.search(v):
        raise ValueError("control characters are not allowed")
    return v


def S(n: int) -> Any:
    """A printable strict string of at most ``n`` characters."""
    return Annotated[StrictStr, Field(max_length=n), AfterValidator(_printable)]


def I(lo: int, hi: int) -> Any:  # noqa: E743 -- reads as the type it is
    """A strict integer (a bool is not an int) in ``[lo, hi]``."""
    return Annotated[StrictInt, Field(ge=lo, le=hi)]


def L(item: Any, n: int) -> Any:
    return Annotated[List[item], Field(max_length=n)]


_SHA256 = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
_YN = Literal["yes", "no"]
_UNAVAILABLE = Literal["tool_missing", "permission_denied", "not_applicable", "unsupported_platform",
                       "daemon_not_running", "unmanaged_kernel", "containerised_agent", "no_data"]
_ERRORS = Literal["timeout", "exit_nonzero", "parse_error", "truncated", "exception"]
_CONF = Literal["exact", "approximate"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


def _section(v_model: Any) -> Any:
    """``ok`` | ``unavailable`` | ``error``: exactly one, discriminated on ``s``."""

    class Ok(_M):
        s: Literal["ok"]
        v: v_model            # type: ignore[valid-type]
        conf: _CONF
        partial: StrictBool

    class Unavailable(_M):
        s: Literal["unavailable"]
        reason: _UNAVAILABLE

    class Err(_M):
        s: Literal["error"]
        reason: _ERRORS
        detail: S(120)        # type: ignore[valid-type]

    return Annotated[Union[Ok, Unavailable, Err], Field(discriminator="s")]


# ---- sshd ----------------------------------------------------------------- #

class SshdConfig(_M):
    """Every key may be ABSENT (never null). The non-Optional annotations with a ``None`` default let the key be
    missing while an explicit ``null`` is still refused."""
    passwordauthentication: _YN = None            # type: ignore[assignment]
    kbdinteractiveauthentication: _YN = None      # type: ignore[assignment]
    pubkeyauthentication: _YN = None              # type: ignore[assignment]
    permitemptypasswords: _YN = None              # type: ignore[assignment]
    usepam: _YN = None                            # type: ignore[assignment]
    x11forwarding: _YN = None                     # type: ignore[assignment]
    permituserenvironment: _YN = None             # type: ignore[assignment]
    hostbasedauthentication: _YN = None           # type: ignore[assignment]
    gssapiauthentication: _YN = None              # type: ignore[assignment]
    strictmodes: _YN = None                       # type: ignore[assignment]
    permitrootlogin: Literal["yes", "no", "prohibit-password", "forced-commands-only"] = None  # type: ignore
    addressfamily: Literal["any", "inet", "inet6"] = None                                       # type: ignore
    allowtcpforwarding: Literal["yes", "no", "all", "local", "remote"] = None                   # type: ignore
    loglevel: Literal["quiet", "fatal", "error", "info", "verbose", "debug", "debug1", "debug2",
                      "debug3"] = None                                                          # type: ignore
    maxauthtries: I(0, 999999999) = None          # type: ignore[valid-type]
    logingracetime: I(0, 999999999) = None        # type: ignore[valid-type]
    maxsessions: I(0, 999999999) = None           # type: ignore[valid-type]
    authenticationmethods: S(200) = None          # type: ignore[valid-type]
    port: L(I(1, 65535), 50) = None               # type: ignore[valid-type]
    listenaddress: L(S(80), 50) = None            # type: ignore[valid-type]
    allowusers: L(S(80), 50) = None               # type: ignore[valid-type]
    allowgroups: L(S(80), 50) = None              # type: ignore[valid-type]
    denyusers: L(S(80), 50) = None                # type: ignore[valid-type]
    denygroups: L(S(80), 50) = None               # type: ignore[valid-type]
    authorizedkeysfile: L(S(120), 50) = None      # type: ignore[valid-type]
    authorizedkeyscommand: Literal["none", "set"] = None                                        # type: ignore


_DeltaValue = Union[StrictStr, StrictInt, List[Union[StrictStr, StrictInt]], None]


class SshdDelta(_M):
    user: S(64)
    addr: S(64)
    delta: Annotated[Dict[S(48), _DeltaValue], Field(max_length=40)]


class SshdProbes(_M):
    addrs: L(S(64), 64)
    users_probed: I(0, 100000)
    users_total: I(0, 10000000)
    planned: I(0, 100000)
    done: I(0, 100000)
    deltas: L(SshdDelta, 400)


class SshdMatch(_M):
    blocks: I(0, 100000)
    criteria: L(S(64), 64)
    known: StrictBool
    unprobed: StrictBool
    unprobed_reasons: L(S(64), 64)


class SshdFile(_M):
    path: S(512)
    sha256: Optional[_SHA256]
    size: I(0, 2 ** 40)


class SshdV(_M):
    installed: StrictBool
    source: Literal["sshd_T", "text"]
    version: Optional[S(64)]
    binary: S(256)
    socket_activated: StrictBool
    config: SshdConfig
    probes: SshdProbes
    match: SshdMatch
    files: L(SshdFile, 64)


# ---- listeners --------------------------------------------------------------- #

class Listener(_M):
    proto: Literal["tcp", "udp"]
    ip: S(64)
    port: I(1, 65535)
    bind_class: Literal["wildcard4", "wildcard6", "loopback", "specific"]
    uid: I(0, 2 ** 32)
    pid: Optional[I(0, 2 ** 32)]
    n_pids: I(0, 1000000)
    comm: Optional[S(16)]
    exe: Optional[S(256)]
    exe_deleted: StrictBool
    exe_sha256: Optional[_SHA256]
    unit: Optional[S(96)]
    container: Optional[S(12)]


class ListenerAttribution(_M):
    status: Literal["ok", "partial", "denied"]
    unreadable_pids: I(0, 10000000)
    unattributed: I(0, 10000000)


class ListenersV(_M):
    count: I(0, 100000)
    listeners: L(Listener, 2000)
    ipv6: StrictBool
    bindv6only: Optional[I(0, 1)]
    attribution: ListenerAttribution


# ---- firewall (the canonical model of paddock_agent.collectors.fwmodel) ------ #

_Range = Annotated[List[I(0, 65535)], Field(min_length=2, max_length=2)]


class FwMatch(_M):
    iif: S(32) = None                                   # type: ignore[valid-type]
    oif: S(32) = None                                   # type: ignore[valid-type]
    src: L(S(64), 4096) = None                          # type: ignore[valid-type]
    dst: L(S(64), 4096) = None                          # type: ignore[valid-type]
    proto: S(16) = None                                 # type: ignore[valid-type]
    sport: L(_Range, 4096) = None                       # type: ignore[valid-type]
    dport: L(_Range, 4096) = None                       # type: ignore[valid-type]
    ct: L(S(16), 8) = None                              # type: ignore[valid-type]
    icmp: L(I(0, 255), 64) = None                       # type: ignore[valid-type]
    dtype: L(S(16), 8) = None                           # type: ignore[valid-type]


class FwRule(_M):
    m: FwMatch
    v: S(120)
    opaque_reason: S(120) = None                        # type: ignore[valid-type]


class FwChain(_M):
    name: S(120)
    hook: Optional[Literal["input"]]
    prio: Optional[I(-100000, 100000)]
    policy: Optional[Literal["accept", "drop"]]
    base: StrictBool
    rules: L(FwRule, 2000)


class FwFamily(_M):
    read: StrictBool
    effective_default: Literal["accept", "drop", "reject", "unknown"]
    chains: L(FwChain, 256)


class FwFlatRule(_M):
    src_cidr: S(64)
    proto: S(16)
    port_lo: I(0, 65535)
    port_hi: I(0, 65535)
    action: Literal["accept", "drop", "reject"]


class FwFlat(_M):
    default_input_policy: Literal["accept", "drop", "reject", "unknown"]
    rules: L(FwFlatRule, 200)
    confidence: Literal["exact", "approximate", "unknown"]


class FwUfw(_M):
    name: Literal["ufw"]
    state: Literal["active", "inactive", "unknown"]
    default_incoming: Literal["deny", "allow", "reject", "unknown"]
    rules: I(0, 1000)


class FwFirewalld(_M):
    name: Literal["firewalld"]
    state: Literal["running", "not_running", "unknown"]
    default_zone: Optional[S(64)]


class FwFamilies(_M):
    ip4: FwFamily
    ip6: FwFamily


class FirewallV(_M):
    v: Literal[1]
    backend: Literal["nft", "legacy", "mixed", "none"]
    frontends: Annotated[List[Annotated[Union[FwUfw, FwFirewalld], Field(discriminator="name")]],
                         Field(max_length=8)]
    ipv6_enabled: StrictBool
    families: FwFamilies
    flat_view: FwFlat
    confidence_reasons: L(S(80), 16)
    opaque_features: L(S(80), 64)
    dataplane: L(S(32), 16)
    other_hooks: L(S(32), 32)
    rule_count: I(0, 1000000)


# ---- patch ---------------------------------------------------------------------- #

def _sub(ok_model: Any, unavailable_extra: Any = None) -> Any:
    """A patch sub-block: ``state`` is ok | unavailable | error."""
    if unavailable_extra is None:
        class Unavailable(_M):
            state: Literal["unavailable"]
            reason: _UNAVAILABLE
    else:
        Unavailable = unavailable_extra

    class Err(_M):
        state: Literal["error"]
        reason: _ERRORS
        detail: S(120)        # type: ignore[valid-type]

    return Annotated[Union[ok_model, Unavailable, Err], Field(discriminator="state")]


class PatchOs(_M):
    state: Literal["ok"]
    id: Optional[S(64)]
    id_like: L(S(64), 16)
    version_id: Optional[S(64)]
    codename: Optional[S(64)]
    pretty_name: Optional[S(80)]
    family: Literal["debian", "rhel", "suse", "alpine", "other"]
    arch: Optional[S(32)]


_PkgRow = Annotated[List[S(200)], Field(min_length=5, max_length=5)]


class PatchManifest(_M):
    state: Literal["ok"]
    mgr: Literal["dpkg", "rpm"]
    count: I(0, 8000)
    sha256: _SHA256
    held: I(0, 8000)
    full: StrictBool
    packages: L(_PkgRow, 8000) = None                   # type: ignore[valid-type]


class PatchPending(_M):
    state: Literal["ok"]
    mgr: Literal["apt", "dnf", "yum"]
    total: I(0, 1000000)
    security: I(0, 1000000)
    security_pkgs: L(S(200), 200)
    kept_back: I(0, 1000000)
    removals: I(0, 1000000)
    metadata_age_s: Optional[I(0, 2 ** 40)]


class PatchAuto(_M):
    state: Literal["ok"]
    mgr: Literal["unattended-upgrades", "dnf-automatic", "yum-cron", "none"]
    installed: StrictBool
    interval_days: Optional[I(0, 3650)] = None
    apply: Optional[StrictBool] = None
    timer_enabled: Optional[StrictBool] = None


class PatchKernelOk(_M):
    state: Literal["ok"]
    running: S(128)
    package: S(128)
    package_version: S(128)
    installed: L(S(128), 20)
    livepatch: StrictBool


class PatchKernelUnavailable(_M):
    state: Literal["unavailable"]
    reason: _UNAVAILABLE
    running: S(128) = None                              # type: ignore[valid-type]
    livepatch: StrictBool = None                        # type: ignore[valid-type]


class PatchReboot(_M):
    state: Literal["ok"]
    required: StrictBool
    pkgs: L(S(200), 50)
    source: Literal["file", "needs-restarting"]


class PatchV(_M):
    os: _sub(PatchOs)
    manifest: _sub(PatchManifest)
    pending: _sub(PatchPending)
    auto_update: _sub(PatchAuto)
    kernel: _sub(PatchKernelOk, PatchKernelUnavailable)
    reboot: _sub(PatchReboot)


# ---- self ----------------------------------------------------------------------- #

class SelfCollector(_M):
    status: Literal["ok", "unavailable", "error"]
    ms: I(0, 10 ** 9)
    reason: Optional[S(64)]


class SelfCollectors(_M):
    sshd: SelfCollector
    listeners: SelfCollector
    firewall: SelfCollector
    patch: SelfCollector


class SelfCaps(_M):
    cap_eff: Optional[Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{16}$")]]
    net_admin: StrictBool
    sys_ptrace: StrictBool
    dac_read_search: StrictBool


class SelfV(_M):
    agent_version: S(32)
    python: S(32)
    platform: S(16)
    collectors: SelfCollectors
    caps: SelfCaps
    is_root: StrictBool
    containerised: StrictBool
    boot_id: Optional[S(64)]
    machine_id_hash: Optional[_SHA256]
    uptime_s: Optional[I(0, 2 ** 40)]
    seq: I(0, 2 ** 62)
    key_id: S(64)
    payload_bytes: I(0, 2 ** 31)
    clock_skew_ms: Optional[I(-(2 ** 40), 2 ** 40)]
    imds_enabled: StrictBool


class _SelfOk(_M):
    s: Literal["ok"]
    v: SelfV
    conf: Literal["exact"]
    partial: Literal[False]


class Sections(_M):
    sshd: _section(SshdV)
    listeners: _section(ListenersV)
    firewall: _section(FirewallV)
    patch: _section(PatchV)
    self_: _SelfOk = Field(alias="self")


class PosturePayload(_M):
    schema_version: Literal[2] = Field(alias="schema")
    collected_at: Annotated[StrictStr, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
    sections: Sections


class HeartbeatPayload(_M):
    agent_version: S(64) = None                         # type: ignore[valid-type]
    status: S(32) = None                                # type: ignore[valid-type]


class RotatePayload(_M):
    new_key_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{32}$")]
    new_public_key_b64: S(128)
    proof_b64: S(256)


_MAX_FW_RULES_PER_FAMILY = 4000


def _error_summary(exc: ValidationError) -> str:
    """A short, secret-free description of the first problems (field paths only, never values)."""
    parts = []
    for err in exc.errors()[:3]:
        loc = ".".join(str(x) for x in err.get("loc", ())[:8])
        parts.append(f"{loc}: {err.get('type', 'invalid')}")
    return "; ".join(parts)[:240]


def _parse_payload_json(raw: bytes) -> Any:
    try:
        return strict_loads(raw)       # a pathologically deep payload is a RecursionError -> ValueError
    except ValueError as exc:
        raise PayloadError("payload_not_json", f"the payload is not strict JSON: {exc}") from exc


def validate_posture(raw: bytes) -> dict[str, Any]:
    """Parse + validate a ``paddock.host.posture/v2`` payload. Returns the PARSED dict (for digesting and
    indexing; the stored bytes stay the original). Raises :class:`PayloadError`."""
    obj = _parse_payload_json(raw)
    if not isinstance(obj, dict):
        raise PayloadError("payload_schema", "the payload must be a JSON object")
    try:
        model = PosturePayload.model_validate(obj)
    except ValidationError as exc:
        raise PayloadError("payload_schema", _error_summary(exc)) from exc
    fw = model.sections.firewall
    if getattr(fw, "s", None) == "ok":
        for fam in (fw.v.families.ip4, fw.v.families.ip6):
            if sum(len(c.rules) for c in fam.chains) > _MAX_FW_RULES_PER_FAMILY:
                raise PayloadError("payload_schema", "sections.firewall: too many rules")
    if model.collected_at and parse_collected(model.collected_at) is None:
        raise PayloadError("payload_schema", "collected_at: not a timestamp")
    return obj


def validate_heartbeat(raw: bytes) -> dict[str, Any]:
    obj = _parse_payload_json(raw)
    if not isinstance(obj, dict):
        raise PayloadError("payload_schema", "the payload must be a JSON object")
    try:
        HeartbeatPayload.model_validate(obj)
    except ValidationError as exc:
        raise PayloadError("payload_schema", _error_summary(exc)) from exc
    return obj


def parse_collected(text: str) -> dt.datetime | None:
    try:
        return parse_issued_at(text)
    except (ValueError, OverflowError):
        return None


def validate_rotate(raw: bytes, *, agent_id: str, old_kid: str) -> tuple[dict[str, Any], bytes]:
    """The rotate payload: the new key, its id and the new key's proof of possession over
    ``paddock-rotate/v1\\n<agent_id>\\n<old_kid>\\n<new_kid>``. Returns ``(payload, new_public_key)``."""
    obj = _parse_payload_json(raw)
    if not isinstance(obj, dict):
        raise PayloadError("payload_schema", "the payload must be a JSON object")
    try:
        p = RotatePayload.model_validate(obj)
    except ValidationError as exc:
        raise PayloadError("payload_schema", _error_summary(exc)) from exc
    try:
        pub = fleet_enroll.parse_public_key_b64(p.new_public_key_b64)
    except fleet_enroll.KeyFormatError as exc:
        raise PayloadError("rotate_new_key_invalid", f"invalid new public key: {exc}") from exc
    if fleet_enroll.key_id_for(pub) != p.new_key_id:
        raise PayloadError("rotate_new_key_invalid", "new_key_id is not the id of new_public_key_b64")
    if p.new_key_id == old_kid:
        raise PayloadError("rotate_new_key_invalid", "the new key must differ from the current key")
    try:
        sig = fleet_enroll.b64_decode_strict(p.proof_b64, max_chars=256)
    except fleet_enroll.KeyFormatError:
        raise PayloadError("rotate_proof_invalid", "the proof of possession is not base64") from None
    msg = (ROTATE_PROOF_DOMAIN + str(uuid.UUID(agent_id)).encode("ascii") + b"\n"
           + old_kid.encode("ascii") + b"\n" + p.new_key_id.encode("ascii"))
    if not fleet_enroll.verify_ed25519(pub, msg, sig):
        raise PayloadError("rotate_proof_invalid", "the new key's proof of possession does not verify")
    return obj, pub


# --------------------------------------------------------------------------- #
# content digest + identity extraction
# --------------------------------------------------------------------------- #

_SELF_VOLATILE = ("uptime_s", "seq", "payload_bytes", "clock_skew_ms", "key_id")


def content_digest(payload: dict[str, Any]) -> str:
    """sha256 of the posture's CONTENT: the payload minus everything that changes on every run without the host
    changing (collection time, per-collector timings, uptime, seq, payload size, clock skew, key id, whether the
    package list was attached, apt metadata age). Anything else that differs is a change."""
    p = json.loads(canon(payload))        # deep copy through the canonical form
    p.pop("collected_at", None)
    secs = p.get("sections") or {}
    me = (secs.get("self") or {}).get("v")
    if isinstance(me, dict):
        for k in _SELF_VOLATILE:
            me.pop(k, None)
        for c in (me.get("collectors") or {}).values():
            if isinstance(c, dict):
                c.pop("ms", None)
    patch = (secs.get("patch") or {}).get("v")
    if isinstance(patch, dict):
        man = patch.get("manifest")
        if isinstance(man, dict):
            man.pop("packages", None)
            man.pop("full", None)
        pend = patch.get("pending")
        if isinstance(pend, dict):
            pend.pop("metadata_age_s", None)
    return hashlib.sha256(canon(p)).hexdigest()


def posture_identity(payload: dict[str, Any]) -> dict[str, Any]:
    """What a posture CLAIMS about who this host is: its specific (non-loopback, non-wildcard) bind addresses,
    the salted machine-id hash and the boot id. All claimed; never trusted for anything but hints."""
    out: dict[str, Any] = {}
    secs = payload.get("sections") or {}
    ips: set[str] = set()
    lis = secs.get("listeners") or {}
    if lis.get("s") == "ok":
        for row in (lis.get("v") or {}).get("listeners") or []:
            if row.get("bind_class") != "specific":
                continue
            try:
                ip = ipaddress.ip_address(row.get("ip"))
            except ValueError:
                continue
            if ip.version == 6 and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                continue
            ips.add(ip.compressed.lower())
    out["ips"] = sorted(ips)[:32]
    me = ((secs.get("self") or {}).get("v")) or {}
    out["machine_id_hash"] = me.get("machine_id_hash")
    out["boot_id"] = me.get("boot_id")
    return out


# --------------------------------------------------------------------------- #
# helpers shared by the ingest and admin paths
# --------------------------------------------------------------------------- #

def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value


async def invalidate_assurance(con: Any) -> None:
    """Ask the assurance runner to rebuild within a tick (``last_build_at = NULL``). Tenant-bound connection."""
    await con.execute(
        "INSERT INTO assurance_state (last_build_at) VALUES (NULL) "
        "ON CONFLICT (tenant_id) DO UPDATE SET last_build_at = NULL")


async def record_rejection(pool: Any, *, tenant_id: str, agent_id: Any, rej: Rejection,
                           request_id: str | None, client_ip: str | None, kind: str | None,
                           actor: str | None = None) -> None:
    """``fleet.evidence.rejected`` in the agent's tenant chain, plus ``rejected_total += 1``. Best effort: a
    failure to record never turns a refusal into an acceptance (the caller re-raises ``rej`` regardless)."""
    try:
        with tenancy.tenant_context(tenant_id):
            async with pool.acquire() as con:
                async with con.transaction():
                    await con.execute(
                        "UPDATE fleet_agents SET rejected_total = rejected_total + 1 WHERE id = $1", agent_id)
                    await audit.record(
                        pool, action="fleet.evidence.rejected", actor=actor or f"agent:{agent_id}", actor_role="agent",
                        resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip,
                        request_id=request_id, status=rej.status,
                        details={"reason": rej.reason, "key_id": rej.key_id, "seq": rej.seq, "kind": kind,
                                 "http_status": rej.status, **rej.extra},
                        con=con, tenant_id=tenant_id)
    except Exception:  # noqa: BLE001
        logger.exception("fleet_rejection_audit_failed", extra={"agent": str(agent_id)})


async def _pending_actions(con: Any, agent_id: Any) -> list[dict[str, Any]]:
    rows = await con.fetch(
        """SELECT id, action_type, target, dry_run, status, reason, revert_of, result
             FROM agent_actions
            WHERE agent_id = $1 AND status = 'approved' AND dry_run = FALSE
            ORDER BY created_at ASC LIMIT 50""", agent_id)
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# the ingest
# --------------------------------------------------------------------------- #

@dataclass
class IngestResult:
    kind: str
    seq: int
    idempotent: bool = False
    stored: bool = False
    changed: bool = False
    came_online: bool = False
    key_id: str | None = None
    new_key_id: str | None = None
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    agent: dict[str, Any] = field(default_factory=dict)
    server_time: str = ""


async def ingest_envelope(pool: Any, *, agent_id: uuid.UUID, tenant_id: str, kind: str, body: bytes,
                          content_encoding: str | None, client_ip: str | None = None,
                          request_id: str | None = None, now: dt.datetime | None = None,
                          actor: str | None = None) -> IngestResult:
    """Run the section-2 checks on a request body for ``kind`` and, if all pass, persist. Must be called with
    the agent's tenant bound (the router does; ``tenant_id`` is re-bound here anyway).

    Raises :class:`Rejection` (already audited as ``fleet.evidence.rejected``).
    """
    if kind not in KINDS:
        raise ValueError(kind)
    now = now or _utcnow()
    ctx: dict[str, Any] = {"key_id": None, "seq": None}
    try:
        with tenancy.tenant_context(tenant_id):
            return await _ingest(pool, agent_id=agent_id, tenant_id=tenant_id, kind=kind, body=body,
                                 encoding=content_encoding, client_ip=client_ip, now=now, ctx=ctx)
    except Rejection as rej:
        rej.key_id = rej.key_id or ctx["key_id"]
        rej.seq = rej.seq if rej.seq is not None else ctx["seq"]
        await record_rejection(pool, tenant_id=tenant_id, agent_id=agent_id, rej=rej, request_id=request_id,
                               client_ip=client_ip, kind=kind, actor=actor)
        raise


async def _ingest(pool: Any, *, agent_id: uuid.UUID, tenant_id: str, kind: str, body: bytes,
                  encoding: str | None, client_ip: str | None, now: dt.datetime,
                  ctx: dict[str, Any]) -> IngestResult:
    # ---- 1-2: size caps, strict parse, field set -------------------------------------------------
    raw = inflate_body(body, encoding)
    env = parse_envelope(raw, kind)
    ctx["key_id"], ctx["seq"] = env.kid, env.seq

    # ---- 3: the agent -----------------------------------------------------------------------------
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, tenant_id, status, legacy, revoked_at FROM fleet_agents WHERE id = $1", agent_id)
    _check_agent_row(row, env, agent_id)

    # ---- 4: the key -------------------------------------------------------------------------------
    async with pool.acquire() as con:
        key = await con.fetchrow(
            "SELECT public_key, status, alg FROM fleet_agent_keys WHERE agent_id = $1 AND key_id = $2",
            agent_id, env.kid)
    if env.header["alg"] != ALG:
        raise Rejection(401, "alg_not_allowed", "only ed25519 is accepted")
    if key is None or key["alg"] != ALG:
        raise Rejection(401, "unknown_key", "the key id is not a key of this agent")
    if key["status"] != "active":
        raise Rejection(401, "key_not_active", f"the key is {key['status']}")

    # ---- 5-7: payload, signature, clock (all read-only) ---------------------------------------------
    payload = decode_payload(env)
    if not verify_signature(key["public_key"], env):
        raise Rejection(401, "bad_signature", "the signature does not verify")
    skew = abs((now - env.issued).total_seconds())
    if skew > CLOCK_WINDOW_S:
        raise Rejection(422, "clock_skew", f"issued_at is {int(skew)} s away from the server clock "
                        f"(window {CLOCK_WINDOW_S} s)",
                        body={"server_now": int(now.timestamp()), "server_time": iso(now)})

    # ---- 8-10: claim + validate + persist, one transaction -----------------------------------------
    async with pool.acquire() as con:
        async with con.transaction():
            return await _claim_and_persist(con, pool, agent_id=agent_id, tenant_id=tenant_id, kind=kind,
                                            env=env, payload=payload, client_ip=client_ip, now=now)


def _check_agent_row(row: Any, env: Envelope, agent_id: uuid.UUID) -> None:
    if row is None:
        raise Rejection(404, "agent_not_found", "no such agent")
    if row["status"] == "revoked" or row["revoked_at"] is not None:
        raise Rejection(403, "agent_revoked", "this agent has been revoked", body={"error": "agent_revoked"})
    if row["legacy"]:
        raise Rejection(403, "re_enroll_required", "this agent predates signed evidence; re-enroll it",
                        body={"error": "re_enroll_required"})
    if env.header["tenant_id"] != str(row["tenant_id"]):
        raise Rejection(403, "tenant_mismatch", "the envelope names another tenant")
    if env.header["agent_id"] != str(agent_id):
        raise Rejection(403, "agent_mismatch", "the envelope names another agent")


async def _claim_and_persist(con: Any, pool: Any, *, agent_id: uuid.UUID, tenant_id: str, kind: str,
                             env: Envelope, payload: bytes, client_ip: str | None,
                             now: dt.datetime) -> IngestResult:
    # Lock order: agent row first (enroll re-key and the admin revokes do the same), then the key row.
    agent = await con.fetchrow(
        """SELECT id, tenant_id, hostname, status, legacy, revoked_at, online, offline_since, identity,
                  node_ref, agent_version, silent_after_s
             FROM fleet_agents WHERE id = $1 FOR UPDATE""", agent_id)
    _check_agent_row(agent, env, agent_id)
    identity = _loads(agent["identity"], {})
    ingest = identity.get("_ingest") if isinstance(identity.get("_ingest"), dict) else {}
    seq, kid, sha = env.seq, env.kid, env.header["payload_sha256"]

    # ---- 8: the atomic seq claim -------------------------------------------------------------------
    claimed = await con.fetchrow(
        """UPDATE fleet_agent_keys SET last_seq = $3
            WHERE agent_id = $1 AND key_id = $2 AND status = 'active' AND alg = 'ed25519' AND last_seq < $3
        RETURNING last_seq""", agent_id, kid, seq)
    if claimed is None:
        cur = await con.fetchrow(
            "SELECT status, last_seq FROM fleet_agent_keys WHERE agent_id = $1 AND key_id = $2", agent_id, kid)
        if cur is None or cur["status"] != "active":
            raise Rejection(401, "key_not_active", "the key is no longer active")
        last_env = ingest.get("last_env") if isinstance(ingest.get("last_env"), dict) else {}
        same_slot = (last_env.get("kid") == kid and last_env.get("seq") == seq == cur["last_seq"])
        if same_slot and last_env.get("sha") == sha and last_env.get("kind") == kind:
            # The same envelope again (our answer was lost): idempotent, nothing is written.
            res = IngestResult(kind=kind, seq=seq, idempotent=True, key_id=kid, server_time=iso(now))
            if kind == "heartbeat":
                res.pending_actions = await _pending_actions(con, agent_id)
                res.agent = {"id": agent_id, "status": agent["status"], "last_seen": now}
            return res
        if not same_slot and seq <= cur["last_seq"] and kind == "posture":
            # An older STORED posture that is sent again (a lost answer, then newer envelopes went through).
            prior = await con.fetchrow(
                "SELECT payload_sha256 FROM agent_posture WHERE agent_id = $1 AND key_id = $2 AND seq = $3",
                agent_id, kid, seq)
            if prior is not None and prior["payload_sha256"] == sha:
                return IngestResult(kind=kind, seq=seq, idempotent=True, key_id=kid, server_time=iso(now))
            if prior is not None:
                same_slot = True
                last_env = {"sha": prior["payload_sha256"]}
        if same_slot:
            rej = Rejection(409, "equivocation",
                            "two different payloads were signed under the same key and seq",
                            body={"expected_min": cur["last_seq"] + 1})
            rej.extra = {"sha256_new": sha, "sha256_accepted": last_env.get("sha")}
            raise rej
        raise Rejection(409, "replayed_seq", "seq is not greater than the last accepted seq",
                        body={"expected_min": cur["last_seq"] + 1})

    # ---- 9: payload schema (inside the transaction: a failure rolls the claim back) ----------------
    parsed: dict[str, Any] | None = None
    new_pub: bytes | None = None
    try:
        if kind == "posture":
            parsed = await _maybe_thread(len(payload), validate_posture, payload)
        elif kind == "heartbeat":
            parsed = validate_heartbeat(payload)
        else:
            parsed, new_pub = validate_rotate(payload, agent_id=str(agent_id), old_kid=kid)
    except PayloadError as exc:
        raise Rejection(422, exc.reason, exc.detail or exc.reason) from exc

    # ---- 10: persist ----------------------------------------------------------------------------------
    res = IngestResult(kind=kind, seq=seq, key_id=kid, server_time=iso(now))
    ingest = dict(ingest)
    ingest["last_env"] = {"kid": kid, "seq": seq, "sha": sha, "kind": kind}
    new_identity = dict(identity)
    node_ref = agent["node_ref"] or f"agent:{agent_id}"
    version = _agent_version(env.header["collectors"], parsed, kind) or agent["agent_version"]
    invalidate = False

    if kind == "posture":
        assert parsed is not None
        digest = content_digest(parsed)
        claimed_id = posture_identity(parsed)
        old_digest = ingest.get("digest")
        stored_at = _parse_stored(ingest.get("stored_at"))
        changed = digest != old_digest
        due = stored_at is None or (now - stored_at).total_seconds() >= HOURLY_S
        res.changed = changed
        res.stored = changed or due
        new_identity.update({"ips": claimed_id["ips"], "machine_id_hash": claimed_id["machine_id_hash"],
                             "boot_id": claimed_id["boot_id"], "peer_ip": client_ip})
        new_identity.setdefault("hostname", agent["hostname"])
        new_identity.setdefault("basis", "claimed")
        if res.stored:
            collected = parse_collected(parsed["collected_at"]) or env.issued
            collected = min(collected, env.issued)     # a claimed collection time can only make data OLDER
            await con.execute(
                """INSERT INTO agent_posture
                       (agent_id, key_id, seq, schema_version, collected_at, received_at, header, payload_raw,
                        payload_sha256, signature, signed, size_bytes)
                   VALUES ($1,$2,$3,2,$4,$5,$6::jsonb,$7,$8,$9,TRUE,$10)
                   ON CONFLICT (tenant_id, agent_id, key_id, seq) DO NOTHING""",
                agent_id, kid, seq, collected, now, json.dumps(env.header), payload, sha,
                b64u_decode(env.sig_b64), len(payload))
            ingest.update({"digest": digest, "stored_at": iso(now), "stored_seq": seq})
            node_ref, new_identity, ident_changed = await _resolve_node(
                con, agent_id, new_identity, node_ref, client_ip)
            invalidate = changed or ident_changed
    elif kind == "heartbeat":
        pass
    else:   # rotate: retire the old key BEFORE the new one becomes active (one active key per agent)
        assert new_pub is not None
        new_kid = fleet_enroll.key_id_for(new_pub)
        await con.execute(
            "UPDATE fleet_agent_keys SET status = 'rotated', retired_at = NOW() "
            "WHERE agent_id = $1 AND key_id = $2 AND status = 'active'", agent_id, kid)
        ins = await con.fetchrow(
            """INSERT INTO fleet_agent_keys (agent_id, key_id, public_key)
               VALUES ($1,$2,$3) ON CONFLICT (tenant_id, key_id) DO NOTHING RETURNING id""",
            agent_id, new_kid, new_pub)
        if ins is None:
            raise Rejection(409, "key_exists", "that public key is already registered")
        res.new_key_id = new_kid
        await audit.record(
            pool, action="fleet.agent.key_rotate", actor=f"agent:{agent['hostname']}", actor_role="agent",
            resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip,
            details={"old_key_id": kid, "new_key_id": new_kid, "seq": seq}, con=con, tenant_id=tenant_id)

    new_identity["_ingest"] = ingest
    came_online = agent["online"] is False
    await con.execute(
        """UPDATE fleet_agents SET last_seen = NOW(), status = 'online', online = TRUE, offline_since = NULL,
                  agent_version = COALESCE($2, agent_version), identity = $3::jsonb, node_ref = $4,
                  last_posture_at = CASE WHEN $5 THEN NOW() ELSE last_posture_at END,
                  last_posture_seq = CASE WHEN $5 THEN $6 ELSE last_posture_seq END
            WHERE id = $1""",
        agent_id, version, json.dumps(new_identity), node_ref, kind == "posture", seq)
    if came_online or invalidate:
        await invalidate_assurance(con)
    res.came_online = came_online
    if kind == "heartbeat":
        res.pending_actions = await _pending_actions(con, agent_id)
    res.agent = {"id": agent_id, "status": "online", "last_seen": now, "node_ref": node_ref}
    return res


async def _maybe_thread(size: int, fn: Any, arg: Any) -> Any:
    """Parsing/validating a big payload takes tens of milliseconds of CPU: keep it off the event loop."""
    if size > 64 * 1024:
        return await asyncio.get_running_loop().run_in_executor(None, fn, arg)
    return fn(arg)


def _parse_stored(text: Any) -> dt.datetime | None:
    if not isinstance(text, str):
        return None
    try:
        return parse_issued_at(text)
    except (ValueError, OverflowError):
        return None


def _agent_version(collectors: dict[str, str], parsed: Any, kind: str) -> str | None:
    v = collectors.get("agent")
    if kind == "heartbeat" and isinstance(parsed, dict) and parsed.get("agent_version"):
        v = parsed["agent_version"]
    if isinstance(v, str) and v and not _CTL_RE.search(v):
        return v[:64]
    return None


# --------------------------------------------------------------------------- #
# node identity (E3): claimed unless corroborated by something the host cannot forge
# --------------------------------------------------------------------------- #

_INSTANCE_TYPES = ("instance", "virtual_machine", "vm", "compute_instance")


def _norm_ips(values: Any) -> set[str]:
    out: set[str] = set()
    for v in values if isinstance(values, list) else [values] if isinstance(values, str) else []:
        try:
            ip = ipaddress.ip_address(str(v).strip())
        except ValueError:
            continue
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        out.add(ip.compressed.lower())
    return out


async def _resolve_node(con: Any, agent_id: uuid.UUID, identity: dict[str, Any], node_ref: str,
                        peer_ip: str | None) -> tuple[str, dict[str, Any], bool]:
    """Decide ``node_ref`` and ``identity.basis`` for this agent. Default and fallback: ``agent:<uuid>`` /
    ``claimed``. An agent is MERGED into a cloud instance node (``asset:<uuid>``, ``corroborated``) only when ALL hold:

    * its claimed bind addresses are a non-empty subset of the private IPs of exactly ONE cloud instance asset;
    * the address the SERVER saw the request come from (trusted-proxy aware) is one of that instance's private or
      public IPs. This is the part a compromised host cannot forge from another machine: without it any enrolled
      host could claim a victim instance's addresses and have its own "all closed" facts attached to the victim;
    * no other live agent claims that instance (by ``node_ref`` or by overlapping claimed addresses). Two agents
      claiming one cloud node merge NEITHER: the other one is demoted too, and the ambiguity is recorded.

    Returns ``(node_ref, identity, changed)``.
    """
    own = f"agent:{agent_id}"
    ips = sorted(_norm_ips(identity.get("ips")))
    peer = sorted(_norm_ips([peer_ip])) if peer_ip else []
    target: str | None = None
    note: str | None = None
    if ips:
        rows = await con.fetch(
            """SELECT id, metadata FROM assets
                WHERE kind = 'cloud_resource' AND (metadata->'private_ips') ?| $1::text[]""", ips)
        cands = []
        for r in rows:
            md = _loads(r["metadata"], {})
            if not isinstance(md, dict):
                continue
            if str(md.get("resource_type") or "").lower() not in _INSTANCE_TYPES:
                continue
            priv = _norm_ips(md.get("private_ips"))
            if set(ips) <= priv:
                cands.append((str(r["id"]), priv, _norm_ips(md.get("public_ips"))))
        if len(cands) == 1:
            aid, priv, pub = cands[0]
            if peer and peer[0] in (priv | pub):
                others = await con.fetch(
                    """SELECT id, node_ref, identity FROM fleet_agents
                        WHERE id <> $1 AND status <> 'revoked' AND legacy = FALSE""", agent_id)
                clash = []
                for o in others:
                    oi = _loads(o["identity"], {})
                    if o["node_ref"] == f"asset:{aid}" or (_norm_ips(oi.get("ips")) & priv):
                        clash.append(o["id"])
                if not clash:
                    target = f"asset:{aid}"
                else:
                    note = "ambiguous_cloud_node"
                    for oid in clash:       # neither merges
                        await con.execute(
                            "UPDATE fleet_agents SET node_ref = 'agent:' || id::text, "
                            "identity = jsonb_set(identity, '{basis}', '\"claimed\"') WHERE id = $1 "
                            "AND node_ref = $2", oid, f"asset:{aid}")
            else:
                note = "peer_address_not_instance"
        elif len(cands) > 1:
            note = "ambiguous_cloud_node"
    new = dict(identity)
    new["basis"] = "corroborated" if target else "claimed"
    if note:
        new["note"] = note
    else:
        new.pop("note", None)
    new_ref = target or own
    changed = new_ref != node_ref or new.get("basis") != identity.get("basis")
    return new_ref, new, changed


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #

async def latest_posture(pool: Any, agent_id: uuid.UUID) -> dict[str, Any] | None:
    """The newest STORED posture of an agent with the state of the key that signed it. ``None`` if none."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """SELECT p.id, p.agent_id, p.key_id, p.seq, p.schema_version, p.collected_at, p.received_at,
                      p.header, p.payload_raw, p.payload_sha256, p.signed, p.size_bytes,
                      k.status AS key_status
                 FROM agent_posture p
                 LEFT JOIN fleet_agent_keys k ON k.agent_id = p.agent_id AND k.key_id = p.key_id
                WHERE p.agent_id = $1
                ORDER BY p.received_at DESC, p.seq DESC LIMIT 1""", agent_id)
    if row is None:
        return None
    try:
        payload = json.loads(bytes(row["payload_raw"]).decode("utf-8"))
    except ValueError:
        payload = None
    return {
        "agent_id": row["agent_id"], "key_id": row["key_id"], "key_status": row["key_status"],
        "seq": row["seq"], "schema_version": row["schema_version"], "collected_at": row["collected_at"],
        "received_at": row["received_at"], "header": _loads(row["header"], {}),
        "payload_sha256": row["payload_sha256"], "size_bytes": row["size_bytes"], "signed": row["signed"],
        "tier": "configured", "payload": payload,
    }


async def list_keys(pool: Any, agent_id: uuid.UUID) -> list[dict[str, Any]]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """SELECT key_id, alg, status, last_seq, created_at, retired_at, revoked_at, revoke_reason
                 FROM fleet_agent_keys WHERE agent_id = $1 ORDER BY created_at, key_id""", agent_id)
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# admin: revoke an agent / a key
# --------------------------------------------------------------------------- #

async def revoke_agent(pool: Any, agent_id: uuid.UUID, *, actor: str, actor_role: str | None,
                       reason: str, client_ip: str | None = None,
                       request_id: str | None = None) -> str:
    """Revoke an agent NOW: ``status='revoked'``, ``revoked_at``, every active key revoked, its pending
    re-key tokens revoked, the assurance graph invalidated. The next call with its credential is a 403 (nothing
    is cached). Returns ``"revoked"``, ``"not_found"`` or ``"already_revoked"``."""
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                "SELECT id, hostname, status, revoked_at FROM fleet_agents WHERE id = $1 FOR UPDATE", agent_id)
            if row is None:
                return "not_found"
            if row["status"] == "revoked" or row["revoked_at"] is not None:
                return "already_revoked"
            await con.execute(
                """UPDATE fleet_agents SET status = 'revoked', revoked_at = NOW(), revoked_by = $2,
                          online = FALSE WHERE id = $1""", agent_id, actor)
            keys = await con.fetch(
                """UPDATE fleet_agent_keys SET status = 'revoked', revoked_at = NOW(), revoke_reason = $2
                    WHERE agent_id = $1 AND status = 'active' RETURNING key_id""",
                agent_id, (reason or "agent revoked")[:512])
            toks = await con.fetch(
                """UPDATE fleet_enroll_tokens SET revoked_at = NOW(), revoked_by = $2
                    WHERE for_agent = $1 AND revoked_at IS NULL AND uses < max_uses RETURNING token_prefix""",
                agent_id, actor)
            await invalidate_assurance(con)
            await audit.record(
                pool, action="fleet.agent.revoke", actor=actor, actor_role=actor_role,
                resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip, request_id=request_id,
                details={"hostname": row["hostname"], "reason": reason,
                         "revoked_keys": sorted(k["key_id"] for k in keys),
                         "revoked_rekey_tokens": sorted(t["token_prefix"] for t in toks)},
                con=con)
    return "revoked"


async def revoke_key(pool: Any, agent_id: uuid.UUID, key_id: str, *, actor: str, actor_role: str | None,
                     reason: str, client_ip: str | None = None, request_id: str | None = None) -> str:
    """Revoke one key of an agent (an active or a rotated one). Returns ``"revoked"``, ``"not_found"`` or
    ``"already_revoked"``. Revoking the active key leaves the agent unable to post until it is re-keyed."""
    async with pool.acquire() as con:
        async with con.transaction():
            ag = await con.fetchrow("SELECT id FROM fleet_agents WHERE id = $1 FOR UPDATE", agent_id)
            if ag is None:
                return "not_found"
            cur = await con.fetchrow(
                "SELECT status FROM fleet_agent_keys WHERE agent_id = $1 AND key_id = $2 FOR UPDATE",
                agent_id, key_id)
            if cur is None:
                return "not_found"
            if cur["status"] == "revoked":
                return "already_revoked"
            await con.execute(
                """UPDATE fleet_agent_keys SET status = 'revoked', revoked_at = NOW(), revoke_reason = $3
                    WHERE agent_id = $1 AND key_id = $2""", agent_id, key_id, (reason or "key revoked")[:512])
            await invalidate_assurance(con)
            await audit.record(
                pool, action="fleet.agent.key_revoke", actor=actor, actor_role=actor_role,
                resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip, request_id=request_id,
                details={"key_id": key_id, "was": cur["status"], "reason": reason}, con=con)
    return "revoked"


__all__ = [
    "Rejection", "PayloadError", "IngestResult", "Envelope", "ingest_envelope", "record_rejection",
    "validate_posture", "validate_heartbeat", "validate_rotate", "content_digest", "posture_identity",
    "inflate_body", "parse_envelope", "decode_payload", "verify_signature", "signing_input", "canon",
    "latest_posture", "list_keys", "revoke_agent", "revoke_key", "invalidate_assurance", "rate_limited",
    "reset_limiters",
]
