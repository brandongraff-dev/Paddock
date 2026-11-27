# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fake credentials for fixtures (contract 4.0.3).

Fixtures contain markers such as ``{{fake:aws_akia}}`` and never a literal token, so GitHub
secret scanning never sees one in the repository. Every family is assembled at run time from
fragments plus a deterministic body derived from sha256, so the value has the shape and the
entropy a detector expects while being neither random nor a real credential.

Marker grammar: ``{{fake:FAMILY}}`` or ``{{fake:FAMILY:N}}`` (N selects a different value).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER_DIGIT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_URLSAFE = _B62 + "_-"
_B64 = _B62 + "/+"
_LOWER_DIGIT = "abcdefghijklmnopqrstuvwxyz0123456789"


def _stream(seed: str):
    counter = 0
    while True:
        block = hashlib.sha256(("paddock-guard-fake|%s|%d" % (seed, counter)).encode()).digest()
        yield from block
        counter += 1


def _body(seed: str, n: int, alphabet: str, *, first: str | None = None) -> str:
    out = []
    gen = _stream(seed)
    for byte in gen:
        out.append(alphabet[byte % len(alphabet)])
        if len(out) >= n:
            break
    if first and not any(c in first for c in out):
        out[0] = first[0]
    return "".join(out)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(seed: str, payload: dict) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _body(seed + "|sig", 43, _URLSAFE)
    return "%s.%s.%s" % (head, body, sig)


def _aws_akia(seed: str) -> str:
    return "AK" + "IA" + _body(seed, 16, _UPPER_DIGIT)


def _aws_secret(seed: str) -> str:
    # 40 characters of [A-Za-z0-9/+=], mixed case, not pure hex (SEC-001 escalation shape).
    b = _body(seed, 40, _B64)
    return "Q" + "z" + b[2:]


def _gh_pat(seed: str) -> str:
    return "gh" + "p_" + _body(seed, 36, _B62)


def _gitlab_pat(seed: str) -> str:
    return "gl" + "pat-" + _body(seed, 20, _URLSAFE)


def _slack(seed: str) -> str:
    return "xo" + "xb-" + _body(seed + "a", 12, "0123456789") + "-" + _body(seed + "b", 12, "0123456789") \
        + "-" + _body(seed + "c", 24, _B62)


def _stripe_live(seed: str) -> str:
    return "sk_" + "live_" + _body(seed, 24, _B62)


def _stripe_whsec(seed: str) -> str:
    return "wh" + "sec_" + _body(seed, 32, _B62)


def _anthropic(seed: str) -> str:
    return "sk-" + "ant-api03-" + _body(seed, 90, _URLSAFE)


def _openai(seed: str) -> str:
    return "sk-" + "proj-" + _body(seed, 48, _URLSAFE)


def _sendgrid(seed: str) -> str:
    return "S" + "G." + _body(seed + "a", 22, _URLSAFE) + "." + _body(seed + "b", 43, _URLSAFE)


def _supabase_service_jwt(seed: str) -> str:
    return _jwt(seed, {"iss": "paddock-test", "ref": _body(seed, 20, _LOWER_DIGIT), "role": "service_role",
                       "iat": 1700000000, "exp": 2000000000})


def _supabase_anon_jwt(seed: str) -> str:
    return _jwt(seed, {"iss": "paddock-test", "ref": _body(seed, 20, _LOWER_DIGIT), "role": "anon",
                       "iat": 1700000000, "exp": 2000000000})


def _supabase_demo_service_jwt(seed: str) -> str:
    # Payload shape of the key the local Supabase stack publishes (iss "supabase-demo"); the
    # signature is fake. The exemption in SEC-006 is keyed on the issuer and on a hash table.
    return _jwt(seed, {"iss": "supabase-demo", "role": "service_role", "exp": 1983812996})


def _pem_rsa(seed: str) -> str:
    lines = [_body(seed + str(i), 64, _B64) for i in range(4)]
    last = _body(seed + "last", 44, _B62) + "=="
    return ("-----" + "BEGIN RSA " + "PRIVATE KEY-----\n" + "\n".join(lines) + "\n" + last + "\n"
            + "-----" + "END RSA " + "PRIVATE KEY-----\n")


def _db_url_pw(seed: str) -> str:
    return "post" + "gres://app:" + _body(seed, 20, _B62) + "@db." + _body(seed + "h", 10, _LOWER_DIGIT) \
        + ".supabase.co:5432/postgres"


_BUILDERS = {
    "aws_akia": _aws_akia,
    "aws_secret": _aws_secret,
    "gh_pat": _gh_pat,
    "gitlab_pat": _gitlab_pat,
    "slack": _slack,
    "stripe_live": _stripe_live,
    "stripe_whsec": _stripe_whsec,
    "anthropic": _anthropic,
    "openai": _openai,
    "sendgrid": _sendgrid,
    "supabase_service_jwt": _supabase_service_jwt,
    "supabase_anon_jwt": _supabase_anon_jwt,
    "supabase_demo_service_jwt": _supabase_demo_service_jwt,
    "pem_rsa": _pem_rsa,
    "db_url_pw": _db_url_pw,
}
FAMILIES: tuple[str, ...] = tuple(_BUILDERS)

_MARKER = re.compile(r"\{\{fake:([a-z0-9_]+)(?::(\d+))?\}\}")


def fake(family: str, variant: int = 1) -> str:
    """The fake credential of ``family``; ``variant`` selects a different deterministic value."""
    return _BUILDERS[family]("%s#%d" % (family, variant))


def expand_text(text: str) -> str:
    """Replace every ``{{fake:FAMILY[:N]}}`` marker; an unknown family raises ``KeyError``."""
    def sub(m: re.Match[str]) -> str:
        return fake(m.group(1), int(m.group(2) or 1))

    return _MARKER.sub(sub, text)


def has_markers(text: str) -> bool:
    return _MARKER.search(text) is not None
