# SPDX-License-Identifier: Apache-2.0
"""The ``_paddock-attest`` TXT record: parser and builder (spec/05-keys-certs-revocation-dns.md section 6).

One implementation, imported by the issuer's server side as well. The parser never raises: a record is ``ok``,
``ignored`` (an unknown version: forward compatibility, silent) or ``malformed`` (ignored with the warning
``dns.record_ignored``). The vectors in ``vectors/primitives/dns-txt-parse.json`` pin every rule.
"""
from __future__ import annotations

import re
from typing import List, NamedTuple, Optional, Sequence

from .. import limits

STATUS_OK, STATUS_IGNORED, STATUS_MALFORMED = "ok", "ignored", "malformed"
KEYS_MAX = 300
GENERATE_CAP = limits.DNS_GENERATE_CAP
GENERATE_WARN = limits.DNS_GENERATE_WARN
CHUNK = 255

_VERSION_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,16}\Z", re.ASCII)
_KEY = re.compile(r"[a-z][a-z0-9_-]*\Z", re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_FP = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)


class TxtResult(NamedTuple):
    status: str
    kid: Optional[str] = None
    fp: Optional[str] = None
    keys: Optional[str] = None


class RrsetResult(NamedTuple):
    too_many: bool
    records: List[TxtResult]


_MALFORMED = TxtResult(STATUS_MALFORMED)
_IGNORED = TxtResult(STATUS_IGNORED)


def parse_txt(strings: Sequence[str]) -> TxtResult:
    """Parse one TXT record given as its character strings (chunks are concatenated with no separator)."""
    try:
        return _parse(strings)
    except Exception:                                   # a hostile record must never become an exception
        return _MALFORMED


def _parse(strings: Sequence[str]) -> TxtResult:
    rec = "".join(strings)
    if len(rec) > limits.MAX_DNS_RECORD_BYTES:
        return _MALFORMED
    try:
        rec.encode("ascii")
    except UnicodeEncodeError:
        return _MALFORMED
    # version pre-scan: exactly one v= field holding a plain token other than 1 -> ignored without parsing further
    versions = []
    for field in rec.split(";"):
        field = field[1:] if field.startswith(" ") else field
        if field.startswith("v="):
            versions.append(field[2:])
    if len(versions) == 1 and versions[0] != "1" and _VERSION_TOKEN.match(versions[0]):
        return _IGNORED
    body = rec[:-1] if rec.endswith(";") else rec
    if body == "":
        return _MALFORMED
    pairs = []
    for i, field in enumerate(body.split(";")):
        if i > 0 and field.startswith(" "):
            field = field[1:]
        if field == "" or field != field.strip(" ") or "\t" in field or " " in field or "=" not in field:
            return _MALFORMED
        key, value = field.split("=", 1)
        if not _KEY.match(key):
            return _MALFORMED
        if value == "" or any(not 0x21 <= ord(c) <= 0x7E for c in value):
            return _MALFORMED
        pairs.append((key, value))
    names = [k for k, _ in pairs]
    if len(set(names)) != len(names):
        return _MALFORMED
    d = dict(pairs)
    if d.get("v") != "1":
        return _MALFORMED
    kid, fp = d.get("kid"), d.get("fp")
    if kid is None or fp is None or not _HEX32.match(kid) or not _FP.match(fp) or fp[7:39] != kid:
        return _MALFORMED
    keys = d.get("keys")
    if keys is not None and (not keys.startswith("https://") or len(keys) <= len("https://") or len(keys) > KEYS_MAX):
        return _MALFORMED
    return TxtResult(STATUS_OK, kid, fp, keys)


def parse_rrset(records: Sequence[Sequence[str]]) -> RrsetResult:
    """Parse every record under the name. More than 8 records or 4 KiB in total is ``too_many`` (a DoS guard)."""
    total = sum(len("".join(r)) for r in records)
    if len(records) > limits.MAX_DNS_RECORDS or total > limits.MAX_DNS_BYTES:
        return RrsetResult(True, [])
    return RrsetResult(False, [parse_txt(r) for r in records])


def build_txt(kid: str, fp: str, keys: Optional[str] = None) -> str:
    """The record text a publisher adds. Refuses a record the parser would not accept and anything over 450 bytes."""
    if not isinstance(kid, str) or not _HEX32.match(kid) or not isinstance(fp, str) or not _FP.match(fp) or fp[7:39] != kid:
        raise ValueError("kid must be 32 lowercase hex and the first half of fp (sha256:<64 hex>)")
    text = "v=1; kid=%s; fp=%s" % (kid, fp)
    if keys is not None:
        if not isinstance(keys, str) or not keys.startswith("https://") or len(keys) <= len("https://") or len(keys) > KEYS_MAX \
                or any(not 0x21 <= ord(c) <= 0x7E or c == ";" for c in keys):
            raise ValueError("keys must be an https URL of at most %d printable characters without ';'" % KEYS_MAX)
        text += "; keys=" + keys
    if len(text) > GENERATE_CAP:
        raise ValueError("record is %d bytes, over the %d byte cap" % (len(text), GENERATE_CAP))
    return text


def needs_split(text: str) -> bool:
    """True when the record exceeds one 255 byte character string (legal, but worth a warning above 255)."""
    return len(text) > GENERATE_WARN


def chunk_txt(text: str, size: int = CHUNK) -> List[str]:
    """Split into character strings of at most ``size`` bytes; the parser joins them with no separator."""
    if size < 1:
        raise ValueError("size")
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]
