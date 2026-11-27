# SPDX-License-Identifier: Apache-2.0
"""The revocation list ``revoked.json`` (spec/05-keys-certs-revocation-dns.md section 5), step 4.

A list counts only when it is a DSSE envelope of the right payload type, signed by the revoker or an issuer whose
certificate chains to a pinned root (valid when the list was issued), for this estate, and fresh. A missing list is
``revocation.missing``, one that fails these checks ``revocation.unverifiable`` and one past ``next_update + 48 h``
(or the policy's age) ``revocation.stale``; all are unverifiable, never accepted. Entries of an authentic list are
applied even when it is stale: a revocation always wins.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from . import canon, dsse, ed25519, jsonstrict, keys as keys_mod, limits, schema, timefmt
from .jsonstrict import JsonError

LIST_TYPE = "https://paddock.dev/revocation-list/v1"
REASONS = ("key_compromise", "superseded", "cessation")


class RevocationList(NamedTuple):
    estate: str
    seq: int
    issued_at: int
    next_update: int
    revoked: List[Tuple[str, str, int]]          # (kid, reason, revoked_at)
    superseded: List[Tuple[str, int]]            # (subject, min_seq)
    signer: str


class Evaluation(NamedTuple):
    status: str                                  # ok | stale | unverifiable | missing
    list: Optional[RevocationList]
    why: str                                     # a fixed token naming the failure (for params)


def _bad(why: str) -> Evaluation:
    return Evaluation("unverifiable", None, why)


def evaluate(data: Optional[bytes], keys: Optional[keys_mod.KeysDoc], roots: keys_mod.TrustRoots, estate: str, now: int,
             max_age_s: int = limits.REVOCATION_STALE_GRACE_SECONDS + 24 * 3600, seq_floor: int = 0) -> Evaluation:
    if data is None:
        return Evaluation("missing", None, "absent")
    if keys is None:
        return _bad("no_keys")
    try:
        env = dsse.parse_envelope(data, expected_type=dsse.PAYLOAD_TYPE_REVOCATION)
        doc = canon.roundtrip(env.payload)
    except JsonError:
        return _bad("malformed")
    parsed = _shape(doc)
    if parsed is None:
        return _bad("schema")
    pub = _signer_key(env.keyid, keys, roots, parsed.issued_at)
    if pub is None:
        return _bad("signer")
    if not keys_mod.verify_sig(pub, dsse.pae(dsse.PAYLOAD_TYPE_REVOCATION, env.payload), env.sig):
        return _bad("signature")
    lst = parsed._replace(signer=env.keyid)
    if lst.estate != estate:
        return _bad("estate")
    if lst.issued_at > now + limits.SKEW_SECONDS:
        return _bad("future")
    if lst.seq < seq_floor:
        return _bad("seq_rollback")
    if now > lst.next_update + limits.REVOCATION_STALE_GRACE_SECONDS or now - lst.issued_at > max_age_s:
        return Evaluation("stale", lst, "stale")
    return Evaluation("ok", lst, "")


def _shape(doc: Any) -> Optional[RevocationList]:
    if not isinstance(doc, dict) or set(doc) != {"_type", "estate", "seq", "issued_at", "next_update", "revoked", "superseded"}:
        return None
    if doc["_type"] != LIST_TYPE or not isinstance(doc["estate"], str) or not schema._ESTATE.match(doc["estate"]):
        return None
    if type(doc["seq"]) is not int or not 1 <= doc["seq"] <= limits.MAX_INT:
        return None
    try:
        issued, nxt = timefmt.parse(doc["issued_at"]), timefmt.parse(doc["next_update"])
    except (JsonError, TypeError):
        return None
    if nxt <= issued or not isinstance(doc["revoked"], list) or len(doc["revoked"]) > 64 \
            or not isinstance(doc["superseded"], list) or len(doc["superseded"]) > 11:
        return None
    revoked, superseded = [], []  # type: List[Tuple[str, str, int]], List[Tuple[str, int]]
    for e in doc["revoked"]:
        if not isinstance(e, dict) or set(e) != {"kid", "reason", "revoked_at"} or not isinstance(e["kid"], str) \
                or not schema._KID.match(e["kid"]) or e["reason"] not in REASONS:
            return None
        try:
            revoked.append((e["kid"], e["reason"], timefmt.parse(e["revoked_at"])))
        except (JsonError, TypeError):
            return None
    subjects = set()
    for e in doc["superseded"]:
        if not isinstance(e, dict) or set(e) != {"subject", "min_seq", "at"} or schema.parse_subject(e["subject"]) is None \
                or type(e["min_seq"]) is not int or not 1 <= e["min_seq"] <= limits.MAX_INT or e["subject"] in subjects:
            return None
        try:
            timefmt.parse(e["at"])
        except (JsonError, TypeError):
            return None
        subjects.add(e["subject"])
        superseded.append((e["subject"], e["min_seq"]))
    return RevocationList(doc["estate"], doc["seq"], issued, nxt, revoked, superseded, "")


def _signer_key(keyid: str, keys: keys_mod.KeysDoc, roots: keys_mod.TrustRoots, t: int) -> Optional[bytes]:
    """The public key of the list's signer if it is the revoker or an issuer chained to a pinned root at ``t``."""
    try:
        rev = keys_mod.parse_cert(keys.revoker)
    except ValueError:
        rev = None
    if rev is not None and rev.kid == keyid:
        chain = keys_mod.check_chain(keys.revoker, keys, roots, t, None, "revoke", None)
        return rev.public_key if not chain.codes else None
    for env in keys.issuers:
        try:
            c = keys_mod.parse_cert(env)
        except ValueError:
            continue
        if c.kid == keyid:
            chain = keys_mod.check_chain(env, keys, roots, t, None, "issue-cert", None)
            return c.public_key if not chain.codes else None
    pinned = roots.find(keyid, "issue-cert")
    if pinned is not None and pinned.not_before <= t < pinned.not_after:
        return pinned.public_key
    return None


class Finding(NamedTuple):
    code: str
    cls: str
    params: Dict[str, Any]


def apply(lst: RevocationList, kid: str, issued_at: int, subject: str, seq: int, issuer_kids: List[str]) -> List[Finding]:
    """What an authentic list says about this statement, in the order of the code table."""
    out = []  # type: List[Finding]
    # A list may name a kid more than once (the spec does not forbid it): every entry counts and the worst wins, so
    # the outcome never depends on the order of the entries. A revocation always beats a retirement warning.
    mine = [(reason, at) for rk, reason, at in lst.revoked if rk == kid]
    rejecting = [reason for reason, at in mine if reason == "key_compromise" or issued_at >= at]
    if rejecting:
        out.append(Finding("key.revoked", "R", {"reason": "key_compromise" if "key_compromise" in rejecting else rejecting[0]}))
    elif mine:
        out.append(Finding("key.revoked_superseded", "W", {"reason": mine[0][0]}))
    if any(rk in issuer_kids for rk, _r, _a in lst.revoked):
        out.append(Finding("issuer.revoked", "R", {}))
    for sub, min_seq in lst.superseded:
        if sub == subject and seq < min_seq:
            out.append(Finding("chain.superseded", "R", {"min_seq": min_seq}))
    return out
