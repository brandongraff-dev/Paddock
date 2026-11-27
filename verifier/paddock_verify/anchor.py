# SPDX-License-Identifier: Apache-2.0
"""Step 10: the audit anchor and the Merkle inclusion proofs (spec/B-anchor-v2.md, spec/04-merkle.md).

An outsider can check that the anchor is signed by a certified, unrevoked estate anchor key, that it names the
statement's estate and agrees with the statement's ``audit_anchor``, and how old it is. It cannot check that the
audit rows are intact: the chain is a keyed hash. Proofs are checked against the statement's own roots and sizes.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, List, NamedTuple, Optional

from . import b64, canon, ed25519, jsonstrict, keys as keys_mod, limits, merkle, schema, timefmt
from .jsonstrict import JsonError

CONTEXT = b"paddock-anchor/v2\n"
_FIELDS = {"alg", "at", "estate", "hash_alg", "head", "kid", "max_id", "sig", "v"}


class AnchorFinding(NamedTuple):
    code: str
    params: Dict[str, Any]


def parse_anchor(data: bytes) -> Dict[str, Any]:
    """The anchor document, or ``ValueError`` carrying the reason code (``anchor.invalid`` or ``anchor.not_ed25519``)."""
    try:
        doc = canon.roundtrip(data)
    except JsonError:
        raise ValueError("anchor.invalid") from None
    if not isinstance(doc, dict):
        raise ValueError("anchor.invalid")
    if doc.get("v") != 2 or type(doc.get("v")) is not int or doc.get("alg") != "ed25519":
        raise ValueError("anchor.not_ed25519")          # a v1 HMAC anchor, or any other format
    if set(doc) != _FIELDS or not isinstance(doc["estate"], str) or not schema._ESTATE.match(doc["estate"]) \
            or doc["hash_alg"] not in schema.HASH_ALGS or not isinstance(doc["head"], str) or not schema._HEX64.match(doc["head"]) \
            or not isinstance(doc["kid"], str) or not schema._KID.match(doc["kid"]) or type(doc["max_id"]) is not int \
            or not 0 <= doc["max_id"] <= limits.MAX_INT:
        raise ValueError("anchor.invalid")
    try:
        timefmt.parse(doc["at"])
        sig = b64.strict_decode(doc["sig"])
    except (JsonError, TypeError):
        raise ValueError("anchor.invalid") from None
    if len(sig) != 64:
        raise ValueError("anchor.invalid")
    return doc


def check_anchor(data: bytes, claimed: Optional[Dict[str, Any]], estate: str, issued_at: int, keys: Optional[keys_mod.KeysDoc],
                 roots: keys_mod.TrustRoots, revoked: Optional[Any], max_age_s: int) -> List[AnchorFinding]:
    """Findings for an anchor document against the statement's ``audit_anchor`` (``claimed``)."""
    try:
        doc = parse_anchor(data)
    except ValueError as e:
        return [AnchorFinding(str(e), {})]
    at = timefmt.parse(doc["at"])
    if keys is None:
        return [AnchorFinding("anchor.invalid", {"why": "no_keys"})]
    entry = keys.entries.get(doc["kid"])
    if entry is None or entry.usage != "anchor" or entry.alg != keys_mod.ALG:
        return [AnchorFinding("anchor.invalid", {"why": "key"})]
    chain = keys_mod.check_chain(entry.cert, keys, roots, at, None, "anchor", estate, entry)
    if chain.codes:
        return [AnchorFinding("anchor.invalid", {"why": "certificate"})]
    for rk, reason, rat in getattr(revoked, "revoked", []) or []:
        if rk == doc["kid"] and (reason == "key_compromise" or at >= rat):
            return [AnchorFinding("anchor.invalid", {"why": "revoked"})]
    body = dict((k, v) for k, v in doc.items() if k != "sig")
    if not keys_mod.verify_sig(entry.public_key, CONTEXT + canon.dumps(body), b64.strict_decode(doc["sig"])):
        return [AnchorFinding("anchor.invalid", {"why": "signature"})]
    out = []  # type: List[AnchorFinding]
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if doc["estate"] != estate or claimed is None or any(claimed.get(k) != doc[k] for k in ("max_id", "head", "hash_alg", "at", "kid")) \
            or claimed.get("digest") != digest:
        out.append(AnchorFinding("anchor.mismatch", {}))
    if issued_at - at > max_age_s:
        out.append(AnchorFinding("anchor.too_old", {"max_age_s": max_age_s}))
    return out


# ------------------------------------------------------------------------------------------------ proofs
ProofLoader = Callable[[int], Optional[Dict[str, bytes]]]


def check_proofs(loader: ProofLoader, predicate: Dict[str, Any]) -> List[AnchorFinding]:
    """Verify every proof file offered for this statement's ``seq`` against the statement's roots.

    ``loader(seq)`` returns ``{file name: bytes}`` or ``None`` when nothing was supplied for that sequence number.
    """
    files = loader(predicate["seq"])
    if not files:
        return [AnchorFinding("merkle.proof_missing", {})]
    out = []  # type: List[AnchorFinding]
    seen = 0
    for name in sorted(files):
        target = _target(name, predicate)
        if target is None:
            continue
        seen += 1
        tree, root, size = target
        try:
            proof = jsonstrict.parse(files[name], max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_AUX_FILE_BYTES)
            if tree is None:
                raise merkle.MerkleError("no result carries this blind-spot tree")
            merkle.verify_proof(proof, root, expected_tree=tree, expected_size=size if size >= 1 else None)
            if size < 1:
                raise merkle.MerkleError("an empty tree has no leaves to prove")
        except (JsonError, merkle.MerkleError):
            out.append(AnchorFinding("merkle.proof_invalid", {}))
            break
    if seen == 0 and not out:
        return [AnchorFinding("merkle.proof_missing", {})]
    return out


def _target(name: str, predicate: Dict[str, Any]):
    """(tree label or None, root, size) for a proof file name, or ``None`` for a file that is not a proof."""
    if name == "graph.json":
        g = predicate["snapshot"]["graph"]
        return "graph", g["root"], g["size"]
    if name == "policy.json":
        return "policy", predicate["policy"]["commitment"], predicate["policy"]["total"]
    if name.startswith("blind__") and name.endswith(".json"):
        inv = name[len("blind__"):-len(".json")].replace("__", ":")
        for r in predicate["results"]:
            if r["invariant"] == inv:
                b = r["blind_spots"]
                return "blind", b["root"], b["size"]
        return None, "sha256:" + "0" * 64, 0
    return None
