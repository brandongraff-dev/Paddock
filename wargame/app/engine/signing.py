"""Hash-chained, key-bound proof entries for a proving-ground run.

A run emits a short sequence of proof entries (setup -> before -> fix -> after
-> summary). Each entry is chained to the previous one and signed, so the
sequence an insurer or auditor later reads cannot be forged, reordered, or
silently truncated -- even though the tenant runs the service:

    payload_hash = sha256(canonical_json(payload))
    entry_hash   = sha256(prev_hash || payload_hash || phase || seq)
    signature    = HMAC-SHA256(key, entry_hash)           (hex; None if unkeyed)

``prev_hash`` of the first entry is the genesis (64 zeros). A verifier replays
the chain: recompute each payload_hash and entry_hash, check it matches the
stored one, check the signature, and check seq is dense from 0. Any edit to a
payload, any dropped or reordered entry, breaks the chain.

In production the signing key is hardware-/KMS-bound and the service never sees
the raw bytes; here it comes from WARGAME_SIGNING_SECRET. An empty secret means
"unsigned dev mode": the hash chain still protects integrity, but entries carry
no signature and a verifier reports them unsigned.

This module is pure (no DB, no I/O) so it is fully unit-testable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Optional

GENESIS_HASH = "0" * 64
MAX_PAYLOAD_BYTES = 8192
_MAX_STR = 500

# Keys whose values are redacted wholesale (defence in depth; scenarios should
# already redact credentials before they reach here).
_SECRET_KEYS = ("password", "passwd", "secret", "token", "credential", "apikey", "api_key", "key")


def _redact_value(k: str, v: Any) -> Any:
    kl = str(k).lower()
    if any(s in kl for s in _SECRET_KEYS) and isinstance(v, str):
        return "<redacted>"
    if isinstance(v, str):
        return v if len(v) <= _MAX_STR else v[:_MAX_STR] + "..."
    if isinstance(v, (list, tuple)):
        return [_redact_value(k, x) for x in list(v)[:50]]
    if isinstance(v, dict):
        return {str(ik): _redact_value(ik, iv) for ik, iv in list(v.items())[:50]}
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    return str(v)[:_MAX_STR]


def redact_and_cap(payload: dict[str, Any], limit: int = MAX_PAYLOAD_BYTES) -> dict[str, Any]:
    """Redact secret-shaped values and clip the whole payload to ``limit`` bytes
    of canonical JSON (dropping the largest values first)."""
    out = {str(k): _redact_value(k, v) for k, v in (payload or {}).items()}
    while len(canonical_json(out).encode("utf-8")) > limit and out:
        biggest = max(out, key=lambda k: len(canonical_json({k: out[k]})))
        if len(out) == 1:
            out[biggest] = "<truncated>"
            break
        del out[biggest]
        out["truncated"] = True
    return out


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, ensure_ascii."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def payload_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def entry_hash(prev_hash: str, p_hash: str, phase: str, seq: int) -> str:
    material = f"{prev_hash}|{p_hash}|{phase}|{seq}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


@dataclass
class ProofEntry:
    seq: int
    phase: str
    prev_hash: str
    payload_hash: str
    entry_hash: str
    signature: Optional[str]
    key_id: Optional[str]
    payload: dict[str, Any]

    def as_row(self) -> dict[str, Any]:
        """Shape for the wargame_proofs INSERT (tenant_id filled by RLS)."""
        return {
            "seq": self.seq,
            "phase": self.phase,
            "prev_hash": self.prev_hash,
            "payload_hash": self.payload_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "key_id": self.key_id,
            "payload": self.payload,
        }


class ProofSigner:
    """Key-bound MAC over entry hashes. Empty secret => unsigned dev mode."""

    def __init__(self, key_id: str = "dev-local", secret: str = "") -> None:
        self.key_id = key_id
        self._secret = (secret or "").encode("utf-8")

    @property
    def active(self) -> bool:
        return bool(self._secret)

    def sign(self, entry_hash_hex: str) -> Optional[str]:
        if not self._secret:
            return None
        return hmac.new(self._secret, entry_hash_hex.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, entry_hash_hex: str, signature: Optional[str]) -> bool:
        expected = self.sign(entry_hash_hex)
        if expected is None:
            return signature is None  # unsigned mode: only an absent sig is valid
        if signature is None:
            return False
        return hmac.compare_digest(expected, signature)


class ProofChain:
    """Builds the sequential, chained, signed proof entries for one run."""

    def __init__(self, signer: ProofSigner) -> None:
        self._signer = signer
        self._prev = GENESIS_HASH
        self._seq = 0
        self.entries: list[ProofEntry] = []

    def add(self, phase: str, payload: dict[str, Any]) -> ProofEntry:
        clean = redact_and_cap(payload)
        p_hash = payload_hash(clean)
        e_hash = entry_hash(self._prev, p_hash, phase, self._seq)
        entry = ProofEntry(
            seq=self._seq,
            phase=phase,
            prev_hash=self._prev,
            payload_hash=p_hash,
            entry_hash=e_hash,
            signature=self._signer.sign(e_hash),
            key_id=self._signer.key_id if self._signer.active else None,
            payload=clean,
        )
        self.entries.append(entry)
        self._prev = e_hash
        self._seq += 1
        return entry


def verify_chain(
    entries: list[dict[str, Any]], signer: ProofSigner
) -> tuple[bool, str]:
    """Replay a stored proof chain. ``entries`` are dicts with the wargame_proofs
    columns (ordered any way; sorted here by seq). Returns (ok, reason)."""
    if not entries:
        return False, "empty chain"
    rows = sorted(entries, key=lambda r: r["seq"])
    prev = GENESIS_HASH
    for i, row in enumerate(rows):
        if row["seq"] != i:
            return False, f"non-dense seq at position {i}: got {row['seq']}"
        if row["prev_hash"] != prev:
            return False, f"broken link at seq {row['seq']}: prev_hash mismatch"
        p_hash = payload_hash(row.get("payload") or {})
        if row["payload_hash"] != p_hash:
            return False, f"payload tampered at seq {row['seq']}"
        e_hash = entry_hash(prev, p_hash, row["phase"], row["seq"])
        if row["entry_hash"] != e_hash:
            return False, f"entry_hash mismatch at seq {row['seq']}"
        if not signer.verify(e_hash, row.get("signature")):
            return False, f"bad signature at seq {row['seq']}"
        prev = e_hash
    return True, "ok"
