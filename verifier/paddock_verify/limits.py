# SPDX-License-Identifier: Apache-2.0
"""Numeric limits of the specification, the pinned limits texts, and the integer threshold arithmetic.

Every number here is normative (spec/01-conventions.md, spec/07-verification-procedure.md). Integer arithmetic
only: a percentage or ratio is never compared as a float.
"""
from __future__ import annotations

import hashlib
import os
import re
from decimal import Decimal, ROUND_FLOOR
from typing import Dict, Optional

MAX_INT = 2 ** 53 - 1                       # largest integer a signed document may carry

MAX_PCJ_BYTES = 1 << 20                     # any PCJ document
MAX_PCJ_DEPTH = 16                          # nesting of any JSON file
MAX_STATEMENT_DEPTH = 8                     # nesting inside a statement
MAX_PAYLOAD_BYTES = 256 * 1024              # decoded statement payload
MAX_ENVELOPE_BYTES = 512 * 1024             # DSSE envelope as received
MAX_AUX_FILE_BYTES = 256 * 1024             # keys.json, revoked.json, policy and proof files
MAX_KEYS_FILE_BYTES = 64 * 1024             # keys.json as served by Paddock
MAX_RUN_BYTES = 8 * 1024 * 1024             # everything read in one run
MAX_RESULTS = 256
MAX_STRING_BYTES = 512
MAX_POLICY_YAML_BYTES = 64 * 1024
MAX_POLICY_YAML_DEPTH = 6

MAX_TTL_SECONDS = 7 * 86400                 # valid_until - issued_at
SKEW_SECONDS = 300                          # tolerated clock skew into the future
SNAPSHOT_MAX_GAP_SECONDS = 900              # issued_at - snapshot.at
REVOCATION_STALE_GRACE_SECONDS = 48 * 3600  # after next_update
DEFAULT_MAX_ANCHOR_AGE_SECONDS = 7200

MAX_DNS_RECORDS = 8                         # parsed per name
MAX_DNS_BYTES = 4096                        # all records of a name
MAX_DNS_RECORD_BYTES = 1024                 # one record after chunks are joined
DNS_GENERATE_CAP = 450                      # a generator never emits a longer record
DNS_GENERATE_WARN = 255

LIMITS_ID = "paddock-limits/1"
_LIMITS_FILES = {LIMITS_ID: "limits-v1.txt"}
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def read_data(name: str) -> bytes:
    """Bytes of a file from ``paddock_verify/data`` (the only place the package reads files from)."""
    with open(os.path.join(DATA_DIR, name), "rb") as fh:
        return fh.read()


def limits_text(limits_id: str) -> Optional[str]:
    """The pinned limits statement for ``limits_id``, or ``None`` when this verifier does not know the id."""
    name = _LIMITS_FILES.get(limits_id) if isinstance(limits_id, str) else None
    if name is None:
        return None
    return read_data(name).decode("ascii")


def limits_digest(limits_id: str) -> Optional[str]:
    """``sha256:<hex>`` of the exact bytes of the pinned text, or ``None`` for an unknown id."""
    name = _LIMITS_FILES.get(limits_id) if isinstance(limits_id, str) else None
    if name is None:
        return None
    return "sha256:" + hashlib.sha256(read_data(name)).hexdigest()


def known_limits_ids() -> Dict[str, str]:
    return {k: limits_digest(k) for k in _LIMITS_FILES}


# ---------------------------------------------------------------------------------------- coverage
def _is_int(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def coverage_meets(covered: int, universe: int, required_bp: int) -> bool:
    """``covered / universe >= required_bp / 10000`` by integer cross-multiplication.

    An empty universe is never covered, ``covered`` above ``universe`` is inconsistent, and a floor above
    10000 basis points cannot be met.
    """
    if not (_is_int(covered) and _is_int(universe) and _is_int(required_bp)):
        raise TypeError("integers required")
    if universe < 1 or covered < 0 or covered > universe or required_bp < 0 or required_bp > 10000:
        return False
    return covered * 10000 >= required_bp * universe


def required_bp_from_float(value: float) -> int:
    """``floor(Decimal(repr(value)) * 10000)``: the engine's float floor as integer basis points.

    Flooring means a statement never claims a stricter floor than the one that was applied.
    """
    if isinstance(value, bool) or not isinstance(value, float):
        raise TypeError("float required")
    if value != value or value < 0.0 or value > 1.0:
        raise ValueError("coverage floor must be within 0..1")
    return int((Decimal(repr(value)) * 10000).to_integral_value(rounding=ROUND_FLOOR))


_THRESHOLD = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,4})?\Z", re.ASCII)


def threshold_bp(text: str) -> int:
    """A consumer threshold such as ``0.95`` as basis points (at most four decimals, within 0..1)."""
    if not isinstance(text, str) or not _THRESHOLD.match(text):
        raise ValueError("a threshold is a decimal with at most four places, 0 to 1")
    d = Decimal(text)
    if d > 1:
        raise ValueError("a threshold above 1 can never be met")
    return int(d * 10000)
