# SPDX-License-Identifier: Apache-2.0
"""Step 1: the shape of a statement (spec/02-statement-predicate.md, spec/07 step 1).

``validate_statement`` returns the issues found, in a fixed traversal order, as ``(code, path)`` pairs. Paths are
built only from this module's own field names and list indexes, never from attacker text. The predicate is strict:
an unknown key anywhere is ``schema.field_unknown``. Windows and counts that only make sense on authentic data
(``time.*``) are not judged here; the structural count rules are.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from . import limits, timefmt

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://paddock.dev/attestation/containment/v1"
ENGINE_NAME = "paddock-assurance"

ASSERTIONS = ("unreachable", "exposes-only", "covered", "host-config")
VERDICTS = ("HOLDS", "VIOLATED", "UNKNOWN")
TIERS = ("declared", "configured", "observed", "tested")
HASH_ALGS = ("sha256", "hmac-sha256")
DISCLOSURE_VERDICTS = ("holds_only", "all")

_H = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_ESTATE = re.compile(r"e_[a-z2-7]{26}\Z", re.ASCII)
_INV = re.compile(r"[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}\Z", re.ASCII)
_LIMITS_ID = re.compile(r"paddock-limits/[0-9]+\Z", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)

_TOP = ("_type", "subject", "predicateType", "predicate")
_PRED_REQUIRED = ("estate", "seq", "issued_at", "valid_until", "kid", "snapshot", "scope", "policy", "disclosure", "results", "engine", "limits")
_PRED_OPTIONAL = ("prev", "audit_anchor")
_COMMON = ("invariant", "digest", "assertion", "verdict", "min_tier", "max_age_s", "coverage", "blind_spots", "selected", "exceptions")
_SPECIFIC = {"HOLDS": ("tier", "valid_until"), "VIOLATED": ("violations",), "UNKNOWN": ("reason_codes",)}
_ALL_SPECIFIC = frozenset(k for v in _SPECIFIC.values() for k in v)
REASON_CODES = (
    "coverage_below_required", "possible_via_unknown_edges", "zone_unknown", "selection_too_large", "host_evidence_unusable",
    "stale_or_missing_evidence", "empty_selector", "graph_incomplete", "invalid_definition", "evaluation_error", "other")


class Issue(NamedTuple):
    code: str
    path: str


class Subject(NamedTuple):
    name: str
    kind: str                   # dns | estate
    value: str                  # the domain or the estate id


def parse_subject(name: Any) -> Optional[Subject]:
    """The structured subject for a valid name, else ``None``."""
    if not isinstance(name, str) or len(name) > 260:
        return None
    if name.startswith("paddock-estate:"):
        v = name[len("paddock-estate:"):]
        return Subject(name, "estate", v) if _ESTATE.match(v) else None
    if name.startswith("dns:"):
        d = name[4:]
        labels = d.split(".")
        if not 3 <= len(d) <= 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
            return None
        if labels[-1].isdigit():
            return None
        try:
            ipaddress.ip_address(d)
            return None
        except ValueError:
            pass
        return Subject(name, "dns", d)
    return None


class _V(object):
    def __init__(self) -> None:
        self.issues = []  # type: List[Issue]

    def add(self, code: str, path: str) -> None:
        self.issues.append(Issue(code, path))

    # -- scalar rules
    def uint(self, d: Dict[str, Any], key: str, path: str, minimum: int = 0, maximum: int = limits.MAX_INT) -> Optional[int]:
        v = d.get(key)
        if type(v) is not int or not minimum <= v <= maximum:
            self.add("schema.field_invalid", "%s.%s" % (path, key))
            return None
        return v

    def boolean(self, d: Dict[str, Any], key: str, path: str) -> Optional[bool]:
        v = d.get(key)
        if type(v) is not bool:
            self.add("schema.field_invalid", "%s.%s" % (path, key))
            return None
        return v

    def rx(self, d: Dict[str, Any], key: str, rx: "re.Pattern[str]", path: str, code: str = "schema.digest_format") -> Optional[str]:
        v = d.get(key)
        if not isinstance(v, str):
            self.add("schema.field_invalid", "%s.%s" % (path, key))
            return None
        if not rx.match(v):
            self.add(code, "%s.%s" % (path, key))
            return None
        return v

    def time(self, d: Dict[str, Any], key: str, path: str) -> Optional[int]:
        v = d.get(key)
        if not isinstance(v, str):
            self.add("schema.field_invalid", "%s.%s" % (path, key))
            return None
        try:
            return timefmt.parse(v)
        except timefmt.TimeError:
            self.add("schema.time_format", "%s.%s" % (path, key))
            return None

    def enum(self, d: Dict[str, Any], key: str, allowed: Tuple[str, ...], path: str) -> Optional[str]:
        v = d.get(key)
        if not isinstance(v, str):
            self.add("schema.field_invalid", "%s.%s" % (path, key))
            return None
        if v not in allowed:
            self.add("schema.enum_unknown", "%s.%s" % (path, key))
            return None
        return v

    def obj(self, d: Dict[str, Any], key: str, required: Tuple[str, ...], path: str, optional: Tuple[str, ...] = ()) -> Optional[Dict[str, Any]]:
        v = d.get(key)
        here = "%s.%s" % (path, key)
        if not isinstance(v, dict):
            self.add("schema.field_invalid", here)
            return None
        self.keys(v, required, optional, here)
        return v

    def keys(self, v: Dict[str, Any], required: Tuple[str, ...], optional: Tuple[str, ...], here: str) -> None:
        allowed = set(required) | set(optional)
        if any(k not in allowed for k in v):
            self.add("schema.field_unknown", here)
        for k in required:
            if k not in v:
                self.add("schema.field_invalid", "%s.%s" % (here, k))


def _long_string(value: Any, depth: int = 0) -> bool:
    """True if any string (or key) in the document is over 512 bytes. Iterative: the parser already bounded depth."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if len(v) > limits.MAX_STRING_BYTES:
                return True
        elif isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                if len(k) > limits.MAX_STRING_BYTES:
                    return True
                stack.append(x)
    return False


def validate_statement(doc: Any) -> Tuple[List[Issue], bool]:
    """``(issues, unsupported)``. ``unsupported`` is True when the predicateType is a string this verifier does not
    know: the predicate is then not interpreted at all and the caller reports ``predicate.unsupported_version``."""
    v = _V()
    if not isinstance(doc, dict):
        v.add("schema.statement_invalid", "statement")
        return v.issues, False
    if _long_string(doc):
        v.add("schema.limit_exceeded", "statement")
        return v.issues, False
    if any(k not in _TOP for k in doc):
        v.add("schema.field_unknown", "statement")
    if any(k not in doc for k in _TOP) or doc.get("_type") != STATEMENT_TYPE:
        v.add("schema.statement_invalid", "statement")
        return v.issues, False
    _subject(doc["subject"], v)
    ptype = doc["predicateType"]
    if not isinstance(ptype, str):
        v.add("schema.statement_invalid", "statement.predicateType")
        return v.issues, False
    if ptype != PREDICATE_TYPE:
        return v.issues, True
    pred = doc["predicate"]
    if not isinstance(pred, dict):
        v.add("schema.field_invalid", "predicate")
        return v.issues, False
    _predicate(pred, v)
    return v.issues, False


def _subject(subject: Any, v: _V) -> None:
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        v.add("schema.subject_invalid", "subject")
        return
    s = subject[0]
    if set(s) != {"name", "digest"} or not isinstance(s["digest"], dict) or set(s["digest"]) != {"sha256"}:
        v.add("schema.subject_invalid", "subject[0]")
        return
    parsed = parse_subject(s["name"])
    digest = s["digest"]["sha256"]
    if parsed is None or not isinstance(digest, str) or digest != hashlib.sha256(s["name"].encode("ascii")).hexdigest():
        v.add("schema.subject_invalid", "subject[0]")


def _predicate(p: Dict[str, Any], v: _V) -> None:
    path = "predicate"
    if any(k not in _PRED_REQUIRED and k not in _PRED_OPTIONAL for k in p):
        v.add("schema.field_unknown", path)
    for k in _PRED_REQUIRED:
        if k not in p:
            v.add("schema.field_invalid", "%s.%s" % (path, k))
    v.rx(p, "estate", _ESTATE, path) if "estate" in p else None
    seq = v.uint(p, "seq", path, minimum=1) if "seq" in p else None
    if seq is not None:
        if (seq > 1) != ("prev" in p):
            v.add("schema.seq_prev_invalid", "%s.prev" % path)
    if "prev" in p:
        v.rx(p, "prev", _H, path)
    if "issued_at" in p:
        v.time(p, "issued_at", path)
    if "valid_until" in p:
        v.time(p, "valid_until", path)
    if "kid" in p:
        v.rx(p, "kid", _KID, path)
    snap = v.obj(p, "snapshot", ("at", "graph"), path) if "snapshot" in p else None
    if snap is not None:
        v.time(snap, "at", "predicate.snapshot") if "at" in snap else None
        g = v.obj(snap, "graph", ("root", "size"), "predicate.snapshot") if "graph" in snap else None
        if g is not None:
            v.rx(g, "root", _H, "predicate.snapshot.graph") if "root" in g else None
            v.uint(g, "size", "predicate.snapshot.graph") if "size" in g else None
    sc = v.obj(p, "scope", ("digest", "entries", "unproven", "private"), path) if "scope" in p else None
    if sc is not None:
        v.rx(sc, "digest", _H, "predicate.scope") if "digest" in sc else None
        for k in ("entries", "unproven", "private"):
            v.uint(sc, k, "predicate.scope") if k in sc else None
    pol = v.obj(p, "policy", ("commitment", "total", "enabled_std", "enabled_custom", "disclosed", "versions"), path) if "policy" in p else None
    counts = {}  # type: Dict[str, Optional[int]]
    if pol is not None:
        v.rx(pol, "commitment", _H, "predicate.policy") if "commitment" in pol else None
        for k in ("total", "enabled_std", "enabled_custom", "disclosed", "versions"):
            counts[k] = v.uint(pol, k, "predicate.policy") if k in pol else None
    dis = v.obj(p, "disclosure", ("verdicts", "custom"), path) if "disclosure" in p else None
    if dis is not None:
        v.enum(dis, "verdicts", DISCLOSURE_VERDICTS, "predicate.disclosure") if "verdicts" in dis else None
        v.boolean(dis, "custom", "predicate.disclosure") if "custom" in dis else None
    results = p.get("results")
    n_results = None  # type: Optional[int]
    if "results" in p:
        if not isinstance(results, list):
            v.add("schema.field_invalid", "predicate.results")
        elif len(results) > limits.MAX_RESULTS:
            v.add("schema.limit_exceeded", "predicate.results")
        else:
            n_results = len(results)
            _results(results, v)
    eng = v.obj(p, "engine", ("name", "version", "ruleset"), path) if "engine" in p else None
    if eng is not None:
        v.enum(eng, "name", (ENGINE_NAME,), "predicate.engine") if "name" in eng else None
        v.rx(eng, "version", _VERSION, "predicate.engine", "schema.field_invalid") if "version" in eng else None
        v.rx(eng, "ruleset", _H, "predicate.engine") if "ruleset" in eng else None
    if "audit_anchor" in p:
        a = v.obj(p, "audit_anchor", ("max_id", "head", "hash_alg", "at", "kid", "digest"), path)
        if a is not None:
            v.uint(a, "max_id", "predicate.audit_anchor") if "max_id" in a else None
            v.rx(a, "head", _HEX64, "predicate.audit_anchor") if "head" in a else None
            v.enum(a, "hash_alg", HASH_ALGS, "predicate.audit_anchor") if "hash_alg" in a else None
            v.time(a, "at", "predicate.audit_anchor") if "at" in a else None
            v.rx(a, "kid", _KID, "predicate.audit_anchor") if "kid" in a else None
            v.rx(a, "digest", _H, "predicate.audit_anchor") if "digest" in a else None
    lim = v.obj(p, "limits", ("id", "digest"), path) if "limits" in p else None
    if lim is not None:
        v.rx(lim, "id", _LIMITS_ID, "predicate.limits", "schema.field_invalid") if "id" in lim else None
        v.rx(lim, "digest", _H, "predicate.limits") if "digest" in lim else None
    # structural count rules
    if all(counts.get(k) is not None for k in ("total", "enabled_std", "enabled_custom", "disclosed")) and n_results is not None:
        enabled = counts["enabled_std"] + counts["enabled_custom"]  # type: ignore[operator]
        if counts["disclosed"] != n_results or counts["disclosed"] > enabled or enabled > counts["total"]:  # type: ignore[operator]
            v.add("schema.counts_inconsistent", "predicate.policy")


def _results(results: List[Any], v: _V) -> None:
    ids = []  # type: List[str]
    for i, r in enumerate(results):
        path = "predicate.results[%d]" % i
        if not isinstance(r, dict):
            v.add("schema.field_invalid", path)
            continue
        inv = _result(r, path, v)
        if inv is not None:
            ids.append(inv)
    if len(set(ids)) != len(ids):
        v.add("schema.result_duplicate", "predicate.results")
    if any(a.encode("ascii") > b.encode("ascii") for a, b in zip(ids, ids[1:])):
        v.add("schema.result_unsorted", "predicate.results")


def _result(r: Dict[str, Any], path: str, v: _V) -> Optional[str]:
    verdict = r.get("verdict")
    specific = _SPECIFIC.get(verdict) if isinstance(verdict, str) else None
    for k in r:
        if k in _COMMON or (specific is not None and k in specific) or (specific is None and k in _ALL_SPECIFIC):
            continue
        if k in _ALL_SPECIFIC:
            v.add("schema.result_inconsistent", path)
        else:
            v.add("schema.field_unknown", path)
    for k in _COMMON:
        if k not in r:
            v.add("schema.field_invalid", "%s.%s" % (path, k))
    inv = v.rx(r, "invariant", _INV, path) if "invariant" in r else None
    v.rx(r, "digest", _H, path) if "digest" in r else None
    v.enum(r, "assertion", ASSERTIONS, path) if "assertion" in r else None
    if "verdict" in r:
        v.enum(r, "verdict", VERDICTS, path)
    v.enum(r, "min_tier", TIERS, path) if "min_tier" in r else None
    v.uint(r, "max_age_s", path) if "max_age_s" in r else None
    v.uint(r, "exceptions", path) if "exceptions" in r else None
    cov = v.obj(r, "coverage", ("universe", "covered", "required_bp", "estate_universe", "estate_covered"), path) if "coverage" in r else None
    if cov is not None:
        c = path + ".coverage"
        for k in ("universe", "covered", "estate_universe", "estate_covered"):
            v.uint(cov, k, c) if k in cov else None
        v.uint(cov, "required_bp", c, maximum=10000) if "required_bp" in cov else None
    bs = v.obj(r, "blind_spots", ("root", "size", "truncated"), path) if "blind_spots" in r else None
    if bs is not None:
        v.rx(bs, "root", _H, path + ".blind_spots") if "root" in bs else None
        v.uint(bs, "size", path + ".blind_spots") if "size" in bs else None
        v.boolean(bs, "truncated", path + ".blind_spots") if "truncated" in bs else None
    sel = v.obj(r, "selected", ("to",), path, ("from", "stop_at")) if "selected" in r else None
    if sel is not None:
        for k in ("to", "from", "stop_at"):
            v.uint(sel, k, path + ".selected") if k in sel else None
    if specific is None:
        return inv
    for k in specific:
        if k not in r:
            v.add("schema.result_inconsistent", path)
    if verdict == "HOLDS":
        v.enum(r, "tier", TIERS, path) if "tier" in r else None
        v.time(r, "valid_until", path) if "valid_until" in r else None
    elif verdict == "VIOLATED":
        if "violations" in r:
            n = r["violations"]
            if type(n) is not int or n < 0 or n > limits.MAX_INT:
                v.add("schema.field_invalid", path + ".violations")
            elif n < 1:
                v.add("schema.result_inconsistent", path)
    else:
        codes = r.get("reason_codes")
        if "reason_codes" in r:
            if not isinstance(codes, list) or any(not isinstance(c, str) for c in codes):
                v.add("schema.field_invalid", path + ".reason_codes")
            else:
                if not codes or codes != sorted(set(codes)):
                    v.add("schema.result_inconsistent", path)
                if any(c not in REASON_CODES for c in codes):
                    v.add("schema.enum_unknown", path + ".reason_codes")
    return inv


# ---------------------------------------------------------------------------------------- other documents
def cert_issues(doc: Any) -> List[Issue]:
    """Shape of a key certificate payload (spec/05 section 2): exactly its fields, ``estate`` only for attest/anchor."""
    v = _V()
    if not isinstance(doc, dict):
        return [Issue("schema.field_invalid", "cert")]
    required = ("_type", "alg", "custody", "issuer_kid", "kid", "not_after", "not_before", "public_key", "serial", "usage")
    usage = doc.get("usage")
    has_estate = usage in ("attest", "anchor")
    v.keys(doc, required + (("estate",) if has_estate else ()), (), "cert")
    if doc.get("_type") != "https://paddock.dev/key-cert/v1":
        v.add("schema.statement_invalid", "cert._type")
    v.enum(doc, "usage", ("attest", "anchor", "issue-cert", "revoke"), "cert") if "usage" in doc else None
    if isinstance(doc.get("alg"), str) is False:
        v.add("schema.field_invalid", "cert.alg")
    v.enum(doc, "custody", ("hosted", "byok-kms", "byok-hsm"), "cert") if "custody" in doc else None
    v.rx(doc, "issuer_kid", _KID, "cert") if "issuer_kid" in doc else None
    v.rx(doc, "kid", _KID, "cert") if "kid" in doc else None
    v.time(doc, "not_before", "cert") if "not_before" in doc else None
    v.time(doc, "not_after", "cert") if "not_after" in doc else None
    v.rx(doc, "public_key", re.compile(r"[A-Za-z0-9+/]{43}=\Z", re.ASCII), "cert") if "public_key" in doc else None
    v.uint(doc, "serial", "cert", minimum=1) if "serial" in doc else None
    if has_estate and "estate" in doc:
        v.rx(doc, "estate", _ESTATE, "cert")
    return v.issues
