# SPDX-License-Identifier: Apache-2.0
"""The consumer's acceptance policy (spec/08-acceptance-policy.md).

JSON is the normative form, a strict YAML subset (``yaml_subset``) is sugar. With no policy the **baseline
profile** applies: authentic, chained to a pinned root, bound by DNS, not revoked, current, ``max_age`` 48 hours,
every disclosed HOLDS at least 95 percent covered, no disclosed violation, std digests pinned, and nothing
required of the content. Thresholds are exact decimals converted to basis points; durations are whole seconds.
"""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from . import canon, limits, timefmt, yaml_subset

CODE = "config.policy_invalid"
TIERS = ("declared", "configured", "observed", "tested")
REQUIRE_TIERS = ("configured", "observed", "tested")

_INV = re.compile(r"[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)
_H = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z", re.ASCII)
_THRESHOLD = re.compile(r"(?:0|1)(?:\.[0-9]{1,4})?\Z", re.ASCII)


class PolicyError(ValueError):
    """The policy file or an override is invalid (exit 64, ``config.policy_invalid``)."""

    code = CODE

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        super().__init__(message if line is None else "line %d: %s" % (line, message))
        self.line = line
        self.detail = message


class Require(NamedTuple):
    invariant: str
    min_tier: Optional[str] = None
    min_coverage_bp: Optional[int] = None
    max_age_s: Optional[int] = None
    digest: Optional[str] = None


class Policy(NamedTuple):
    profile: str                       # baseline | policy
    name: Optional[str]
    require: Tuple[Require, ...]
    max_age_s: int
    min_coverage_bp: int
    disclosure: str
    violations: str
    max_exceptions: Optional[int]
    max_stop_at_share_bp: Optional[int]
    vendor_cert: str
    dns_binding: str
    dnssec: str
    revocation: str
    revocation_max_age_s: int
    history: str
    std_registry: str
    engine_advisories: str
    anchor: str
    require_latest: bool
    sha256: Optional[str]
    source: Dict[str, Any]             # the parsed document the hash is computed over (nulls dropped)


_DEFAULTS = dict(
    max_age_s=48 * 3600, min_coverage_bp=9500, disclosure="any", violations="reject", max_exceptions=None,
    max_stop_at_share_bp=None, vendor_cert="required", dns_binding="required", dnssec="off", revocation="required",
    revocation_max_age_s=72 * 3600, history="if_available", std_registry="strict", engine_advisories="reject",
    anchor="off", require_latest=False)


def baseline() -> Policy:
    return Policy(profile="baseline", name=None, require=(), sha256=None, source={}, **_DEFAULTS)


# ------------------------------------------------------------------------------------------ field parsers
def _bad(msg: str, line: Optional[int] = None) -> PolicyError:
    return PolicyError(msg, line)


def _enum(d: Dict[str, Any], key: str, allowed: Tuple[str, ...], default: str, where: str = "") -> str:
    if key not in d:
        return default
    v = d[key]
    if not isinstance(v, str) or v not in allowed:
        raise _bad("%s%s must be one of %s" % (where, key, ", ".join(allowed)))
    return v


def _duration(v: Any, what: str) -> int:
    if not isinstance(v, str):
        raise _bad("%s must be a duration such as 48h (an integer followed by s, m, h or d)" % what)
    try:
        return timefmt.parse_duration(v)
    except timefmt.TimeError:
        raise _bad("%s must be a duration such as 48h (an integer followed by s, m, h or d)" % what) from None


def _threshold_text(v: Any, what: str) -> str:
    if isinstance(v, bool):
        raise _bad("%s must be a decimal between 0 and 1" % what)
    if isinstance(v, int):
        v = str(v)
    elif isinstance(v, Decimal):
        v = format(v, "f")
    if not isinstance(v, str) or not _THRESHOLD.match(v):
        raise _bad("%s must be a decimal between 0 and 1 with at most four places" % what)
    return v


def _bp(text: str) -> int:
    try:
        return limits.threshold_bp(text)
    except ValueError as e:
        raise _bad(str(e)) from None


def _name_of(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    safe = re.sub(r"[^A-Za-z0-9._:-]", "_", base)[:64]
    return safe or None


def _require_entry(raw: Any, i: int) -> Tuple[Require, Dict[str, Any]]:
    where = "require[%d]" % i
    if not isinstance(raw, dict):
        raise _bad("%s must be an object" % where)
    extra = set(raw) - {"invariant", "verdict", "min_tier", "min_coverage", "max_age", "digest"}
    if extra:
        raise _bad("%s has an unknown field %s" % (where, sorted(extra)[0]))
    inv = raw.get("invariant")
    if not isinstance(inv, str) or not _INV.match(inv):
        raise _bad("%s.invariant must be an invariant id such as std:name" % where)
    if raw.get("verdict", "HOLDS") != "HOLDS":
        raise _bad("%s.verdict: only HOLDS can be required" % where)
    tier = raw.get("min_tier")
    if tier is not None and tier not in REQUIRE_TIERS:
        raise _bad("%s.min_tier must be one of %s" % (where, ", ".join(REQUIRE_TIERS)))
    cov = raw.get("min_coverage")
    cov_text = None if cov is None else _threshold_text(cov, where + ".min_coverage")
    age = raw.get("max_age")
    digest = raw.get("digest")
    if digest is not None and (not isinstance(digest, str) or not _H.match(digest)):
        raise _bad("%s.digest must be sha256: followed by 64 lowercase hex characters" % where)
    entry = Require(inv, tier, None if cov_text is None else _bp(cov_text), None if age is None else _duration(age, where + ".max_age"), digest)
    src = {"invariant": inv, "verdict": "HOLDS"}
    if tier is not None:
        src["min_tier"] = tier
    if cov_text is not None:
        src["min_coverage"] = cov_text
    if age is not None:
        src["max_age"] = age
    if digest is not None:
        src["digest"] = digest
    return entry, src


_TOP = {"policy_version", "require", "max_age", "min_coverage", "disclosure", "violations", "max_exceptions", "max_stop_at_share",
        "trust", "history", "std_registry", "engine_advisories", "anchor", "require_latest", "name"}
_TRUST = {"vendor_cert", "dns_binding", "dnssec", "revocation", "revocation_max_age"}


def parse_policy_dict(doc: Any, filename: Optional[str] = None) -> Policy:
    if not isinstance(doc, dict):
        raise _bad("a policy is an object")
    extra = set(doc) - _TOP
    if extra:
        raise _bad("unknown field %s" % sorted(extra)[0])
    v = doc.get("policy_version")
    if isinstance(v, bool) or v != 1 or not isinstance(v, int):
        raise _bad("policy_version must be 1")
    source = {"policy_version": 1}  # type: Dict[str, Any]
    d = dict(_DEFAULTS)
    req_raw = doc.get("require", [])
    if not isinstance(req_raw, list) or len(req_raw) > limits.MAX_RESULTS:
        raise _bad("require must be a list of at most %d entries" % limits.MAX_RESULTS)
    reqs = []  # type: List[Require]
    req_src = []  # type: List[Dict[str, Any]]
    for i, raw in enumerate(req_raw):
        entry, src = _require_entry(raw, i)
        if any(r.invariant == entry.invariant for r in reqs):
            raise _bad("require lists %s twice" % entry.invariant)
        reqs.append(entry)
        req_src.append(src)
    if req_src:
        source["require"] = req_src
    if "max_age" in doc:
        d["max_age_s"] = _duration(doc["max_age"], "max_age")
        source["max_age"] = doc["max_age"]
    if "min_coverage" in doc:
        t = _threshold_text(doc["min_coverage"], "min_coverage")
        d["min_coverage_bp"] = _bp(t)
        source["min_coverage"] = t
    d["disclosure"] = _enum(doc, "disclosure", ("any", "complete"), d["disclosure"])
    d["violations"] = _enum(doc, "violations", ("reject", "warn"), d["violations"])
    for k in ("disclosure", "violations"):
        if k in doc:
            source[k] = doc[k]
    if doc.get("max_exceptions") is not None:
        me = doc["max_exceptions"]
        if isinstance(me, bool) or not isinstance(me, int) or me < 0 or me > limits.MAX_INT:
            raise _bad("max_exceptions must be a non-negative integer or null")
        d["max_exceptions"] = me
        source["max_exceptions"] = me
    if doc.get("max_stop_at_share") is not None:
        t = _threshold_text(doc["max_stop_at_share"], "max_stop_at_share")
        d["max_stop_at_share_bp"] = _bp(t)
        source["max_stop_at_share"] = t
    trust = doc.get("trust", {})
    if not isinstance(trust, dict):
        raise _bad("trust must be an object")
    extra = set(trust) - _TRUST
    if extra:
        raise _bad("trust has an unknown field %s" % sorted(extra)[0])
    d["vendor_cert"] = _enum(trust, "vendor_cert", ("required", "optional"), d["vendor_cert"], "trust.")
    d["dns_binding"] = _enum(trust, "dns_binding", ("required", "optional"), d["dns_binding"], "trust.")
    d["dnssec"] = _enum(trust, "dnssec", ("off", "required"), d["dnssec"], "trust.")
    d["revocation"] = _enum(trust, "revocation", ("required", "best_effort"), d["revocation"], "trust.")
    if "revocation_max_age" in trust:
        secs = _duration(trust["revocation_max_age"], "trust.revocation_max_age")
        if secs > _DEFAULTS["revocation_max_age_s"]:
            raise _bad("trust.revocation_max_age may not exceed the 72h staleness rule")
        d["revocation_max_age_s"] = secs
    if trust:
        source["trust"] = dict(trust)
    d["history"] = _enum(doc, "history", ("required", "if_available", "off"), d["history"])
    d["std_registry"] = _enum(doc, "std_registry", ("strict", "warn"), d["std_registry"])
    d["engine_advisories"] = _enum(doc, "engine_advisories", ("reject", "warn"), d["engine_advisories"])
    d["anchor"] = _enum(doc, "anchor", ("off", "optional", "required"), d["anchor"])
    for k in ("history", "std_registry", "engine_advisories", "anchor"):
        if k in doc:
            source[k] = doc[k]
    if "require_latest" in doc:
        if not isinstance(doc["require_latest"], bool):
            raise _bad("require_latest must be true or false")
        d["require_latest"] = doc["require_latest"]
        source["require_latest"] = doc["require_latest"]
    name = None
    if "name" in doc:
        name = doc["name"]
        if not isinstance(name, str) or not _NAME.match(name):
            raise _bad("name must be 1 to 64 characters of letters, digits and ._:-")
        source["name"] = name
    return _finish(Policy(profile="policy", name=name or _name_of(filename), require=tuple(reqs), sha256=None, source=source, **d))


def _finish(p: Policy) -> Policy:
    try:
        digest = hashlib.sha256(canon.dumps(p.source)).hexdigest()
    except canon.CanonError:
        raise _bad("the policy contains a value that cannot be hashed") from None
    return p._replace(sha256=digest)


# ------------------------------------------------------------------------------------------- text forms
def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise PolicyError("duplicate key %r" % k)
        d[k] = v
    return d


def _no_float(x):
    raise PolicyError("write numbers as integers and thresholds as strings such as \"0.95\"")


def _no_const(x):
    raise PolicyError("%s is not allowed" % x)


def parse_policy_text(text: Any, filename: Optional[str] = None) -> Policy:
    """Parse a policy file: JSON when the first non-blank character is ``{``, otherwise the YAML subset."""
    if isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
        if len(raw) > limits.MAX_AUX_FILE_BYTES:
            raise _bad("policy file over %d bytes" % limits.MAX_AUX_FILE_BYTES)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise _bad("a policy file is ASCII", 1) from None
    if len(text) > limits.MAX_AUX_FILE_BYTES:
        raise _bad("policy file over %d bytes" % limits.MAX_AUX_FILE_BYTES)
    if text.lstrip(" \t\r\n").startswith(("{", "[", '"')) or text.strip() in ("null", "true", "false"):
        try:
            doc = json.loads(text, object_pairs_hook=_no_dupes, parse_float=_no_float, parse_constant=_no_const)
        except PolicyError:
            raise
        except RecursionError:
            raise _bad("nesting too deep") from None
        except ValueError as e:
            raise _bad("not valid JSON: %s" % str(e)[:80]) from None
    else:
        try:
            doc = yaml_subset.loads(text)
        except yaml_subset.YamlError as e:
            raise PolicyError(e.detail, e.line) from None
        except RecursionError:
            raise _bad("nesting too deep") from None
    return parse_policy_dict(doc, filename)


def load_policy_file(path: str) -> Policy:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limits.MAX_AUX_FILE_BYTES + 1)
    except OSError as e:
        raise PolicyError("cannot read the policy file: %s" % (e.strerror or "error")) from None
    return parse_policy_text(raw, filename=path)


# ------------------------------------------------------------------------------------------- overrides
def _parse_require_spec(spec: str) -> Tuple[str, str]:
    """``std:name`` or ``std:name:tier`` (an invariant id itself contains exactly one colon)."""
    parts = spec.split(":")
    if len(parts) == 2:
        return spec, ""
    if len(parts) == 3:
        return parts[0] + ":" + parts[1], parts[2]
    raise PolicyError("--require takes ID or ID:TIER, for example std:no-internet-to-datastore:observed")


def apply_overrides(p: Policy, max_age: Optional[str] = None, min_coverage: Optional[str] = None,
                    require: Optional[List[str]] = None) -> Policy:
    """``--max-age``, ``--min-coverage`` and ``--require ID[:TIER]`` on top of a policy or the baseline."""
    if max_age is None and min_coverage is None and not require:
        return p
    d = dict(p.source) if p.source else {"policy_version": 1}
    if max_age is not None:
        _duration(max_age, "--max-age")
        d["max_age"] = max_age
    if min_coverage is not None:
        d["min_coverage"] = _threshold_text(min_coverage, "--min-coverage")
    if require:
        items = list(d.get("require", []))
        for spec in require:
            inv, tier = _parse_require_spec(spec)
            entry = {"invariant": inv, "verdict": "HOLDS"}
            if tier:
                entry["min_tier"] = tier
            items = [e for e in items if e["invariant"] != inv] + [entry]
        d["require"] = items
    out = parse_policy_dict(d)
    return out._replace(name=p.name if p.profile == "policy" else "command-line")
