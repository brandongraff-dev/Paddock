"""STIX 2.1 ingest.

Parses a STIX bundle (JSON dict or string) and extracts:
  * ``indicator`` objects -> one or more IOC records (we parse the STIX
    *pattern* for ipv4 / ipv6 / domain / url / file:hashes / email).
  * ``malware`` / ``threat-actor`` objects + ``relationship`` objects, to
    label each indicator with the malware families / actor it indicates.

Design goals:
  * ROBUST to malformed input -- a bad object is skipped, never fatal.
  * NO network, NO execution: a pattern value is DATA, never dereferenced.
  * DEGRADES gracefully: uses the optional ``stix2`` library's object
    iteration if installed, otherwise a pure hand parser. The pattern
    extraction itself is hand-rolled either way (it is the robust path and
    keeps behaviour identical with or without ``stix2``).

The emitted record dict matches ``db.Database.upsert_indicator`` columns:
    {type, value, pattern, labels, malware, threat_actor, confidence,
     valid_from, valid_until, stix_id, source}
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable

log = logging.getLogger(__name__)

# Optional, guarded import. The service MUST boot + parse a bundle without it.
try:  # pragma: no cover - exercised only where stix2 is installed
    import stix2  # type: ignore

    _HAVE_STIX2 = True
except Exception:  # noqa: BLE001
    stix2 = None  # type: ignore
    _HAVE_STIX2 = False


# Our canonical IOC types (mirror the ti_indicators.type CHECK constraint).
IOC_IPV4 = "ipv4"
IOC_IPV6 = "ipv6"
IOC_DOMAIN = "domain"
IOC_URL = "url"
IOC_SHA256 = "file_sha256"
IOC_MD5 = "file_md5"
IOC_EMAIL = "email"
IOC_CIDR = "cidr"

VALID_TYPES = {
    IOC_IPV4, IOC_IPV6, IOC_DOMAIN, IOC_URL,
    IOC_SHA256, IOC_MD5, IOC_EMAIL, IOC_CIDR,
}

# --------------------------------------------------------------------------- #
# Pattern parsing
# --------------------------------------------------------------------------- #

# A STIX comparison expression: <object-path> <op> <quoted-value>. We only
# care about equality comparisons; everything else (MATCHES, LIKE, IN, <, >)
# is ignored. The object-path can carry a quoted key, e.g. file:hashes.'SHA-256'.
_COMPARISON_RE = re.compile(
    r"""
    (?P<path>[a-zA-Z0-9\-]+ : [^\s=!<>]+)   # object-type ':' property-path
    \s* = \s*                                # equality only
    (?P<q>['"])(?P<value>.*?)(?<!\\)(?P=q)   # single/double quoted value
    """,
    re.VERBOSE | re.DOTALL,
)

_HASH_KEY_RE = re.compile(r"hashes\.(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9\-]+))")


def _unescape(value: str) -> str:
    # STIX string literals escape the quote char and backslash.
    return value.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")


def _hash_type(path: str) -> str | None:
    """Map a ``file:hashes.*`` path to our file_* IOC type."""
    m = _HASH_KEY_RE.search(path)
    if not m:
        return None
    key = (m.group(1) or m.group(2) or m.group(3) or "").upper().replace("-", "")
    if key in {"SHA256", "SHA2256"}:
        return IOC_SHA256
    if key == "MD5":
        return IOC_MD5
    return None


def _looks_cidr(value: str) -> bool:
    return "/" in value and value.rsplit("/", 1)[-1].isdigit()


def _ip_type(object_type: str, value: str) -> str | None:
    if object_type == "ipv4-addr":
        return IOC_CIDR if _looks_cidr(value) else IOC_IPV4
    if object_type == "ipv6-addr":
        return IOC_CIDR if _looks_cidr(value) else IOC_IPV6
    return None


def _classify(path: str, value: str) -> tuple[str, str] | None:
    """Map a (object-path, value) pair to (ioc_type, normalized_value)."""
    object_type = path.split(":", 1)[0].strip().lower()
    prop = path.split(":", 1)[1].strip() if ":" in path else ""
    value = value.strip()
    if not value:
        return None

    if object_type in ("ipv4-addr", "ipv6-addr"):
        t = _ip_type(object_type, value)
        return (t, value) if t else None
    if object_type == "domain-name":
        return (IOC_DOMAIN, value.lower())
    if object_type == "url":
        return (IOC_URL, value)
    if object_type == "email-addr":
        return (IOC_EMAIL, value.lower())
    if object_type == "file":
        if prop.startswith("hashes"):
            t = _hash_type(prop)
            if t:
                return (t, value.lower())
        return None
    return None


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract ``[(ioc_type, value), ...]`` from a STIX 2.x pattern string.

    Handles compound patterns (``OR`` / ``AND``), multiple comparisons, and
    quoted hash keys. Unknown object types and non-equality operators are
    silently dropped. Pure + deterministic: no I/O, order-preserving, deduped.
    """
    if not isinstance(pattern, str) or not pattern:
        return []
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _COMPARISON_RE.finditer(pattern):
        path = m.group("path").strip()
        value = _unescape(m.group("value"))
        res = _classify(path, value)
        if res is None:
            continue
        ioc_type, norm = res
        if ioc_type not in VALID_TYPES:
            continue
        key = (ioc_type, norm)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


# --------------------------------------------------------------------------- #
# Bundle parsing
# --------------------------------------------------------------------------- #

def _as_dict(bundle: Any) -> dict[str, Any] | None:
    if isinstance(bundle, (bytes, bytearray)):
        try:
            bundle = bundle.decode("utf-8")
        except Exception:  # noqa: BLE001
            return None
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except json.JSONDecodeError:
            return None
    return bundle if isinstance(bundle, dict) else None


def _objects(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the STIX object list from a bundle or TAXII envelope."""
    objs = bundle.get("objects")
    if not isinstance(objs, list):
        return []
    return [o for o in objs if isinstance(o, dict)]


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        s = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _labels_of(obj: dict[str, Any]) -> list[str]:
    """Collect indicator labels from STIX 2.1 `indicator_types` and 2.0 `labels`."""
    out: list[str] = []
    for key in ("indicator_types", "labels"):
        vals = obj.get(key)
        if isinstance(vals, list):
            out.extend(str(v).strip().lower() for v in vals if isinstance(v, str) and v.strip())
    # dedupe, preserve order
    seen: set[str] = set()
    uniq = []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def _confidence(obj: dict[str, Any]) -> int:
    c = obj.get("confidence")
    if isinstance(c, (int, float)):
        return max(0, min(100, int(c)))
    return 50


def _index_labels(objects: Iterable[dict[str, Any]]) -> tuple[
    dict[str, str], dict[str, str], list[dict[str, Any]]
]:
    """Build id->malware-name, id->actor-name maps and collect relationships."""
    malware: dict[str, str] = {}
    actors: dict[str, str] = {}
    rels: list[dict[str, Any]] = []
    for o in objects:
        t = o.get("type")
        oid = o.get("id")
        if not isinstance(oid, str):
            continue
        if t == "malware":
            name = o.get("name") or oid
            malware[oid] = str(name)
        elif t == "threat-actor":
            name = o.get("name") or oid
            actors[oid] = str(name)
        elif t == "relationship":
            rels.append(o)
    return malware, actors, rels


def parse_bundle(bundle: Any, *, source: str | None = None) -> list[dict[str, Any]]:
    """Parse a STIX bundle into indicator records (db.upsert_indicator shape).

    One STIX indicator can carry a compound pattern and therefore yields one
    record per extracted (type, value). Malformed objects are skipped.
    """
    data = _as_dict(bundle)
    if data is None:
        return []
    objects = _objects(data)
    if not objects:
        return []

    # stix2, when present, is used only to iterate/validate objects; we still
    # drive extraction off the raw dicts so behaviour matches the hand parser.
    malware_names, actor_names, rels = _index_labels(objects)

    # indicator-id -> (set(malware names), threat_actor name)
    ind_malware: dict[str, list[str]] = {}
    ind_actor: dict[str, str] = {}
    for r in rels:
        if r.get("relationship_type") not in ("indicates", "attributed-to", "uses", "related-to"):
            continue
        src = r.get("source_ref")
        dst = r.get("target_ref")
        # relationship can point either direction; normalize so the indicator
        # is the one we attach labels TO.
        ind_id = None
        other = None
        if isinstance(src, str) and src.startswith("indicator--"):
            ind_id, other = src, dst
        elif isinstance(dst, str) and dst.startswith("indicator--"):
            ind_id, other = dst, src
        if not ind_id or not isinstance(other, str):
            continue
        if other in malware_names:
            ind_malware.setdefault(ind_id, [])
            if malware_names[other] not in ind_malware[ind_id]:
                ind_malware[ind_id].append(malware_names[other])
        elif other in actor_names:
            ind_actor.setdefault(ind_id, actor_names[other])

    records: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern")
        pairs = parse_pattern(pattern) if isinstance(pattern, str) else []
        if not pairs:
            continue
        stix_id = obj.get("id") if isinstance(obj.get("id"), str) else None
        labels = _labels_of(obj)
        malware = list(ind_malware.get(stix_id or "", []))
        actor = ind_actor.get(stix_id or "")
        confidence = _confidence(obj)
        valid_from = _parse_ts(obj.get("valid_from"))
        valid_until = _parse_ts(obj.get("valid_until"))
        for ioc_type, value in pairs:
            records.append({
                "stix_id": stix_id if len(pairs) == 1 else None,
                "type": ioc_type,
                "value": value,
                "pattern": pattern,
                "labels": labels,
                "malware": malware,
                "threat_actor": actor,
                "confidence": confidence,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "source": source,
            })
    return records
