"""Finding lifecycle: dedupe identity, suppression, SLA, and explained priority.

Schema: ``schema/019_finding_lifecycle.sql``. This module is the single place
that knows how a finding is

* **identified across engines** -- ``asset_key`` + ``vuln_keys`` +
  ``fingerprint``. The same CVE on the same host reported by nuclei,
  cve_match and sca collapses into one primary finding (``duplicate_of``);
* **suppressed** -- operator rules matched at ingest. Suppressed findings are
  stored (countable, auditable) but hidden from default reads;
* **dated** -- ``due_at`` / ``sla_breached`` from ``sla_policies`` (or the
  finding's ticket ``sla_due`` when one exists);
* **explained** -- ``priority_score`` 0-100 plus the ``why`` factors that
  produced it ("KEV-listed", "EPSS 0.92", "2 hops from crown jewel db-1" ...).

Pure functions come first (unit-tested without a DB); the async helpers below
them batch every lookup for a page of findings so reads stay O(queries), not
O(rows).
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from . import audit
from .models import FindingBulkOut, FindingDetailOut, FindingOut
from .scope import normalize as scope_normalize

logger = logging.getLogger(__name__)

# Statuses an SLA clock runs for. Everything else is closed or dismissed.
SLA_OPEN_STATUSES = frozenset({"open", "triaged"})
# Dismissed states that require a reason and may carry an expiry.
DISMISSED_STATUSES = frozenset({"accepted", "false_positive"})
# Statuses the expiry sweep reopens (accepted_risk is the legacy alias).
EXPIRING_STATUSES = ("accepted", "false_positive", "accepted_risk")

SYSTEM_ACTOR = "system:lifecycle"


# =========================================================================== #
# Response models (kept here, not in models.py, to stay out of shared files)
# =========================================================================== #

class WhyFactor(BaseModel):
    key: str
    label: str
    weight: int


class FindingSource(BaseModel):
    finding_id: UUID
    rule_source: str
    rule_id: str
    status: str
    last_seen: datetime
    primary: bool = False


class FindingLifecycleOut(FindingOut):
    """``FindingOut`` + lifecycle fields. Every addition is optional so the
    response stays a strict superset of the legacy shape."""

    status_reason: str | None = None
    status_by: str | None = None
    status_changed_at: datetime | None = None
    accepted_until: datetime | None = None
    suppressed: bool = False
    suppressed_by: UUID | None = None
    suppressed_at: datetime | None = None
    fingerprint: str | None = None
    vuln_keys: list[str] = Field(default_factory=list)
    duplicate_of: UUID | None = None
    sources: list[FindingSource] = Field(default_factory=list)
    source_count: int = 1
    due_at: datetime | None = None
    sla_hours: int | None = None
    sla_breached: bool = False
    owner: str | None = None
    kev: bool | None = None
    priority_score: int | None = None
    why: list[WhyFactor] = Field(default_factory=list)
    # schema 026: safe-check verification state ("is it real", "did the fix hold")
    exploitability: str = "unverified"
    last_verified_at: datetime | None = None
    fix_verified_at: datetime | None = None


class FindingLifecyclePage(BaseModel):
    items: list[FindingLifecycleOut]
    total: int
    limit: int
    offset: int
    # Hidden-by-default rows, counted under the same filters.
    suppressed_total: int = 0
    duplicates_total: int = 0


class StatusHistoryOut(BaseModel):
    id: UUID
    from_status: str | None
    to_status: str
    reason: str | None
    accepted_until: datetime | None
    actor: str
    at: datetime


class FindingLifecycleDetailOut(FindingDetailOut):
    finding: FindingLifecycleOut  # type: ignore[assignment]
    history: list[StatusHistoryOut] = Field(default_factory=list)


class FindingBulkLifecycleOut(FindingBulkOut):
    items: list[FindingLifecycleOut]  # type: ignore[assignment]
    suppressed: int = 0
    duplicates: int = 0


SuppressedFilter = Literal["exclude", "include", "only"]


# =========================================================================== #
# Identity: asset_key / vuln_keys / fingerprint (pure)
# =========================================================================== #

_NETWORK_KINDS = frozenset({"domain", "subdomain", "ipv4", "ipv6", "endpoint", "port", "service"})
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)


def asset_key(kind: str | None, value: str | None, canonical: str | None = None,
              metadata: dict[str, Any] | None = None) -> str:
    """Normalized asset identity used for cross-engine dedupe.

    Network assets collapse to their host (``https://Example.com:8443/x`` and
    ``example.com`` are one asset); ``metadata.host`` wins when an engine
    attached a technology/service asset to a known host. Everything else keys
    on ``kind:canonical``.
    """
    md = metadata or {}
    host = md.get("host") if isinstance(md.get("host"), str) else None
    if host:
        h = scope_normalize(host)
        if h:
            return f"host:{h}"
    v = (canonical or value or "").strip()
    if (kind or "") in _NETWORK_KINDS and v:
        h = scope_normalize(v)
        if h:
            return f"host:{h}"
    return f"{(kind or 'unknown').lower()}:{v.lower()}"


def _strings(*values: Any) -> Iterable[str]:
    for v in values:
        if isinstance(v, str):
            yield v
        elif isinstance(v, (list, tuple, set)):
            for x in v:
                if isinstance(x, str):
                    yield x


def extract_cves(rule_id: str, evidence: dict[str, Any] | None,
                 metadata: dict[str, Any] | None) -> list[str]:
    ev = evidence or {}
    md = metadata or {}
    cls = md.get("classification") if isinstance(md.get("classification"), dict) else {}
    found: set[str] = set()
    for s in _strings(rule_id, ev.get("cve_ids"), ev.get("cve_id"), ev.get("cve"),
                      md.get("cve_ids"), md.get("cve_id"), md.get("cve"),
                      cls.get("cve-id"), cls.get("cve_id")):
        for m in _CVE_RE.findall(s):
            found.add(m.upper())
    return sorted(found)


def extract_ghsas(rule_id: str, evidence: dict[str, Any] | None) -> list[str]:
    ev = evidence or {}
    found: set[str] = set()
    for s in _strings(rule_id, ev.get("osv_ids"), ev.get("ghsa_ids")):
        for m in _GHSA_RE.findall(s):
            found.add("GHSA" + m[4:].lower())
    return sorted(found)


def vuln_keys(rule_source: str, rule_id: str, evidence: dict[str, Any] | None,
              metadata: dict[str, Any] | None) -> list[str]:
    """Normalized vulnerability identities, most specific first.

    CVE/GHSA ids identify a vulnerability regardless of engine. A CWE only
    identifies one together with its code location (``CWE-89@app.py:12``).
    Anything else falls back to ``rule:<source>:<rule_id>``, which never
    collapses findings from different engines.
    """
    ev = evidence or {}
    md = metadata or {}
    keys = [f"cve:{c}" for c in extract_cves(rule_id, ev, md)]
    keys += [f"ghsa:{g}" for g in extract_ghsas(rule_id, ev)]
    if keys:
        return keys
    cwe = ev.get("cwe") or md.get("cwe")
    file = ev.get("file")
    line = ev.get("start_line")
    if isinstance(cwe, str) and cwe and isinstance(file, str) and file:
        loc = f"{file}:{line}" if line else file
        return [f"cwe:{cwe.upper()}@{loc}"]
    return [f"rule:{rule_source}:{rule_id}"]


def fingerprint(akey: str, vkeys: list[str]) -> str:
    primary = vkeys[0] if vkeys else ""
    return hashlib.sha256(f"{akey}|{primary}".encode()).hexdigest()[:32]


def identity(rule_source: str, rule_id: str, evidence: dict[str, Any] | None,
             metadata: dict[str, Any] | None, asset: dict[str, Any] | None) -> dict[str, Any]:
    """Dedupe identity for one finding. An engine that knows which host the
    issue lives on (e.g. SCA for a deployed service) may say so with
    ``metadata.host`` / ``evidence.host``; that overrides the asset's own key."""
    a = asset or {}
    declared = (metadata or {}).get("host") or (evidence or {}).get("host")
    if isinstance(declared, str) and scope_normalize(declared):
        akey = f"host:{scope_normalize(declared)}"
    else:
        akey = asset_key(a.get("kind"), a.get("value"), a.get("canonical"), a.get("metadata"))
    vk = vuln_keys(rule_source, rule_id, evidence, metadata)
    return {"asset_key": akey, "vuln_keys": vk, "fingerprint": fingerprint(akey, vk)}


# =========================================================================== #
# Suppression matching (pure)
# =========================================================================== #

def _glob(pattern: str | None, value: str | None) -> bool:
    if not pattern:
        return True
    return fnmatch.fnmatchcase((value or "").lower(), pattern.lower())


def _tags(*mds: Any) -> set[str]:
    out: set[str] = set()
    for md in mds:
        if isinstance(md, dict):
            t = md.get("tags")
            if isinstance(t, (list, tuple)):
                out.update(str(x).lower() for x in t)
    return out


def suppression_active(sup: dict[str, Any], now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if not sup.get("enabled", True):
        return False
    exp = sup.get("expires_at")
    return exp is None or exp > now


def suppression_matches(sup: dict[str, Any], finding: dict[str, Any],
                        asset: dict[str, Any] | None) -> bool:
    """All set matchers must hold (AND). At least one matcher is guaranteed by
    the table CHECK, so an empty rule can never suppress everything."""
    a = asset or {}
    if not (sup.get("rule_id") or sup.get("asset_pattern") or sup.get("tag")):
        return False
    if sup.get("rule_source") and sup["rule_source"] != finding.get("rule_source"):
        return False
    if not _glob(sup.get("rule_id"), finding.get("rule_id")):
        return False
    pat = sup.get("asset_pattern")
    if pat and not (_glob(pat, a.get("value")) or _glob(pat, a.get("canonical"))):
        return False
    tag = sup.get("tag")
    if tag and tag.lower() not in _tags(a.get("metadata"), finding.get("metadata")):
        return False
    return True


def first_matching_suppression(sups: list[dict[str, Any]], finding: dict[str, Any],
                               asset: dict[str, Any] | None,
                               now: datetime | None = None) -> dict[str, Any] | None:
    for s in sups:
        if suppression_active(s, now) and suppression_matches(s, finding, asset):
            return s
    return None


# =========================================================================== #
# Ownership (mirrors triage/app/owners.py semantics)
# =========================================================================== #

def _asset_ip(asset: dict[str, Any]) -> str | None:
    md = asset.get("metadata") or {}
    for cand in (asset.get("value"), md.get("ip") if isinstance(md, dict) else None):
        if isinstance(cand, str):
            try:
                return str(ipaddress.ip_address(cand.strip()))
            except ValueError:
                continue
    return None


def owner_matches(match: dict[str, Any], asset: dict[str, Any]) -> bool:
    kinds = match.get("kinds")
    if kinds and asset.get("kind") not in kinds:
        return False
    if match.get("value_regex"):
        try:
            if not re.search(match["value_regex"], asset.get("value") or ""):
                return False
        except re.error:
            return False
    if match.get("cidr"):
        ip = _asset_ip(asset)
        try:
            if not ip or ipaddress.ip_address(ip) not in ipaddress.ip_network(match["cidr"], strict=False):
                return False
        except ValueError:
            return False
    md = asset.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}
    if match.get("metadata_env") and md.get("env") != match["metadata_env"]:
        return False
    if match.get("tag"):
        tags = md.get("tags")
        if not isinstance(tags, (list, tuple)) or match["tag"] not in tags:
            return False
    return True


def resolve_owner(asset: dict[str, Any], rules: list[dict[str, Any]]) -> str | None:
    md = asset.get("metadata") or {}
    if isinstance(md, dict):
        for k in ("owner_team", "owner", "team"):
            if isinstance(md.get(k), str) and md[k].strip():
                return md[k].strip()
    for r in sorted(rules, key=lambda r: r.get("priority", 100)):
        m = r.get("match") or {}
        if isinstance(m, str):
            try:
                m = json.loads(m)
            except ValueError:
                m = {}
        if owner_matches(m, asset):
            return r.get("team")
    return None


# =========================================================================== #
# SLA (pure)
# =========================================================================== #

def compute_due(first_seen: datetime | None, sla_hours: int | None,
                ticket_due: datetime | None = None) -> datetime | None:
    if ticket_due is not None:
        return ticket_due
    if first_seen is None or not sla_hours or sla_hours <= 0:
        return None
    return first_seen + timedelta(hours=int(sla_hours))


def is_breached(status: str, due_at: datetime | None, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return status in SLA_OPEN_STATUSES and due_at is not None and due_at < now


# =========================================================================== #
# Explained priority (pure)
# =========================================================================== #

SEVERITY_WEIGHT = {"critical": 35, "high": 25, "medium": 14, "low": 6, "info": 1}

# Safe-check verdicts (schema 026): (why key, label, weight).
VERIFICATION_WEIGHT = {
    "confirmed": ("verified_exploitable", "Verified exploitable", 15),
    "not_reproducible": ("not_reproducible", "Not reproducible", -12),
    "inconclusive": ("verification_inconclusive", "Verification inconclusive", 0),
}


def explain_priority(
    *,
    severity: str,
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool = False,
    internet_facing: bool = False,
    crown_jewel: str | None = None,
    path_distance: int | None = None,
    path_target: str | None = None,
    blast_score: float | None = None,
    chain_title: str | None = None,
    engines: Iterable[str] = (),
    sla_breached: bool = False,
    owner: str | None = None,
    exploitability: str | None = None,
    verified_at: datetime | None = None,
) -> tuple[int, list[WhyFactor]]:
    """Return ``(priority_score 0-100, why factors sorted by weight desc)``.

    Additive and deliberately simple so every point is attributable: the sum
    of factor weights IS the score (clamped to 0..100). Context-only factors
    (owner) carry weight 0. A safe-check verdict (schema 026) is a factor like
    any other: ``confirmed`` raises, ``not_reproducible`` lowers (negative
    weight), ``inconclusive`` is shown but moves nothing. It never closes a
    finding.
    """
    f: list[WhyFactor] = [WhyFactor(key="severity", label=f"severity: {severity}",
                                    weight=SEVERITY_WEIGHT.get(severity, 1))]
    if kev:
        f.append(WhyFactor(key="kev", label="KEV-listed", weight=25))
    if epss is not None and epss >= 0.05:
        f.append(WhyFactor(key="epss", label=f"EPSS {epss:.2f}", weight=round(epss * 20)))
    if cvss is not None and cvss >= 7.0:
        f.append(WhyFactor(key="cvss", label=f"CVSS {cvss:.1f}", weight=round((cvss - 6.0) * 2)))
    if internet_facing:
        f.append(WhyFactor(key="internet_facing", label="internet-facing", weight=10))
    if crown_jewel:
        f.append(WhyFactor(key="crown_jewel", label=f"is crown jewel {crown_jewel}", weight=15))
    elif path_distance is not None and path_target:
        hops = "hop" if path_distance == 1 else "hops"
        f.append(WhyFactor(key="attack_path",
                           label=f"{path_distance} {hops} from crown jewel {path_target}",
                           weight=max(4, 15 - 3 * path_distance)))
    if blast_score is not None and blast_score >= 40:
        f.append(WhyFactor(key="blast", label=f"blast radius {blast_score:.0f}",
                           weight=min(10, round(blast_score / 10))))
    if chain_title:
        f.append(WhyFactor(key="chain", label=f"in chain: {chain_title}", weight=8))
    distinct = sorted(set(engines))
    if len(distinct) >= 2:
        f.append(WhyFactor(key="engines", label=f"seen by {len(distinct)} engines",
                           weight=min(10, 4 * (len(distinct) - 1))))
    if sla_breached:
        f.append(WhyFactor(key="sla", label="SLA breached", weight=5))
    if owner:
        f.append(WhyFactor(key="owner", label=f"owner: {owner}", weight=0))
    if exploitability in VERIFICATION_WEIGHT:
        when = f" on {verified_at.date().isoformat()}" if verified_at else ""
        key, text, weight = VERIFICATION_WEIGHT[exploitability]
        f.append(WhyFactor(key=key, label=f"{text}{when}", weight=weight))
    score = max(0, min(100, sum(x.weight for x in f)))
    f.sort(key=lambda x: -x.weight)
    return score, f


# =========================================================================== #
# DB helpers: ingest
# =========================================================================== #

async def load_active_suppressions(con) -> list[dict[str, Any]]:
    rows = await con.fetch(
        """
        SELECT id, rule_id, rule_source, asset_pattern, tag, enabled, expires_at
          FROM finding_suppressions
         WHERE enabled AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY created_at
        """
    )
    return [dict(r) for r in rows]


async def _asset_for(con, asset_id: UUID, cache: dict[UUID, dict[str, Any]]) -> dict[str, Any]:
    if asset_id not in cache:
        row = await con.fetchrow(
            "SELECT id, kind, value, canonical, metadata FROM assets WHERE id = $1", asset_id
        )
        d = dict(row) if row else {}
        if isinstance(d.get("metadata"), str):
            d["metadata"] = json.loads(d["metadata"])
        cache[asset_id] = d
    return cache[asset_id]


async def apply_ingest(con, finding: dict[str, Any], suppressions: list[dict[str, Any]],
                       asset_cache: dict[UUID, dict[str, Any]]) -> dict[str, Any]:
    """Stamp identity, collapse duplicates and apply suppressions to one
    freshly upserted finding row (same transaction as the upsert).

    Returns ``{"duplicate_of", "suppressed_by", "asset_key", "vuln_keys",
    "fingerprint"}`` -- the caller merges it into the response row.
    """
    asset = await _asset_for(con, finding["asset_id"], asset_cache)
    ident = identity(finding["rule_source"], finding["rule_id"], finding.get("evidence"),
                     finding.get("metadata"), asset)
    duplicate_of = finding.get("duplicate_of")
    if duplicate_of is None:
        duplicate_of = await con.fetchval(
            """
            SELECT id FROM findings
             WHERE id <> $1 AND duplicate_of IS NULL AND asset_key = $2
               AND (fingerprint = $3 OR vuln_keys && $4::text[])
               AND (first_seen < $5 OR (first_seen = $5 AND fingerprint IS NOT NULL))
             ORDER BY first_seen, id
             LIMIT 1
            """,
            finding["id"], ident["asset_key"], ident["fingerprint"], ident["vuln_keys"],
            finding["first_seen"],
        )
    suppressed_by = finding.get("suppressed_by")
    if suppressed_by is None:
        hit = first_matching_suppression(suppressions, finding, asset)
        if hit is not None:
            suppressed_by = hit["id"]
            await con.execute(
                "UPDATE finding_suppressions SET match_count = match_count + 1, "
                "last_matched_at = NOW() WHERE id = $1",
                suppressed_by,
            )
    await con.execute(
        """
        UPDATE findings
           SET asset_key = $2, vuln_keys = $3::text[], fingerprint = $4,
               duplicate_of = $5,
               suppressed_by = $6,
               suppressed_at = CASE WHEN $6::uuid IS NULL THEN NULL
                                    ELSE COALESCE(suppressed_at, NOW()) END
         WHERE id = $1
        """,
        finding["id"], ident["asset_key"], ident["vuln_keys"], ident["fingerprint"],
        duplicate_of, suppressed_by,
    )
    return {**ident, "duplicate_of": duplicate_of, "suppressed_by": suppressed_by}


async def apply_suppression_to_existing(con, sup: dict[str, Any]) -> int:
    """Retroactively suppress already-stored findings that match a new rule."""
    rows = await con.fetch(
        """
        SELECT f.id, f.rule_id, f.rule_source, f.metadata,
               a.kind, a.value, a.canonical, a.metadata AS asset_metadata
          FROM findings f JOIN assets a ON a.id = f.asset_id
         WHERE f.suppressed_by IS NULL
        """
    )
    hit_ids: list[UUID] = []
    for r in rows:
        md = r["metadata"]
        amd = r["asset_metadata"]
        finding = {"rule_id": r["rule_id"], "rule_source": r["rule_source"],
                   "metadata": json.loads(md) if isinstance(md, str) else md}
        asset = {"kind": r["kind"], "value": r["value"], "canonical": r["canonical"],
                 "metadata": json.loads(amd) if isinstance(amd, str) else amd}
        if suppression_matches(sup, finding, asset):
            hit_ids.append(r["id"])
    if hit_ids:
        await con.execute(
            "UPDATE findings SET suppressed_by = $1, suppressed_at = NOW() "
            "WHERE id = ANY($2::uuid[])",
            sup["id"], hit_ids,
        )
        await con.execute(
            "UPDATE finding_suppressions SET match_count = match_count + $2, "
            "last_matched_at = NOW() WHERE id = $1",
            sup["id"], len(hit_ids),
        )
    return len(hit_ids)


async def release_suppression(con, sup_id: UUID) -> int:
    res = await con.execute(
        "UPDATE findings SET suppressed_by = NULL, suppressed_at = NULL WHERE suppressed_by = $1",
        sup_id,
    )
    return int(res.split()[-1]) if res else 0


async def backfill_identity(con) -> dict[str, int]:
    """Stamp identity on rows that predate 019 (or were inserted directly) and
    collapse the duplicates among them. Oldest finding wins as primary."""
    rows = await con.fetch(
        """
        SELECT f.id, f.rule_id, f.rule_source, f.evidence, f.metadata, f.first_seen,
               a.kind, a.value, a.canonical, a.metadata AS asset_metadata
          FROM findings f JOIN assets a ON a.id = f.asset_id
         WHERE f.fingerprint IS NULL
         ORDER BY f.first_seen, f.id
        """
    )
    stamped = collapsed = 0
    for r in rows:
        def _j(v):
            return json.loads(v) if isinstance(v, str) else (v or {})
        asset = {"kind": r["kind"], "value": r["value"], "canonical": r["canonical"],
                 "metadata": _j(r["asset_metadata"])}
        ident = identity(r["rule_source"], r["rule_id"], _j(r["evidence"]), _j(r["metadata"]), asset)
        dup = await con.fetchval(
            """
            SELECT id FROM findings
             WHERE id <> $1 AND duplicate_of IS NULL AND asset_key = $2
               AND (fingerprint = $3 OR vuln_keys && $4::text[])
               AND (first_seen < $5 OR (first_seen = $5 AND fingerprint IS NOT NULL))
             ORDER BY first_seen, id LIMIT 1
            """,
            r["id"], ident["asset_key"], ident["fingerprint"], ident["vuln_keys"], r["first_seen"],
        )
        await con.execute(
            "UPDATE findings SET asset_key = $2, vuln_keys = $3::text[], fingerprint = $4, "
            "duplicate_of = COALESCE(duplicate_of, $5) WHERE id = $1",
            r["id"], ident["asset_key"], ident["vuln_keys"], ident["fingerprint"], dup,
        )
        stamped += 1
        collapsed += 1 if dup else 0
    return {"stamped": stamped, "collapsed": collapsed}


# =========================================================================== #
# DB helpers: transitions + expiry sweep
# =========================================================================== #

async def record_history(con, finding_id: UUID, from_status: str | None, to_status: str,
                         reason: str | None, accepted_until: datetime | None, actor: str) -> None:
    await con.execute(
        """
        INSERT INTO finding_status_history
            (finding_id, from_status, to_status, reason, accepted_until, actor)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        finding_id, from_status, to_status, reason, accepted_until, actor,
    )


_last_sweep = 0.0


async def sweep_expired(pool, now: datetime | None = None) -> dict[str, int]:
    """Reopen expired acceptances / false-positive marks and release findings
    held by expired or disabled suppressions. Idempotent; audited per finding.

    Called from the scheduler loop every tick and (throttled) on read, so an
    expiry is honoured even when the scheduler is disabled.
    """
    now = now or datetime.now(timezone.utc)
    async with pool.acquire() as con:
        async with con.transaction():
            reopened = await con.fetch(
                """
                WITH due AS (
                    SELECT id, status, accepted_until FROM findings
                     WHERE accepted_until IS NOT NULL AND accepted_until <= $1
                       AND status = ANY($2::text[])
                     FOR UPDATE
                )
                UPDATE findings f
                   SET status = 'open',
                       status_reason = 'auto-reopened: acceptance expired',
                       status_by = $3, status_changed_at = $1, accepted_until = NULL
                  FROM due WHERE f.id = due.id
              RETURNING f.id, due.status AS from_status, due.accepted_until AS expired_at
                """,
                now, list(EXPIRING_STATUSES), SYSTEM_ACTOR,
            )
            for r in reopened:
                await record_history(con, r["id"], r["from_status"], "open",
                                     "auto-reopened: acceptance expired", None, SYSTEM_ACTOR)
            released = await con.execute(
                """
                UPDATE findings SET suppressed_by = NULL, suppressed_at = NULL
                 WHERE suppressed_by IN (
                     SELECT id FROM finding_suppressions
                      WHERE NOT enabled OR (expires_at IS NOT NULL AND expires_at <= $1))
                """,
                now,
            )
    for r in reopened:
        try:
            await audit.record(
                pool, action="update", actor=SYSTEM_ACTOR, actor_role="service",
                resource_type="findings", resource_id=str(r["id"]),
                details={"transition": "auto_reopen", "from": r["from_status"], "to": "open",
                         "expired_at": r["expired_at"].isoformat()},
            )
        except Exception:  # noqa: BLE001 -- never fail the sweep on audit
            logger.exception("lifecycle_audit_failed")
    n_released = int(released.split()[-1]) if released else 0
    if reopened or n_released:
        logger.info("lifecycle_sweep", extra={"reopened": len(reopened), "released": n_released})
    return {"reopened": len(reopened), "released": n_released}


async def maybe_sweep(pool, min_interval_s: float = 30.0) -> None:
    """On-read sweep, throttled per process. Never raises."""
    global _last_sweep
    t = time.monotonic()
    if t - _last_sweep < min_interval_s:
        return
    _last_sweep = t
    try:
        await sweep_expired(pool)
    except Exception:  # noqa: BLE001
        logger.exception("lifecycle_sweep_on_read_failed")


def reset_sweep_throttle() -> None:
    global _last_sweep
    _last_sweep = 0.0


# =========================================================================== #
# DB helpers: read-side enrichment (why / priority / sources / SLA / owner)
# =========================================================================== #

def _j(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return {}
    return v or {}


def _truthy(*vals: Any) -> bool:
    return any(v is True or (isinstance(v, str) and v.lower() == "true") for v in vals)


async def enrich(con, rows: list[dict[str, Any]], now: datetime | None = None) -> list[FindingLifecycleOut]:
    """Turn coerced finding rows (which carry ``asset_metadata``,
    ``ticket_owner``, ``ticket_due`` and ``sla_hours`` from the read query)
    into ``FindingLifecycleOut`` with sources, SLA, owner, why and score."""
    now = now or datetime.now(timezone.utc)
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    roots = list({r.get("duplicate_of") or r["id"] for r in rows})
    asset_ids = list({r["asset_id"] for r in rows})
    src_rows = await con.fetch(
        """
        SELECT id, duplicate_of, rule_source, rule_id, status, last_seen, epss, cvss,
               vuln_keys,
               COALESCE(metadata->>'kev', metadata->>'known_exploited', evidence->>'kev')
                   AS kev_flag
          FROM findings WHERE id = ANY($1::uuid[]) OR duplicate_of = ANY($1::uuid[])
         ORDER BY first_seen, id
        """,
        roots,
    )
    groups: dict[UUID, list[FindingSource]] = {}
    # Risk signals pooled across a duplicate group: the primary speaks for all.
    pooled: dict[UUID, dict[str, Any]] = {}
    for s in src_rows:
        root = s["duplicate_of"] or s["id"]
        p = pooled.setdefault(root, {"epss": [], "cvss": [], "kev": False, "cves": set()})
        if s["epss"] is not None:
            p["epss"].append(float(s["epss"]))
        if s["cvss"] is not None:
            p["cvss"].append(float(s["cvss"]))
        p["kev"] = p["kev"] or _truthy(s["kev_flag"])
        p["cves"].update(k[4:] for k in (s["vuln_keys"] or []) if k.startswith("cve:"))
        groups.setdefault(root, []).append(FindingSource(
            finding_id=s["id"], rule_source=s["rule_source"], rule_id=s["rule_id"],
            status=s["status"], last_seen=s["last_seen"], primary=s["duplicate_of"] is None,
        ))

    cve_ids = sorted({c for p in pooled.values() for c in p["cves"]}
                     | {c for r in rows for c in extract_cves(r["rule_id"], r.get("evidence"),
                                                               r.get("metadata"))})
    cves: dict[str, dict[str, Any]] = {}
    if cve_ids:
        for c in await con.fetch(
            "SELECT id, known_exploited, epss FROM cves WHERE id = ANY($1::text[])", cve_ids
        ):
            cves[c["id"]] = dict(c)

    # attack paths touching these assets: distance from asset to the target.
    path_rows = await con.fetch(
        """
        SELECT ap.id, ap.target_asset_id, ap.source_asset_id,
               t.value AS target_value, h.ord::int AS pos,
               jsonb_array_length(ap.hops) AS n, h.hop->>'asset_id' AS hop_asset
          FROM attack_paths ap
          CROSS JOIN LATERAL jsonb_array_elements(ap.hops) WITH ORDINALITY AS h(hop, ord)
          LEFT JOIN assets t ON t.id = ap.target_asset_id
         WHERE h.hop->>'asset_id' = ANY($1::text[])
        """,
        [str(a) for a in asset_ids],
    )
    nearest: dict[str, tuple[int, str]] = {}
    jewel: dict[str, str] = {}
    sources_of_paths: set[str] = set()
    for p in path_rows:
        aid = p["hop_asset"]
        dist = int(p["n"]) - int(p["pos"])
        tval = p["target_value"] or str(p["target_asset_id"])
        if dist == 0:
            jewel[aid] = tval
        elif aid not in nearest or dist < nearest[aid][0]:
            nearest[aid] = (dist, tval)
        if int(p["pos"]) == 1:
            sources_of_paths.add(aid)

    chain_by_finding: dict[UUID, str] = {}
    for c in await con.fetch(
        "SELECT title, finding_ids FROM finding_chains WHERE finding_ids && $1::uuid[] "
        "ORDER BY created_at DESC",
        ids,
    ):
        for fid in c["finding_ids"] or []:
            chain_by_finding.setdefault(fid, c["title"])

    owner_rules = [dict(r) for r in await con.fetch(
        "SELECT match, team, priority FROM asset_owners WHERE enabled ORDER BY priority"
    )]

    out: list[FindingLifecycleOut] = []
    for r in rows:
        d = dict(r)
        amd = _j(d.pop("asset_metadata", None))
        ticket_owner = d.pop("ticket_owner", None)
        ticket_due = d.pop("ticket_due", None)
        sla_hours = d.pop("sla_hours", None)
        md, ev = d.get("metadata") or {}, d.get("evidence") or {}
        aid = str(d["asset_id"])
        root = d.get("duplicate_of") or d["id"]
        group = groups.get(root, [])
        pool_ = pooled.get(root, {"epss": [], "cvss": [], "kev": False, "cves": set()})
        cve_list = sorted(set(extract_cves(d["rule_id"], ev, md)) | pool_["cves"])
        kev = _truthy(md.get("kev"), md.get("known_exploited"), ev.get("kev")) or pool_["kev"] \
            or any(cves.get(c, {}).get("known_exploited") for c in cve_list)
        epss_vals = [float(x) for x in [d.get("epss"), *pool_["epss"]]
                     + [cves.get(c, {}).get("epss") for c in cve_list] if x is not None]
        epss = max(epss_vals) if epss_vals else None
        cvss_vals = [float(x) for x in [d.get("cvss"), *pool_["cvss"]] if x is not None]
        cvss = max(cvss_vals) if cvss_vals else None
        internet = (_truthy(amd.get("public"), amd.get("internet_facing"))
                    or amd.get("exposure") == "internet" or aid in sources_of_paths
                    or d.get("asset_kind") == "endpoint")
        owner = ticket_owner or resolve_owner(
            {"kind": d.get("asset_kind"), "value": d.get("asset_value"), "metadata": amd}, owner_rules)
        due = compute_due(d.get("first_seen"), sla_hours, ticket_due)
        breached = is_breached(d["status"], due, now)
        near = nearest.get(aid)
        score, why = explain_priority(
            severity=d["severity"], cvss=cvss, epss=epss, kev=kev,
            internet_facing=internet, crown_jewel=jewel.get(aid),
            path_distance=near[0] if near else None, path_target=near[1] if near else None,
            blast_score=d.get("blast_score"), chain_title=chain_by_finding.get(d["id"]),
            engines=[s.rule_source for s in group] or [d["rule_source"]],
            sla_breached=breached, owner=owner,
            exploitability=d.get("exploitability"), verified_at=d.get("last_verified_at"),
        )
        d.update(
            suppressed=d.get("suppressed_by") is not None,
            sources=group, source_count=max(1, len(group)),
            due_at=due, sla_hours=sla_hours if sla_hours and sla_hours > 0 else None,
            sla_breached=breached, owner=owner, kev=kev,
            priority_score=score, why=why,
        )
        d["vuln_keys"] = list(d.get("vuln_keys") or [])
        out.append(FindingLifecycleOut.model_validate(d))
    return out
