"""Persist a :class:`ParseResult`: assets, findings (lifecycle dedupe),
SBOM components. Everything runs in the caller's transaction.

Reuses the existing write paths so ingested data behaves exactly like data
from Paddock's own engines: the findings upsert key, the lifecycle
fingerprint / duplicate collapse / suppression rules (``lifecycle.apply_ingest``),
and the SBOM upserts used by ``POST /v1/import/sbom``. Nothing here touches a
target, so no scope check applies: this is data the caller already holds.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .. import lifecycle
from ..scope import normalize
from .common import ParseResult, clean

_NET_KINDS = {"domain", "subdomain", "ipv4", "ipv6", "endpoint"}

_ASSET_SQL = """
INSERT INTO assets (kind, value, canonical, source, confidence, metadata)
VALUES ($1, $2, $3, 'ingest', 90, $4::jsonb)
ON CONFLICT (tenant_id, kind, canonical) DO UPDATE SET last_seen = NOW()
RETURNING id, (xmax = 0) AS was_inserted
"""


def _canonical(kind: str, value: str) -> str:
    if kind in _NET_KINDS:
        return normalize(value) or value.lower()
    return value.lower()


async def _asset_id(con, cache: dict[tuple[str, str], Any], kind: str, value: str,
                    source: str, counters: dict[str, int]) -> Any:
    key = (kind, value)
    if key not in cache:
        row = await con.fetchrow(_ASSET_SQL, kind, value, _canonical(kind, value),
                                 json.dumps({"ingest_source": source}))
        cache[key] = row["id"]
        if row["was_inserted"]:
            counters["assets"] += 1
    return cache[key]


async def persist(con, res: ParseResult, *, source: str, project: str | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Write ``res``. Returns ``(counts, events)``; ``events`` are
    ``finding_opened`` / ``finding_suppressed`` / ``asset_added`` dicts the
    caller publishes after commit."""
    # imported here: routers import this package, so the reverse would cycle
    from ..routers import exports as exports_router
    from ..routers import findings as findings_router

    counters = {"assets": 0}
    out = {"findings_new": 0, "findings_updated": 0, "duplicates": 0, "suppressed": 0,
           "components": 0, "vulnerabilities": 0, "assets": 0}
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    asset_cache: dict[tuple[str, str], Any] = {}
    lc_cache: dict[Any, dict[str, Any]] = {}
    suppressions = await lifecycle.load_active_suppressions(con) if res.findings else []

    for f in res.findings:
        aid = await _asset_id(con, asset_cache, f.asset_kind, f.asset_value, source, counters)
        md = {**f.metadata}
        md.setdefault("ingest", {})
        md["ingest"] = {**md["ingest"], "source": source, "at": now}
        row = await con.fetchrow(
            findings_router._BULK_SQL, aid, f.rule_id, f.rule_source, f.severity,
            clean(f.title, 512) or f.rule_id, f.description or f.title, f.impact, f.remediation,
            json.dumps(f.evidence, default=str), f.cvss, None, list(f.references), json.dumps(md, default=str))
        d = findings_router._coerce_finding_row(row)
        inserted = d.pop("was_inserted")
        d.update(await lifecycle.apply_ingest(con, d, suppressions, lc_cache))
        suppressed = d.get("suppressed_by") is not None
        out["suppressed"] += 1 if suppressed else 0
        out["duplicates"] += 1 if d.get("duplicate_of") else 0
        if inserted:
            out["findings_new"] += 1
            events.append({"event": "finding_suppressed" if suppressed else "finding_opened",
                           "finding_id": str(d["id"]), "asset_id": str(d["asset_id"]),
                           "severity": d["severity"], "rule_id": d["rule_id"],
                           "rule_source": d["rule_source"],
                           "duplicate_of": str(d["duplicate_of"]) if d.get("duplicate_of") else None,
                           "ts": d["first_seen"].isoformat()})
        else:
            out["findings_updated"] += 1

    comps = res.components
    vulns = res.component_vulns
    sbom = res.sbom
    if sbom is not None:
        comps, vulns = sbom["components"], sbom.get("vulns") or []
    if comps:
        pname = clean(project or res.project_hint or source, 200) or source
        out.update(await _store_components(con, exports_router, pname, res.format, comps, vulns,
                                           asset_cache, source, counters))
    out["assets"] = counters["assets"]
    return out, events


async def _store_components(con, exports_router, pname: str, fmt: str, comps: list[dict[str, Any]],
                            vulns: list[dict[str, Any]], asset_cache, source: str,
                            counters: dict[str, int]) -> dict[str, int]:
    # one row per natural key (a single INSERT .. ON CONFLICT cannot hit a row twice)
    comps = list({(c["ecosystem"], c["name"], c["version"]): c for c in comps}.values())
    ecosystems = sorted({c["ecosystem"] for c in comps})
    prow = await con.fetchrow(exports_router._UPSERT_PROJECT, pname, f"ingest:{fmt}", ecosystems)
    pid = prow["id"]
    aid = await _asset_id(con, asset_cache, "repository", pname, source, counters)
    await con.execute("UPDATE sca_projects SET asset_id = COALESCE(asset_id, $2) WHERE id = $1", pid, aid)
    rows = await con.fetch(
        exports_router._UPSERT_COMPONENTS, pid,
        [c["ecosystem"] for c in comps], [c["name"] for c in comps], [c["version"] for c in comps],
        [c.get("purl") for c in comps], [bool(c.get("direct")) for c in comps],
        [min(int(c.get("depth") or 0), 32767) for c in comps],
        [json.dumps(c.get("paths") or []) for c in comps],
        [json.dumps(c.get("metadata") or {}) for c in comps])
    ids = {(r["ecosystem"], r["name"], r["version"]): r["id"] for r in rows}
    n_v = 0
    for v in vulns:
        cid = ids.get(tuple(v["key"]))
        if cid is None:
            continue
        await con.execute(exports_router._UPSERT_VULN, cid, v["osv_id"], v.get("cve_id"), v["severity"],
                          v.get("cvss"), v.get("summary"), v.get("reachability"))
        n_v += 1
    if fmt in ("cyclonedx", "spdx"):          # sca_project_manifests.kind only allows SBOM documents
        digest = hashlib.sha256(json.dumps(sorted(map(str, ids)), default=str).encode()).hexdigest()
        await con.execute(exports_router._UPSERT_MANIFEST, pid, f"import:{fmt}", None, fmt, digest,
                          len(comps), f"ingest:{source}")
    return {"components": len(ids), "vulnerabilities": n_v, "project_id": str(pid), "project": pname}
