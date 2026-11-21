"""OSV.dev adapter: batch-query the dependency graph, then fetch details.

Flow:
  1. ``POST /v1/querybatch`` with {package:{ecosystem,name}, version} for every
     component (chunked to <=1000 queries per request).
  2. For every hit, ``GET /v1/vulns/{id}`` once (cached) for full details.
  3. Map each detail to an ``sbom_component_vulns``-shaped dict:
     osv_id, cve_id (from aliases), severity (from CVSS), cvss, summary,
     fixed_version (from affected ranges), refs.

Read-only consumption of a public vulnerability database. Nothing here probes,
exploits, or fetches exploit code -- it records which of the owner's own
components are known-vulnerable.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

import aiohttp

log = logging.getLogger("sca.osv")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

MAX_BATCH = 1000


# ---------------------------------------------------------------------------
# query building / id extraction
# ---------------------------------------------------------------------------
def build_queries(packages: Iterable[tuple[str, str, str]]) -> dict[str, Any]:
    """Build a querybatch body from (ecosystem, name, version) tuples."""
    queries: list[dict[str, Any]] = []
    for ecosystem, name, version in packages:
        q: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            q["version"] = version
        queries.append(q)
    return {"queries": queries}


def extract_ids(response: dict[str, Any]) -> list[list[str]]:
    """Per query, the list of OSV vuln ids returned (parallel to the input)."""
    out: list[list[str]] = []
    for result in (response or {}).get("results", []) or []:
        vulns = (result or {}).get("vulns") or []
        out.append([v["id"] for v in vulns if isinstance(v, dict) and v.get("id")])
    return out


def cve_from_aliases(vuln: dict[str, Any]) -> str | None:
    for alias in (vuln.get("aliases") or []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return None


def is_malicious(vuln: dict[str, Any]) -> bool:
    """OSV flags malicious packages with a ``MAL-`` id (and 'malware')."""
    vid = str(vuln.get("id") or "")
    if vid.startswith("MAL-"):
        return True
    for alias in (vuln.get("aliases") or []):
        if isinstance(alias, str) and alias.startswith("MAL-"):
            return True
    return False


# ---------------------------------------------------------------------------
# CVSS parsing
# ---------------------------------------------------------------------------
def severity_bucket(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _round_up(x: float) -> float:
    import math
    return math.ceil(x * 10) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.0/3.1 base score from a vector string."""
    try:
        parts = dict(
            kv.split(":", 1)
            for kv in vector.strip().split("/")
            if ":" in kv
        )
    except Exception:
        return None
    if not any(k.startswith("CVSS:3") for k in [vector.split("/", 1)[0]]):
        # allow bare vectors too
        pass
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV"))
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC"))
    ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI"))
    scope = parts.get("S")
    pr_raw = parts.get("PR")
    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr_raw)
    if pr_raw in ("L", "H") and scope == "C":
        pr = {"L": 0.68, "H": 0.50}[pr_raw]
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("C"))
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("I"))
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("A"))
    if None in (av, ac, ui, pr, c, i, a) or scope not in ("U", "C"):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    return _round_up(base)


def severity_and_score(vuln: dict[str, Any]) -> tuple[str, float | None]:
    """Derive (severity, cvss) for a vuln from its ``severity`` entries, or a
    database-specific severity label as a fallback."""
    score: float | None = None
    for entry in (vuln.get("severity") or []):
        if not isinstance(entry, dict):
            continue
        val = str(entry.get("score") or "")
        etype = str(entry.get("type") or "")
        if val.startswith("CVSS:3") or (etype.startswith("CVSS_V3") and "/" in val):
            s = cvss3_base_score(val)
            if s is not None:
                score = s if score is None else max(score, s)
        else:
            try:
                score = float(val) if score is None else max(score, float(val))
            except ValueError:
                pass
    if score is not None:
        return severity_bucket(score), score
    # fallback: database_specific.severity label (GHSA: LOW/MODERATE/HIGH/CRITICAL)
    label = _label_severity(vuln)
    return label or "medium", None


def _label_severity(vuln: dict[str, Any]) -> str | None:
    ds = vuln.get("database_specific") or {}
    label = str(ds.get("severity") or "").upper()
    mapping = {
        "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
        "MEDIUM": "medium", "LOW": "low",
    }
    return mapping.get(label)


def fixed_version_for(vuln: dict[str, Any], ecosystem: str, name: str) -> str | None:
    """First ``fixed`` event in the affected ranges matching this package."""
    for aff in (vuln.get("affected") or []):
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
            continue
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if isinstance(ev, dict) and ev.get("fixed"):
                    return str(ev["fixed"])
    # relax ecosystem/name match if nothing exact
    for aff in (vuln.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if isinstance(ev, dict) and ev.get("fixed"):
                    return str(ev["fixed"])
    return None


def ref_urls(vuln: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for r in (vuln.get("references") or []):
        if isinstance(r, dict) and r.get("url"):
            out.append(str(r["url"]))
        elif isinstance(r, str):
            out.append(r)
    return out[:20]


def map_vuln(vuln: dict[str, Any], ecosystem: str, name: str) -> dict[str, Any]:
    """Map an OSV vuln detail to an sbom_component_vulns-shaped dict."""
    severity, cvss = severity_and_score(vuln)
    return {
        "osv_id": vuln.get("id"),
        "cve_id": cve_from_aliases(vuln),
        "severity": severity,
        "cvss": cvss,
        "summary": vuln.get("summary") or (vuln.get("details") or "")[:500] or None,
        "fixed_version": fixed_version_for(vuln, ecosystem, name),
        "refs": ref_urls(vuln),
        "malicious": is_malicious(vuln),
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
async def batch_query(
    session: aiohttp.ClientSession,
    packages: list[tuple[str, str, str]],
    *,
    url: str = OSV_BATCH_URL,
) -> list[list[str]]:
    """Query OSV in <=MAX_BATCH chunks; return per-package lists of vuln ids."""
    ids: list[list[str]] = []
    for start in range(0, len(packages), MAX_BATCH):
        chunk = packages[start:start + MAX_BATCH]
        body = build_queries(chunk)
        try:
            async with session.post(url, json=body) as resp:
                resp.raise_for_status()
                data = await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("osv: querybatch failed: %s", exc)
            ids.extend([[] for _ in chunk])
            continue
        ids.extend(extract_ids(data))
    return ids


async def get_vuln(
    session: aiohttp.ClientSession, vuln_id: str, *, url: str = OSV_VULN_URL
) -> dict[str, Any] | None:
    try:
        async with session.get(url.format(vuln_id=vuln_id)) as resp:
            if resp.status == 404:
                return None
            resp.raise_for_status()
            return await resp.json()
    except aiohttp.ClientError as exc:
        log.warning("osv: get_vuln %s failed: %s", vuln_id, exc)
        return None


async def scan_components(
    session: aiohttp.ClientSession,
    components: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """For each component with a version, return its mapped vuln records.

    Returns a map keyed by ``"{ecosystem}|{name}|{version}"`` -> [vuln dicts].
    Vuln details are fetched once per unique OSV id and reused.
    """
    queryable = [c for c in components if c.get("name") and c.get("version")]
    packages = [(c["ecosystem"], c["name"], c["version"]) for c in queryable]
    if not packages:
        return {}
    per_pkg_ids = await batch_query(session, packages)

    detail_cache: dict[str, dict[str, Any] | None] = {}
    result: dict[str, list[dict[str, Any]]] = {}
    for comp, vuln_ids in zip(queryable, per_pkg_ids):
        key = f"{comp['ecosystem']}|{comp['name']}|{comp['version']}"
        mapped: list[dict[str, Any]] = []
        for vid in vuln_ids:
            if vid not in detail_cache:
                detail_cache[vid] = await get_vuln(session, vid)
            detail = detail_cache[vid]
            if detail is None:
                # keep the bare id even if detail fetch failed
                mapped.append({
                    "osv_id": vid, "cve_id": None, "severity": "medium",
                    "cvss": None, "summary": None, "fixed_version": None,
                    "refs": [], "malicious": vid.startswith("MAL-"),
                })
            else:
                mapped.append(map_vuln(detail, comp["ecosystem"], comp["name"]))
        if mapped:
            result[key] = mapped
    return result
