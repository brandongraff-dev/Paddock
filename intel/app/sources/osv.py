"""OSV.dev batch-query adapter (optional).

Given a list of (ecosystem, package, version) tuples, calls
``POST /v1/querybatch`` on OSV.dev and emits vulnerability records.
When an OSV entry carries a CVE alias we return that CVE id so the
caller can reuse the row already ingested from NVD; otherwise we return
the OSV id itself so it can be stored as an ``OSV-``-prefixed row.

This is kept deliberately minimal — happy path only — so the service
can skip it entirely when ``ENABLE_OSV=false``.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

import aiohttp

log = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


def build_queries(packages: Iterable[tuple[str, str, str]]) -> dict[str, Any]:
    """Build the batchquery body from (ecosystem, name, version) tuples."""
    queries: list[dict[str, Any]] = []
    for ecosystem, name, version in packages:
        q: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            q["version"] = version
        queries.append(q)
    return {"queries": queries}


def extract_ids(response: dict[str, Any]) -> list[list[str]]:
    """Per query, the list of OSV vuln ids returned."""
    out: list[list[str]] = []
    for result in (response or {}).get("results", []) or []:
        vulns = (result or {}).get("vulns") or []
        out.append([v["id"] for v in vulns if isinstance(v, dict) and v.get("id")])
    return out


def cve_or_osv_id(vuln_record: dict[str, Any]) -> str | None:
    """Prefer any CVE alias over the native OSV id."""
    if not isinstance(vuln_record, dict):
        return None
    for alias in (vuln_record.get("aliases") or []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return vuln_record.get("id")


async def batch_query(
    session: aiohttp.ClientSession,
    packages: Iterable[tuple[str, str, str]],
    *,
    url: str = OSV_BATCH_URL,
) -> dict[str, Any]:
    body = build_queries(packages)
    async with session.post(url, json=body) as resp:
        resp.raise_for_status()
        return await resp.json()


async def get_vuln(
    session: aiohttp.ClientSession, vuln_id: str, *, url: str = OSV_VULN_URL
) -> dict[str, Any] | None:
    try:
        async with session.get(url.format(vuln_id=vuln_id)) as resp:
            if resp.status == 404:
                return None
            resp.raise_for_status()
            return await resp.json()
    except aiohttp.ClientError as exc:  # pragma: no cover
        log.warning("osv: get_vuln %s failed: %s", vuln_id, exc)
        return None


async def sync(
    db: Any,
    session: aiohttp.ClientSession,
    *,
    packages: Iterable[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """Happy-path wiring: query OSV for the provided packages and record ids.

    Without packages (e.g. no OSS inventory yet), return a no-op result.
    """
    if not packages:
        return {"queried": 0, "linked": 0}
    response = await batch_query(session, packages)
    per_query = extract_ids(response)
    linked = 0
    for ids in per_query:
        linked += len(ids)
    return {"queried": sum(1 for _ in per_query), "linked": linked}
