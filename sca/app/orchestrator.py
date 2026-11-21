"""Thin async client for the orchestrator HTTP API.

SCA posts one ``sca`` finding per vulnerable component via
``POST /v1/findings/bulk`` (upsert by asset_id/asset_value + rule_id +
rule_source). It never writes assets or findings directly in Postgres.
"""
from __future__ import annotations

import os

import logging
from typing import Any

import aiohttp

log = logging.getLogger("sca.orchestrator")

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def worst_severity(severities: list[str]) -> str:
    best = "low"
    for s in severities:
        if _SEV_RANK.get(s, 0) > _SEV_RANK.get(best, 0):
            best = s
    return best


def build_sca_finding(
    *,
    component: dict[str, Any],
    vulns: list[dict[str, Any]],
    project: dict[str, Any],
) -> dict[str, Any]:
    """Build a ``POST /v1/findings/bulk`` item for one vulnerable component.

    Attached to the project's linked repository asset when it has one, else to
    an asset identified by the project name (kind ``repository``). Remediation
    is generic -- this service emits no exploit guidance.
    """
    eco = component.get("ecosystem")
    name = component.get("name")
    version = component.get("version")
    severity = worst_severity([v.get("severity") or "medium" for v in vulns])
    osv_ids = [v.get("osv_id") for v in vulns if v.get("osv_id")]
    cve_ids = [v.get("cve_id") for v in vulns if v.get("cve_id")]
    fixed = next((v.get("fixed_version") for v in vulns if v.get("fixed_version")), None)
    cvss = max((v.get("cvss") for v in vulns if v.get("cvss") is not None), default=None)
    refs: list[str] = []
    for v in vulns:
        refs.extend(v.get("refs") or [])

    title = f"Vulnerable dependency {name}@{version} ({eco})"
    impact_bits = [
        f"{len(vulns)} known vulnerabilit" + ("y" if len(vulns) == 1 else "ies"),
        "in a " + ("direct" if component.get("direct") else "transitive") + " dependency",
    ]
    if cve_ids:
        impact_bits.append("(" + ", ".join(dict.fromkeys(cve_ids)) + ")")
    remediation = (
        f"Upgrade {name} to {fixed} or later." if fixed else
        f"Upgrade {name} to a release that is not in the affected range; "
        "see the advisories in `references`."
    )

    item: dict[str, Any] = {
        "rule_id": f"sca:{eco}:{name}",
        "rule_source": "sca",
        "severity": severity,
        "title": title,
        "description": (
            f"{name}@{version} ({eco}) matches {len(vulns)} OSV advisory record(s): "
            + ", ".join(dict.fromkeys(osv_ids))
        ),
        "impact": " ".join(impact_bits) + ".",
        "remediation": remediation,
        "evidence": {
            "ecosystem": eco,
            "package": name,
            "version": version,
            "direct": component.get("direct"),
            "depth": component.get("depth"),
            "paths": component.get("paths") or [],
            "osv_ids": list(dict.fromkeys(osv_ids)),
            "cve_ids": list(dict.fromkeys(cve_ids)),
            "fixed_version": fixed,
        },
        "cvss": cvss,
        "references": list(dict.fromkeys(refs))[:20],
        "metadata": {"source": "sca", "project": project.get("name")},
    }
    if project.get("asset_id"):
        item["asset_id"] = project["asset_id"]
    else:
        item["asset_value"] = project.get("name") or name
        item["asset_kind"] = "repository"
    return item


class OrchestratorClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: int = 30,
        user_agent: str = "paddock-sca/0.1",
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._ua = user_agent
        self._session = session
        self._owns_session = session is None

    async def __aenter__(self) -> "OrchestratorClient":
        await self.ensure()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def ensure(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                headers={
                    "User-Agent": self._ua,
                    "Accept": "application/json",
                    # Service credential for AUTH_MODE=enforce (hardened profile).
                    **({"X-API-Key": k} if (k := os.environ.get("SERVICE_API_KEY")) else {}),
                },
            )

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        await self.ensure()
        assert self._session is not None
        url = f"{self.base_url}/v1/assets/{asset_id}"
        try:
            async with self._session.get(url) as resp:
                if resp.status == 404:
                    return None
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: get_asset %s failed: %s", asset_id, exc)
            return None

    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """POST /v1/findings/bulk -- upsert a batch of findings."""
        await self.ensure()
        assert self._session is not None
        if not findings:
            return {"accepted": 0}
        url = f"{self.base_url}/v1/findings/bulk"
        try:
            async with self._session.post(url, json={"items": findings}) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as exc:
            log.warning("orchestrator: bulk_findings failed: %s", exc)
            return {"accepted": 0, "error": str(exc)}
