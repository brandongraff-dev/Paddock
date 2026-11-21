"""Shared fixtures + an in-memory stand-in for app.db.Database.

The pipeline, gate, injection, verifier and generators are pure/unit-testable,
so the whole suite runs WITHOUT Postgres and WITHOUT the anthropic SDK.

Crucially, ``FakeDB.resolve_dependency_spec`` reads the OSV ``fixed_version``
from its seeded SCA store — NOT from the finding — mirroring the production DB
property that the fixed version is DB-authoritative.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.config import Config


class FakeDB:
    def __init__(self) -> None:
        self.findings: dict[str, dict[str, Any]] = {}
        # component_id -> {ecosystem, package, current_version, fixed_version,
        #                  osv_id, cve_id, repo}
        self.vulns: dict[str, dict[str, Any]] = {}
        self.remediations: list[dict[str, Any]] = []

    # --- seed helpers -----------------------------------------------------
    def add_finding(self, **kw: Any) -> str:
        fid = kw.get("id") or str(uuid.uuid4())
        rec = {
            "id": fid,
            "asset_id": kw.get("asset_id") or str(uuid.uuid4()),
            "rule_id": kw.get("rule_id", "rule"),
            "rule_source": kw.get("rule_source", "sca"),
            "severity": kw.get("severity", "high"),
            "title": kw.get("title", "finding"),
            "description": kw.get("description", "desc"),
            "impact": kw.get("impact"),
            "remediation": kw.get("remediation"),
            "evidence": kw.get("evidence", {}),
            "metadata": kw.get("metadata", {}),
            "cvss": kw.get("cvss"),
            "epss": kw.get("epss"),
            "status": kw.get("status", "open"),
            "asset": kw.get("asset", {"kind": "repository", "value": "example/repo"}),
        }
        self.findings[fid] = rec
        return fid

    def add_vuln(self, component_id: str, **kw: Any) -> None:
        self.vulns[component_id] = {
            "ecosystem": kw.get("ecosystem", "PyPI"),
            "package": kw.get("package", "lib"),
            "current_version": kw.get("current_version", "1.0.0"),
            "fixed_version": kw.get("fixed_version", "1.0.1"),
            "osv_id": kw.get("osv_id", "GHSA-xxxx"),
            "cve_id": kw.get("cve_id"),
            "repo": kw.get("repo", "example/repo"),
        }

    # --- Database surface used by the pipeline ---------------------------
    async def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        f = self.findings.get(finding_id)
        return dict(f) if f else None

    async def resolve_dependency_spec(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        ev = finding.get("evidence") or {}
        meta = finding.get("metadata") or {}
        merged = {**meta, **ev}
        comp = merged.get("component_id")
        if comp and comp in self.vulns:
            return dict(self.vulns[comp])
        # match by ecosystem+package
        eco = (merged.get("ecosystem") or "").lower()
        pkg = (merged.get("package") or merged.get("name") or "").lower()
        for v in self.vulns.values():
            if v["ecosystem"].lower() == eco and v["package"].lower() == pkg:
                return dict(v)
        return None

    async def insert_remediation(self, rec: dict[str, Any]) -> dict[str, Any]:
        saved = dict(rec)
        saved["id"] = str(uuid.uuid4())
        saved.setdefault("created_at", "2026-01-01T00:00:00+00:00")
        if hasattr(saved.get("verified_at"), "isoformat"):
            saved["verified_at"] = saved["verified_at"].isoformat()
        self.remediations.append(saved)
        return saved

    async def get_remediation(self, rid: str) -> dict[str, Any] | None:
        for r in self.remediations:
            if r["id"] == rid:
                return dict(r)
        return None

    async def list_remediations(self, status=None, limit=50, offset=0):
        rows = [r for r in self.remediations if status is None or r["status"] == status]
        return rows[offset:offset + limit], len(rows)

    async def stats(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for r in self.remediations:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        return {"total": len(self.remediations), "by_status": by_status, "by_kind": by_kind}

    async def ping(self) -> bool:
        return True


class FakeLLM:
    """Disabled LLM (the no-key path). Pipeline must work fully with this."""

    def is_enabled(self) -> bool:
        return False

    async def explain(self, *_a, **_k):
        return None

    async def verify_second_opinion(self, *_a, **_k):
        return None


@pytest.fixture
def fake_db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def fake_llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture
def cfg() -> Config:
    # Defaults: open_pr false, no token -> no PR is ever pushed.
    return Config()
