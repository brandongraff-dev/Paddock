"""Shared fixtures + a very small in-memory stand-in for the Database."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime
from typing import Any

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    path = FIXTURES / name
    if name.endswith(".json"):
        return json.loads(path.read_text())
    return path.read_text()


class FakeDB:
    """In-memory substitute for app.db.Database used in unit tests."""

    def __init__(self) -> None:
        self.cves: dict[str, dict[str, Any]] = {}
        self.matches: list[dict[str, Any]] = []
        self.cursors: dict[str, dict[str, Any]] = {}

    async def upsert_cve(self, record: dict[str, Any]) -> bool:
        cur = self.cves.get(record["id"])
        if cur is None:
            self.cves[record["id"]] = dict(record)
            return True
        cur_mod = cur.get("modified_at")
        new_mod = record.get("modified_at")
        if cur_mod and new_mod and new_mod < cur_mod:
            return False
        cur.update(record)
        return True

    async def update_epss(self, cve_id: str, epss: float, pct: float) -> bool:
        if cve_id not in self.cves:
            return False
        self.cves[cve_id]["epss"] = epss
        self.cves[cve_id]["epss_percentile"] = pct
        return True

    async def mark_kev(self, cve_id: str, added_at: datetime | None) -> bool:
        if cve_id not in self.cves:
            return False
        self.cves[cve_id]["known_exploited"] = True
        self.cves[cve_id]["kev_added_at"] = added_at
        return True

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        return self.cves.get(cve_id)

    async def candidate_cves_for(
        self, vendor: str, product: str, limit: int = 500
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        vendor_l = (vendor or "").lower()
        product_l = (product or "").lower()
        for cve in self.cves.values():
            for entry in cve.get("cpe_affected") or []:
                e_v = (entry.get("vendor") or "").lower()
                e_p = (entry.get("product") or "").lower()
                if product_l and e_p == product_l and (not vendor_l or e_v == vendor_l):
                    out.append(cve)
                    break
        return out[:limit]

    async def upsert_match(
        self, cve_id: str, asset_id: str, confidence: int, matcher: str
    ) -> bool:
        for m in self.matches:
            if m["cve_id"] == cve_id and m["asset_id"] == asset_id:
                m["confidence"] = max(m["confidence"], int(confidence))
                m["matcher"] = matcher
                return False
        self.matches.append({
            "cve_id": cve_id,
            "asset_id": asset_id,
            "confidence": int(confidence),
            "matcher": matcher,
        })
        return True

    async def get_cursor(self, source: str) -> dict[str, Any] | None:
        return self.cursors.get(source)

    async def set_cursor(
        self,
        source: str,
        last_synced: datetime | None = None,
        last_cursor: str | None = None,
        stats: dict[str, Any] | None = None,
    ) -> None:
        cur = self.cursors.setdefault(source, {"source": source, "stats": {}})
        if last_synced:
            cur["last_synced"] = last_synced
        if last_cursor:
            cur["last_cursor"] = last_cursor
        if stats:
            cur["stats"].update(stats)


class FakeOrchestrator:
    def __init__(self, assets: list[dict[str, Any]] | None = None) -> None:
        self._assets = list(assets or [])
        self.posted_findings: list[dict[str, Any]] = []

    async def ensure(self) -> None: ...
    async def close(self) -> None: ...

    async def list_technology_assets(
        self, *, limit: int = 500, offset: int = 0
    ) -> list[dict[str, Any]]:
        return self._assets[offset:offset + limit]

    async def iter_technology_assets(self, *, page_size: int = 500):
        for a in self._assets:
            yield a

    async def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        for a in self._assets:
            if a.get("id") == asset_id:
                return a
        return None

    async def bulk_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        self.posted_findings.extend(findings)
        return {"accepted": len(findings)}


@pytest.fixture
def fake_db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def fake_orch() -> FakeOrchestrator:
    return FakeOrchestrator()
