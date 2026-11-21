"""NVD 2.0 CVE feed adapter.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Flow:
- Determine window [startDate, endDate] from stored cursor (or bootstrap).
- Walk pages of up to 2000 results, respecting rate limits.
- Parse each ``vulnerabilities[*].cve`` record into the shape we store.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import aiohttp

from . import TokenBucket

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD maximum
# NVD hard-caps the (lastModStartDate, lastModEndDate) window at 120 days;
# anything larger must be split. We bite off 110-day chunks.
MAX_WINDOW_DAYS = 110


def _fmt_ts(ts: datetime) -> str:
    """NVD requires ISO-8601 with explicit zone offset, no microseconds."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # Some records use "...Z", some "...+00:00".
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _en_text(entries: Iterable[dict[str, Any]] | None) -> str | None:
    if not entries:
        return None
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("lang") == "en" and e.get("value"):
            return e["value"]
    # fall back to the first available value
    for e in entries:
        if isinstance(e, dict) and e.get("value"):
            return e["value"]
    return None


def _best_cvss_v3(metrics: dict[str, Any] | None) -> tuple[float | None, str | None]:
    """Return (base_score, vector_string) choosing v3.1 > v3.0 > None."""
    if not isinstance(metrics, dict):
        return (None, None)
    for key in ("cvssMetricV31", "cvssMetricV30"):
        bucket = metrics.get(key) or []
        for item in bucket:
            cvss = (item or {}).get("cvssData") or {}
            score = cvss.get("baseScore")
            vec = cvss.get("vectorString")
            if score is not None:
                try:
                    return (float(score), vec)
                except (TypeError, ValueError):
                    continue
    return (None, None)


def _best_cvss_v2(metrics: dict[str, Any] | None) -> float | None:
    if not isinstance(metrics, dict):
        return None
    bucket = metrics.get("cvssMetricV2") or []
    for item in bucket:
        cvss = (item or {}).get("cvssData") or {}
        score = cvss.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return None


def _cwe_ids(weaknesses: Iterable[dict[str, Any]] | None) -> list[str]:
    out: list[str] = []
    if not weaknesses:
        return out
    seen: set[str] = set()
    for w in weaknesses:
        for desc in (w or {}).get("description", []) or []:
            v = (desc or {}).get("value")
            if v and v.startswith("CWE-") and v not in seen:
                seen.add(v)
                out.append(v)
    return out


def _refs(references: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not references:
        return out
    for r in references:
        url = (r or {}).get("url")
        if not url:
            continue
        # Deliberate: we STORE exploit URLs but will never fetch them.
        tags = (r or {}).get("tags") or []
        out.append({"url": url, "tags": list(tags), "source": (r or {}).get("source")})
    return out


def _cpe_from_criteria(criteria: str) -> dict[str, str]:
    """Split a CPE 2.3 string into its component map.

    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    parts = criteria.split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return {}
    keys = ["part", "vendor", "product", "version", "update", "edition",
            "language", "sw_edition", "target_sw", "target_hw", "other"]
    return {k: parts[i + 2] for i, k in enumerate(keys)}


def _cpe_affected(configurations: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Flatten NVD's nested configurations to a list of match specs.

    Each item carries vendor/product/version plus any range constraints so
    downstream matchers don't have to re-parse CPE strings.
    """
    out: list[dict[str, Any]] = []
    if not configurations:
        return out
    for cfg in configurations:
        for node in (cfg or {}).get("nodes", []) or []:
            for m in (node or {}).get("cpeMatch", []) or []:
                criteria = m.get("criteria")
                if not criteria:
                    continue
                comp = _cpe_from_criteria(criteria)
                if not comp:
                    continue
                entry: dict[str, Any] = {
                    "criteria": criteria,
                    "vulnerable": bool(m.get("vulnerable", True)),
                    "vendor": comp.get("vendor", ""),
                    "product": comp.get("product", ""),
                    "version": comp.get("version", "*"),
                    "part": comp.get("part", ""),
                }
                for k in (
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding",
                ):
                    if m.get(k):
                        entry[k] = m[k]
                out.append(entry)
    return out


def parse_cve(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a single ``vulnerabilities[*].cve`` record into our schema."""
    if not isinstance(raw, dict):
        return None
    cve = raw.get("cve") if "cve" in raw else raw
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not cve_id:
        return None
    cvss_v3, vec = _best_cvss_v3(cve.get("metrics"))
    return {
        "id": cve_id,
        "published_at": _parse_ts(cve.get("published")),
        "modified_at": _parse_ts(cve.get("lastModified")),
        "cvss_v3": cvss_v3,
        "cvss_v3_vector": vec,
        "cvss_v2": _best_cvss_v2(cve.get("metrics")),
        "description": _en_text(cve.get("descriptions")),
        "refs": _refs(cve.get("references")),
        "cpe_affected": _cpe_affected(cve.get("configurations")),
        "cwe_ids": _cwe_ids(cve.get("weaknesses")),
    }


# ---------------------------------------------------------------------------
# Live sync
# ---------------------------------------------------------------------------
class NVDClient:
    """Rate-limited paginator for the NVD 2.0 API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_key: str | None,
        *,
        bucket: TokenBucket | None = None,
    ) -> None:
        self.session = session
        self.api_key = api_key
        # Default to no-key quota: 5 req / 30s. With a key: 50 / 30s.
        if bucket is not None:
            self.bucket = bucket
        elif api_key:
            self.bucket = TokenBucket(capacity=50, window=30.0)
        else:
            self.bucket = TokenBucket(capacity=5, window=30.0)

    def _headers(self) -> dict[str, str]:
        hdrs = {"Accept": "application/json"}
        if self.api_key:
            hdrs["apiKey"] = self.api_key
        return hdrs

    async def _get(self, params: dict[str, str]) -> dict[str, Any]:
        """One rate-limited GET with a couple of simple retries on 429/5xx."""
        last_exc: Exception | None = None
        for attempt in range(4):
            await self.bucket.acquire()
            try:
                async with self.session.get(
                    NVD_API, params=params, headers=self._headers()
                ) as resp:
                    if resp.status == 429 or 500 <= resp.status < 600:
                        delay = 2 ** attempt
                        log.warning("nvd: %s on attempt %d, sleeping %ds",
                                    resp.status, attempt + 1, delay)
                        await asyncio.sleep(delay)
                        continue
                    resp.raise_for_status()
                    return await resp.json()
            except aiohttp.ClientError as exc:
                last_exc = exc
                await asyncio.sleep(2 ** attempt)
        raise RuntimeError(f"nvd: giving up after retries: {last_exc!r}")

    async def iter_window(
        self, start: datetime, end: datetime
    ) -> "asyncio.Queue[dict[str, Any]]":
        """Yield parsed CVE dicts for one lastModified window (<=120 days)."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def producer() -> None:
            try:
                start_idx = 0
                while True:
                    params = {
                        "lastModStartDate": _fmt_ts(start),
                        "lastModEndDate": _fmt_ts(end),
                        "resultsPerPage": str(PAGE_SIZE),
                        "startIndex": str(start_idx),
                    }
                    body = await self._get(params)
                    vulns = body.get("vulnerabilities") or []
                    for v in vulns:
                        parsed = parse_cve(v)
                        if parsed:
                            await q.put(parsed)
                    total = int(body.get("totalResults", 0) or 0)
                    start_idx += len(vulns)
                    if not vulns or start_idx >= total:
                        break
            finally:
                await q.put(_SENTINEL)

        asyncio.create_task(producer())
        return q


_SENTINEL: dict[str, Any] = {"__sentinel__": True}


def iter_windows(
    start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    """Split a time range into <=max_days sub-windows."""
    if start >= end:
        return []
    out: list[tuple[datetime, datetime]] = []
    step = timedelta(days=max_days)
    cur = start
    while cur < end:
        nxt = min(cur + step, end)
        out.append((cur, nxt))
        cur = nxt
    return out


async def sync(
    db: Any,
    session: aiohttp.ClientSession,
    *,
    api_key: str | None,
    bootstrap_days: int = 7,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Pull the incremental NVD feed and upsert into `cves`."""
    now = now or datetime.now(timezone.utc)
    cursor = await db.get_cursor("nvd")
    if cursor and cursor.get("last_synced"):
        start = cursor["last_synced"]
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
    else:
        start = now - timedelta(days=bootstrap_days)

    client = NVDClient(session, api_key)
    ingested = 0
    changed = 0
    for w_start, w_end in iter_windows(start, now):
        q = await client.iter_window(w_start, w_end)
        while True:
            item = await q.get()
            if item.get("__sentinel__"):
                break
            if await db.upsert_cve(item):
                changed += 1
            ingested += 1

    await db.set_cursor(
        "nvd",
        last_synced=now,
        stats={"ingested": ingested, "changed": changed, "last_run_ts": now.isoformat()},
    )
    log.info("nvd: sync complete ingested=%d changed=%d", ingested, changed)
    return {"ingested": ingested, "changed": changed, "window_start": start.isoformat()}
