"""Thin Anthropic client wrapper.

The Anthropic SDK is an OPTIONAL dependency. The import is guarded so the
service boots and self-tests without the package installed. `is_enabled()`
is True only when BOTH a key is present AND the SDK is importable; otherwise
the triage/ask paths fall back to deterministic logic.

The API key is NEVER logged. It comes from, in order: the key an admin saved in
the dashboard (fetched from the orchestrator with the fleet service key,
cached briefly, see ``refresh_key``), then ``ANTHROPIC_API_KEY`` in the
environment. Without either the deterministic fallbacks run.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

from .config import Config

log = logging.getLogger("brain.llm")


def _anthropic_available() -> bool:
    """Whether the optional SDK can be imported. Split out so tests can
    exercise the enabled path without the package installed."""
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:
        return False


_CREDENTIAL_PATH = "/v1/system/ai/credential"
_RETRY_AFTER_ERROR_S = 15.0


async def _fetch_stored_key(base_url: str, service_key: str, timeout_s: float = 3.0) -> str | None:
    """The dashboard-saved key, or None when none is saved. Raises on any failure
    (unreachable, 401/403, bad body) so the caller can keep what it already has."""
    import aiohttp  # a hard dependency of the service (pyproject)

    url = base_url.rstrip("/") + _CREDENTIAL_PATH
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as http:
        async with http.get(url, headers={"X-API-Key": service_key}) as resp:
            if resp.status != 200:
                raise RuntimeError(f"orchestrator answered {resp.status}")
            data = await resp.json()
    key = (data or {}).get("api_key")
    return key if isinstance(key, str) and key else None


_SQL_FENCE = re.compile(r"```(?:sql)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


class LLM:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._client: Any | None = None
        self._client_key: str | None = None
        self._stored_key: str | None = None      # saved in the dashboard
        self._next_refresh = 0.0                 # monotonic time of the next fetch

    def _api_key(self) -> str | None:
        return self._stored_key or self.cfg.anthropic_api_key

    def is_enabled(self) -> bool:
        return bool(self._api_key()) and _anthropic_available()

    async def refresh_key(self, force: bool = False) -> None:
        """Pick up a key saved (or removed) in the dashboard. Cheap: at most one
        orchestrator call per ``ai_key_ttl_s``. Any failure keeps the key we
        already have, so a restart of the orchestrator never turns AI off."""
        cfg = self.cfg
        if not cfg.orchestrator_url or not cfg.service_api_key:
            return
        now = time.monotonic()
        if not force and now < self._next_refresh:
            return
        try:
            key = await _fetch_stored_key(cfg.orchestrator_url, cfg.service_api_key)
        except Exception as exc:  # noqa: BLE001 -- never log anything but the type
            log.warning("could not read the saved AI key from the orchestrator (%s); keeping the current one",
                        type(exc).__name__)
            self._next_refresh = now + _RETRY_AFTER_ERROR_S
            return
        self._next_refresh = now + max(1, cfg.ai_key_ttl_s)
        if key != self._stored_key:
            log.info("AI key from the dashboard: %s", "set" if key else "removed")
            self._stored_key = key

    def _get_client(self) -> Any:
        key = self._api_key()
        if self._client is None or key != self._client_key:
            import anthropic  # local import — optional dependency

            self._client_key = key
            self._client = anthropic.Anthropic(
                api_key=key,
                timeout=float(self.cfg.llm_timeout_s),
                max_retries=1,
            )
        return self._client

    # -- low-level call ----------------------------------------------------
    def _messages_text(self, system: str, user: str, max_tokens: int) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=self.cfg.anthropic_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = []
        for block in getattr(resp, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
        return "".join(parts).strip()

    # -- triage ------------------------------------------------------------
    async def summarize_clusters(
        self, clusters: list[dict[str, Any]]
    ) -> list[dict[str, str]] | None:
        """Given cluster skeletons (label + sample findings), ask the model
        for a tight label/summary/remediation per cluster in ONE batched
        call. Returns a list aligned to ``clusters`` or None on any failure
        (the caller then falls back to templates)."""
        if not clusters:
            return []
        system = (
            "You are a defensive attack-surface-management triage assistant. "
            "For each finding cluster, write a concise analyst summary. "
            "Describe impact and remediation at a high level only — never "
            "include exploitation steps, payloads, or commands. "
            "Respond with a JSON array; each element must be an object with "
            "keys: label, summary, remediation. Return the same number of "
            "elements, in the same order, as the input."
        )
        payload = [
            {
                "index": i,
                "asset": c.get("asset_value"),
                "severity": c.get("severity"),
                "rule_family": c.get("rule_source"),
                "count": len(c.get("finding_ids", [])),
                "examples": c.get("examples", [])[:5],
            }
            for i, c in enumerate(clusters)
        ]
        user = "Clusters:\n" + json.dumps(payload, default=str)
        try:
            raw = await asyncio.to_thread(
                self._messages_text, system, user, self.cfg.llm_max_tokens
            )
            data = _extract_json(raw)
            if not isinstance(data, list) or len(data) != len(clusters):
                log.warning("llm triage: shape mismatch; falling back")
                return None
            out = []
            for item in data:
                if not isinstance(item, dict):
                    return None
                out.append({
                    "label": str(item.get("label", "")).strip(),
                    "summary": str(item.get("summary", "")).strip(),
                    "remediation": str(item.get("remediation", "")).strip(),
                })
            return out
        except Exception as exc:  # network / API / parse — degrade gracefully
            log.warning("llm triage call failed: %s", type(exc).__name__)
            return None

    # -- NL -> SQL ---------------------------------------------------------
    async def nl_to_sql(self, question: str, schema_desc: str) -> str | None:
        """Translate a question into ONE read-only SELECT over the ask_*
        views. Returns the SQL string (unvalidated — the caller MUST run it
        through the guard) or None on failure."""
        system = (
            "You translate an analyst question into a SINGLE read-only "
            "PostgreSQL SELECT statement. You may reference ONLY these views:\n"
            f"{schema_desc}\n"
            "Rules: output exactly one SELECT statement and nothing else; no "
            "semicolons; no CTE writes; no DDL/DML; never reference any table "
            "other than the three views above; always include a LIMIT of at "
            "most 500. Output only the SQL, with no prose and no code fences."
        )
        try:
            raw = await asyncio.to_thread(
                self._messages_text, system, question, 512
            )
        except Exception as exc:
            log.warning("llm nl_to_sql call failed: %s", type(exc).__name__)
            return None
        return _strip_sql(raw)


def _extract_json(text: str) -> Any:
    m = _SQL_FENCE.search(text)
    if m:
        text = m.group(1).strip()
    text = text.strip()
    # Trim to the outermost JSON array/object.
    start = min(
        [i for i in (text.find("["), text.find("{")) if i != -1],
        default=-1,
    )
    if start > 0:
        text = text[start:]
    return json.loads(text)


def _strip_sql(text: str) -> str | None:
    if not text:
        return None
    m = _SQL_FENCE.search(text)
    if m:
        text = m.group(1)
    text = text.strip().rstrip(";").strip()
    return text or None
