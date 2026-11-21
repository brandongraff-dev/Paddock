"""Thin Anthropic client wrapper.

The Anthropic SDK is an OPTIONAL dependency. The import is guarded so the
service boots and self-tests without the package installed. `is_enabled()`
is True only when BOTH a key is present AND the SDK is importable; otherwise
the triage/ask paths fall back to deterministic logic.

The API key is read from config (env) only and is NEVER logged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
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


_SQL_FENCE = re.compile(r"```(?:sql)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


class LLM:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._client: Any | None = None

    def is_enabled(self) -> bool:
        return bool(self.cfg.anthropic_api_key) and _anthropic_available()

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic  # local import — optional dependency

            self._client = anthropic.Anthropic(
                api_key=self.cfg.anthropic_api_key,
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
