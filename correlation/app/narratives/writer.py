"""Generates the one-paragraph impact narrative attached to each chain.

The narrative templates the chain rule's `impact` field with concrete
evidence from the matched findings and assets. We use a tiny safe
substitution — a single `{name}`-style pass with a strict allowlist —
rather than the full Jinja/f-string surface, so a malicious or buggy
rule can't call anything.

Hard rule: if either the TEMPLATE or the EVIDENCE values contain
exploitation-style content (shell commands, payloads, reverse shells),
we fall back to a neutral default rather than rendering them.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Mapping

from ..engine.policy import (
    UnsafeRuleError,
    validate_narrative_text,
)

log = logging.getLogger(__name__)


_VAR_RE = re.compile(r"\{\s*([a-zA-Z0-9_.]+)\s*\}")
_DEFAULT_NARRATIVE = (
    "Multiple findings on this asset combine into a higher-severity "
    "issue. Review the linked findings together for impact scope."
)


def _lookup(ns: Mapping[str, Any], dotted: str) -> str:
    """Look up `a.b.c` in a nested dict. Missing keys return ''."""
    cur: Any = ns
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
        if cur is None:
            return ""
    if isinstance(cur, (list, tuple)):
        return ", ".join(str(x) for x in cur)
    return str(cur)


def _safe_substitute(template: str, ns: Mapping[str, Any]) -> str:
    def repl(m: re.Match) -> str:
        return _lookup(ns, m.group(1))

    return _VAR_RE.sub(repl, template)


class NarrativeWriter:
    def write(
        self,
        rule_impact: str,
        anchor_finding: Mapping[str, Any],
        matched_findings: list[Mapping[str, Any]],
        matched_assets: list[Mapping[str, Any]],
    ) -> str:
        """Render the impact narrative for a chain.

        The template surface deliberately exposes only descriptive fields
        (host, kind, severity, rule_id, cvss, version, file path) and
        hides raw evidence blobs that could contain copy-pasted
        attacker output."""
        try:
            validate_narrative_text(rule_impact or "")
        except UnsafeRuleError as e:
            log.warning(
                "narrative template rejected (unsafe): %s", e
            )
            return _DEFAULT_NARRATIVE

        host_value = anchor_finding.get("asset_value") or ""
        versions = sorted(
            {
                str(
                    (f.get("evidence") or {}).get("version")
                    or (f.get("metadata") or {}).get("version")
                    or ""
                )
                for f in matched_findings
            }
            - {""}
        )
        paths = sorted(
            {
                str((f.get("evidence") or {}).get("path") or "")
                for f in matched_findings
            }
            - {""}
        )

        ns = {
            "host": host_value,
            "asset": host_value,
            "severity": anchor_finding.get("severity"),
            "rule_id": anchor_finding.get("rule_id"),
            "cvss": anchor_finding.get("cvss"),
            "versions": versions,
            "paths": paths,
            "findings_count": len(matched_findings),
            "finding_rule_ids": [
                f.get("rule_id") for f in matched_findings
            ],
            "asset_values": [a.get("value") for a in matched_assets],
        }

        template = rule_impact.strip() or _DEFAULT_NARRATIVE
        rendered = _safe_substitute(template, ns).strip()

        try:
            validate_narrative_text(rendered)
        except UnsafeRuleError as e:
            log.warning("rendered narrative failed validation: %s", e)
            return _DEFAULT_NARRATIVE

        # Keep to one paragraph: squash newlines.
        rendered = re.sub(r"\s*\n+\s*", " ", rendered)
        return rendered
