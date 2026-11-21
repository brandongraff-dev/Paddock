"""Narrative writer tests. Pure python, no DB."""
from __future__ import annotations

from app.narratives.writer import NarrativeWriter


def test_substitutes_host():
    w = NarrativeWriter()
    out = w.write(
        "The host {host} is affected.",
        {"asset_value": "api.example.com", "severity": "high"},
        [{"asset_value": "api.example.com", "rule_id": "cve-x"}],
        [],
    )
    assert "api.example.com" in out


def test_falls_back_on_unsafe_template():
    w = NarrativeWriter()
    out = w.write(
        "run bash -c 'rm -rf /' then win",
        {"asset_value": "x"},
        [],
        [],
    )
    assert "bash -c" not in out
    assert out  # non-empty fallback


def test_templating_respects_variable_allowlist():
    w = NarrativeWriter()
    # `{random}` is not in the allowlist -> rendered as empty string.
    out = w.write(
        "sev={severity} unknown='{random}' host={host}",
        {"asset_value": "h", "severity": "critical"},
        [],
        [],
    )
    assert "sev=critical" in out
    assert "unknown=''" in out
    assert "host=h" in out


def test_newlines_collapsed():
    w = NarrativeWriter()
    out = w.write(
        "line1\nline2\n\nline3",
        {"asset_value": "h"},
        [],
        [],
    )
    assert "\n" not in out


def test_evidence_values_scrubbed_on_render():
    """Even if a template is clean, evidence values that look like
    exploit output must not end up in the final narrative."""
    w = NarrativeWriter()
    # Our allowlist only exposes host/versions/paths/etc — raw evidence
    # is not reachable. Confirm {raw_response} renders empty.
    out = w.write(
        "{host} with raw={raw_response}",
        {"asset_value": "h"},
        [{"evidence": {"raw_response": "bash -c 'id'"}}],
        [],
    )
    assert "bash -c" not in out
    assert "raw=" in out
