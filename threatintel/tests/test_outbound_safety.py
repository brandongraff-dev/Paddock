"""Guardrail tests: this service is DEFENSIVE.

We assert the SAFETY INVARIANT declared in app/__init__.py holds in code:

  1. The matching + parsing layers (match.py, stix.py) perform NO network I/O
     -- they never import aiohttp. Matching is read-only over the owner's data.
  2. Every outbound HTTP call site targets a URL derived from a feed row /
     request body (user-configured), never a hardcoded external host and never
     an indicator's value.
"""
from __future__ import annotations

import pathlib
import re

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def test_match_and_stix_do_no_network():
    for name in ("match.py", "stix.py"):
        text = (APP / name).read_text()
        assert "aiohttp" not in text, f"{name} must not do network I/O"
        assert "session.get" not in text and "session.post" not in text


# config.py / orchestrator.py hold internal control-plane defaults (the DB,
# Redis, and orchestrator endpoints -- same as the sibling intel service). Feed
# fetching lives elsewhere; those are what must never hardcode a host.
_CONTROL_PLANE = {"config.py", "orchestrator.py"}


def test_no_hardcoded_external_feed_host_in_fetch_code():
    """No concrete http(s)://<host> URL literal in the feed-fetching code.

    Every feed/IOC fetch targets a URL that came from a user-configured feed
    row or a POST /ingest/stix body. Media types (application/taxii+json;
    version=2.1) carry no scheme, so they are fine.
    """
    url_literal = re.compile(r"""["']https?://[a-z0-9.\-]+""", re.IGNORECASE)
    offenders: list[str] = []
    for py in APP.rglob("*.py"):
        if py.name in _CONTROL_PLANE:
            continue
        for i, line in enumerate(py.read_text().splitlines(), 1):
            if url_literal.search(line):
                offenders.append(f"{py.name}:{i}: {line.strip()}")
    assert offenders == [], offenders


def test_outbound_calls_use_variables_not_literals():
    """Each GET/POST call site passes a variable URL, not a string literal."""
    call = re.compile(r"\.(get|post)\(\s*([^,)\n]+)")
    for py in APP.rglob("*.py"):
        text = py.read_text()
        for m in call.finditer(text):
            arg = m.group(2).strip()
            # A literal URL would start with a quote; a variable/expression won't.
            assert not arg.startswith(("'http", '"http')), f"{py.name}: literal outbound URL {arg}"
