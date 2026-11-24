"""Tiny builders so each test states only what it is about."""
from __future__ import annotations

import datetime as dt
from typing import Any

from paddock_assurance import ReachGraph, compile_text

NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
FRESH = "2026-12-01T08:30:00Z"
STALE = "2026-11-28T08:30:00Z"


def node(id_: str, zone: str | None = None, *, kind: str = "host", cls: str | None = None,
         tags: tuple[str, ...] = (), tier: str | None = "observed", seen: str = FRESH) -> dict[str, Any]:
    n: dict[str, Any] = {"id": id_, "kind": kind, "tags": list(tags)}
    if zone:
        n["zone"] = zone
    if cls:
        n["class"] = cls
    if tier:
        n["coverage"] = {"tier": tier, "observed_at": seen, "source": "test"}
    return n


def fact(direction: str = "both", tier: str = "observed", seen: str = FRESH,
         source: str = "test") -> dict[str, Any]:
    return {"direction": direction, "tier": tier, "observed_at": seen, "source": source}


def dnode(id_: str, zone: str | None = None, *facts: dict[str, Any], kind: str = "host",
          cls: str | None = None, tags: tuple[str, ...] = ()) -> dict[str, Any]:
    """A node whose coverage is an explicit list of directional facts (none = blind)."""
    n: dict[str, Any] = {"id": id_, "kind": kind, "tags": list(tags), "coverage": list(facts)}
    if zone:
        n["zone"] = zone
    if cls:
        n["class"] = cls
    return n


def edge(src: str, dst: str, ports: str = "443", proto: str = "tcp",
         basis: str = "observed") -> dict[str, Any]:
    return {"src": src, "dst": dst, "proto": proto, "ports": ports, "basis": basis}


def graph(nodes: list[dict], edges: list[dict]) -> ReachGraph:
    return ReachGraph.from_dict({"version": 1, "nodes": nodes, "edges": edges})


REACH_YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:a-cannot-reach-b
title: A cannot reach B
severity: high
subjects:
  from: {{ zone: a }}
  to: {{ zone: b }}
assert: unreachable
{extra}
"""


def reach(extra: str = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"):
    return compile_text(REACH_YAML.format(extra=extra))


EXPOSE_YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:only-web
title: Only web is exposed
subjects:
  from: {{ zone: internet }}
assert: exposes-only
ports: [80, 443]
{extra}
"""


def expose(extra: str = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"):
    return compile_text(EXPOSE_YAML.format(extra=extra))
