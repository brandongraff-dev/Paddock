"""The contract between builders (pure) and the store (DB). Frozen on purpose."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Literal

Basis = Literal["declared", "configured", "observed", "tested"]
Proto = Literal["icmp", "tcp", "udp", "any"]
Direction = Literal["in", "out"]
# 'replace': this source owns its whole edge set; anything it does not re-emit is deleted.
# 'window':  observational; edges persist until last_seen ages past the window.
Mode = Literal["replace", "window"]


@dataclass(frozen=True)
class NodeOut:
    ref: str
    kind: str                     # one of refs.KINDS
    label: str = ""
    asset_id: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EdgeOut:
    src_ref: str
    dst_ref: str
    proto: Proto
    port_lo: int
    port_hi: int
    basis: Basis
    source: str
    last_seen: dt.datetime
    first_seen: dt.datetime | None = None
    confidence: int = 100
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CoverageOut:
    node_ref: str
    direction: Direction
    tier: Basis
    observed_at: dt.datetime
    source: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class BuildOutput:
    """What one builder run asserts. ``source`` owns edges and coverage rows with that source."""
    source: str
    mode: Mode
    nodes: list[NodeOut] = field(default_factory=list)
    edges: list[EdgeOut] = field(default_factory=list)
    coverage: list[CoverageOut] = field(default_factory=list)
    window: dt.timedelta | None = None          # required when mode == 'window'
    notes: list[str] = field(default_factory=list)   # e.g. "12 SGs had no persisted rules"
