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


@dataclass(frozen=True)
class FactOut:
    """Per-node host facts one builder asserts (docs/ASSURANCE_P2.md section 7.2).

    ``(node_ref, source)`` is the key; ``tier`` and ``observed_at`` are the DEFAULTS for every
    collector entry in ``facts`` (an entry may carry a weaker ``tier`` / an older ``observed_at`` of
    its own: the weaker wins, so an entry can never claim more than the row).

    ``facts`` maps a collector name (``sshd``, ``listeners``, ``firewall``, ``patch``, ...:
    ``[a-z][a-z0-9_]{0,31}``, at most 16 per node) to one entry, a JSON object with no floats:

        status        'ok' | 'error' | 'unavailable'                      (required)
        signed        bool: the server verified the agent's signature     (required; False never HOLDS)
        key_id        str   the verifying key (witness provenance)        (default '')
        seq           int   the envelope sequence number                  (default 0)
        evidence_ref  str   where the signed bytes can be found again     (default '')
        conf          'exact' | 'approximate'   (default 'approximate': never HOLDS)
        partial       bool  the section is known incomplete  (default True: never HOLDS)
        reason        str   why status is not 'ok' (collector vocabulary, <= 64)
        conflict      bool | non-empty object | non-empty list of objects: an independent
                      source disagrees; the library treats the fact as unusable (UNKNOWN)
        tier          optional, weaker than the row's tier wins
        observed_at   optional ISO-8601 with timezone, older than the row's wins
        data          the collector's compact values the registry reads  (default {})

    The ``source`` of each entry in the graph document is the row's ``source``.
    """
    node_ref: str
    source: str
    tier: Basis
    observed_at: dt.datetime
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass
class BuildOutput:
    """What one builder run asserts. ``source`` owns edges, coverage and fact rows with that source."""
    source: str
    mode: Mode
    nodes: list[NodeOut] = field(default_factory=list)
    edges: list[EdgeOut] = field(default_factory=list)
    coverage: list[CoverageOut] = field(default_factory=list)
    window: dt.timedelta | None = None          # required when mode == 'window'
    notes: list[str] = field(default_factory=list)   # e.g. "12 SGs had no persisted rules"
    # Host facts (P2). Default empty (and last, so positional construction is unchanged): builders
    # that know nothing about facts are untouched. A source that emits none REPLACES its previous
    # facts with nothing, like coverage.
    facts: list[FactOut] = field(default_factory=list)
