"""Observed-flow and pentest-result ingest for the Wargame engine.

DEFENSIVE. This module only *reads* logs and reports that already exist and
turns them into engine objects. It runs nothing, sends nothing and never
touches the network.

* Flows (:func:`parse_flows`) -> :class:`~.model.Flow` for the
  impossible-traffic detector. Formats: generic JSON, Zeek ``conn.log``
  (JSONL), firewall allow/deny logs.
* Pentest results (:func:`parse_sarif` + :func:`imported_edges`) -> graph
  :class:`~.model.Edge` objects labelled ``IMPORTED``: a third party
  demonstrated the hop; we record it and never run it.

Pure, deterministic, stdlib only. A bad row is skipped and counted, never
raised.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .model import Edge, EvidenceLabel, Flow
from .parsers.base import proto_from

_ALLOW_ACTIONS = frozenset({"allow", "accept", "permit"})
_ESTABLISHED_STATES = frozenset({"established", "sf"})

#: Zeek conn_state values where data flowed / the handshake completed.
#: S0 (no reply) and REJ (rejected) are deliberately absent: a dropped or
#: half-open attempt proves the boundary works. Unknown states are treated
#: as not established (never over-claim a crossing).
ZEEK_ESTABLISHED: frozenset[str] = frozenset({"SF", "S1", "RSTO", "RSTR"})

_FORMATS = frozenset({"auto", "generic", "zeek", "firewall"})


@dataclass
class IngestStats:
    parsed: int = 0
    skipped: int = 0
    reasons: list[str] = field(default_factory=list)

    def skip(self, why: str) -> None:
        self.skipped += 1
        self.reasons.append(why)


@dataclass
class ImportedFinding:
    rule_id: str
    message: str
    src_hint: str = ""
    dst_hint: str = ""
    level: str = ""


# ---------------------------------------------------------------------------
# Flow ingest
# ---------------------------------------------------------------------------

def _load_records(raw: Any, stats: IngestStats) -> tuple[list[Any], bool]:
    """Return (records, was_jsonl). Accepts a list, a JSON string (array or
    JSONL), or bytes. Never raises."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            stats.skip("input is not valid UTF-8")
            return [], False
    if isinstance(raw, (list, tuple)):
        return list(raw), False
    if isinstance(raw, dict):
        return [raw], False
    if not isinstance(raw, str):
        stats.skip(f"unsupported input type {type(raw).__name__}")
        return [], False
    text = raw.strip()
    if not text:
        return [], False
    if text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            stats.skip("invalid JSON array")
            return [], False
        return (data if isinstance(data, list) else [data]), False
    # JSONL (a lone object is a one-line JSONL).
    out: list[Any] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append(_BadLine(n))
    return out, True


@dataclass
class _BadLine:
    lineno: int


def _sniff(records: list[Any]) -> str:
    dicts = [r for r in records if isinstance(r, dict)]
    if any("id.orig_h" in r or "conn_state" in r for r in dicts):
        return "zeek"
    if any("action" in r for r in dicts):
        return "firewall"
    return "generic"


def _first(rec: dict, *keys: str) -> Any:
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


def _port(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 65535 else None


def _ts(v: Any) -> str:
    return "" if v is None else str(v)


def _one_flow(rec: dict, fmt: str) -> Flow:
    """Build a Flow from one record. Raises ValueError on a bad row."""
    if fmt == "zeek":
        # Flattened exports (src/dst/dport + conn_state) are tolerated too.
        src = _first(rec, "id.orig_h", "src", "src_ip")
        dst = _first(rec, "id.resp_h", "dst", "dst_ip")
        dport = _first(rec, "id.resp_p", "dport", "dst_port")
        proto_tok = rec.get("proto")
    else:
        src = _first(rec, "src", "src_ip")
        dst = _first(rec, "dst", "dst_ip")
        dport = _first(rec, "dport", "dst_port")
        proto_tok = rec.get("proto")
    if not isinstance(src, str) or not isinstance(dst, str):
        raise ValueError("missing src/dst address")
    port = _port(dport)
    if port is None:
        # ICMP has no port; tolerate a missing one only for icmp.
        if dport is None and proto_from(proto_tok).value == "icmp":
            port = 0
        else:
            raise ValueError("missing or invalid destination port")
    proto = proto_from(proto_tok)

    handshake = dst_seen = fw_allow = False
    kind = ""
    if fmt == "zeek":
        state = str(rec.get("conn_state", "")).strip().upper()
        if not state:
            raise ValueError("missing conn_state")
        handshake = state in ZEEK_ESTABLISHED
        # Zeek sits where it can see the responder, but only an answered
        # flow is evidence the traffic got *through*. A dropped S0/REJ
        # attempt must not read as a crossing (see impossible.flow_is_real).
        dst_seen = handshake
        svc = rec.get("service")
        kind = str(svc) if svc else ""
    else:
        action = str(rec.get("action", "")).strip().lower()
        state = str(rec.get("state", "")).strip().lower()
        if fmt == "firewall" and not action:
            raise ValueError("missing action")
        fw_allow = action in _ALLOW_ACTIONS
        handshake = state in _ESTABLISHED_STATES
        svc = rec.get("service")
        kind = str(svc) if svc else ""
    return Flow(
        src_ip=src.strip(),
        dst_ip=dst.strip(),
        proto=proto,
        dst_port=port,
        handshake_completed=handshake,
        dst_side_observed=dst_seen,
        firewall_allow_logged=fw_allow,
        kind=kind,
        ts=_ts(_first(rec, "ts", "timestamp", "time")),
    )


def parse_flows_detailed(raw: Any, fmt: str = "auto") -> tuple[list[Flow], IngestStats]:
    """Parse observed flows; returns ``(flows, stats)``. Never raises."""
    stats = IngestStats()
    try:
        records, _jsonl = _load_records(raw, stats)
        fmt = (fmt or "auto").lower()
        if fmt not in _FORMATS:
            stats.skip(f"unknown format {fmt!r}")
            return [], stats
        if fmt == "auto":
            fmt = _sniff(records)
        flows: list[Flow] = []
        for i, rec in enumerate(records):
            if isinstance(rec, _BadLine):
                stats.skip(f"row {i}: invalid JSON on line {rec.lineno}")
                continue
            if not isinstance(rec, dict):
                stats.skip(f"row {i}: not an object")
                continue
            try:
                flows.append(_one_flow(rec, fmt))
            except (ValueError, TypeError) as exc:
                stats.skip(f"row {i}: {exc}")
        stats.parsed = len(flows)
        return flows, stats
    except Exception as exc:  # pragma: no cover - last-resort guard
        stats.skip(f"unexpected error: {type(exc).__name__}")
        return [], stats


def parse_flows(raw: Any, *, fmt: str = "auto") -> list[Flow]:
    """Parse observed flows, skipping bad rows. See :func:`parse_flows_detailed`."""
    return parse_flows_detailed(raw, fmt)[0]


# ---------------------------------------------------------------------------
# SARIF (pentest results) -> findings -> IMPORTED edges
# ---------------------------------------------------------------------------

def _text(v: Any) -> str:
    return v.strip() if isinstance(v, str) else ""


def parse_sarif(raw: Any) -> list[ImportedFinding]:
    """Minimal SARIF 2.1.0 reader. Never raises; malformed pieces are skipped.

    Hints: the first ``artifactLocation.uri`` becomes ``src_hint``; the first
    ``logicalLocations[].fullyQualifiedName`` (or, failing that, the second
    URI) becomes ``dst_hint``. The pairing is a convention for
    :func:`imported_edges`, which maps both through a caller-owned table.
    """
    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8")
        doc = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(doc, dict):
            return []
        out: list[ImportedFinding] = []
        for run in doc.get("runs") or []:
            if not isinstance(run, dict):
                continue
            for res in run.get("results") or []:
                if not isinstance(res, dict):
                    continue
                rule_id = _text(res.get("ruleId"))
                if not rule_id:
                    continue
                msg = res.get("message")
                message = _text(msg.get("text")) if isinstance(msg, dict) else _text(msg)
                uris: list[str] = []
                logical: list[str] = []
                for loc in res.get("locations") or []:
                    if not isinstance(loc, dict):
                        continue
                    phys = loc.get("physicalLocation")
                    if isinstance(phys, dict):
                        art = phys.get("artifactLocation")
                        if isinstance(art, dict) and _text(art.get("uri")):
                            uris.append(_text(art.get("uri")))
                    for ll in loc.get("logicalLocations") or []:
                        if isinstance(ll, dict) and _text(ll.get("fullyQualifiedName")):
                            logical.append(_text(ll.get("fullyQualifiedName")))
                src_hint = uris[0] if uris else ""
                if logical:
                    dst_hint = logical[0]
                elif len(uris) > 1:
                    dst_hint = uris[1]
                else:
                    dst_hint = ""
                out.append(
                    ImportedFinding(
                        rule_id=rule_id,
                        message=message,
                        src_hint=src_hint,
                        dst_hint=dst_hint,
                        level=_text(res.get("level")),
                    )
                )
        return out
    except Exception:
        return []


def imported_edges(findings: list[ImportedFinding], mapping: dict[str, str]) -> list[Edge]:
    """Directed IMPORTED edges for findings whose both hints map to node ids.

    A third party demonstrated the hop; it is recorded as evidence, never
    executed. Findings with an unmapped hint, or mapping to the same node,
    are dropped. Output follows input order, de-duplicated on
    (src, dst, rule_id).
    """
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()
    for f in findings:
        src = mapping.get(f.src_hint) if f.src_hint else None
        dst = mapping.get(f.dst_hint) if f.dst_hint else None
        if not src or not dst or src == dst:
            continue
        key = (src, dst, f.rule_id)
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            Edge(
                src=src,
                dst=dst,
                base_labels=frozenset({EvidenceLabel.IMPORTED}),
                metadata={"rule_id": f.rule_id, "source": "pentest"},
            )
        )
    return edges
