"""Service-key ingest of aggregated passive flows from otdiscovery (schema 039 reach_flow_obs).

Owned by the Sentry work package (docs/ASSURANCE_P1.md section 4.3). Registered in main.py,
auth.py (write) and service_routes.py (COMPUTE_ROUTES).

WHY the validation is strict and all-or-nothing: these rows are the *input* of a security proof
(the ``sentry_flow`` builder turns them into reach edges and, for silent-free sensors, into
coverage). A malformed address must not become a node, a future timestamp must not keep an edge
"fresh" forever, and a batch that is half-stored would make the sensor's retry ambiguous. So a bad
record rejects the whole batch with 422 and nothing is written; the sender (otdiscovery) pre-checks
with the same rules so a well-behaved sensor never trips this.

Tenancy: nothing here names ``tenant_id``. The pool stamps it from the request's tenant context
and ``ON CONFLICT`` targets include it (the column default reads the same setting).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..assurance.builders._ipmap import norm_ip
from ..db import get_pool

router = APIRouter(prefix="/v1/reach", tags=["assurance"])

MAX_BATCH = 1000
#: longest accepted address text (a v6 literal with a v4 tail is 45 characters).
MAX_IP_TEXT = 64
#: the canonical dashed UUID text; pydantic's own parser also takes braces, ``urn:uuid:`` and bare
#: hex, i.e. several spellings of one sensor.
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
#: A sensor clock may run ahead; beyond this we do not believe it (same slack as the store/library).
CLOCK_SLACK = dt.timedelta(minutes=5)
#: Per-record counter ceiling, and the saturation point of the stored sums (BIGINT is 2**63-1).
MAX_COUNTER = 10**15
_SATURATE = 2**62


class FlowIn(BaseModel):
    """One aggregated flow: ``src`` opened ``proto`` connections to ``dst:dst_port``."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    src_ip: str = Field(max_length=MAX_IP_TEXT)
    dst_ip: str = Field(max_length=MAX_IP_TEXT)
    proto: Literal["icmp", "tcp", "udp", "any"]
    dst_port: int = Field(ge=0, le=65535)
    sensor_id: UUID
    first_seen: dt.datetime
    last_seen: dt.datetime
    packets: int = Field(default=0, ge=0, le=MAX_COUNTER)
    bytes: int = Field(default=0, ge=0, le=MAX_COUNTER)
    oriented: Literal["syn", "heuristic"] = "heuristic"

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        """Canonical text (compressed, lowercase, v4-mapped unwrapped): the same spelling the
        builder's identity map uses, so one machine never appears under two spellings."""
        # An IPv6 scope id (``fe80::1%eth0``, ``2001:db8::1%9``) is accepted by ``ipaddress`` since
        # Python 3.9 but names no distinct machine: stored as text it would become a phantom node
        # that the real host's edges and coverage never meet (review finding security-8). Reject it
        # here (not only in ``norm_ip``) so the stored text never depends on that helper.
        if "%" in v or len(v) > MAX_IP_TEXT:
            raise ValueError("not an IP address (scope ids are not accepted)")
        try:
            ipaddress.ip_address(v.strip("[]"))
        except ValueError as exc:
            raise ValueError("not an IP address") from exc
        out = norm_ip(v)
        if out is None:  # pragma: no cover - norm_ip accepts everything ip_address does
            raise ValueError("not an IP address")
        return out

    @field_validator("sensor_id", mode="before")
    @classmethod
    def _sensor_spelling(cls, v: Any) -> Any:
        """One spelling per sensor: the stored key is part of the upsert's conflict target."""
        if isinstance(v, str) and not _UUID_RE.fullmatch(v):
            raise ValueError("sensor_id must be a UUID in canonical dashed form")
        return v

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware(cls, v: dt.datetime) -> dt.datetime:
        # A naive timestamp is taken as UTC (the sensor sends epoch/ISO-Z; never local time).
        return v.replace(tzinfo=dt.timezone.utc) if v.tzinfo is None else v.astimezone(dt.timezone.utc)

    @model_validator(mode="after")
    def _order(self) -> "FlowIn":
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen is after last_seen")
        return self


class FlowBulkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flows: list[FlowIn] = Field(max_length=MAX_BATCH)


class FlowBulkOut(BaseModel):
    received: int
    merged: int          # distinct keys after folding duplicates inside the batch
    inserted: int
    updated: int


def clamp_ts(ts: dt.datetime, now: dt.datetime) -> dt.datetime:
    """Never later than ``now + 5 min``: a lying clock must not pin an edge fresh forever."""
    return min(ts, now + CLOCK_SLACK)


def fold(flows: list[FlowIn], now: dt.datetime) -> list[dict[str, Any]]:
    """Merge records that share a key inside one batch.

    ``INSERT .. ON CONFLICT DO UPDATE`` refuses to touch one row twice in a statement, and the
    fold is exactly what the upsert would compute anyway (min first, max last, counters add).
    A 'syn' orientation wins: an observed handshake is authoritative, a guess is not.
    """
    acc: dict[tuple, dict[str, Any]] = {}
    for f in flows:
        first, last = clamp_ts(f.first_seen, now), clamp_ts(f.last_seen, now)
        first = min(first, last)
        key = (f.src_ip, f.dst_ip, f.proto, f.dst_port, f.sensor_id)
        cur = acc.get(key)
        if cur is None:
            acc[key] = {"first": first, "last": last, "packets": f.packets, "bytes": f.bytes,
                        "oriented": f.oriented}
            continue
        cur["first"], cur["last"] = min(cur["first"], first), max(cur["last"], last)
        cur["packets"] = min(cur["packets"] + f.packets, _SATURATE)
        cur["bytes"] = min(cur["bytes"] + f.bytes, _SATURATE)
        if f.oriented == "syn":
            cur["oriented"] = "syn"
    return [{"key": k, **v} for k, v in sorted(acc.items(), key=lambda kv: tuple(map(str, kv[0])))]


# first_seen = LEAST, last_seen = GREATEST, counters add (saturating): contract 4.3.
# xmax = 0 identifies a freshly inserted row (as /v1/assets/bulk does).
_UPSERT = f"""
INSERT INTO reach_flow_obs
       (src_ip, dst_ip, proto, dst_port, sensor_id, first_seen, last_seen, packets, bytes, oriented)
SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::int[], $5::uuid[],
                     $6::timestamptz[], $7::timestamptz[], $8::bigint[], $9::bigint[], $10::text[])
ON CONFLICT (tenant_id, src_ip, dst_ip, proto, dst_port, sensor_id) DO UPDATE SET
  first_seen = LEAST(reach_flow_obs.first_seen, EXCLUDED.first_seen),
  last_seen  = GREATEST(reach_flow_obs.last_seen, EXCLUDED.last_seen),
  packets    = LEAST(reach_flow_obs.packets + EXCLUDED.packets, {_SATURATE}),
  bytes      = LEAST(reach_flow_obs.bytes + EXCLUDED.bytes, {_SATURATE}),
  oriented   = CASE WHEN reach_flow_obs.oriented = 'syn' OR EXCLUDED.oriented = 'syn'
                    THEN 'syn' ELSE 'heuristic' END
RETURNING (xmax = 0) AS inserted
"""


@router.post("/flows/bulk", response_model=FlowBulkOut)
async def bulk_flows(body: FlowBulkIn, pool=Depends(get_pool)) -> FlowBulkOut:
    """Upsert aggregated flows; one statement, so the batch is stored whole or not at all."""
    now = dt.datetime.now(dt.timezone.utc)
    rows: list[dict[str, Any]] = fold(body.flows, now)
    if not rows:
        return FlowBulkOut(received=0, merged=0, inserted=0, updated=0)
    cols: list[list[Any]] = [[] for _ in range(10)]
    for r in rows:
        src, dst, proto, port, sensor = r["key"]
        for col, val in zip(cols, (src, dst, proto, port, sensor, r["first"], r["last"],
                                   r["packets"], r["bytes"], r["oriented"])):
            col.append(val)
    async with pool.acquire() as con:
        res = await con.fetch(_UPSERT, *cols)
    inserted = sum(1 for x in res if x["inserted"])
    return FlowBulkOut(received=len(body.flows), merged=len(rows), inserted=inserted,
                       updated=len(res) - inserted)


__all__ = ["router", "FlowIn", "FlowBulkIn", "FlowBulkOut", "MAX_BATCH", "clamp_ts", "fold"]
