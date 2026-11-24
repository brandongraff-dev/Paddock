"""The passive discovery pipeline.

ingest/analyze flow, end to end:

    raw input (pcap bytes | observations JSON)
        -> normalized observations
        -> device fingerprinting (OUI + mDNS/SSDP + DHCP + OT protocols)
        -> segmentation + exposure analysis
        -> CVE matching against the shared feed
        -> project devices/segments as assets, emit edges + findings
           (all posted through the orchestrator)

Every analysis runs inside ``active_probe_guard(device_ips)`` so that any
accidental socket connection to a discovered device is turned into a hard,
test-visible failure. The service's legitimate egress (orchestrator, Postgres)
is to other hosts and passes through untouched.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from . import active_probe_guard, pcap
from .config import Config
from . import behavior
from . import tenancy
from .cvematch import match_devices
from .db import Database
from .exposure import ExposureResult, analyze as analyze_exposure
from .fingerprint import Device, fingerprint_devices
from .orchestrator import FLOW_BATCH, OrchestratorClient

log = logging.getLogger("otdiscovery.pipeline")


# --------------------------------------------------------------------------- #
# Input normalization
# --------------------------------------------------------------------------- #

def _infer_kind(obs: dict[str, Any]) -> str:
    if obs.get("kind"):
        return str(obs["kind"])
    keys = set(obs)
    if keys & {"vendor_class", "param_req_list", "option55", "option60", "vci", "prl"}:
        return "dhcp"
    if keys & {"st", "nt", "usn", "server", "location"}:
        return "ssdp"
    if keys & {"service"} and not keys & {"src_port", "dst_port"}:
        return "mdns"
    if keys & {"src_port", "dst_port", "proto", "transport"}:
        return "packet"
    if keys & {"mac", "ip"} and not keys & {"src_port", "dst_port"}:
        return "arp"
    return "packet"


def _coerce_port(v: Any) -> Any:
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return v


def normalize_observations(raw: list[Any]) -> list[dict[str, Any]]:
    """Coerce a list of arbitrary observation dicts into the internal shape."""
    out: list[dict[str, Any]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        obs = dict(item)
        obs["kind"] = _infer_kind(obs)
        for pk in ("src_port", "dst_port"):
            if pk in obs:
                obs[pk] = _coerce_port(obs[pk])
        out.append(obs)
    return out


def parse_input(
    *, pcap_bytes: Optional[bytes] = None, observations: Optional[list[Any]] = None
) -> list[dict[str, Any]]:
    """Turn either input source into normalized observations (passive parse)."""
    obs: list[dict[str, Any]] = []
    if pcap_bytes:
        obs.extend(pcap.parse(pcap_bytes))
    if observations:
        obs.extend(normalize_observations(observations))
    return obs


# --------------------------------------------------------------------------- #
# Projection
# --------------------------------------------------------------------------- #

def project_assets(
    devices: list[Device], exposure: ExposureResult
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build (asset_items, edge_items) for the orchestrator bulk endpoints."""
    assets: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for seg in exposure.segments:
        assets.append({
            "kind": "network_segment",
            "value": seg.cidr,
            "source": "otdiscovery",
            "confidence": 80,
            "metadata": seg.to_metadata(),
        })

    for dev in devices:
        if not dev.is_device:
            continue
        kind = "ot_device" if dev.role == "ot" else "iot_device"
        value = dev.asset_value()
        md = dev.to_metadata()
        seg_cidr = exposure.device_segment.get(dev.key)
        if seg_cidr:
            md["segment"] = seg_cidr
        assets.append({
            "kind": kind,
            "value": value,
            "source": "otdiscovery",
            "confidence": max(1, min(100, dev.confidence)),
            "metadata": md,
        })
        if seg_cidr:
            edges.append({
                "src_kind": kind,
                "src_canonical": value,
                "dst_kind": "network_segment",
                "dst_canonical": seg_cidr,
                "kind": "member_of",
                "metadata": {"source": "otdiscovery"},
            })

    return assets, edges


# --------------------------------------------------------------------------- #
# Reach-graph flow reporting (docs/ASSURANCE_P1.md section 4.3)
# --------------------------------------------------------------------------- #

_REACH_PROTOS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmp", "icmp6": "icmp",
                 "ipv6-icmp": "icmp"}
_MAX_COUNTER = 10**15      # mirrors the orchestrator's per-record ceiling


def _canon_ip(v: Any) -> Optional[str]:
    """Canonical text for an address (same spelling the orchestrator stores), or ``None``."""
    if not isinstance(v, str):
        return None
    try:
        ip = ipaddress.ip_address(v.strip().strip("[]"))
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed.lower()


def _epoch(v: Any, default: float) -> float:
    """A usable epoch second, else ``default`` (a bad clock must not poison the whole batch)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 < v < 32503680000:
        return default
    return float(v)


def _counter(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0:
        return 0
    return min(int(v), _MAX_COUNTER)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def clean_sensor_id(v: Any) -> Optional[str]:
    """The sensor id as the orchestrator spells it (a UUID), or ``None`` when it is not one."""
    try:
        return str(uuid.UUID(str(v)))
    except (ValueError, TypeError, AttributeError):
        return None


class ReachFlowBuffer:
    """Per-tenant aggregate of sensor-stamped flows that the orchestrator has not seen yet.

    WHY it exists instead of re-posting the engine's flow list: analysis re-runs over everything
    the engine remembers, and the orchestrator ADDS counters on conflict, so posting the full
    state every run would inflate packets/bytes without bound. Each entry therefore remembers what
    was already delivered and only the difference is sent; the watermark advances only for a batch
    the orchestrator acknowledged, so a failed post is retried, never lost.

    Flows without a sensor id (the legacy shared-token path) are not tracked: the sensor id is the
    row's identity and the basis of coverage, and a client-supplied one is never trusted.
    """

    def __init__(self, max_entries: int = 100_000, retention_s: float = 86_400.0) -> None:
        self._e: dict[tuple, dict[str, Any]] = {}
        self.max_entries = max_entries
        self.retention_s = retention_s
        self.dropped = 0

    def __len__(self) -> int:
        return len(self._e)

    def add(self, observations: list[dict[str, Any]], sensor_id: Optional[str]) -> int:
        """Fold flow observations from ``sensor_id`` into the buffer; returns how many were taken."""
        sid = clean_sensor_id(sensor_id)
        if sid is None:
            return 0
        now = time.time()
        taken = 0
        for o in observations:
            if not isinstance(o, dict) or o.get("kind") != "flow":
                continue
            src, dst = _canon_ip(o.get("src_ip")), _canon_ip(o.get("dst_ip"))
            proto = _REACH_PROTOS.get(str(o.get("proto") or "").lower(), "any")
            port = _coerce_port(o.get("dst_port"))
            if src is None or dst is None:
                continue
            if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535 or proto in ("icmp", "any"):
                port = 0
            last = _epoch(o.get("last_seen"), now)
            first = min(_epoch(o.get("first_seen"), last), last)
            key = (src, dst, proto, port, sid)
            cur = self._e.get(key)
            if cur is None:
                if len(self._e) >= self.max_entries and not self._evict_one():
                    self.dropped += 1
                    continue
                cur = self._e[key] = {"first": first, "last": last, "packets": 0, "bytes": 0, "syn": False,
                                      "p_last": None, "p_packets": 0, "p_bytes": 0, "p_syn": False}
            cur["first"], cur["last"] = min(cur["first"], first), max(cur["last"], last)
            cur["packets"] = min(cur["packets"] + _counter(o.get("packets")), _MAX_COUNTER)
            cur["bytes"] = min(cur["bytes"] + _counter(o.get("bytes")), _MAX_COUNTER)
            cur["syn"] = cur["syn"] or (proto == "tcp" and bool(o.get("tcp_syn")))
            taken += 1
        return taken

    def _evict_one(self) -> bool:
        """Make room by dropping the oldest ALREADY DELIVERED entry; never an undelivered one."""
        delivered = [(e["last"], k) for k, e in self._e.items() if self._done(e)]
        if not delivered:
            return False
        del self._e[min(delivered)[1]]
        return True

    @staticmethod
    def _done(e: dict[str, Any]) -> bool:
        return (e["p_last"] is not None and e["last"] <= e["p_last"] and e["packets"] <= e["p_packets"]
                and e["bytes"] <= e["p_bytes"] and (e["p_syn"] or not e["syn"]))

    def pending(self) -> list[tuple[tuple, dict[str, Any], dict[str, Any]]]:
        """``(key, wire_record, snapshot)`` for every entry with something new, sorted for stability."""
        out = []
        for key in sorted(self._e):
            e = self._e[key]
            if self._done(e):
                continue
            src, dst, proto, port, sid = key
            rec = {"src_ip": src, "dst_ip": dst, "proto": proto, "dst_port": port, "sensor_id": sid,
                   "first_seen": _iso(e["first"]), "last_seen": _iso(e["last"]),
                   "packets": max(0, e["packets"] - e["p_packets"]), "bytes": max(0, e["bytes"] - e["p_bytes"]),
                   "oriented": "syn" if e["syn"] else "heuristic"}
            out.append((key, rec, {"last": e["last"], "packets": e["packets"], "bytes": e["bytes"], "syn": e["syn"]}))
        return out

    def mark_posted(self, key: tuple, snap: dict[str, Any]) -> None:
        e = self._e.get(key)
        if e is not None:
            e["p_last"], e["p_packets"], e["p_bytes"], e["p_syn"] = snap["last"], snap["packets"], snap["bytes"], snap["syn"]

    def prune(self) -> None:
        """Forget delivered entries that aged out (undelivered ones are kept until delivered)."""
        if not self._e:
            return
        horizon = max(e["last"] for e in self._e.values()) - self.retention_s
        for k in [k for k, e in self._e.items() if e["last"] < horizon and self._done(e)]:
            del self._e[k]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

def _flow_key(o: dict[str, Any]) -> tuple:
    return (o.get("proto"), o.get("src_ip"), o.get("dst_ip"), o.get("src_mac"), o.get("dst_mac"),
            o.get("dst_port"))


class DiscoveryEngine:
    """Holds the passive observation store and runs ingest/analyze."""

    def __init__(
        self,
        cfg: Config,
        *,
        db: Optional[Database] = None,
        orch: Optional[OrchestratorClient] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.orch = orch
        # One engine per tenant: observations, sensors, flows and behaviour
        # baselines are in-memory state that must never mix across tenants.
        self.tenant_id = tenancy.norm(tenant_id)
        self.observations: list[dict[str, Any]] = []
        # One record per distinct flow (a sensor reports the same peer pair every
        # 30 s window; storing each repeat made analysis O(flow events) per upload).
        self._flow_index: dict[tuple, dict[str, Any]] = {}
        self._reach = ReachFlowBuffer(max_entries=cfg.max_observations, retention_s=cfg.flow_retention_s)
        self._lock = asyncio.Lock()
        self._last_run_mono = 0.0
        self._deferred: Optional[asyncio.Task] = None
        path = cfg.baseline_path
        if path and self.tenant_id and self.tenant_id != tenancy.DEFAULT_TENANT_ID:
            path = f"{path}.{self.tenant_id}"  # per-tenant baseline file
        self.baselines = behavior.BaselineStore(path)
        self.sensors: dict[str, dict[str, Any]] = {}
        self.last_segment_matrix: list[dict[str, Any]] = []
        self.last_inventory: list[Device] = []
        self.last_guard_attempts: list[str] = []
        self.last_guard_violations: list[str] = []
        self.stats: dict[str, Any] = {
            "ingests": 0, "analyses": 0, "observations_stored": 0,
            "devices": 0, "ot_devices": 0, "iot_devices": 0, "segments": 0,
            "findings_posted": 0, "last_run": None,
            "guard_violations_total": 0,
        }

    # -- CVE fetcher backed by the (optional) DB ------------------------- #
    async def _cve_fetch(self, tokens: set[str]) -> list[dict[str, Any]]:
        if not self.cfg.enable_cve_match or self.db is None:
            return []
        try:
            return await self.db.cve_candidates(tokens)
        except Exception:
            log.exception("cve_candidates query failed; skipping cve match")
            return []

    async def ingest(
        self,
        *,
        pcap_bytes: Optional[bytes] = None,
        observations: Optional[list[Any]] = None,
        replace: bool = False,
        sensor_id: Optional[str] = None,
    ) -> dict[str, Any]:
        parsed = parse_input(pcap_bytes=pcap_bytes, observations=observations)
        # The sensor id comes from the authenticated claim, never from the payload: stamp every
        # flow (overwriting anything the sender wrote) so one sensor cannot speak for another.
        sid = clean_sensor_id(sensor_id) if sensor_id else None
        for o in parsed:
            if o.get("kind") == "flow":
                o["sensor_id"] = sid
        self._reach.add(parsed, sid)
        if replace:
            self.observations = []
            self._flow_index = {}
        self._store(parsed)
        self._prune()
        self.stats["ingests"] += 1
        self.stats["observations_stored"] = len(self.observations)
        interval = self.cfg.analyze_interval_s
        if interval > 0 and not replace:
            # Coalesce: many uploads, one analysis per interval. The data is
            # already stored; the next analysis posts everything it knows.
            self._schedule_analysis(interval)
            return {"observations_ingested": len(parsed), "analysis": "scheduled",
                    "analysis_interval_s": interval, "orchestrator": {}}
        result = await self._run(self.observations)
        result["observations_ingested"] = len(parsed)
        return result

    def _store(self, parsed: list[dict[str, Any]]) -> None:
        for o in parsed:
            if o.get("kind") != "flow":
                self.observations.append(o)
                continue
            key = _flow_key(o)
            cur = self._flow_index.get(key)
            if cur is None:
                self._flow_index[key] = o
                self.observations.append(o)
                continue
            for f in ("packets", "bytes"):
                if isinstance(o.get(f), (int, float)) and isinstance(cur.get(f), (int, float)):
                    cur[f] = cur[f] + o[f]
            try:
                cur["last_seen"] = max(float(cur.get("last_seen") or 0), float(o.get("last_seen") or 0))
                cur["first_seen"] = min(float(cur.get("first_seen") or o.get("first_seen") or 0),
                                        float(o.get("first_seen") or cur.get("first_seen") or 0))
            except (TypeError, ValueError):
                pass
            cur["tcp_syn"] = bool(cur.get("tcp_syn")) or bool(o.get("tcp_syn"))

    def _schedule_analysis(self, interval: float) -> None:
        if self._deferred is not None and not self._deferred.done():
            return
        wait = max(0.0, self._last_run_mono + interval - time.monotonic())

        async def _later() -> None:
            try:
                await asyncio.sleep(wait)
                await self._run(self.observations)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled analysis failed; the next upload retries")

        self._deferred = asyncio.get_running_loop().create_task(_later())

    async def flush(self) -> None:
        """Wait for a scheduled analysis (tests, shutdown)."""
        if self._deferred is not None:
            await self._deferred

    def note_sensor(self, sensor: dict[str, Any] | None) -> None:
        if not isinstance(sensor, dict) or not sensor.get("id"):
            return
        sid = str(sensor["id"])[:128]
        rec = self.sensors.setdefault(sid, {"batches": 0})
        rec.update({
            "site": sensor.get("site"), "version": sensor.get("version"),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "last_window": sensor.get("window"),
        })
        rec["batches"] += 1

    def _prune(self) -> None:
        """Bound memory: flows age out; then cap the store, oldest flows first.
        Announcements/OT samples (identity evidence) are kept preferentially."""
        flows = [o for o in self.observations if o.get("kind") == "flow"]
        if flows:
            newest = max(float(o.get("last_seen") or 0) for o in flows)
            horizon = newest - self.cfg.flow_retention_s
            self.observations = [
                o for o in self.observations
                if o.get("kind") != "flow" or float(o.get("last_seen") or 0) >= horizon
            ]
        self._flow_index = {_flow_key(o): o for o in self.observations if o.get("kind") == "flow"}
        excess = len(self.observations) - self.cfg.max_observations
        if excess > 0:
            idx = [i for i, o in enumerate(self.observations) if o.get("kind") == "flow"][:excess]
            drop = set(idx)
            self.observations = [o for i, o in enumerate(self.observations) if i not in drop]
            if len(self.observations) > self.cfg.max_observations:
                self.observations = self.observations[-self.cfg.max_observations:]
            self._flow_index = {_flow_key(o): o for o in self.observations if o.get("kind") == "flow"}

    async def analyze(self) -> dict[str, Any]:
        self.stats["analyses"] += 1
        return await self._run(self.observations)

    def _analyze_cpu(self, observations: list[dict[str, Any]]):  # type: ignore[no-untyped-def]
        devices = fingerprint_devices(observations)
        exposure = analyze_exposure(
            devices,
            v4_prefix=self.cfg.ipv4_segment_prefix,
            v6_prefix=self.cfg.ipv6_segment_prefix,
        )
        flows = [o for o in observations if o.get("kind") == "flow"]
        behav = behavior.analyze(
            devices, flows,
            params=behavior.BehaviorParams(
                window_s=self.cfg.behavior_window_s, scan_hosts=self.cfg.scan_hosts,
                scan_ports=self.cfg.scan_ports, learn_s=self.cfg.baseline_learn_s,
                v4_prefix=self.cfg.ipv4_segment_prefix, v6_prefix=self.cfg.ipv6_segment_prefix,
            ),
            baselines=self.baselines,
        )
        return devices, exposure, behav

    async def _run(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        async with self._lock:
            self._last_run_mono = time.monotonic()
            if self.cfg.analyze_interval_s > 0:
                # keep the event loop (heartbeats, uploads) responsive during the CPU work
                devices, exposure, behav = await asyncio.to_thread(self._analyze_cpu, list(observations))
            else:
                devices, exposure, behav = self._analyze_cpu(observations)
            result = await self._project(devices, exposure, behav)
            self._last_run_mono = time.monotonic()
            return result

    async def _post_reach_flows(self) -> dict[str, Any]:
        """Deliver not-yet-delivered flow aggregates to the reach graph, <= FLOW_BATCH per call.

        Returns ``{}`` when there is nothing to send, ``{"error": ...}`` on the first failed batch
        (the same convention as the other bulk calls, so a managed ingest answers 503 and the
        sensor retries), else the totals. Batches already acknowledged stay acknowledged.
        """
        pending = self._reach.pending()
        if not pending or self.orch is None:
            return {}
        sent = {"received": 0, "inserted": 0, "updated": 0}
        for i in range(0, len(pending), FLOW_BATCH):
            chunk = pending[i:i + FLOW_BATCH]
            resp = await self.orch.bulk_flows([rec for _, rec, _ in chunk])
            if not isinstance(resp, dict) or "error" in resp:
                err = resp.get("error") if isinstance(resp, dict) else None
                return {"error": err or "flow post failed", **sent}
            for key, _, snap in chunk:
                self._reach.mark_posted(key, snap)
            for k in sent:
                sent[k] += int(resp.get(k, 0) or 0)
        self._reach.prune()
        self.stats["reach_flows_posted"] = self.stats.get("reach_flows_posted", 0) + sent["received"]
        return sent

    async def _project(self, devices, exposure, behav) -> dict[str, Any]:  # type: ignore[no-untyped-def]

        # Every IP we discovered is forbidden as an active-connection target.
        device_ips: set[str] = set()
        for dev in devices:
            device_ips |= set(dev.ips)

        posted_findings = 0
        asset_resp: dict[str, Any] = {}
        edge_resp: dict[str, Any] = {}
        finding_resp: dict[str, Any] = {}
        flow_resp: dict[str, Any] = {}

        self.last_segment_matrix = behav.segment_matrix

        with active_probe_guard(device_ips) as guard:
            cve_findings = await match_devices(devices, self._cve_fetch)
            findings = exposure.findings + cve_findings + behav.findings

            assets, edges = project_assets(devices, exposure)
            # Segments that only appear in observed traffic still need a node
            # for the reachability edges to attach to.
            known_segs = {a["value"] for a in assets if a["kind"] == "network_segment"}
            for cell in behav.segment_matrix:
                for cidr in (cell["from"], cell["to"]):
                    if cidr not in known_segs:
                        known_segs.add(cidr)
                        assets.append({"kind": "network_segment", "value": cidr,
                                       "source": "otdiscovery", "confidence": 60,
                                       "metadata": {"cidr": cidr, "classification": "unknown",
                                                    "observed_only": True, "passive": True}})
            edges = edges + behav.edges
            if self.orch is not None:
                asset_resp = await self.orch.bulk_assets(assets)
                if edges:
                    edge_resp = await self.orch.bulk_edges(edges)
                if findings:
                    finding_resp = await self.orch.bulk_findings(findings)
                    posted_findings = int(finding_resp.get("inserted", 0) or 0) + int(
                        finding_resp.get("updated", 0) or 0
                    )
                flow_resp = await self._post_reach_flows()

        self.last_inventory = devices
        self.last_guard_attempts = list(guard.attempts)
        self.last_guard_violations = list(guard.violations)

        ot_devices = [d for d in devices if d.role == "ot"]
        iot_devices = [d for d in devices if d.role == "iot"]

        self.stats.update({
            "devices": len([d for d in devices if d.is_device]),
            "ot_devices": len(ot_devices),
            "iot_devices": len(iot_devices),
            "segments": len(exposure.segments),
            "findings_posted": posted_findings,
            "last_run": datetime.now(timezone.utc).isoformat(),
        })
        self.stats["guard_violations_total"] += len(self.last_guard_violations)

        return {
            "devices": len([d for d in devices if d.is_device]),
            "ot_devices": len(ot_devices),
            "iot_devices": len(iot_devices),
            "segments": len(exposure.segments),
            "exposure_findings": len(exposure.findings),
            "ot_it_violations": exposure.ot_it_violations,
            "ot_public_exposures": exposure.ot_public,
            "cve_matches": len(cve_findings),
            "behavior_findings": len(behav.findings),
            "behavior": behav.stats,
            "segment_matrix": behav.segment_matrix,
            "findings_total": len(findings),
            "findings_posted": posted_findings,
            "assets_projected": len([d for d in devices if d.is_device])
            + len(exposure.segments),
            "orchestrator": {
                "assets": asset_resp, "edges": edge_resp, "findings": finding_resp,
                **({"flows": flow_resp} if flow_resp else {}),
            },
            # surfaced for the safety test: active-probe guard accounting
            "active_probe_attempts_to_devices": len(self.last_guard_violations),
            "inventory": [_device_summary(d, exposure) for d in devices if d.is_device],
        }


def _device_summary(dev: Device, exposure: ExposureResult) -> dict[str, Any]:
    return {
        "device_id": dev.key,
        "value": dev.asset_value(),
        "role": dev.role,
        "type": dev.type,
        "vendor": dev.vendor,
        "model": dev.model,
        "protocols": sorted(dev.protocols),
        "confidence": dev.confidence,
        "segment": exposure.device_segment.get(dev.key),
    }
