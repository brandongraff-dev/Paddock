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
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from . import active_probe_guard, pcap
from .config import Config
from . import behavior
from .cvematch import match_devices
from .db import Database
from .exposure import ExposureResult, analyze as analyze_exposure
from .fingerprint import Device, fingerprint_devices
from .orchestrator import OrchestratorClient

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
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.orch = orch
        self.observations: list[dict[str, Any]] = []
        # One record per distinct flow (a sensor reports the same peer pair every
        # 30 s window; storing each repeat made analysis O(flow events) per upload).
        self._flow_index: dict[tuple, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._last_run_mono = 0.0
        self._deferred: Optional[asyncio.Task] = None
        self.baselines = behavior.BaselineStore(cfg.baseline_path)
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
    ) -> dict[str, Any]:
        parsed = parse_input(pcap_bytes=pcap_bytes, observations=observations)
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

    async def _project(self, devices, exposure, behav) -> dict[str, Any]:  # type: ignore[no-untyped-def]

        # Every IP we discovered is forbidden as an active-connection target.
        device_ips: set[str] = set()
        for dev in devices:
            device_ips |= set(dev.ips)

        posted_findings = 0
        asset_resp: dict[str, Any] = {}
        edge_resp: dict[str, Any] = {}
        finding_resp: dict[str, Any] = {}

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
