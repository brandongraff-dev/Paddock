"""Behaviour analytics over passively-observed flows (Paddock Sentry).

Fingerprinting says *what* a device is; this module says whether it is
*behaving like one*. Two layers:

1. **Day-one policy detectors** -- need no learning, so a new site gets value
   in its first hour:
     * ``device_lateral_scan``    IoT/OT device initiating to many internal
                                  hosts or ports (worm / compromised-device
                                  behaviour).
     * ``ot_internet_egress``     OT device initiating to a public address.
     * ``cleartext_management``   Telnet/FTP/TFTP/SNMPv1-2 sessions to an
                                  IoT/OT device.
     * ``iot_crosses_segment``    IoT device initiating to another internal
                                  segment on a non-infrastructure port (the
                                  "lobby TV -> payment server" path).

2. **Learned per-model baselines** -- for every device *class* (vendor/type/
   model, not individual device) we learn the set of (peer scope, proto, port)
   it initiates. After the learning period a new tuple is ``behavior_drift``.
   Learning per class means the second identical fridge on a site -- and,
   with fleet-shared profiles, the 500th customer's -- is covered from day one.

Also emits the **observed segmentation map**: segment -> segment reachability
edges built from real traffic, not firewall intent.

Pure functions over data we were handed. Never touches a device.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .fingerprint.device import Device

log = logging.getLogger(__name__)

# Ports every device legitimately uses to reach infrastructure on other segments.
INFRA_PORTS = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353, 5355})
CLEARTEXT_MGMT = {
    ("tcp", 23): "Telnet", ("tcp", 2323): "Telnet", ("tcp", 21): "FTP",
    ("udp", 69): "TFTP", ("udp", 161): "SNMP v1/v2c",
}


@dataclass
class BehaviorParams:
    window_s: float = 900.0          # analyse flows from the last 15 min of traffic
    scan_hosts: int = 16             # distinct internal hosts initiated to
    scan_ports: int = 24             # distinct ports on a single internal host
    learn_s: float = 7 * 86400.0     # baseline learning period per device class
    v4_prefix: int = 24
    v6_prefix: int = 64


@dataclass
class BehaviorResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    segment_matrix: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Baselines
# --------------------------------------------------------------------------- #

class BaselineStore:
    """Per device-class behaviour profiles, optionally persisted as JSON.

    ``profiles[class_key] = {"first_seen": ts, "tuples": {tuple_key: first_ts}}``
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.profiles: dict[str, dict[str, Any]] = {}
        self.alerted: set[str] = set()
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                self.profiles = raw.get("profiles", {})
                self.alerted = set(raw.get("alerted", []))
            except (OSError, ValueError):
                self.profiles, self.alerted = {}, set()

    def save(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        try:
            with self._lock, open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"profiles": self.profiles, "alerted": sorted(self.alerted)}, fh)
            os.replace(tmp, self.path)
        except OSError as exc:
            # Never let persistence break detection; baselines stay in memory.
            log.error("baseline_save_failed: %s (%s); continuing in-memory", self.path, exc)

    def observe(self, class_key: str, tuple_key: str, ts: float, learn_s: float) -> bool:
        """Record a behaviour; return True when it is NEW after learning."""
        with self._lock:
            prof = self.profiles.setdefault(class_key, {"first_seen": ts, "tuples": {}})
            prof["first_seen"] = min(prof["first_seen"], ts)
            tuples = prof["tuples"]
            if tuple_key in tuples:
                return False
            learning = ts - prof["first_seen"] < learn_s
            tuples[tuple_key] = ts
            return not learning

    def learned(self, class_key: str, now: float, learn_s: float) -> bool:
        prof = self.profiles.get(class_key)
        return bool(prof) and now - prof["first_seen"] >= learn_s


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _ip(s: Any) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(str(s))
    except ValueError:
        return None


def _is_internal(ip: ipaddress._BaseAddress) -> bool:
    return bool(ip.is_private or ip.is_link_local or ip.is_loopback)


def _segment(ip: str, p: BehaviorParams) -> Optional[str]:
    a = _ip(ip)
    if a is None:
        return None
    try:
        return str(ipaddress.ip_network(f"{ip}/{p.v4_prefix if a.version == 4 else p.v6_prefix}", strict=False))
    except ValueError:
        return None


def device_class(dev: Device) -> str:
    return "|".join((dev.vendor or "?", dev.type or "?", dev.model or "?")).lower()


def _label(dev: Device) -> str:
    bits = [b for b in (dev.vendor, dev.model or dev.type) if b and b != "unknown"]
    return " ".join(bits) or dev.role.upper()


def _finding(dev: Device, rule_id: str, severity: str, title: str, description: str,
             impact: str, remediation: str, evidence: dict[str, Any]) -> dict[str, Any]:
    kind = "ot_device" if dev.role == "ot" else "iot_device"
    return {
        "asset_value": dev.asset_value(),
        "asset_kind": kind,
        "rule_id": rule_id,
        "rule_source": "policy",
        "severity": severity,
        "title": title,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "evidence": {**evidence, "detector": rule_id, "passive": True},
        "metadata": {"source": "otdiscovery.behavior", "device_id": dev.key,
                     "role": dev.role, "type": dev.type, "device_class": device_class(dev)},
    }


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def analyze(
    devices: Iterable[Device],
    flows: list[dict[str, Any]],
    *,
    params: BehaviorParams | None = None,
    baselines: BaselineStore | None = None,
) -> BehaviorResult:
    p = params or BehaviorParams()
    res = BehaviorResult()
    by_ip: dict[str, Device] = {}
    for d in devices:
        for ip in d.ips:
            by_ip[ip] = d

    if not flows:
        return res
    newest = max(float(f.get("last_seen") or 0) for f in flows)
    recent = [f for f in flows if float(f.get("last_seen") or 0) >= newest - p.window_s]

    out_hosts: dict[str, set[str]] = defaultdict(set)
    out_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    seg_pairs: dict[tuple[str, str], dict[str, Any]] = {}
    seen_rules: set[tuple[str, str, str]] = set()

    def emit(dev: Device, dedupe: str, finding: dict[str, Any]) -> None:
        key = (dev.key, finding["rule_id"], dedupe)
        if key not in seen_rules:
            seen_rules.add(key)
            res.findings.append(finding)

    for f in recent:
        src, dst = str(f.get("src_ip") or ""), str(f.get("dst_ip") or "")
        sa, da = _ip(src), _ip(dst)
        if sa is None or da is None:
            continue
        proto, port = str(f.get("proto") or ""), int(f.get("dst_port") or 0)
        sdev, ddev = by_ip.get(src), by_ip.get(dst)
        s_seg, d_seg = _segment(src, p), _segment(dst, p)

        # observed segmentation map (internal <-> internal only)
        if _is_internal(sa) and _is_internal(da) and s_seg and d_seg and s_seg != d_seg:
            cell = seg_pairs.setdefault((s_seg, d_seg), {"flows": 0, "ports": set(), "bytes": 0})
            cell["flows"] += 1
            cell["bytes"] += int(f.get("bytes") or 0)
            cell["ports"].add(f"{proto}/{port}")

        # cleartext management TO a device
        mgmt = CLEARTEXT_MGMT.get((proto, port))
        if mgmt and ddev is not None and ddev.is_device:
            emit(ddev, mgmt, _finding(
                ddev, "cleartext_management", "medium",
                f"{mgmt} management in use on {_label(ddev)}",
                f"{src} opened a {mgmt} session ({proto}/{port}) to {ddev.asset_value()}. "
                "Credentials and commands cross the network unencrypted.",
                "Anyone on the path can capture the device's admin credentials and replay them.",
                f"Disable {mgmt}; manage the device over SSH/HTTPS/SNMPv3 from a management VLAN only.",
                {"client": src, "proto": proto, "port": port, "packets": f.get("packets")},
            ))

        if sdev is None or not sdev.is_device:
            continue

        # initiator-side behaviour of IoT/OT devices
        if _is_internal(da):
            out_hosts[sdev.key].add(dst)
            out_ports[(sdev.key, dst)].add(port)
        elif sdev.role == "ot":
            emit(sdev, dst, _finding(
                sdev, "ot_internet_egress", "high",
                f"OT device {_label(sdev)} is talking to the internet",
                f"{sdev.asset_value()} initiated {proto}/{port} to public address {dst}. "
                "Controllers should not reach the internet directly.",
                "Direct internet paths from OT are how ransomware and remote-access abuse reach "
                "physical processes.",
                "Block OT egress at the IT/OT boundary; route vendor remote access through a "
                "brokered, MFA-protected jump host.",
                {"peer": dst, "proto": proto, "port": port, "bytes": f.get("bytes")},
            ))

        if (sdev.role == "iot" and _is_internal(da) and s_seg and d_seg and s_seg != d_seg
                and port not in INFRA_PORTS):
            emit(sdev, f"{d_seg}:{port}", _finding(
                sdev, "iot_crosses_segment", "medium",
                f"{_label(sdev)} reaches another network segment",
                f"IoT device {sdev.asset_value()} ({s_seg}) initiated {proto}/{port} to {dst} in "
                f"{d_seg}. IoT devices should be confined to their own segment.",
                "A compromised smart device becomes a foothold into the segment it can reach.",
                "Move IoT devices to an isolated VLAN/SSID and allow only the cloud endpoints "
                "they need.",
                {"peer": dst, "peer_segment": d_seg, "proto": proto, "port": port},
            ))

        # learned baselines (per device CLASS)
        if baselines is not None:
            scope = ("internet" if not _is_internal(da)
                     else "same_segment" if s_seg == d_seg else "other_segment")
            tkey = f"out|{scope}|{proto}|{port}"
            ts = float(f.get("first_seen") or f.get("last_seen") or time.time())
            if baselines.observe(device_class(sdev), tkey, ts, p.learn_s):
                alert_key = f"{sdev.key}|{tkey}"
                if alert_key not in baselines.alerted:
                    baselines.alerted.add(alert_key)
                    emit(sdev, tkey, _finding(
                        sdev, "behavior_drift", "medium",
                        f"{_label(sdev)} started a new kind of connection",
                        f"{sdev.asset_value()} initiated {proto}/{port} to {scope.replace('_', ' ')} "
                        f"({dst}), which no device of this model did during its learning period.",
                        "New behaviour from a fixed-function device often means compromise, "
                        "misconfiguration or an unannounced firmware change.",
                        "Confirm with the device owner/vendor; if unexpected, quarantine the device "
                        "and inspect its firmware and credentials.",
                        {"peer": dst, "scope": scope, "proto": proto, "port": port,
                         "device_class": device_class(sdev)},
                    ))

    # lateral scanning
    for dev_key, hosts in out_hosts.items():
        dev = next((d for d in devices if d.key == dev_key), None)
        if dev is None:
            continue
        widest = max((len(v) for (k, _), v in out_ports.items() if k == dev_key), default=0)
        if len(hosts) >= p.scan_hosts or widest >= p.scan_ports:
            emit(dev, "scan", _finding(
                dev, "device_lateral_scan", "high",
                f"{_label(dev)} is scanning the internal network",
                f"{dev.asset_value()} initiated connections to {len(hosts)} internal hosts "
                f"(up to {widest} ports on a single host) within {int(p.window_s // 60)} minutes. "
                "Fixed-function devices don't do this.",
                "This is the signature of a compromised device (e.g. Mirai-style worms) "
                "looking for its next victim.",
                "Quarantine the device now (switch port / VLAN / SSID), then reflash firmware "
                "and rotate its credentials before reconnecting.",
                {"distinct_hosts": len(hosts), "max_ports_one_host": widest,
                 "sample_hosts": sorted(hosts)[:10]},
            ))

    for (s, d), cell in sorted(seg_pairs.items()):
        ports = sorted(cell["ports"])
        res.segment_matrix.append({"from": s, "to": d, "flows": cell["flows"],
                                   "bytes": cell["bytes"], "ports": ports})
        res.edges.append({
            "src_kind": "network_segment", "src_canonical": s,
            "dst_kind": "network_segment", "dst_canonical": d,
            "kind": "can_reach_observed",
            "metadata": {"source": "otdiscovery.behavior", "flows": cell["flows"],
                         "ports": ports[:50], "observed": True},
        })

    if baselines is not None:
        baselines.save()
    res.stats = {"flows_analyzed": len(recent), "segment_pairs": len(seg_pairs),
                 "behavior_findings": len(res.findings)}
    return res
