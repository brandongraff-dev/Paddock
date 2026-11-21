"""Segmentation + exposure analysis over the discovered device inventory.

Everything here is derived from the passively-observed flows and the device
inventory; no probe is ever sent. We produce:

  * network_segment records (one per observed subnet) with an IT/OT/mixed
    classification,
  * device -> segment membership edges,
  * exposure findings:
      - ``ot_it_exposure``  : an OT device reachable from an IT/IoT segment
        (flat network, or an observed cross-segment flow) -- the canonical
        water-utility IT/OT segmentation violation. severity: high.
      - ``ot_public_exposure`` : an OT device observed with a public,
        internet-routable address. severity: high.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Optional

from .fingerprint.device import Device


@dataclass
class Segment:
    cidr: str
    classification: str = "unknown"   # ot | it | mixed | unknown
    members: set[str] = field(default_factory=set)   # device keys
    member_ips: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    internet_facing: bool = False

    def to_metadata(self) -> dict[str, Any]:
        return {
            "cidr": self.cidr,
            "classification": self.classification,
            "device_count": len(self.members),
            "roles": sorted(self.roles),
            "internet_facing": self.internet_facing,
            "member_ips": sorted(self.member_ips),
            "discovered_by": "otdiscovery",
            "passive": True,
        }


@dataclass
class ExposureResult:
    segments: list[Segment]
    device_segment: dict[str, str]           # device key -> segment cidr
    findings: list[dict[str, Any]]
    ot_it_violations: int = 0
    ot_public: int = 0


def _ip_obj(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def _segment_cidr(ip: str, v4_prefix: int, v6_prefix: int) -> Optional[str]:
    addr = _ip_obj(ip)
    if addr is None:
        return None
    prefix = v4_prefix if addr.version == 4 else v6_prefix
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    return str(net)


def _is_public(ip: str) -> bool:
    addr = _ip_obj(ip)
    if addr is None:
        return False
    return addr.is_global


def build_segments(
    devices: list[Device], v4_prefix: int = 24, v6_prefix: int = 64
) -> tuple[list[Segment], dict[str, str]]:
    """Group devices into subnet segments and classify each IT/OT/mixed."""
    segments: dict[str, Segment] = {}
    device_segment: dict[str, str] = {}

    for dev in devices:
        ip = dev.primary_ip
        if not ip:
            continue
        cidr = _segment_cidr(ip, v4_prefix, v6_prefix)
        if cidr is None:
            continue
        seg = segments.get(cidr)
        if seg is None:
            seg = Segment(cidr=cidr)
            segments[cidr] = seg
        seg.members.add(dev.key)
        for dip in dev.ips:
            seg.member_ips.add(dip)
        seg.roles.add(dev.role)
        if _is_public(ip):
            seg.internet_facing = True
        device_segment[dev.key] = cidr

    for seg in segments.values():
        has_ot = "ot" in seg.roles
        has_it = "it" in seg.roles
        has_iot = "iot" in seg.roles
        if has_ot and (has_it or has_iot):
            seg.classification = "mixed"
        elif has_ot:
            seg.classification = "ot"
        elif has_it or has_iot:
            seg.classification = "it"
        else:
            seg.classification = "unknown"

    return list(segments.values()), device_segment


def _peer_ips(dev: Device) -> set[str]:
    peers: set[str] = set()
    for rec in dev.evidence.get("ot_protocols", []) or []:
        p = rec.get("peer_ip")
        if p:
            peers.add(p)
    return peers


def analyze(
    devices: list[Device], v4_prefix: int = 24, v6_prefix: int = 64
) -> ExposureResult:
    segments, device_segment = build_segments(devices, v4_prefix, v6_prefix)
    seg_by_cidr = {s.cidr: s for s in segments}

    # Map every observed member IP to the classification of its segment, so a
    # cross-segment OT<->IT flow can be judged by the peer's segment.
    ip_segment: dict[str, str] = {}
    for seg in segments:
        for ip in seg.member_ips:
            ip_segment[ip] = seg.cidr

    findings: list[dict[str, Any]] = []
    ot_it = 0
    ot_public = 0

    for dev in devices:
        if dev.role != "ot":
            continue
        dev_cidr = device_segment.get(dev.key)
        dev_seg = seg_by_cidr.get(dev_cidr) if dev_cidr else None
        asset_value = dev.asset_value()
        label = dev.vendor or dev.type or "OT device"

        # ---- public / internet-routable OT address --------------------- #
        public_ips = sorted(ip for ip in dev.ips if _is_public(ip))
        if public_ips:
            ot_public += 1
            findings.append({
                "asset_value": asset_value,
                "asset_kind": "ot_device",
                "rule_id": "ot_public_exposure",
                "rule_source": "policy",
                "severity": "high",
                "title": f"OT device {label} observed on a public address",
                "description": (
                    f"The OT device {asset_value} ({dev.type}) was observed in the "
                    f"capture using internet-routable address(es): "
                    f"{', '.join(public_ips)}. Industrial equipment must never be "
                    "directly reachable from the public internet."
                ),
                "impact": (
                    "Internet-exposed OT/ICS equipment is routinely discovered and "
                    "attacked (Shodan-class exposure). A reachable PLC/RTU/controller "
                    "can be disrupted, with physical-process consequences."
                ),
                "remediation": (
                    "Remove the device from any public/NAT path immediately. Place it "
                    "behind an OT DMZ / data diode; expose process data only through a "
                    "polled historian or broker, never the controller itself."
                ),
                "evidence": {
                    "public_ips": public_ips,
                    "protocols": sorted(dev.protocols),
                    "detector": "ot_public_exposure",
                    "passive": True,
                },
                "metadata": {"source": "otdiscovery", "device_id": dev.key,
                             "role": "ot", "type": dev.type},
            })

        # ---- IT/OT segmentation violation ------------------------------ #
        violated = False
        reasons: list[str] = []
        it_peers: list[dict[str, str]] = []

        # (a) flat network: OT shares its segment with IT/IoT hosts
        if dev_seg is not None and dev_seg.classification == "mixed":
            violated = True
            reasons.append(
                f"OT device shares segment {dev_seg.cidr} with IT/IoT hosts "
                "(no IT/OT segmentation)"
            )

        # (b) observed cross-segment flow to an IT/IoT segment
        for peer in _peer_ips(dev):
            peer_cidr = ip_segment.get(peer)
            peer_seg = seg_by_cidr.get(peer_cidr) if peer_cidr else None
            peer_class = peer_seg.classification if peer_seg else None
            if peer_cidr and peer_cidr != dev_cidr and peer_class in ("it", "mixed"):
                violated = True
                it_peers.append({"peer_ip": peer, "peer_segment": peer_cidr,
                                 "peer_class": peer_class})
                reasons.append(
                    f"observed flow from an IT segment host {peer} "
                    f"({peer_cidr}) to this OT device"
                )

        if violated:
            ot_it += 1
            findings.append({
                "asset_value": asset_value,
                "asset_kind": "ot_device",
                "rule_id": "ot_it_exposure",
                "rule_source": "policy",
                "severity": "high",
                "title": f"OT device {label} reachable from the IT network",
                "description": (
                    f"The OT device {asset_value} ({dev.type}) is not isolated from "
                    "IT/IoT hosts. " + "; ".join(reasons) + "."
                ),
                "impact": (
                    "Flat IT/OT networks are the canonical water-utility / critical-"
                    "infrastructure risk: a foothold on an ordinary IT host (phishing, "
                    "a vulnerable IoT device) then has a direct path to safety-critical "
                    "control equipment."
                ),
                "remediation": (
                    "Enforce IT/OT segmentation: move the controller onto a dedicated "
                    "OT VLAN behind a firewall/OT-DMZ (Purdue model). Allow only the "
                    "specific historian/engineering flows required, deny the rest, and "
                    "alert on any new IT->OT conversation."
                ),
                "evidence": {
                    "device_segment": dev_cidr,
                    "device_segment_class": dev_seg.classification if dev_seg else None,
                    "it_peers": it_peers,
                    "protocols": sorted(dev.protocols),
                    "detector": "ot_it_exposure",
                    "passive": True,
                },
                "metadata": {"source": "otdiscovery", "device_id": dev.key,
                             "role": "ot", "type": dev.type},
            })

    return ExposureResult(
        segments=segments,
        device_segment=device_segment,
        findings=findings,
        ot_it_violations=ot_it,
        ot_public=ot_public,
    )
