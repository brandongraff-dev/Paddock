"""Fuse passive signals (OUI, mDNS/SSDP/UPnP, DHCP, OT protocols) into devices.

Given a list of normalized observations, build one ``Device`` per distinct
endpoint, correlating IP<->MAC where both were seen, and deriving a device
``type``, ``vendor``, ``model`` and ``role`` (iot vs ot vs it) with a
confidence score. Everything here is pure computation over data already in
hand -- no network, no probing.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Optional

from . import dhcp as dhcp_fp
from . import mdns as mdns_fp
from . import oui as oui_fp
from . import otproto

# Device classes we treat as OT equipment regardless of how they were spotted.
_OT_TYPES = {
    "plc", "rtu", "hvac_controller", "building_controller", "ot_server",
    "hmi", "ied", "controller",
}
_IOT_TYPES = {
    "camera", "printer", "thermostat", "smart_bulb", "media_player",
    "voice_assistant", "appliance", "home_controller", "sbc",
    "microcontroller", "file_server", "router", "nvr", "scanner",
}


@dataclass
class Device:
    key: str
    mac: Optional[str] = None
    ips: set[str] = field(default_factory=set)
    vendor: Optional[str] = None
    model: Optional[str] = None
    type: str = "unknown"
    role: str = "unknown"            # ot | iot | it | unknown
    os: Optional[str] = None
    device_class: Optional[str] = None
    protocols: set[str] = field(default_factory=set)
    confidence: int = 0
    sources: set[str] = field(default_factory=set)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def primary_ip(self) -> Optional[str]:
        if not self.ips:
            return None
        # Prefer a routable-looking IPv4, then any, sorted for stability.
        def _sort_key(ip: str) -> tuple[int, str]:
            try:
                addr = ipaddress.ip_address(ip)
                return (0 if addr.version == 4 else 1, ip)
            except ValueError:
                return (2, ip)
        return sorted(self.ips, key=_sort_key)[0]

    @property
    def is_device(self) -> bool:
        """True when this endpoint is an IoT/OT device worth projecting."""
        return self.role in ("iot", "ot")

    def asset_value(self) -> str:
        return self.primary_ip or self.mac or self.key

    def to_metadata(self) -> dict[str, Any]:
        return {
            "device_id": self.key,
            "mac": self.mac,
            "ips": sorted(self.ips),
            "vendor": self.vendor,
            "model": self.model,
            "type": self.type,
            "role": self.role,
            "os": self.os,
            "device_class": self.device_class,
            "protocols": sorted(self.protocols),
            "confidence": self.confidence,
            "sources": sorted(self.sources),
            "evidence": self.evidence,
            "discovered_by": "otdiscovery",
            "passive": True,
        }


def _usable_ip(ip: Optional[str]) -> Optional[str]:
    """Return a clean endpoint IP, or None for addresses that aren't a host.

    Drops the unspecified (0.0.0.0/::), broadcast, and multicast addresses a
    capture is full of -- they are never a device we would inventory.
    """
    if not isinstance(ip, str) or not ip.strip():
        return None
    s = ip.strip()
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return None
    if addr.version == 4 and s == "255.255.255.255":
        return None
    return s


class _Builder:
    def __init__(self) -> None:
        self.devices: dict[str, Device] = {}
        self.ip_to_mac: dict[str, str] = {}
        self.mac_to_ip: dict[str, set[str]] = {}

    # --- endpoint correlation -------------------------------------------- #
    def learn_link(self, ip: Optional[str], mac: Optional[str]) -> None:
        mac_n = oui_fp.normalize_mac(mac) if mac else None
        ip_n = _usable_ip(ip)
        if ip_n and mac_n and not oui_fp.is_locally_administered(mac_n):
            self.ip_to_mac.setdefault(ip_n, mac_n)
            self.mac_to_ip.setdefault(mac_n, set()).add(ip_n)

    def key_for(self, ip: Optional[str], mac: Optional[str]) -> Optional[str]:
        mac_n = oui_fp.normalize_mac(mac) if mac else None
        ip_n = _usable_ip(ip)
        if mac_n and not oui_fp.is_locally_administered(mac_n):
            return f"mac:{mac_n}"
        if ip_n and ip_n in self.ip_to_mac:
            return f"mac:{self.ip_to_mac[ip_n]}"
        if ip_n:
            return f"ip:{ip_n}"
        if mac_n:
            return f"mac:{mac_n}"
        return None

    def device_for(self, ip: Optional[str], mac: Optional[str]) -> Optional[Device]:
        key = self.key_for(ip, mac)
        if key is None:
            return None
        dev = self.devices.get(key)
        if dev is None:
            dev = Device(key=key)
            self.devices[key] = dev
        mac_n = oui_fp.normalize_mac(mac) if mac else None
        if mac_n and not oui_fp.is_locally_administered(mac_n):
            dev.mac = mac_n
        ip_n = _usable_ip(ip)
        if ip_n:
            dev.ips.add(ip_n)
        return dev


def _apply_oui(dev: Device) -> None:
    if not dev.mac:
        return
    hit = oui_fp.lookup(dev.mac)
    if not hit:
        return
    dev.sources.add("oui")
    dev.evidence["oui"] = hit
    if not dev.vendor:
        dev.vendor = hit.get("vendor")
    if hit.get("type") and dev.type == "unknown":
        dev.type = hit["type"]
    if hit.get("role"):
        _bump_role(dev, hit["role"])
    dev.confidence = max(dev.confidence, 45)


def _apply_mdns(dev: Device, hit: mdns_fp.MdnsHit) -> None:
    dev.sources.add("mdns/ssdp")
    dev.evidence.setdefault("announcements", []).append(dict(hit))
    if hit.get("vendor") and not dev.vendor:
        dev.vendor = hit["vendor"]
    if hit.get("model") and not dev.model:
        dev.model = hit["model"]
    if hit.get("type") and dev.type in ("unknown", "host"):
        dev.type = hit["type"]
    if hit.get("role"):
        _bump_role(dev, hit["role"])
    dev.confidence = max(dev.confidence, 60)


def _apply_dhcp(dev: Device, hit: dhcp_fp.DhcpHit) -> None:
    dev.sources.add("dhcp")
    dev.evidence["dhcp"] = dict(hit)
    if hit.get("os") and not dev.os:
        dev.os = hit["os"]
    cls = hit.get("device_class")
    if cls:
        dev.device_class = cls
        if dev.type == "unknown" and cls in _IOT_TYPES | _OT_TYPES:
            dev.type = cls
        if cls in ("workstation", "mobile", "host"):
            _bump_role(dev, "it")
        elif cls in _OT_TYPES:
            _bump_role(dev, "ot")
        elif cls in _IOT_TYPES:
            _bump_role(dev, "iot")
    dev.confidence = max(dev.confidence, int(hit.get("confidence", 30)))


def _apply_ot(dev: Device, hit: otproto.OtHit) -> None:
    dev.sources.add("ot_protocol")
    dev.protocols.add(hit.protocol)
    dev.evidence.setdefault("ot_protocols", []).append(
        {
            "protocol": hit.protocol,
            "port": hit.port,
            "banner_matched": hit.banner_matched,
            "evidence": hit.evidence,
            "peer_ip": hit.peer_ip,
        }
    )
    # OT protocol on the server side is the strongest role signal we have.
    dev.role = "ot"
    if dev.type in ("unknown", "host"):
        dev.type = hit.type
    dev.confidence = max(dev.confidence, hit.confidence)


# role precedence: ot > iot > it > unknown (a stronger signal never downgrades)
_ROLE_RANK = {"unknown": 0, "it": 1, "iot": 2, "ot": 3}


def _bump_role(dev: Device, role: str) -> None:
    if _ROLE_RANK.get(role, 0) > _ROLE_RANK.get(dev.role, 0):
        dev.role = role


def fingerprint_devices(observations: list[dict[str, Any]]) -> list[Device]:
    """Build the device inventory from a list of normalized observations."""
    b = _Builder()

    # Pass 1: learn IP<->MAC links from every endpoint we can see.
    for obs in observations:
        kind = obs.get("kind")
        if kind in ("packet", "flow", "arp"):
            b.learn_link(obs.get("src_ip"), obs.get("src_mac"))
            b.learn_link(obs.get("dst_ip"), obs.get("dst_mac"))
        else:
            b.learn_link(obs.get("src_ip") or obs.get("ip"),
                         obs.get("src_mac") or obs.get("mac"))

    # Pass 2: attach each observation's evidence to the right device.
    for obs in observations:
        kind = obs.get("kind")

        if kind in ("mdns", "ssdp", "upnp"):
            hit = mdns_fp.classify(obs)
            dev = b.device_for(obs.get("src_ip") or obs.get("ip"),
                               obs.get("src_mac") or obs.get("mac"))
            if dev is not None and hit is not None:
                _apply_mdns(dev, hit)

        elif kind == "dhcp":
            hit = dhcp_fp.classify(obs)
            dev = b.device_for(obs.get("ip") or obs.get("src_ip"),
                               obs.get("mac") or obs.get("src_mac"))
            if dev is not None and hit is not None:
                _apply_dhcp(dev, hit)

        elif kind in ("packet", "flow", "arp"):
            ot = otproto.identify(obs)
            if ot is not None:
                dev = b.device_for(ot.device_ip, ot.device_mac)
                if dev is not None:
                    _apply_ot(dev, ot)
            else:
                # still register both endpoints so they exist for segmentation
                b.device_for(obs.get("src_ip"), obs.get("src_mac"))
                b.device_for(obs.get("dst_ip"), obs.get("dst_mac"))

    # Pass 3: OUI vendor/type/role for every device that has a MAC.
    for dev in b.devices.values():
        _apply_oui(dev)
        # tidy: if still unknown role but we have an IoT-ish type, call it iot
        if dev.role == "unknown" and dev.type in _IOT_TYPES:
            dev.role = "iot"
        if dev.role == "unknown" and dev.type in _OT_TYPES:
            dev.role = "ot"
        dev.confidence = min(100, dev.confidence)

    return list(b.devices.values())
