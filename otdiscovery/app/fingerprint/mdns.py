"""Map mDNS / SSDP / UPnP announcement strings to a device type.

These are announcements the device *broadcasts* (mDNS/Bonjour service records,
SSDP NOTIFY/M-SEARCH responses, UPnP device descriptions). We only read what
was observed; we never send an M-SEARCH or fetch a UPnP description URL.
"""
from __future__ import annotations

import re
from typing import Any, Optional, TypedDict

# service-string / server substring  ->  (device_type, role)
# Ordered most-specific first; first match wins.
_SERVICE_RULES: list[tuple[str, tuple[str, str]]] = [
    # printers
    ("_ipp._tcp", ("printer", "iot")),
    ("_ipps._tcp", ("printer", "iot")),
    ("_printer._tcp", ("printer", "iot")),
    ("_pdl-datastream._tcp", ("printer", "iot")),
    ("_scanner._tcp", ("printer", "iot")),
    # cameras / NVR
    ("_rtsp._tcp", ("camera", "iot")),
    ("_axis-video._tcp", ("camera", "iot")),
    ("onvif", ("camera", "iot")),
    ("_onvif._tcp", ("camera", "iot")),
    ("hipcam", ("camera", "iot")),
    ("ipcamera", ("camera", "iot")),
    # media / cast
    ("_googlecast._tcp", ("media_player", "iot")),
    ("_airplay._tcp", ("media_player", "iot")),
    ("_raop._tcp", ("media_player", "iot")),
    ("_spotify-connect._tcp", ("media_player", "iot")),
    # home automation / appliance controllers
    ("_hap._tcp", ("home_controller", "iot")),
    ("_homekit._tcp", ("home_controller", "iot")),
    ("_hue._tcp", ("smart_bulb", "iot")),
    ("thermostat", ("thermostat", "iot")),
    ("nest", ("thermostat", "iot")),
    ("ecobee", ("thermostat", "iot")),
    ("refrigerator", ("appliance", "iot")),
    ("fridge", ("appliance", "iot")),
    ("smartthings", ("home_controller", "iot")),
    ("_ewelink._tcp", ("appliance", "iot")),
    # building / OT-ish controllers announced over SSDP/UPnP (rare but seen)
    ("bacnet", ("hvac_controller", "ot")),
    ("niagara", ("building_controller", "ot")),
    ("tridium", ("building_controller", "ot")),
    # NAS / compute
    ("_smb._tcp", ("file_server", "iot")),
    ("_afpovertcp._tcp", ("file_server", "iot")),
    ("_nfs._tcp", ("file_server", "iot")),
    # network gear via UPnP IGD
    ("internetgatewaydevice", ("router", "iot")),
    ("urn:schemas-upnp-org:device:wandevice", ("router", "iot")),
    # generic workstation / OS announcements
    ("_workstation._tcp", ("workstation", "it")),
    ("_device-info._tcp", ("workstation", "it")),
    ("_ssh._tcp", ("host", "it")),
]

# vendor hints pulled from announcement text
_VENDOR_HINTS: list[tuple[str, str]] = [
    ("axis", "Axis Communications"),
    ("hikvision", "Hikvision"),
    ("dahua", "Dahua Technology"),
    ("hewlett", "Hewlett-Packard"),
    (" hp ", "Hewlett-Packard"),
    ("brother", "Brother"),
    ("kyocera", "Kyocera"),
    ("nest", "Google / Nest"),
    ("ecobee", "ecobee"),
    ("sonos", "Sonos"),
    ("google", "Google"),
    ("amazon", "Amazon"),
    ("synology", "Synology"),
    ("tridium", "Tridium / Honeywell"),
    ("siemens", "Siemens"),
    ("schneider", "Schneider Electric"),
    ("honeywell", "Honeywell"),
]

_MODEL_RE = re.compile(
    r"(?:modelname|model|md)\s*[=:]\s*([A-Za-z0-9][\w .\-/]{1,48})", re.IGNORECASE
)


class MdnsHit(TypedDict, total=False):
    type: str
    role: str
    vendor: str
    model: str
    matched: str


def _haystack(obs: dict[str, Any]) -> str:
    """Flatten the announcement fields we match against into one lowercase blob."""
    parts: list[str] = []
    for key in (
        "service",
        "name",
        "type",
        "st",
        "nt",
        "usn",
        "server",
        "location",
        "model",
        "model_name",
        "manufacturer",
        "device_type",
        "friendly_name",
    ):
        v = obs.get(key)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple)):
            parts.extend(str(x) for x in v)
    txt = obs.get("txt")
    if isinstance(txt, dict):
        parts.extend(f"{k}={v}" for k, v in txt.items())
    elif isinstance(txt, (list, tuple)):
        parts.extend(str(x) for x in txt)
    return " ".join(parts).lower()


def classify(obs: dict[str, Any]) -> Optional[MdnsHit]:
    """Classify one mDNS/SSDP/UPnP announcement observation."""
    hay = _haystack(obs)
    if not hay.strip():
        return None

    hit: MdnsHit = {}
    for needle, (dtype, role) in _SERVICE_RULES:
        if needle in hay:
            hit["type"] = dtype
            hit["role"] = role
            hit["matched"] = needle
            break

    for needle, vendor in _VENDOR_HINTS:
        if needle in hay:
            hit["vendor"] = vendor
            break

    # explicit vendor/model fields take precedence over text sniffing
    for key in ("manufacturer", "model_name", "model"):
        val = obs.get(key)
        if isinstance(val, str) and val.strip():
            if key == "manufacturer" and "vendor" not in hit:
                hit["vendor"] = val.strip()
            elif key in ("model", "model_name") and "model" not in hit:
                hit["model"] = val.strip()

    if "model" not in hit:
        m = _MODEL_RE.search(hay)
        if m:
            hit["model"] = m.group(1).strip()

    return hit or None
