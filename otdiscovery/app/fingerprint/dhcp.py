"""DHCP fingerprint -> OS / device class.

Two passive signals, both taken from DHCP DISCOVER/REQUEST packets seen on the
wire (never solicited by us):

  * option 60 (vendor class identifier), e.g. ``MSFT 5.0``, ``android-dhcp-13``
  * option 55 (parameter request list), whose ordered option numbers form a
    coarse OS fingerprint (the basis of tools like Fingerbank / p0f).

We return a best-effort ``{os, class, confidence}`` with a soft default so an
unknown fingerprint still yields *something* without over-claiming.
"""
from __future__ import annotations

from typing import Any, Optional, TypedDict

# Substring of the vendor-class-identifier (option 60) -> (os, class)
_VCI_RULES: list[tuple[str, tuple[str, str]]] = [
    ("msft", ("Windows", "workstation")),
    ("android-dhcp", ("Android", "mobile")),
    ("android", ("Android", "mobile")),
    ("dhcpcd", ("Linux/embedded", "embedded")),
    ("udhcp", ("Linux/embedded (BusyBox)", "embedded")),
    ("iPXE", ("iPXE/firmware", "embedded")),
    ("Hewlett-Packard", ("HP device firmware", "printer")),
    ("HUAWEI", ("Huawei", "mobile")),
    ("Mitsubishi", ("Mitsubishi controller", "plc")),
    ("Siemens", ("Siemens firmware", "plc")),
    ("Rockwell", ("Rockwell firmware", "plc")),
    ("AXIS", ("Axis firmware", "camera")),
    ("Hikvision", ("Hikvision firmware", "camera")),
    ("ltrx", ("Lantronix device server", "embedded")),
    ("DigiConnect", ("Digi device server", "embedded")),
]

# Parameter-request-list (option 55) signatures. The exact ordered list is a
# known fingerprint; stored as a comma-joined string of option numbers.
_PRL_SIGNATURES: dict[str, tuple[str, str]] = {
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("Windows 10/11", "workstation"),
    "1,15,3,6,44,46,47,31,33,121,249,43": ("Windows 7/8", "workstation"),
    "1,33,3,6,15,26,28,51,58,59,43": ("Android", "mobile"),
    "1,121,3,6,15,119,252,95,44,46": ("macOS/iOS", "workstation"),
    "1,3,6,12,15,28,42": ("Linux/embedded", "embedded"),
    "1,3,6,15,28,33": ("embedded/RTOS", "embedded"),
    "1,3,6,42,51,54,58,59": ("printer firmware", "printer"),
}


class DhcpHit(TypedDict, total=False):
    os: str
    device_class: str
    confidence: int
    vendor_class: str
    param_request_list: str


def _prl_string(obs: dict[str, Any]) -> Optional[str]:
    prl = obs.get("param_req_list") or obs.get("option55") or obs.get("prl")
    if prl is None:
        return None
    if isinstance(prl, str):
        # accept "1,3,6,15" or "1 3 6 15"
        nums = [p for p in prl.replace(" ", ",").split(",") if p.strip().isdigit()]
    elif isinstance(prl, (list, tuple)):
        nums = [str(int(x)) for x in prl if str(x).strip().lstrip("-").isdigit()]
    else:
        return None
    return ",".join(nums) if nums else None


def classify(obs: dict[str, Any]) -> Optional[DhcpHit]:
    """Classify a DHCP fingerprint observation into OS / device class."""
    hit: DhcpHit = {}

    vci = obs.get("vendor_class") or obs.get("option60") or obs.get("vci")
    if isinstance(vci, str) and vci.strip():
        hit["vendor_class"] = vci.strip()
        low = vci.lower()
        for needle, (os_name, cls) in _VCI_RULES:
            if needle.lower() in low:
                hit["os"] = os_name
                hit["device_class"] = cls
                hit["confidence"] = 70
                break

    prl = _prl_string(obs)
    if prl:
        hit["param_request_list"] = prl
        sig = _PRL_SIGNATURES.get(prl)
        if sig is not None:
            # A matched PRL signature is strong; let it set/raise confidence.
            hit["os"] = sig[0]
            hit["device_class"] = sig[1]
            hit["confidence"] = max(hit.get("confidence", 0), 80)
        elif "os" not in hit:
            # Unknown PRL but we still saw DHCP: soft, low-confidence default.
            hit["device_class"] = "host"
            hit["confidence"] = 25

    if not hit:
        return None
    hit.setdefault("confidence", 30)
    return hit
