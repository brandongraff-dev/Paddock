"""Unit tests for the passive fingerprinters: OUI, mDNS/SSDP, DHCP."""
from __future__ import annotations

from app.fingerprint import device as device_mod
from app.fingerprint import dhcp, mdns, oui


# --------------------------------------------------------------------------- #
# OUI -> vendor
# --------------------------------------------------------------------------- #

def test_oui_resolves_known_ot_vendor():
    hit = oui.lookup("00:1b:1b:aa:bb:cc")
    assert hit is not None
    assert hit["vendor"] == "Siemens"
    assert hit["role"] == "ot"
    assert hit["type"] == "plc"


def test_oui_resolves_iot_vendor_any_case_and_separator():
    assert oui.vendor_for("AC-CC-8E-11-22-33") == "Axis Communications"
    assert oui.vendor_for("001b78112233") == "Hewlett-Packard"


def test_oui_unknown_prefix_returns_none():
    assert oui.lookup("de:ad:be:ef:00:01") is None


def test_locally_administered_mac_is_detected():
    # second nibble 2/6/a/e => locally administered (randomized) MAC
    assert oui.is_locally_administered("02:11:22:33:44:55") is True
    assert oui.is_locally_administered("00:1b:1b:00:00:10") is False


def test_normalize_mac_rejects_non_mac():
    assert oui.normalize_mac("not-a-mac") is None
    assert oui.normalize_mac("00:1b:1b:00:00:10") == "00:1b:1b:00:00:10"


# --------------------------------------------------------------------------- #
# mDNS / SSDP / UPnP -> device type
# --------------------------------------------------------------------------- #

def test_mdns_printer():
    hit = mdns.classify({"service": "_ipp._tcp.local", "name": "HP LaserJet"})
    assert hit["type"] == "printer"
    assert hit["role"] == "iot"


def test_ssdp_onvif_camera():
    hit = mdns.classify({
        "server": "Linux/4.9 UPnP/1.0 Axis/9.80",
        "st": "urn:schemas-onvif-org:device:NetworkVideoTransmitter:1",
    })
    assert hit["type"] == "camera"
    assert hit["role"] == "iot"
    assert hit["vendor"] == "Axis Communications"


def test_upnp_model_extraction_and_vendor():
    hit = mdns.classify({
        "service": "_hap._tcp.local",
        "manufacturer": "ecobee",
        "model_name": "ecobee3 lite",
    })
    assert hit["role"] == "iot"
    assert hit["vendor"] == "ecobee"
    assert hit["model"] == "ecobee3 lite"


# --------------------------------------------------------------------------- #
# DHCP fingerprint -> OS / class
# --------------------------------------------------------------------------- #

def test_dhcp_vendor_class_windows():
    hit = dhcp.classify({"vendor_class": "MSFT 5.0"})
    assert hit["os"] == "Windows"
    assert hit["device_class"] == "workstation"


def test_dhcp_prl_signature_android():
    hit = dhcp.classify({"param_req_list": "1,33,3,6,15,26,28,51,58,59,43"})
    assert hit["os"] == "Android"
    assert hit["device_class"] == "mobile"
    assert hit["confidence"] >= 80


def test_dhcp_unknown_prl_soft_default():
    hit = dhcp.classify({"param_req_list": [7, 8, 9]})
    assert hit["device_class"] == "host"
    assert hit["confidence"] < 50


# --------------------------------------------------------------------------- #
# Fusion: a device fused from multiple signals
# --------------------------------------------------------------------------- #

def test_device_fuses_oui_and_mdns():
    obs = [
        {"kind": "mdns", "src_ip": "10.0.0.60", "src_mac": "00:1b:78:00:00:60",
         "service": "_ipp._tcp.local", "name": "HP OfficeJet"},
    ]
    devices = device_mod.fingerprint_devices(obs)
    assert len(devices) == 1
    d = devices[0]
    assert d.role == "iot"
    assert d.type == "printer"
    assert d.vendor == "Hewlett-Packard"
    assert d.primary_ip == "10.0.0.60"
    assert d.is_device is True
