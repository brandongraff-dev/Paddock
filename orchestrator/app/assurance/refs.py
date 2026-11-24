"""Node references: the one vocabulary every builder, loader and API shares.

  internet            the public internet (one per tenant; never an assets row)
  asset:<uuid>        an assets row (cloud instance/db/lb, device, host)
  ip:<addr>           a host with no asset row (canonical, compressed, lowercase)
  cidr:<net>          a network (security-group source ranges, declared zones)

Refs are canonical strings so equal things compare equal across builders.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Optional

INTERNET = "internet"
KINDS = ("internet", "host", "cloud_instance", "cloud_db", "cloud_lb", "device", "ip", "cidr")
_PREFIXES = ("asset", "ip", "cidr")
_MAX_REF = 128


class RefError(ValueError):
    pass


def asset_ref(asset_id: "uuid.UUID | str") -> str:
    try:
        return f"asset:{uuid.UUID(str(asset_id))}"
    except ValueError as exc:
        raise RefError(f"bad asset id {asset_id!r}") from exc


def ip_ref(addr: str) -> str:
    try:
        return f"ip:{ipaddress.ip_address(str(addr).strip().strip('[]')).compressed.lower()}"
    except ValueError as exc:
        raise RefError(f"bad ip {addr!r}") from exc


def cidr_ref(net: str) -> str:
    try:
        return f"cidr:{ipaddress.ip_network(str(net).strip(), strict=False).compressed.lower()}"
    except ValueError as exc:
        raise RefError(f"bad cidr {net!r}") from exc


def parse_ref(ref: str) -> tuple[str, Optional[str]]:
    """``(prefix, value)``; ``('internet', None)`` for the internet. Raises ``RefError``."""
    if not isinstance(ref, str) or not ref or len(ref) > _MAX_REF:
        raise RefError("bad ref")
    if ref == INTERNET:
        return INTERNET, None
    prefix, sep, value = ref.partition(":")
    if not sep or prefix not in _PREFIXES or not value:
        raise RefError(f"bad ref {ref!r}")
    canon = {"asset": asset_ref, "ip": ip_ref, "cidr": cidr_ref}[prefix](value)
    if canon != ref:
        raise RefError(f"non-canonical ref {ref!r} (expected {canon!r})")
    return prefix, value


def is_valid_ref(ref: str) -> bool:
    try:
        parse_ref(ref)
        return True
    except RefError:
        return False


_LABEL_TAG_RE = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")


def is_valid_tag(tag: str) -> bool:
    return bool(_LABEL_TAG_RE.match(tag or ""))
