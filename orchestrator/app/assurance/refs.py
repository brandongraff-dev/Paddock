"""Node references: the one vocabulary every builder, loader and API shares.

  internet            the public internet (one per tenant; never an assets row)
  asset:<uuid>        an assets row (cloud instance/db/lb, device, host)
  agent:<uuid>        a managed host known only through its Paddock agent (a fleet_agents row;
                      kind ``host``). Replaced by ``asset:<uuid>`` only when the agent is
                      corroborated as one cloud instance (docs/ASSURANCE_P2.md E3)
  ip:<addr>           a host with no asset row (canonical, compressed, lowercase)
  cidr:<net>          a network (security-group source ranges, declared zones)
  estate:<acct>:<region>:<vpc|none>
                      the RESIDUAL of a cloud account/region/VPC: whatever may sit in a referenced
                      security group that no builder models (Lambda, Fargate, endpoints, ...). Never
                      covered, never CIDR-expanded, never an asset (docs/ASSURANCE_P2_1.md D31)

Refs are canonical strings so equal things compare equal across builders.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Optional

INTERNET = "internet"
KINDS = ("internet", "host", "cloud_instance", "cloud_db", "cloud_lb", "device", "ip", "cidr", "estate")
_PREFIXES = ("asset", "agent", "ip", "cidr", "estate")
_MAX_REF = 128


class RefError(ValueError):
    pass


def asset_ref(asset_id: "uuid.UUID | str") -> str:
    try:
        return f"asset:{uuid.UUID(str(asset_id))}"
    except ValueError as exc:
        raise RefError(f"bad asset id {asset_id!r}") from exc


def agent_ref(agent_id: "uuid.UUID | str") -> str:
    """``agent:<uuid>``: canonical (lowercase, hyphenated) like ``asset_ref``."""
    try:
        return f"agent:{uuid.UUID(str(agent_id))}"
    except ValueError as exc:
        raise RefError(f"bad agent id {agent_id!r}") from exc


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


_ESTATE_ACCOUNT_RE = re.compile(r"[0-9]{12}")
_ESTATE_REGION_RE = re.compile(r"[a-z]{2,4}(?:-[a-z]+)+-[0-9]{1,2}")
_ESTATE_VPC_RE = re.compile(r"vpc-[0-9a-f]{1,32}")


def estate_ref(account: str, region: str, vpc: Optional[str]) -> str:
    """``estate:<12-digit account>:<region>:<vpc-id|none>``: strict (no case folding, no whitespace,
    ASCII digits only) so two builders can never mint two spellings of one residual. ``vpc`` of
    ``None``, ``''`` or ``'none'`` is the account/region residual with no VPC."""
    if not (isinstance(account, str) and _ESTATE_ACCOUNT_RE.fullmatch(account)):
        raise RefError(f"bad estate account {account!r}")
    if not (isinstance(region, str) and len(region) <= 32 and _ESTATE_REGION_RE.fullmatch(region)):
        raise RefError(f"bad estate region {region!r}")
    if vpc is None or vpc in ("", "none"):
        vpc = "none"
    elif not (isinstance(vpc, str) and _ESTATE_VPC_RE.fullmatch(vpc)):
        raise RefError(f"bad estate vpc {vpc!r}")
    return f"estate:{account}:{region}:{vpc}"


def parse_ref(ref: str) -> tuple[str, Optional[str]]:
    """``(prefix, value)``; ``('internet', None)`` for the internet. Raises ``RefError``."""
    if not isinstance(ref, str) or not ref or len(ref) > _MAX_REF:
        raise RefError("bad ref")
    if ref == INTERNET:
        return INTERNET, None
    prefix, sep, value = ref.partition(":")
    if not sep or prefix not in _PREFIXES or not value:
        raise RefError(f"bad ref {ref!r}")
    if prefix == "estate":
        parts = value.split(":")
        if len(parts) != 3:
            raise RefError(f"bad ref {ref!r}")
        canon = estate_ref(*parts)
    else:
        canon = {"asset": asset_ref, "agent": agent_ref, "ip": ip_ref, "cidr": cidr_ref}[prefix](value)
    if canon != ref:
        raise RefError(f"non-canonical ref {ref!r} (expected {canon!r})")
    return prefix, value


def is_estate_ref(ref: object) -> bool:
    """True for any ``estate:`` ref (valid or not): the prefix alone decides where a node may carry coverage,
    facts or labels, so a malformed spelling cannot slip past a check that only looks at valid refs."""
    return isinstance(ref, str) and ref.startswith("estate:")


def is_valid_ref(ref: str) -> bool:
    try:
        parse_ref(ref)
        return True
    except RefError:
        return False


_LABEL_TAG_RE = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")


def is_valid_tag(tag: str) -> bool:
    return bool(_LABEL_TAG_RE.match(tag or ""))
