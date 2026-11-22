"""Wargame config parsers: real firewall/cloud exports → RuleSet.

Importing this package registers every available vendor parser, so
``parse("aws", data)`` / ``parse("cisco_asa", text)`` work. The vendor
modules are imported defensively so the package still loads while a parser
is being added.
"""
from __future__ import annotations

import contextlib

from .base import (
    ANY_CIDRS,
    AddressObject,
    ConditionalFeature,
    ObjectTable,
    ParseResult,
    ParseWarning,
    Parser,
    ResolvedAddresses,
    ResolvedService,
    RuleSetBinding,
    ServiceObject,
    WarningLevel,
    WELL_KNOWN_SERVICES,
    available_vendors,
    build_rule,
    get_parser,
    normalize_cidrs,
    parse,
    port_range,
    proto_from,
    register,
    service_from_name,
)

# Register vendor parsers. Guarded so the package imports even if one
# module is mid-development; each becomes available once its file lands.
for _mod in ("aws", "cisco_asa", "fortinet", "paloalto"):
    with contextlib.suppress(ImportError):
        __import__(f"{__name__}.{_mod}")

__all__ = [
    "ANY_CIDRS",
    "AddressObject",
    "ConditionalFeature",
    "ObjectTable",
    "ParseResult",
    "ParseWarning",
    "Parser",
    "ResolvedAddresses",
    "ResolvedService",
    "RuleSetBinding",
    "ServiceObject",
    "WarningLevel",
    "WELL_KNOWN_SERVICES",
    "available_vendors",
    "build_rule",
    "get_parser",
    "normalize_cidrs",
    "parse",
    "port_range",
    "proto_from",
    "register",
    "service_from_name",
]
