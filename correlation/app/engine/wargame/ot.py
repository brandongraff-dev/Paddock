"""OT / ICS conduit modelling for Wargame (IEC 62443-3-2 zones and conduits).

This is *conduit analysis*, not interaction: given the L4 ports a rule set
allows and whether the enforcing firewall can inspect industrial protocol
function codes (DPI), it answers one question honestly: can a *write* reach
the OT device across this conduit?

The key point: an L3/L4-only firewall that allows an industrial port allows
**every** function code on it. A plant that believes a conduit is
"read-only" is only right if a DPI-capable firewall enforces that. Without
DPI the conduit cannot be proved read-only, so the verdict is write-possible
and conditional.

Pure, deterministic, stdlib only. Nothing here sends traffic or builds
protocol messages; function-code tables are classification data only.

Limits (see docs/WARGAME.md section 11): serial/fieldbus links, cellular
modems, USB and proprietary PLC internals are outside the model. Only IP
reachability and what a firewall can enforce are represented.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .model import PortRange, Proto, Route

#: Industrial services by well-known port.
INDUSTRIAL_SERVICES: dict[str, PortRange] = {
    "modbus": PortRange.single(Proto.TCP, 502),
    "s7comm": PortRange.single(Proto.TCP, 102),
    "dnp3": PortRange.single(Proto.TCP, 20000),
    "ethernet_ip": PortRange.single(Proto.TCP, 44818),
    "cip_io": PortRange.single(Proto.UDP, 2222),
    "bacnet": PortRange.single(Proto.UDP, 47808),
    "opc_ua": PortRange.single(Proto.TCP, 4840),
    "iec104": PortRange.single(Proto.TCP, 2404),
    "profinet": PortRange(Proto.UDP, 34962, 34964),
}


def is_industrial(proto: Proto, port: int) -> Optional[str]:
    """Protocol name if ``(proto, port)`` is an industrial service, else None."""
    for name, pr in INDUSTRIAL_SERVICES.items():
        if pr.contains(proto, port):
            return name
    return None


class Access(str, Enum):
    READ = "read"
    WRITE = "write"
    CONFIG = "config"


#: Function codes by access class. APPROXIMATE: a coarse classification for
#: policy reasoning, not a full protocol spec. Vendor-specific and
#: user-defined codes are not listed, and a DPI product may classify
#: differently. Treat as guidance for what a DPI rule would need to match.
FUNCTION_CLASSES: dict[str, dict[Access, tuple[int, ...]]] = {
    # Modbus/TCP public function codes.
    "modbus": {
        Access.READ: (1, 2, 3, 4),
        Access.WRITE: (5, 6, 15, 16),
        Access.CONFIG: (8, 43),
    },
    # DNP3 application-layer codes: read=1; write/select/operate/direct
    # operate = 2 is write; control codes 3,4,5,6 (select, operate, direct
    # operate, direct operate no-ack).
    "dnp3": {
        Access.READ: (1,),
        Access.WRITE: (3, 4, 5, 6),
    },
    # S7comm is very coarse: ROSCTR job functions 0x04 read var, 0x05 write
    # var. Other functions (download/upload, PLC control) are not modelled.
    "s7comm": {
        Access.READ: (0x04,),
        Access.WRITE: (0x05,),
    },
}


@dataclass
class ConduitVerdict:
    protocol: str
    write_possible: bool
    enforced_read_only: bool
    conditional: bool
    note: str


def assess_conduit(
    *,
    proto: Proto,
    port: int,
    dpi_capable: bool,
    allowed_function_access: Optional[set[Access]] = None,
) -> Optional[ConduitVerdict]:
    """Assess whether a write is possible across an allowed industrial port."""
    name = is_industrial(proto, port)
    if name is None:
        return None

    if not dpi_capable:
        return ConduitVerdict(
            protocol=name,
            write_possible=True,
            enforced_read_only=False,
            conditional=True,
            note=(
                f"{name}: an L3/L4 rule cannot restrict function codes, so "
                "allowing the port allows every function including writes. "
                "The conduit cannot be proved read-only without a "
                "DPI-capable firewall enforcing it."
            ),
        )

    if allowed_function_access is None:
        return ConduitVerdict(
            protocol=name,
            write_possible=True,
            enforced_read_only=False,
            conditional=True,
            note=(
                f"{name}: firewall is DPI-capable but the permitted function "
                "access is unknown; write cannot be ruled out."
            ),
        )

    if Access.WRITE in allowed_function_access or Access.CONFIG in allowed_function_access:
        return ConduitVerdict(
            protocol=name,
            write_possible=True,
            enforced_read_only=False,
            conditional=False,
            note=f"{name}: DPI policy permits write or configuration function codes.",
        )

    return ConduitVerdict(
        protocol=name,
        write_possible=False,
        enforced_read_only=True,
        conditional=False,
        note=(
            f"{name}: DPI policy limits the conduit to read function codes "
            "(as configured; assumes the DPI classification is accurate)."
        ),
    )


def _within(inner: PortRange, outer: PortRange) -> bool:
    return (
        outer.proto.matches(inner.proto)
        and inner.proto is not Proto.ANY
        and outer.low <= inner.low
        and inner.high <= outer.high
    )


def annotate_route(
    route: Route, *, dpi_capable_rulesets: set[str] = frozenset()  # type: ignore[assignment]
) -> list[str]:
    """Plain-text notes for each industrial hop of a route.

    A hop's gating ruleset is taken from ``hop.rule_ref``: it counts as
    DPI-capable when ``rule_ref`` equals a ruleset id in
    ``dpi_capable_rulesets`` or starts with ``<id>:`` or ``<id>/``. The
    function-access policy is not known at this level, so a DPI-capable
    ruleset yields a conditional note rather than a read-only claim.
    """
    notes: list[str] = []
    for hop in route.hops:
        if hop.port is None:
            continue
        name = next(
            (n for n, pr in INDUSTRIAL_SERVICES.items() if _within(hop.port, pr)),
            None,
        )
        if name is None:
            continue
        ref = hop.rule_ref
        dpi = any(
            ref == rs or ref.startswith(rs + ":") or ref.startswith(rs + "/")
            for rs in dpi_capable_rulesets
        )
        verdict = assess_conduit(
            proto=hop.port.proto,
            port=hop.port.low,
            dpi_capable=dpi,
        )
        if verdict is None:  # pragma: no cover - guarded by _within
            continue
        ruleset = ref or "unreferenced rule"
        notes.append(
            f"{hop.src} -> {hop.dst} ({name}, via {ruleset}): "
            + (
                "write to the OT device is possible; "
                if verdict.write_possible
                else "write not possible; "
            )
            + verdict.note
        )
    return notes
