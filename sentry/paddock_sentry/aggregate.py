"""Turn a packet stream into a small, privacy-preserving observation batch.

Per window (default 30 s) the sensor keeps:

* **announcements** (DHCP / mDNS / SSDP) -- deduplicated; these carry the
  device-identity signal (hostname, vendor class, model strings).
* **flow summaries** -- one record per (initiator, responder, proto, server
  port): packet/byte counts, first/last seen, whether a TCP handshake was
  started. No payload. This is what behaviour baselines and the observed
  segmentation map are built from.
* **OT samples** -- for industrial protocols only, the first few packets of a
  flow WITH their payload prefix, because identifying Modbus vs S7 vs BACnet
  needs the header bytes. Nothing else ever leaves the sensor with payload.

Bounded memory: past ``max_flows`` new flows in a window are counted as
``dropped_flows`` rather than tracked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Must stay a superset of otdiscovery/app/fingerprint/otproto.py server ports.
OT_PORTS = frozenset({502, 20000, 47808, 44818, 2222, 102, 4840, 789, 1911, 9600, 2404, 34962, 34963, 34964})
_EPHEMERAL_FLOOR = 32768
_SYN, _ACK = 0x02, 0x10


@dataclass
class _Flow:
    src_ip: str
    dst_ip: str
    src_mac: str | None
    dst_mac: str | None
    proto: str
    dst_port: int
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    syn: bool = False
    ot_samples: int = 0

    def to_obs(self) -> dict[str, Any]:
        return {
            "kind": "flow",
            "proto": self.proto,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_mac": self.src_mac, "dst_mac": self.dst_mac,
            "dst_port": self.dst_port,
            "packets": self.packets, "bytes": self.bytes,
            "first_seen": round(self.first, 3), "last_seen": round(self.last, 3),
            "tcp_syn": self.syn,
        }


def orient(obs: dict[str, Any]) -> tuple[bool, int]:
    """Return (src_is_initiator, server_port) for a packet observation.

    TCP SYN without ACK is authoritative. Otherwise the endpoint on a
    well-known (OT or < 1024) or non-ephemeral port is the server.
    """
    sp, dp = int(obs.get("src_port") or 0), int(obs.get("dst_port") or 0)
    flags = obs.get("tcp_flags")
    if isinstance(flags, int) and flags & _SYN:
        return (not (flags & _ACK)), (dp if not flags & _ACK else sp)
    for port, src_is_init in ((dp, True), (sp, False)):
        if port in OT_PORTS or 0 < port < 1024:
            return src_is_init, port
    if dp < _EPHEMERAL_FLOOR <= sp:
        return True, dp
    if sp < _EPHEMERAL_FLOOR <= dp:
        return False, sp
    return (True, dp) if dp <= sp else (False, sp)


@dataclass
class Aggregator:
    window_s: float = 30.0
    ot_samples_per_flow: int = 3
    max_flows: int = 50_000
    flows: dict[tuple, _Flow] = field(default_factory=dict)
    announcements: dict[tuple, dict[str, Any]] = field(default_factory=dict)
    ot_samples: list[dict[str, Any]] = field(default_factory=list)
    window_start: float | None = None
    dropped_flows: int = 0
    packets_seen: int = 0

    def due(self, now: float) -> bool:
        return self.window_start is not None and now - self.window_start >= self.window_s

    def add(self, ts: float, wire_len: int, obs: dict[str, Any]) -> None:
        if self.window_start is None:
            self.window_start = ts
        self.packets_seen += 1
        kind = obs.get("kind")
        if kind in ("dhcp", "mdns", "ssdp"):
            key = (kind, obs.get("src_mac") or obs.get("mac"),
                   tuple(sorted((k, str(v)) for k, v in obs.items() if k not in ("src_port", "dst_port"))))
            self.announcements.setdefault(key, obs)
            return
        if kind != "packet":
            return

        src_init, server_port = orient(obs)
        if src_init:
            a_ip, b_ip, a_mac, b_mac = obs["src_ip"], obs["dst_ip"], obs.get("src_mac"), obs.get("dst_mac")
        else:
            a_ip, b_ip, a_mac, b_mac = obs["dst_ip"], obs["src_ip"], obs.get("dst_mac"), obs.get("src_mac")
        key = (obs.get("proto"), a_ip, b_ip, server_port)
        fl = self.flows.get(key)
        if fl is None:
            if len(self.flows) >= self.max_flows:
                self.dropped_flows += 1
                return
            fl = _Flow(a_ip, b_ip, a_mac, b_mac, str(obs.get("proto")), server_port, ts, ts)
            self.flows[key] = fl
        fl.packets += 1
        fl.bytes += int(wire_len or 0)
        fl.last = max(fl.last, ts)
        flags = obs.get("tcp_flags")
        if isinstance(flags, int) and flags & _SYN and not flags & _ACK:
            fl.syn = True
        # Sample only packets that carry payload: handshake/ACK packets can't
        # identify a protocol, and would use up the per-flow sample budget.
        if server_port in OT_PORTS and obs.get("payload_hex") and fl.ot_samples < self.ot_samples_per_flow:
            fl.ot_samples += 1
            sample = {k: v for k, v in obs.items() if k != "tcp_flags"}
            self.ot_samples.append(sample)

    def flush(self) -> dict[str, Any]:
        """Return the window's batch and reset."""
        obs: list[dict[str, Any]] = list(self.announcements.values())
        obs += self.ot_samples
        obs += [f.to_obs() for f in self.flows.values()]
        batch = {
            "observations": obs,
            "window": {
                "start": self.window_start,
                "packets": self.packets_seen,
                "flows": len(self.flows),
                "announcements": len(self.announcements),
                "ot_samples": len(self.ot_samples),
                "dropped_flows": self.dropped_flows,
            },
        }
        self.flows.clear()
        self.announcements.clear()
        self.ot_samples.clear()
        self.window_start = None
        self.dropped_flows = 0
        self.packets_seen = 0
        return batch
