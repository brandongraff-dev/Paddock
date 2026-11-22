"""Heartbeat: the sensor's only telemetry, and exactly what it contains.

Every ``interval`` seconds the sensor POSTs ``{server}/heartbeat`` with:

* ``version`` and the NIC list it enrolled with (name, link up, speed, MAC),
* counters about itself: packets seen, packets dropped by the kernel/NIC,
  flows dropped, upload-buffer fill and eviction counts, last upload time,
  uptime, and its wall clock (so the server can show clock skew).

It never contains traffic, addresses of observed devices, or anything about
the host beyond that. The server answers with its clock and the interval. A
successful heartbeat also nudges the shipper to drain its buffer, so a sensor
on a quiet link catches up as soon as the server is reachable again.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import __version__, netif
from .ship import Shipper

log = logging.getLogger("paddock_sentry.health")


@dataclass
class RunStats:
    """Cumulative counters for the heartbeat (the aggregator resets per window)."""
    started: float = field(default_factory=time.time)
    packets_seen: int = 0
    flows_dropped: int = 0
    flows_seen: int = 0
    nic_drops_start: int | None = None

    def add_window(self, window: dict[str, Any]) -> None:
        self.packets_seen += int(window.get("packets") or 0)
        self.flows_seen += int(window.get("flows") or 0)
        self.flows_dropped += int(window.get("dropped_flows") or 0)


class Heartbeat:
    def __init__(self, server: str, credential: str, shipper: Shipper, stats: RunStats, *,
                 iface: str | None = None, interval: float = 60.0, timeout: float = 10.0,
                 sysfs: str = netif.SYSFS) -> None:
        self.url = server.rstrip("/") + "/heartbeat"
        self.credential = credential
        self.shipper = shipper
        self.stats = stats
        self.iface = iface
        self.interval = interval
        self.timeout = timeout
        self.sysfs = sysfs
        self.last_ok: float | None = None
        self.skew_s: float | None = None

    def snapshot(self) -> dict[str, Any]:
        health: dict[str, Any] = {
            "sent_at": round(time.time(), 3),
            "uptime_s": int(time.time() - self.stats.started),
            "packets_seen": self.stats.packets_seen,
            "flows_dropped": self.stats.flows_dropped,
            **self.shipper.health(),
        }
        if self.iface:
            health["iface"] = self.iface
            cur = netif.nic_drops(self.iface, self.sysfs)
            if self.stats.nic_drops_start is None:
                self.stats.nic_drops_start = cur
            health["packets_dropped"] = max(0, cur - self.stats.nic_drops_start)
        return {k: v for k, v in health.items() if v is not None}

    def post(self) -> bool:
        body = {"version": __version__, "interfaces": netif.interface_report(), "health": self.snapshot()}
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.credential}")
        req.add_header("User-Agent", f"paddock-sentry/{__version__} (+passive sensor)")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed server URL
                out = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.shipper.auth_failed = exc.code
                log.error("heartbeat rejected (HTTP %s): sensor revoked or credential wrong", exc.code)
            else:
                log.debug("heartbeat failed: HTTP %s", exc.code)
            return False
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            log.debug("heartbeat failed: %s", exc)
            return False
        self.last_ok = time.time()
        server_time = out.get("server_time")
        if isinstance(server_time, (int, float)):
            self.skew_s = round(time.time() - float(server_time), 1)
            if abs(self.skew_s) > 30:
                log.warning("this device's clock is %+.0fs off the server: check NTP", self.skew_s)
        if self.shipper.pending:
            self.shipper.drain(force=True)  # the server just answered: catch up now
        return True

    def run(self, stop: threading.Event, *, sleep: Callable[[float], bool] | None = None) -> None:
        wait = sleep or stop.wait
        while not stop.is_set():
            try:
                self.post()
            except Exception:  # noqa: BLE001 - the heartbeat must never take the sensor down
                log.exception("heartbeat error")
            wait(self.interval)

    def start(self) -> tuple[threading.Thread, threading.Event]:
        stop = threading.Event()
        t = threading.Thread(target=self.run, args=(stop,), name="paddock-sentry-heartbeat", daemon=True)
        t.start()
        return t, stop
