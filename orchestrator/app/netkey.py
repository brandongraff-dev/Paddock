"""Canonical client-address keys for rate limiting.

A limiter keyed on the raw textual address is trivially bypassed: an IPv6 host
owns a whole /64 (privacy extensions hand out a fresh address per connection),
and ``::ffff:203.0.113.9`` is the same client as ``203.0.113.9``. Every
per-client limiter in the public / token surface keys on :func:`client_key`.
"""
from __future__ import annotations

import ipaddress
import time
from collections import deque


def client_key(ip: str | None) -> str:
    """IPv4 as-is; IPv4-mapped IPv6 as IPv4; other IPv6 collapsed to its /64."""
    if not ip:
        return "unknown"
    try:
        a = ipaddress.ip_address(ip.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return "invalid"
    if a.version == 6:
        if a.ipv4_mapped is not None:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False).network_address) + "/64"
    return str(a)


class SlidingWindowLimiter:
    """At most ``limit`` hits per ``window_s`` per key.

    Memory is bounded: reads never create keys, expired keys are swept when the
    table is full, and only if that is not enough are the OLDEST-ACTIVE keys
    dropped (so a spray of fresh keys cannot clear a standing lockout, which is
    always among the most recently active)."""

    def __init__(self, limit: int, window_s: float, *, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}

    def _live(self, key: str, now: float) -> deque[float] | None:
        q = self._hits.get(key)
        if q is None:
            return None
        while q and now - q[0] > self.window_s:
            q.popleft()
        if not q:
            self._hits.pop(key, None)
            return None
        return q

    def blocked(self, key: str, now: float | None = None) -> bool:
        q = self._live(key, time.monotonic() if now is None else now)
        return q is not None and len(q) >= self.limit

    def _make_room(self, now: float) -> None:
        for k in list(self._hits):
            self._live(k, now)
        if len(self._hits) < self.max_keys:
            return
        # Still full of live keys: drop the ones with the FEWEST recent hits
        # first (a lockout has the most), oldest first among equals.
        victims = sorted(self._hits, key=lambda k: (len(self._hits[k]), self._hits[k][-1]))
        for k in victims[: max(1, self.max_keys // 10)]:
            self._hits.pop(k, None)

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record a hit. Returns False when the key is over its limit."""
        now = time.monotonic() if now is None else now
        q = self._live(key, now)
        if q is not None and len(q) >= self.limit:
            return False
        if q is None:
            if len(self._hits) >= self.max_keys:
                self._make_room(now)
            q = self._hits.setdefault(key, deque())
        q.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()
