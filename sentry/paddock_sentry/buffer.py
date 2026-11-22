"""Bounded on-disk upload buffer.

Batches that cannot be delivered wait here (gzip JSON, one file each) until
the server is reachable again. The buffer has a hard byte cap: when it would
overflow, the **oldest** batches are evicted first, because the newest data is
the most useful and a sensor that is offline for weeks must not fill the disk
of a Raspberry Pi. Eviction is counted (``dropped``) and reported in the
heartbeat so the dashboard can say "buffer overflowed".
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("paddock_sentry.buffer")


class Outbox:
    def __init__(self, path: str | os.PathLike[str] | None, max_bytes: int = 256 * 1024 * 1024) -> None:
        self.path = Path(path) if path else None
        self.max_bytes = max_bytes
        self.dropped = 0
        self._last_ns = 0
        if self.path:
            self.path.mkdir(parents=True, exist_ok=True)
            for stale in self.path.glob("*.tmp"):  # a crash mid-write
                stale.unlink(missing_ok=True)

    # -- inspection ------------------------------------------------------- #
    def files(self) -> list[Path]:
        return sorted(self.path.glob("*.json.gz")) if self.path else []

    def size(self) -> int:
        total = 0
        for f in self.files():
            try:
                total += f.stat().st_size
            except OSError:
                pass
        return total

    def __len__(self) -> int:
        return len(self.files())

    def fill_pct(self) -> float:
        return round(100.0 * self.size() / self.max_bytes, 1) if self.max_bytes > 0 else 0.0

    # -- mutation --------------------------------------------------------- #
    def put(self, payload: dict[str, Any]) -> int:
        """Store a payload; returns how many batches were evicted to fit."""
        if not self.path:
            self.dropped += 1
            return 1
        # strictly increasing names keep oldest-first order even within one tick
        ns = max(time.time_ns(), self._last_ns + 1)
        self._last_ns = ns
        final = self.path / f"{ns:020d}.json.gz"
        tmp = self.path / f"{ns:020d}.tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"))
        os.replace(tmp, final)
        return self._enforce_cap()

    def _enforce_cap(self) -> int:
        files = self.files()
        sizes = {}
        for f in files:
            try:
                sizes[f] = f.stat().st_size
            except OSError:
                sizes[f] = 0
        total = sum(sizes.values())
        evicted = 0
        while files and total > self.max_bytes:
            victim = files.pop(0)  # oldest first
            total -= sizes[victim]
            victim.unlink(missing_ok=True)
            evicted += 1
        self.dropped += evicted
        if evicted:
            log.warning("upload buffer full (cap %d bytes): dropped %d oldest batch(es)",
                        self.max_bytes, evicted)
        return evicted

    def read(self, path: Path) -> dict[str, Any] | None:
        """Load one buffered payload; a corrupt file is removed and skipped."""
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, EOFError, ValueError):
            log.warning("discarding unreadable buffered batch %s", path.name)
            path.unlink(missing_ok=True)
            return None

    def delete(self, path: Path) -> None:
        path.unlink(missing_ok=True)
