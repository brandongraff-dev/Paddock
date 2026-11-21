"""Ship observation batches to the Paddock server, surviving outages.

* POST ``{server}/ingest`` with ``Authorization: Bearer <sensor token>``.
* Exponential backoff on failure; after the retries the batch is written to a
  bounded on-disk outbox (gzip JSON) and drained oldest-first on the next
  success -- a WAN outage at a store or plant loses no data.
* Standard library only, so the sensor runs on a Raspberry Pi or a router.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import __version__

log = logging.getLogger("paddock_sentry.ship")


class Shipper:
    def __init__(
        self,
        server: str,
        token: str | None,
        *,
        sensor_id: str,
        site: str | None = None,
        outbox: str | os.PathLike[str] | None = None,
        outbox_max_bytes: int = 256 * 1024 * 1024,
        retries: int = 3,
        timeout: float = 20.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = server.rstrip("/") + "/ingest"
        self.token = token
        self.sensor_id = sensor_id
        self.site = site
        self.outbox = Path(outbox) if outbox else None
        self.outbox_max_bytes = outbox_max_bytes
        self.retries = retries
        self.timeout = timeout
        self._sleep = sleep
        self.stats = {"sent": 0, "failed": 0, "spooled": 0, "drained": 0, "dropped": 0}
        if self.outbox:
            self.outbox.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def _post(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", f"paddock-sentry/{__version__} (+passive sensor)")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed server URL
            if resp.status >= 300:
                raise urllib.error.HTTPError(self.url, resp.status, "bad status", resp.headers, None)

    def _envelope(self, batch: dict[str, Any]) -> dict[str, Any]:
        return {
            "observations": batch.get("observations", []),
            "sensor": {
                "id": self.sensor_id,
                "site": self.site,
                "version": __version__,
                "window": batch.get("window"),
            },
        }

    def send(self, batch: dict[str, Any]) -> bool:
        """Deliver one batch (and any backlog). Returns True if delivered now."""
        payload = self._envelope(batch)
        for attempt in range(self.retries):
            try:
                self._post(payload)
                self.stats["sent"] += 1
                self.drain()
                return True
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                code = getattr(exc, "code", None)
                if code in (400, 401, 403, 413):
                    # Not transient: retrying or spooling won't help.
                    log.error("server rejected batch (HTTP %s); check token/sensor config", code)
                    self.stats["failed"] += 1
                    return False
                log.warning("ship attempt %d failed: %s", attempt + 1, exc)
                self._sleep(min(30.0, 2.0 ** attempt))
        self.stats["failed"] += 1
        self._spool(payload)
        return False

    # ------------------------------------------------------------------ #
    def _outbox_files(self) -> list[Path]:
        if not self.outbox:
            return []
        return sorted(self.outbox.glob("*.json.gz"))

    def _spool(self, payload: dict[str, Any]) -> None:
        if not self.outbox:
            self.stats["dropped"] += 1
            return
        path = self.outbox / f"{time.time_ns()}.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.stats["spooled"] += 1
        # Bounded: evict oldest batches past the cap (newest data is most useful).
        files = self._outbox_files()
        total = sum(f.stat().st_size for f in files)
        while files and total > self.outbox_max_bytes:
            victim = files.pop(0)
            total -= victim.stat().st_size
            victim.unlink(missing_ok=True)
            self.stats["dropped"] += 1

    def drain(self, limit: int = 50) -> int:
        """Re-send spooled batches oldest-first; stop at the first failure."""
        sent = 0
        for path in self._outbox_files()[:limit]:
            try:
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    payload = json.load(fh)
                self._post(payload)
            except (urllib.error.URLError, OSError, TimeoutError, ValueError):
                break
            path.unlink(missing_ok=True)
            sent += 1
        self.stats["drained"] += sent
        return sent
