"""Ship observation batches to the Paddock server, surviving outages.

* ``POST {server}/ingest`` with ``Authorization: Bearer <sensor credential>``,
  body gzip-compressed JSON.
* Every batch gets a ``batch_id`` when it is cut. The id travels with the
  batch through the buffer and every retry, and the server applies a given id
  once, so a retry after a timeout (the server processed it, the reply was
  lost) never double counts.
* A failed delivery goes to the bounded on-disk :class:`Outbox` (oldest
  evicted first). After a failure the shipper backs off exponentially (with
  jitter, so a hundred sensors do not stampede a recovering server) and, while
  backing off, buffers without touching the network so the capture loop is
  never blocked. The buffer drains oldest-first when the server answers again.
* Standard library only, so the sensor runs on a Raspberry Pi or a router.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable

from . import __version__
from .buffer import Outbox

log = logging.getLogger("paddock_sentry.ship")

# HTTP answers that retrying the same bytes can never fix.
_FATAL_AUTH = (401, 403)          # bad / revoked credential: stop, tell the operator
_POISON = (400, 413, 422)         # the server will never accept this batch: drop it
MAX_BACKOFF_S = 300.0


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
        clock: Callable[[], float] = time.monotonic,
        compress: bool = True,
    ) -> None:
        self.url = server.rstrip("/") + "/ingest"
        self.token = token
        self.sensor_id = sensor_id
        self.site = site
        self.box = Outbox(outbox, outbox_max_bytes)
        self.retries = retries
        self.timeout = timeout
        self.compress = compress
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.RLock()
        self._fail_n = 0
        self._retry_at = 0.0
        self.auth_failed: int | None = None     # 401/403 seen: credential revoked or wrong
        self.last_upload_ts: float | None = None
        self.last_upload_ok: bool | None = None
        self.stats = {"sent": 0, "failed": 0, "spooled": 0, "drained": 0, "dropped": 0, "rejected": 0}

    # ------------------------------------------------------------------ #
    # wire
    # ------------------------------------------------------------------ #
    def _post(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.compress:
            req.data = gzip.compress(body, compresslevel=6)
            req.add_header("Content-Encoding", "gzip")
        req.add_header("User-Agent", f"paddock-sentry/{__version__} (+passive sensor)")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed server URL
            if resp.status >= 300:
                raise urllib.error.HTTPError(self.url, resp.status, "bad status", resp.headers, None)

    def _envelope(self, batch: dict[str, Any]) -> dict[str, Any]:
        return {
            "batch_id": batch.get("batch_id") or uuid.uuid4().hex,
            "observations": batch.get("observations", []),
            "sensor": {
                "id": self.sensor_id,
                "site": self.site,
                "version": __version__,
                "window": batch.get("window"),
            },
        }

    # ------------------------------------------------------------------ #
    # delivery
    # ------------------------------------------------------------------ #
    def _backing_off(self) -> bool:
        return self._clock() < self._retry_at

    def _note_failure(self) -> None:
        self._fail_n += 1
        delay = min(MAX_BACKOFF_S, 5.0 * 2 ** (self._fail_n - 1)) * random.uniform(0.75, 1.25)
        self._retry_at = self._clock() + delay
        self.last_upload_ok = False

    def _note_success(self) -> None:
        self._fail_n = 0
        self._retry_at = 0.0
        self.auth_failed = None
        self.last_upload_ok = True
        self.last_upload_ts = time.time()

    def send(self, batch: dict[str, Any]) -> bool:
        """Deliver one batch (and any backlog). Returns True if delivered now."""
        payload = self._envelope(batch)
        with self._lock:
            if self._backing_off():
                self._spool(payload)
                return False
            for attempt in range(self.retries):
                try:
                    self._post(payload)
                except (urllib.error.URLError, OSError, TimeoutError) as exc:
                    code = getattr(exc, "code", None)
                    if code in _FATAL_AUTH:
                        # Not transient: retrying or spooling won't help.
                        self.auth_failed = code
                        log.error("server rejected the sensor credential (HTTP %s): the sensor was "
                                  "revoked or the credential is wrong; re-enroll it", code)
                        self.stats["failed"] += 1
                        return False
                    if code in _POISON:
                        log.error("server rejected batch (HTTP %s); dropping it", code)
                        self.stats["rejected"] += 1
                        return False
                    log.warning("ship attempt %d failed: %s", attempt + 1, exc)
                    if attempt + 1 < self.retries:
                        self._sleep(min(30.0, 2.0 ** attempt))
                    continue
                self.stats["sent"] += 1
                self._note_success()
                self.drain_locked()
                return True
            self.stats["failed"] += 1
            self._note_failure()
            self._spool(payload)
            return False

    # ------------------------------------------------------------------ #
    # buffer
    # ------------------------------------------------------------------ #
    def _spool(self, payload: dict[str, Any]) -> None:
        evicted = self.box.put(payload)
        self.stats["spooled"] += 1
        self.stats["dropped"] += evicted

    def drain(self, limit: int = 50, *, force: bool = False) -> int:
        """Re-send buffered batches oldest-first; stop at the first failure.
        ``force`` ignores the backoff (used by the heartbeat once the server
        has just answered)."""
        with self._lock:
            if self._backing_off() and not force:
                return 0
            return self.drain_locked(limit)

    def drain_locked(self, limit: int = 50) -> int:
        sent = 0
        for path in self.box.files()[:limit]:
            payload = self.box.read(path)
            if payload is None:
                continue
            try:
                self._post(payload)
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                code = getattr(exc, "code", None)
                if code in _POISON:
                    self.box.delete(path)
                    self.stats["rejected"] += 1
                    continue
                if code in _FATAL_AUTH:
                    self.auth_failed = code
                else:
                    self._note_failure()
                break
            self.box.delete(path)
            sent += 1
            self._note_success()
        self.stats["drained"] += sent
        return sent

    @property
    def pending(self) -> int:
        return len(self.box)

    def health(self) -> dict[str, Any]:
        """Buffer / upload counters for the heartbeat."""
        return {
            "buffer_fill_pct": self.box.fill_pct(),
            "buffer_bytes": self.box.size(),
            "buffer_batches": len(self.box),
            "batches_dropped": self.stats["dropped"],
            "last_upload_ts": self.last_upload_ts,
            "last_upload_ok": self.last_upload_ok,
        }
