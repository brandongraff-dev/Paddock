"""Short-term in-process TTL cache.

Used for:
- scope_check responses (60s TTL hard rule)
- idempotent passive-source responses (dedupe bursts of the same query)
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Generic, Optional, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    def __init__(self, ttl_seconds: float, max_entries: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._data: dict[str, tuple[float, T]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[T]:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires, value = entry
            if expires < time.monotonic():
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: T) -> None:
        async with self._lock:
            if len(self._data) >= self.max_entries:
                # Evict the oldest entry — cheap O(n) but bounded by max_entries.
                oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
                self._data.pop(oldest, None)
            self._data[key] = (time.monotonic() + self.ttl, value)

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    def size(self) -> int:
        return len(self._data)
