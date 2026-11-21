"""Redis stream:events subscriber (consumer group ``changewatch``).

A thin helper around ``xreadgroup`` that mirrors the correlation service: it
creates the consumer group, blocks for new events, decodes the payload (either
a single JSON field or flat key/values) and hands it to an async handler, then
acks. Redis is optional — if the library or server is unavailable the helper
logs and returns so the periodic loop keeps running.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Optional

log = logging.getLogger("changewatch.events")

Handler = Callable[[dict[str, Any]], Awaitable[None]]


def decode_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Normalise a stream entry's fields into an event payload dict."""
    for key in ("json", "data"):
        if key in fields and isinstance(fields[key], str):
            try:
                return json.loads(fields[key])
            except json.JSONDecodeError:
                return {}
    return dict(fields)


class EventSubscriber:
    def __init__(
        self,
        redis_url: str,
        stream: str,
        group: str,
        consumer: str,
        handler: Handler,
    ) -> None:
        self.redis_url = redis_url
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.handler = handler
        self._client: Any = None

    async def connect(self) -> bool:
        try:
            import redis.asyncio as aioredis  # type: ignore
        except Exception:
            log.warning("redis library not available; event stream disabled")
            return False
        try:
            # socket_timeout > XREADGROUP block (redis-py >= 6 defaults it to 5s).
            self._client = aioredis.from_url(
                self.redis_url, decode_responses=True, socket_timeout=30
            )
            await self._client.ping()
        except Exception as exc:
            log.warning("redis connect failed: %s; event stream disabled", exc)
            self._client = None
            return False
        await self._ensure_group()
        return True

    async def ping(self) -> bool:
        if self._client is None:
            return False
        try:
            await self._client.ping()
            return True
        except Exception:
            return False

    async def _ensure_group(self) -> None:
        try:
            await self._client.xgroup_create(
                self.stream, self.group, id="$", mkstream=True
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                log.warning("xgroup_create: %s", exc)

    async def run(self, stop: asyncio.Event) -> None:
        if self._client is None:
            return
        log.info(
            "event consumer started: stream=%s group=%s name=%s",
            self.stream, self.group, self.consumer,
        )
        while not stop.is_set():
            try:
                resp = await self._client.xreadgroup(
                    groupname=self.group,
                    consumername=self.consumer,
                    streams={self.stream: ">"},
                    count=16,
                    block=5000,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("xreadgroup failed; backing off")
                await asyncio.sleep(2.0)
                continue
            if not resp:
                continue
            for _stream_name, items in resp:
                for msg_id, fields in items:
                    try:
                        await self.handler(decode_fields(fields))
                    except Exception:
                        log.exception("event %s failed", msg_id)
                    finally:
                        try:
                            await self._client.xack(self.stream, self.group, msg_id)
                        except Exception:
                            log.warning("xack failed for %s", msg_id)

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # pragma: no cover
                pass
            self._client = None
