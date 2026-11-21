"""Append-only anchoring sinks for the audit chain head.

An *anchor* is a small signed statement ``(tenant_id, max_id, head_hash,
hash_alg, ts)`` published OUTSIDE the database. ``audit.verify()`` compares the
live chain against the latest anchor, which detects what a hash chain alone
cannot: deletion of the newest rows (tail truncation) and a wholesale rewrite
of the chain by someone with database superuser.

Sinks (``AUDIT_ANCHOR_SINKS=file,s3,webhook``):

* :class:`FileAnchorSink`    -- one JSON line per anchor, ``O_APPEND`` + fsync.
  Put the file on a separate volume/host and mark it append-only
  (``chattr +a``) -- the process can otherwise truncate its own file.
* :class:`S3AnchorSink`      -- one object per anchor in an S3-compatible bucket
  with Object Lock (COMPLIANCE mode by default): neither Paddock nor the bucket
  owner can delete or overwrite it until the retention date. Needs the optional
  ``boto3`` dependency (``pip install 'paddock-orchestrator[s3]'``).
* :class:`WebhookAnchorSink` -- POSTs the anchor (HMAC-signed body) to an
  external append-only service (SIEM, transparency log, ticketing). Verification
  can read back through an optional ``..._LATEST_URL``.

This module deliberately knows nothing about how anchors are signed; see
``audit.sign_anchor`` / ``audit.check_anchor``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .config import settings

logger = logging.getLogger(__name__)


class AnchorSinkError(RuntimeError):
    """A sink could not publish or read back an anchor."""


@dataclass
class Anchor:
    tenant_id: str
    max_id: int
    head_hash: str
    hash_alg: str
    ts: str
    v: int = 1
    kid: str | None = None
    sig: str | None = None

    def signed_body(self) -> bytes:
        """Canonical bytes the signature covers (everything except ``sig``)."""
        d = asdict(self)
        d.pop("sig", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Anchor":
        return cls(
            tenant_id=str(d["tenant_id"]),
            max_id=int(d["max_id"]),
            head_hash=str(d["head_hash"]),
            hash_alg=str(d.get("hash_alg") or "sha256"),
            ts=str(d["ts"]),
            v=int(d.get("v", 1)),
            kid=d.get("kid"),
            sig=d.get("sig"),
        )

    def order_key(self) -> tuple[int, str]:
        return (self.max_id, self.ts)


@runtime_checkable
class AnchorSink(Protocol):
    name: str

    async def publish(self, anchor: Anchor) -> dict[str, Any]:
        """Durably record ``anchor``; return a receipt (sink-specific)."""
        ...

    async def latest(self, tenant_id: str) -> Anchor | None:
        """The most recent anchor for ``tenant_id`` (highest max_id), or None."""
        ...


# --------------------------------------------------------------------------- #
# Local append-only file
# --------------------------------------------------------------------------- #

class FileAnchorSink:
    name = "file"

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def _append(self, line: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    async def publish(self, anchor: Anchor) -> dict[str, Any]:
        line = (anchor.to_json() + "\n").encode("utf-8")
        try:
            await asyncio.to_thread(self._append, line)
        except OSError as exc:
            raise AnchorSinkError(f"file sink: {exc}") from exc
        return {"sink": self.name, "path": str(self.path)}

    def _scan(self, tenant_id: str) -> Anchor | None:
        best: Anchor | None = None
        try:
            fh = self.path.open("r", encoding="utf-8")
        except FileNotFoundError:
            return None
        with fh:
            for raw in fh:  # streamed; the file is never loaded whole
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    a = Anchor.from_dict(json.loads(raw))
                except (ValueError, KeyError, TypeError):
                    logger.warning("anchor_file_bad_line", extra={"path": str(self.path)})
                    continue
                if a.tenant_id == tenant_id and (best is None or a.order_key() > best.order_key()):
                    best = a
        return best

    async def latest(self, tenant_id: str) -> Anchor | None:
        try:
            return await asyncio.to_thread(self._scan, tenant_id)
        except OSError as exc:
            raise AnchorSinkError(f"file sink: {exc}") from exc


# --------------------------------------------------------------------------- #
# S3-compatible object storage with Object Lock
# --------------------------------------------------------------------------- #

class S3AnchorSink:
    """One immutable object per anchor: ``<prefix><tenant>/<max_id:020d>-<ts>.json``.

    The bucket must have Object Lock enabled (which implies versioning). Each
    PUT carries ``ObjectLockMode`` + ``ObjectLockRetainUntilDate`` so the anchor
    cannot be deleted/overwritten before retention expires, even by the
    account root in COMPLIANCE mode.
    """

    name = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "paddock/audit-anchors/",
        region: str | None = None,
        endpoint_url: str | None = None,
        retention_days: int = 400,
        lock_mode: str = "COMPLIANCE",
        client: Any = None,
    ) -> None:
        if not bucket:
            raise ValueError("S3 anchor sink needs a bucket")
        self.bucket = bucket
        self.prefix = prefix if prefix.endswith("/") else prefix + "/"
        self.region = region
        self.endpoint_url = endpoint_url
        self.retention_days = int(retention_days)
        self.lock_mode = lock_mode
        self._client_obj = client

    def _client(self) -> Any:
        if self._client_obj is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise AnchorSinkError(
                    "S3 anchor sink needs boto3: pip install 'paddock-orchestrator[s3]'"
                ) from exc
            self._client_obj = boto3.client(
                "s3", region_name=self.region, endpoint_url=self.endpoint_url
            )
        return self._client_obj

    def _key(self, anchor: Anchor) -> str:
        ts = anchor.ts.replace(":", "").replace("-", "").replace("+", "Z")
        return f"{self.prefix}{anchor.tenant_id}/{anchor.max_id:020d}-{ts}.json"

    def _put(self, anchor: Anchor) -> dict[str, Any]:
        body = anchor.to_json().encode("utf-8")
        retain = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        resp = self._client().put_object(
            Bucket=self.bucket,
            Key=self._key(anchor),
            Body=body,
            ContentType="application/json",
            ObjectLockMode=self.lock_mode,
            ObjectLockRetainUntilDate=retain,
            ChecksumAlgorithm="SHA256",
        )
        return {
            "sink": self.name,
            "bucket": self.bucket,
            "key": self._key(anchor),
            "version_id": (resp or {}).get("VersionId"),
            "retain_until": retain.isoformat(),
        }

    async def publish(self, anchor: Anchor) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(self._put, anchor)
        except AnchorSinkError:
            raise
        except Exception as exc:  # noqa: BLE001 - botocore raises many types
            raise AnchorSinkError(f"s3 sink: {exc}") from exc

    def _latest(self, tenant_id: str) -> Anchor | None:
        client = self._client()
        best_key: str | None = None
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=f"{self.prefix}{tenant_id}/"):
            for obj in page.get("Contents", []) or []:
                k = obj["Key"]
                if best_key is None or k > best_key:  # zero-padded max_id sorts
                    best_key = k
        if best_key is None:
            return None
        body = client.get_object(Bucket=self.bucket, Key=best_key)["Body"].read()
        return Anchor.from_dict(json.loads(body))

    async def latest(self, tenant_id: str) -> Anchor | None:
        try:
            return await asyncio.to_thread(self._latest, tenant_id)
        except AnchorSinkError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AnchorSinkError(f"s3 sink: {exc}") from exc


# --------------------------------------------------------------------------- #
# HTTP webhook
# --------------------------------------------------------------------------- #

class WebhookAnchorSink:
    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        secret: str | None = None,
        latest_url: str | None = None,
        timeout: float = 10.0,
        transport: Any = None,
    ) -> None:
        self.url = url
        self.secret = secret
        self.latest_url = latest_url
        self.timeout = timeout
        self._transport = transport  # tests inject an httpx.MockTransport

    def _client(self):
        import httpx

        return httpx.AsyncClient(timeout=self.timeout, transport=self._transport)

    async def publish(self, anchor: Anchor) -> dict[str, Any]:
        body = anchor.to_json().encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Paddock-Event": "audit.anchor"}
        if self.secret:
            mac = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Paddock-Signature"] = f"sha256={mac}"
        try:
            async with self._client() as c:
                resp = await c.post(self.url, content=body, headers=headers)
        except Exception as exc:  # noqa: BLE001
            raise AnchorSinkError(f"webhook sink: {exc}") from exc
        if resp.status_code >= 300:
            raise AnchorSinkError(f"webhook sink: HTTP {resp.status_code}")
        return {"sink": self.name, "status": resp.status_code}

    async def latest(self, tenant_id: str) -> Anchor | None:
        if not self.latest_url:
            return None  # write-only sink
        try:
            async with self._client() as c:
                resp = await c.get(self.latest_url, params={"tenant_id": tenant_id})
        except Exception as exc:  # noqa: BLE001
            raise AnchorSinkError(f"webhook sink: {exc}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code >= 300:
            raise AnchorSinkError(f"webhook sink: HTTP {resp.status_code}")
        data = resp.json()
        return Anchor.from_dict(data) if data else None


# --------------------------------------------------------------------------- #
# Fan-out + construction from settings
# --------------------------------------------------------------------------- #

class MultiAnchorSink:
    """Publish to every sink; read back the newest anchor any sink holds."""

    name = "multi"

    def __init__(self, sinks: list[Any]) -> None:
        self.sinks = list(sinks)

    async def publish(self, anchor: Anchor) -> dict[str, Any]:
        receipts: list[dict[str, Any]] = []
        errors: list[str] = []
        for s in self.sinks:
            try:
                receipts.append(await s.publish(anchor))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{s.name}: {exc}")
        if errors:
            raise AnchorSinkError("; ".join(errors))
        return {"sink": self.name, "receipts": receipts}

    async def latest(self, tenant_id: str) -> Anchor | None:
        best: Anchor | None = None
        for s in self.sinks:
            a = await s.latest(tenant_id)  # a sink error fails verification closed
            if a is not None and (best is None or a.order_key() > best.order_key()):
                best = a
        return best


def sink_from_settings() -> Any | None:
    """Build the configured sink (or None when anchoring is disabled)."""
    names = [n.strip().lower() for n in settings.audit_anchor_sinks.split(",") if n.strip()]
    sinks: list[Any] = []
    for n in names:
        if n == "file":
            sinks.append(FileAnchorSink(settings.audit_anchor_file))
        elif n == "s3":
            sinks.append(
                S3AnchorSink(
                    settings.audit_anchor_s3_bucket or "",
                    prefix=settings.audit_anchor_s3_prefix,
                    region=settings.audit_anchor_s3_region,
                    endpoint_url=settings.audit_anchor_s3_endpoint_url,
                    retention_days=settings.audit_anchor_s3_retention_days,
                    lock_mode=settings.audit_anchor_s3_lock_mode,
                )
            )
        elif n == "webhook":
            if not settings.audit_anchor_webhook_url:
                raise ValueError("AUDIT_ANCHOR_SINKS has webhook but AUDIT_ANCHOR_WEBHOOK_URL is unset")
            sinks.append(
                WebhookAnchorSink(
                    settings.audit_anchor_webhook_url,
                    secret=settings.audit_anchor_webhook_secret,
                    latest_url=settings.audit_anchor_webhook_latest_url,
                )
            )
        else:
            raise ValueError(f"unknown audit anchor sink {n!r} (expected file, s3, webhook)")
    if not sinks:
        return None
    return sinks[0] if len(sinks) == 1 else MultiAnchorSink(sinks)
