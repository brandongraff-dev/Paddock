"""Continuous CertStream subscription.

A long-running task — launched from a `passive_ct_watch` job — that
subscribes to the CertStream firehose (wss://certstream.calidog.io),
filters certificates whose SANs touch a scope domain, and emits
`subdomain` + `certificate` assets through the orchestrator in real time.

Reconnects with exponential backoff (max from settings) on any socket
error. The task runs until the main loop cancels it.

This module is unusual: instead of returning a `ModuleResult` once, it
runs forever and pushes directly through the orchestrator for each hit.
We still batch across a small time window to avoid chatter.
"""
from __future__ import annotations

import asyncio
import json
import random
import time
from typing import Any, Iterable

from loguru import logger

try:
    import websockets
    from websockets.exceptions import WebSocketException
except Exception:  # pragma: no cover - import guard
    websockets = None  # type: ignore
    WebSocketException = Exception  # type: ignore

from ..context import ModuleContext


BATCH_FLUSH_SECONDS = 2.0
BATCH_MAX = 200


def _match_domains(all_names: Iterable[str], apex_list: list[str]) -> list[tuple[str, str]]:
    """Return list of (sub, apex) pairs — sub normalized, apex matched."""
    out: list[tuple[str, str]] = []
    for raw in all_names:
        if not raw:
            continue
        name = raw.strip().lower().lstrip("*.").rstrip(".")
        for apex in apex_list:
            if name == apex or name.endswith("." + apex):
                out.append((name, apex))
                break
    return out


def _cert_assets_from_message(
    msg: dict[str, Any], apex_list: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = msg.get("data") or {}
    if (msg.get("message_type") or "") != "certificate_update":
        return [], []
    leaf = data.get("leaf_cert") or {}
    all_domains = leaf.get("all_domains") or []
    pairs = _match_domains(all_domains, apex_list)
    if not pairs:
        return [], []

    serial = (leaf.get("serial_number")
              or leaf.get("fingerprint")
              or f"certstream:{data.get('cert_index','?')}")
    issuer = (leaf.get("issuer") or {}).get("CN") or (leaf.get("issuer") or {}).get("O")
    not_before = leaf.get("not_before")
    not_after = leaf.get("not_after")

    assets: list[dict[str, Any]] = [{
        "kind": "certificate",
        "value": str(serial),
        "source": "certstream",
        "metadata": {
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "names": [n for n, _ in pairs],
        },
    }]
    edges: list[dict[str, Any]] = []
    seen_subs: set[str] = set()
    for sub, apex in pairs:
        if sub in seen_subs:
            continue
        seen_subs.add(sub)
        assets.append({
            "kind": "subdomain",
            "value": sub,
            "source": "certstream",
            "metadata": {"apex": apex},
        })
        edges.append({
            "src_kind": "subdomain", "src_value": sub,
            "dst_kind": "domain", "dst_value": apex,
            "kind": "contains",
        })
        edges.append({
            "src_kind": "certificate", "src_value": str(serial),
            "dst_kind": "subdomain", "dst_value": sub,
            "kind": "issued_for",
        })
    return assets, edges


async def _flush(ctx: ModuleContext, pending: list[dict[str, Any]]) -> None:
    if not pending:
        return
    values = [a["value"] for a in pending]
    kept = set(await ctx.orchestrator.filter_in_scope(values))
    batch = [a for a in pending if a["value"] in kept]
    if batch:
        try:
            await ctx.orchestrator.post_assets(batch)
        except Exception as e:  # noqa: BLE001
            logger.warning("certstream flush post_assets failed: {}", e)


async def watch(
    apex_list: list[str],
    ctx: ModuleContext,
    *,
    stop_event: asyncio.Event | None = None,
) -> int:
    """Run the CertStream subscription until stop_event is set.

    Returns the number of certstream messages observed.
    """
    if websockets is None:
        logger.error("websockets lib not installed; certstream disabled")
        return 0

    apex_list = [a.strip().lower().rstrip(".") for a in apex_list if a]
    if not apex_list:
        return 0

    stop_event = stop_event or asyncio.Event()
    backoff = 1.0
    seen = 0
    pending_assets: list[dict[str, Any]] = []
    last_flush = time.monotonic()

    while not stop_event.is_set():
        try:
            async with websockets.connect(ctx.settings.certstream_url) as ws:
                backoff = 1.0
                while not stop_event.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=BATCH_FLUSH_SECONDS)
                    except asyncio.TimeoutError:
                        raw = None
                    if raw:
                        try:
                            msg = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        seen += 1
                        assets, _edges = _cert_assets_from_message(msg, apex_list)
                        pending_assets.extend(assets)
                    now = time.monotonic()
                    if pending_assets and (
                        len(pending_assets) >= BATCH_MAX
                        or (now - last_flush) >= BATCH_FLUSH_SECONDS
                    ):
                        await _flush(ctx, pending_assets)
                        pending_assets.clear()
                        last_flush = now
        except (WebSocketException, OSError, asyncio.TimeoutError) as e:
            jitter = random.uniform(0, backoff / 2)
            logger.warning("certstream disconnect; reconnecting in {:.1f}s err={}",
                           backoff + jitter, e)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff + jitter)
            except asyncio.TimeoutError:
                pass
            backoff = min(ctx.settings.certstream_backoff_max_s, backoff * 2)
        except Exception as e:  # noqa: BLE001
            logger.error("certstream unexpected error: {}", e)
            backoff = min(ctx.settings.certstream_backoff_max_s, backoff * 2)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass

    # final flush
    await _flush(ctx, pending_assets)
    return seen
