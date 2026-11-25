"""v2 host collectors. ``collect_all(ctx)`` is the one entry point (Python 3.8 syntax only).

Each collector is ``collect(ctx) -> Section`` (see :mod:`base`); every parser is a pure
function over text. A collector that raises, overruns its budget or returns a malformed
Section becomes ``error(exception|timeout)``: one broken collector never blocks the post.
"""
import time

from . import base, firewall, health, listeners, patch, sshd
from .base import SCHEMA, error, payload_bytes, validate_section
from ..runner import CollectorTimeout

COLLECTOR_VERSIONS = {"sshd": "1", "listeners": "1", "firewall": "1", "patch": "1", "self": "1"}
SECTION_NAMES = ("sshd", "listeners", "firewall", "patch", "self")
_DATA_COLLECTORS = (("sshd", sshd.collect), ("listeners", listeners.collect),
                    ("firewall", firewall.collect), ("patch", patch.collect))

__all__ = ["collect_all", "payload_bytes", "COLLECTOR_VERSIONS", "SECTION_NAMES", "SCHEMA",
           "base", "fwmodel"]


def _run_one(ctx, name, fn, budget):
    start = time.monotonic()
    if budget <= 1:
        sec = error("timeout", "%s: total budget exhausted" % name)
    else:
        ctx.set_deadline(budget)
        try:
            sec = fn(ctx)
            validate_section(sec)
        except CollectorTimeout:
            sec = error("timeout", "%s: collector budget exhausted" % name)
        except Exception as exc:  # noqa: BLE001 - a collector bug must not stop the post
            sec = error("exception", "%s: %s" % (name, type(exc).__name__))
        finally:
            ctx.clear_deadline()
    ms = int((time.monotonic() - start) * 1000)
    return sec, {"status": sec["s"], "ms": ms, "reason": sec.get("reason")}


def collect_all(ctx):
    """Run every collector and return ``{"schema": 2, "collected_at", "sections": {...}}``."""
    collected_at = ctx.now_iso()
    started = time.monotonic()
    sections = {}
    ctx.stats = {}
    for name, fn in _DATA_COLLECTORS:
        left = ctx.total_budget_s - (time.monotonic() - started)
        sec, stat = _run_one(ctx, name, fn, min(ctx.collector_budget_s, left))
        sections[name] = sec
        ctx.stats[name] = stat
    ctx.cache["data_bytes"] = len(payload_bytes(
        {"schema": SCHEMA, "collected_at": collected_at, "sections": sections}))
    sec, _stat = _run_one(ctx, "self", health.collect, 30)
    sections["self"] = sec
    return {"schema": SCHEMA, "collected_at": collected_at, "sections": sections}
