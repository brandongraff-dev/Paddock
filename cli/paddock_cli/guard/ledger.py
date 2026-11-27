# SPDX-License-Identifier: AGPL-3.0-or-later
"""The local ledger (contract 3.10, D30).

``<state>/ledger.jsonl``: one JSON object per line, at most 4 KB each, rotated at 5 MB
(``ledger.jsonl.1``, one generation), mode 0600, written only through ``files.safe_append``.
It stores check ids, fingerprints, counts and statuses, never file contents, evidence or
secrets: only the fields listed in ``FIELDS`` are kept, each validated against a strict shape.
It is agent-writable and not tamper-evident, so receipts label ledger-derived numbers
``self-reported by the local ledger``.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable

from paddock_cli.guard import GUARD_VERSION, files, textsafe
from paddock_cli.guard.errors import GuardError

EVENTS = frozenset({
    "check", "hook_block", "hook_allow", "hook_ignored_by_agent", "hook_error", "fix", "verify", "pkg",
    "deps", "url", "net_call", "suppression_added", "init",
})
LEDGER_NAME = "ledger.jsonl"
ROTATE_BYTES = 5 * 1024 * 1024
MAX_LINE = 4096
MAX_READ = 6 * 1024 * 1024

_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
_CHECK_ID = re.compile(r"^PGX?-[A-Z0-9-]{3,45}-\d{3}$")
_FP = re.compile(r"^[0-9a-f]{16}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,100}$")
_SHA_OR_REF = re.compile(r"^[0-9a-f]{7,40}$")


def _is_code(v: Any) -> bool:
    return isinstance(v, str) and bool(_CODE.match(v))


def _is_fp_or_check(v: Any) -> bool:
    return isinstance(v, str) and bool(_FP.match(v) or _CHECK_ID.match(v))


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and -10**12 < v < 10**12


# field name -> (validator for one value, list allowed)
FIELDS: dict[str, tuple[Callable[[Any], bool], bool]] = {
    "tier": (_is_code, False), "scope": (_is_code, False), "mode": (_is_code, False),
    "status": (_is_code, False), "kind": (_is_code, False), "severity": (_is_code, False),
    "ecosystem": (_is_code, False), "verdict": (_is_code, False), "reason_code": (_is_code, False),
    "blocking": (_int, False), "open": (_int, False), "suppressed": (_int, False), "baselined": (_int, False),
    "count": (_int, False), "exit_code": (_int, False), "duration_ms": (_int, False), "retries": (_int, False),
    "errors": (_int, False), "skipped": (_int, False), "files": (_int, False), "packages": (_int, False),
    "complete": (lambda v: isinstance(v, bool), False), "verified": (lambda v: isinstance(v, bool), False),
    "checks": (lambda v: isinstance(v, str) and bool(_CHECK_ID.match(v)), True),
    "check_ids": (lambda v: isinstance(v, str) and bool(_CHECK_ID.match(v)), True),
    "fingerprints": (lambda v: isinstance(v, str) and bool(_FP.match(v)), True),
    "target": (_is_fp_or_check, False),
    "host": (lambda v: isinstance(v, str) and bool(_HOST.match(v)), False),
    "base": (lambda v: isinstance(v, str) and bool(_SHA_OR_REF.match(v)), False),
}


def _clean_session(s: str) -> str:
    s = textsafe.safe_text(s, cap=64)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)[:64] or "cli"


class Ledger:
    """Append-only (by convention) event log in a per-project state directory."""

    def __init__(self, state_dir: str | None, *, session: str = "cli", clock: Callable[[], float] = time.time):
        self.state_dir = state_dir
        self.session = _clean_session(session)
        self._clock = clock
        self.last_error: str | None = None

    @property
    def path(self) -> str | None:
        return os.path.join(self.state_dir, LEDGER_NAME) if self.state_dir else None

    def _record(self, event: str, fields: dict[str, Any]) -> bytes:
        rec: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
            "session": self.session, "event": event, "tool_version": GUARD_VERSION,
        }
        lists: dict[str, list[Any]] = {}
        for k, v in fields.items():
            spec = FIELDS.get(k)
            if spec is None:
                continue
            ok, many = spec
            if many:
                if isinstance(v, (list, tuple)):
                    items = [x for x in v if ok(x)]
                    lists[k] = items
            elif ok(v):
                rec[k] = v
        rec.update(lists)
        truncated = False
        while True:
            line = json.dumps(rec, separators=(",", ":"), sort_keys=False)
            if len(line.encode("utf-8")) + 1 <= MAX_LINE:
                break
            truncated = True
            rec["truncated"] = True
            longest = max(lists, key=lambda k: len(rec[k]), default=None)
            if longest is None or not rec[longest]:
                for k in [k for k in rec if k not in ("ts", "session", "event", "tool_version", "truncated")]:
                    del rec[k]
                continue
            rec[longest] = rec[longest][: max(0, len(rec[longest]) // 2)]
        if truncated:
            rec["truncated"] = True
            line = json.dumps(rec, separators=(",", ":"))
        return (line + "\n").encode("utf-8")

    def append(self, event: str, **fields: Any) -> bool:
        """Append one event; False when there is no state directory or the write was refused."""
        if event not in EVENTS:
            raise ValueError("unknown ledger event %r" % (event,))
        if not self.state_dir:
            return False
        data = self._record(event, fields)
        try:
            self._rotate_if_needed()
            files.safe_append(self.state_dir, LEDGER_NAME, data)
        except GuardError as exc:
            self.last_error = str(exc)
            return False
        except OSError as exc:
            self.last_error = type(exc).__name__
            return False
        return True

    def _rotate_if_needed(self) -> None:
        p = self.path
        if p is None:
            return
        try:
            size = os.lstat(p).st_size
        except OSError:
            return
        if size >= ROTATE_BYTES:
            files.safe_rename(self.state_dir, LEDGER_NAME, LEDGER_NAME + ".1")

    def read(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Records in order (oldest first, both generations); malformed lines are skipped."""
        if not self.state_dir:
            return []
        out: list[dict[str, Any]] = []
        for name in (LEDGER_NAME + ".1", LEDGER_NAME):
            view, _why = files.read_file(self.state_dir, name, limit=MAX_READ + ROTATE_BYTES)
            if view is None:
                continue
            for raw in view.text.splitlines():
                if not raw or len(raw) > MAX_LINE:
                    continue
                try:
                    rec = json.loads(raw)
                except (ValueError, RecursionError):
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("event"), str):
                    out.append(rec)
        return out[-limit:] if limit else out

    def clear(self) -> int:
        """Remove both generations; returns how many files were removed."""
        if not self.state_dir:
            return 0
        n = 0
        for name in (LEDGER_NAME, LEDGER_NAME + ".1"):
            try:
                if files.safe_remove(self.state_dir, name):
                    n += 1
            except GuardError as exc:
                self.last_error = str(exc)
        return n
