# SPDX-License-Identifier: Apache-2.0
"""The local state file (spec/07 section 6): the highest sequence number seen per subject, so a rollback is caught.

``{"state_version": 1, "subjects": {"dns:example.com": {"seq": 12, "digest": "sha256:...", "anchor": {"max_id": 9, "at": "T", "head": "<hex>"}}},
"revocation": {"e_...": {"seq": 42}}}``. The state reduces rollback acceptance; it cannot fix clock manipulation.
It is updated only after steps 0 to 4 passed, and written atomically.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any, Dict, Optional

from . import limits, schema, timefmt
from .jsonstrict import JsonError
from . import jsonstrict

VERSION = 1


class StateError(Exception):
    """The state file exists but cannot be used (``chain.state_unreadable``)."""


def _valid(doc: Any) -> bool:
    if not isinstance(doc, dict) or set(doc) - {"state_version", "subjects", "revocation"} or doc.get("state_version") != VERSION:
        return False
    subjects, rev = doc.get("subjects", {}), doc.get("revocation", {})
    if not isinstance(subjects, dict) or not isinstance(rev, dict) or len(subjects) > 4096 or len(rev) > 4096:
        return False
    for name, e in subjects.items():
        if schema.parse_subject(name) is None or not isinstance(e, dict) or set(e) - {"seq", "digest", "anchor"}:
            return False
        if type(e.get("seq")) is not int or not 1 <= e["seq"] <= limits.MAX_INT or not isinstance(e.get("digest"), str) \
                or not schema._H.match(e["digest"]):
            return False
        a = e.get("anchor")
        if a is not None:
            if not isinstance(a, dict) or set(a) != {"max_id", "at", "head"} or type(a["max_id"]) is not int or a["max_id"] < 0 \
                    or not isinstance(a["head"], str) or not schema._HEX64.match(a["head"]):
                return False
            try:
                timefmt.parse(a["at"])
            except (JsonError, TypeError):
                return False
    for estate, e in rev.items():
        if not isinstance(estate, str) or not schema._ESTATE.match(estate) or not isinstance(e, dict) or set(e) != {"seq"} \
                or type(e["seq"]) is not int or e["seq"] < 1:
            return False
    return True


class State(object):
    def __init__(self, data: Optional[Dict[str, Any]] = None, path: Optional[str] = None) -> None:
        if data is None:
            data = {"state_version": VERSION, "subjects": {}, "revocation": {}}
        if not _valid(data):
            raise StateError("not a state document")
        self.data = copy.deepcopy(data)
        self.data.setdefault("subjects", {})
        self.data.setdefault("revocation", {})
        self.path = path

    @classmethod
    def load(cls, path: str) -> "State":
        """A missing file is an empty state (the first run); an unreadable or invalid one is a ``StateError``."""
        try:
            with open(path, "rb") as fh:
                raw = fh.read(limits.MAX_AUX_FILE_BYTES + 1)
        except FileNotFoundError:
            return cls(None, path)
        except OSError:
            raise StateError("cannot read the state file") from None
        if len(raw) > limits.MAX_AUX_FILE_BYTES:
            raise StateError("state file too large")
        try:
            doc = jsonstrict.parse(raw, max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_AUX_FILE_BYTES)
        except JsonError:
            raise StateError("not valid JSON") from None
        return cls(doc, path)

    def subject(self, name: str) -> Optional[Dict[str, Any]]:
        return self.data["subjects"].get(name)

    def revocation_seq(self, estate: str) -> int:
        e = self.data["revocation"].get(estate)
        return e["seq"] if e else 0

    def apply(self, update: Dict[str, Any]) -> None:
        """Merge a ``state_update`` produced by ``verify`` (never lowers a recorded value)."""
        sub = update.get("subject")
        if sub is not None:
            cur = self.data["subjects"].get(sub["name"])
            if cur is None or sub["seq"] > cur["seq"] or (sub["seq"] == cur["seq"] and sub["digest"] == cur["digest"]):
                entry = {"seq": sub["seq"], "digest": sub["digest"]}
                if sub.get("anchor") is not None:
                    entry["anchor"] = sub["anchor"]
                elif cur is not None and cur.get("anchor") is not None and sub["seq"] == cur["seq"]:
                    entry["anchor"] = cur["anchor"]
                self.data["subjects"][sub["name"]] = entry
        rev = update.get("revocation")
        if rev is not None and rev["seq"] > self.revocation_seq(rev["estate"]):
            self.data["revocation"][rev["estate"]] = {"seq": rev["seq"]}

    def save(self, path: Optional[str] = None, make_dir: bool = False) -> None:
        """Write atomically. ``make_dir`` creates the (single, private, mode 0700) parent directory when it is missing:
        the default location ``~/.paddock`` does not exist on a first run, and a state that is never written would
        silently switch off rollback protection."""
        target = path or self.path
        if not target:
            raise StateError("no path")
        text = (json.dumps(self.data, sort_keys=True, indent=2) + "\n").encode("ascii")
        d = os.path.dirname(os.path.abspath(target))
        if make_dir and not os.path.isdir(d):
            try:
                os.mkdir(d, 0o700)
            except FileExistsError:
                pass
            except OSError:
                raise StateError("cannot create the state directory") from None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".paddock-state-", dir=d)
        except OSError:
            raise StateError("cannot write the state file") from None
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(text)
            os.replace(tmp, target)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise StateError("cannot write the state file") from None
