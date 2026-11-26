# SPDX-License-Identifier: Apache-2.0
"""``file:<path>``: a resolver backed by a JSON fixture, for offline use, tests and the conformance corpus.

Fixture format::

    {"resolver": "<label>", "ad": null | true | false,
     "answers": {"<qname>": {"status": "ok|nxdomain|nodata|servfail|timeout|error",
                             "txt": ["<record>", ["<chunk>", "<chunk>"], ...], "ad": bool, "ttl": int}}}

A record is a string or a list of character strings (joined with no separator). A name that is not listed does
not exist (NXDOMAIN). Several fixtures, one per ``--dns-resolver file:`` flag, express disagreement and quorum.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .. import limits
from .resolver import STATUSES, DnsAnswer

MAX_FIXTURE_BYTES = limits.MAX_AUX_FILE_BYTES


class FixtureError(ValueError):
    """The fixture file is unusable (a configuration error, exit 64)."""


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise FixtureError("duplicate key %r" % k)
        d[k] = v
    return d


def _reject(x):
    raise FixtureError("numbers other than integers are not allowed")


class FileResolver(object):
    network = False

    def __init__(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_FIXTURE_BYTES + 1)
        except OSError as e:
            raise FixtureError("cannot read %s: %s" % (path, e.strerror or "error")) from None
        if len(raw) > MAX_FIXTURE_BYTES:
            raise FixtureError("fixture over %d bytes" % MAX_FIXTURE_BYTES)
        try:
            doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_float=_reject, parse_constant=_reject)
        except FixtureError:
            raise
        except (ValueError, RecursionError):
            raise FixtureError("not JSON") from None
        if not isinstance(doc, dict) or not isinstance(doc.get("answers"), dict):
            raise FixtureError("a fixture is an object with an 'answers' object")
        label = doc.get("resolver")
        if label is not None and not isinstance(label, str):
            raise FixtureError("resolver must be a string")
        self.name = "file:" + (label if label else os.path.basename(path))
        default_ad = doc.get("ad")
        if default_ad is not None and not isinstance(default_ad, bool):
            raise FixtureError("ad must be true, false or null")
        self._answers = {}  # type: Dict[str, DnsAnswer]
        for qname, entry in doc["answers"].items():
            self._answers[str(qname).lower().rstrip(".")] = self._entry(qname, entry, default_ad)

    def _entry(self, qname: str, entry: Any, default_ad) -> DnsAnswer:
        if not isinstance(entry, dict) or entry.get("status") not in STATUSES:
            raise FixtureError("%s: status must be one of %s" % (qname, ", ".join(STATUSES)))
        status = entry["status"]
        txt = []  # type: List[str]
        if status == "ok":
            records = entry.get("txt")
            if not isinstance(records, list) or not records:
                raise FixtureError("%s: an ok answer lists its records" % qname)
            for rec in records:
                if isinstance(rec, str):
                    txt.append(rec)
                elif isinstance(rec, list) and all(isinstance(c, str) for c in rec):
                    txt.append("".join(rec))
                else:
                    raise FixtureError("%s: a record is a string or a list of strings" % qname)
        ad = entry.get("ad", default_ad)
        if ad is not None and not isinstance(ad, bool):
            raise FixtureError("%s: ad must be true, false or null" % qname)
        ttl = entry.get("ttl")
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0):
            raise FixtureError("%s: ttl must be a non-negative integer" % qname)
        return DnsAnswer(status, txt, ad, self.name, ttl)

    def resolve_txt(self, qname: str, timeout: float) -> DnsAnswer:
        a = self._answers.get(qname.lower().rstrip("."))
        if a is None:
            return DnsAnswer("nxdomain", [], None, self.name)
        return a
