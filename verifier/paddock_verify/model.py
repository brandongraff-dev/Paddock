# SPDX-License-Identifier: Apache-2.0
"""Plain data shared by the pipeline: reasons, the bundle handle and the verification result."""
from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional

from . import limits


class Bundle(object):
    """A handle on the files of one bundle: the envelope under test plus lazily read siblings.

    ``read`` caches, applies the per-run byte budget (8 MiB) and the per-file cap, and returns ``None`` for a file
    that is not there. Files named in ``overrides`` (``keys.json``, ``revoked.json``) come from local paths.
    """

    def __init__(self, source: Any, envelope_path: Optional[str] = "attestation/latest.json", envelope_file: Optional[str] = None,
                 overrides: Optional[Dict[str, str]] = None, label: str = "", budget: int = limits.MAX_RUN_BYTES) -> None:
        self.source = source
        self.envelope_path = envelope_path
        self.envelope_file = envelope_file
        self.overrides = dict(overrides or {})
        self.label = label
        self.budget = budget
        self.used = 0
        self._cache = {}  # type: Dict[str, Optional[bytes]]
        self._error = None  # type: Optional[tuple]

    @classmethod
    def failed(cls, code: str, detail: str = "", label: str = "") -> "Bundle":
        """A bundle that could not be acquired: reading its envelope raises the ``input.*`` error."""
        b = cls(None, None, label=label)
        b._error = (code, detail)
        return b

    def _account(self, key: str, data: Optional[bytes]) -> Optional[bytes]:
        from .fetch import FetchError
        self._cache[key] = data
        if data is not None:
            self.used += len(data)
            if self.used > self.budget:
                raise FetchError("input.too_large", "more than %d bytes read in one run" % self.budget)
        return data

    def read(self, path: str, max_bytes: int = limits.MAX_AUX_FILE_BYTES) -> Optional[bytes]:
        if path in self._cache:
            return self._cache[path]
        from .fetch import read_file
        if self.source is None and path not in self.overrides:
            return None
        if path in self.overrides:
            return self._account(path, read_file(self.overrides[path], max_bytes))
        return self._account(path, self.source.read(path, max_bytes))

    def envelope(self) -> bytes:
        from .fetch import FetchError, read_file
        if self._error is not None:
            raise FetchError(*self._error)
        key = "<envelope>"
        if key in self._cache and self._cache[key] is not None:
            return self._cache[key]  # type: ignore[return-value]
        if self.envelope_file is not None:
            data = read_file(self.envelope_file, limits.MAX_ENVELOPE_BYTES)
        else:
            data = self.source.read(self.envelope_path, limits.MAX_ENVELOPE_BYTES)
        if data is None:
            raise FetchError("input.not_found", "no attestation at this location")
        return self._account(key, data)  # type: ignore[return-value]


class Registry(object):
    """The standard-invariant registry (the only place a ``std:`` digest becomes trusted) plus engine advisories."""

    def __init__(self, rulesets: Dict[str, Any], advisories: List[Dict[str, Any]]) -> None:
        self.rulesets = rulesets
        self.advisories = advisories

    @classmethod
    def from_bytes(cls, data: bytes, extra_advisories: bool = True) -> "Registry":
        from . import jsonstrict
        try:
            doc = jsonstrict.parse(data, max_depth=limits.MAX_PCJ_DEPTH, max_bytes=2 * limits.MAX_AUX_FILE_BYTES)
        except ValueError as e:
            raise ValueError("the standard registry is not valid strict JSON: %s" % e) from None
        if not isinstance(doc, dict) or doc.get("registry_version") != 1 or not isinstance(doc.get("rulesets"), dict):
            raise ValueError("the standard registry has registry_version 1 and a rulesets object")
        for rs, body in doc["rulesets"].items():
            if not isinstance(body, dict) or not isinstance(body.get("std"), dict):
                raise ValueError("a ruleset lists its std invariants")
            for inv, e in body["std"].items():
                if not isinstance(e, dict) or not isinstance(e.get("digest"), str) or not isinstance(e.get("name"), str):
                    raise ValueError("a std entry has a digest and a name")
        adv = []  # type: List[Dict[str, Any]]
        raw = doc.get("advisories")
        if raw is not None:
            if not isinstance(raw, list):
                raise ValueError("advisories is a list")
            for a in raw:
                if not isinstance(a, dict) or not isinstance(a.get("engine"), str) or a.get("effect") not in ("reject", "warn"):
                    raise ValueError("an advisory has an engine version and an effect (reject or warn)")
                adv.append(a)
        return cls(doc["rulesets"], adv)

    def with_advisories(self, items: List[Dict[str, Any]]) -> "Registry":
        return Registry(self.rulesets, self.advisories + list(items))


def load_default_registry() -> Registry:
    """The registry and advisories shipped in ``data/``."""
    from . import jsonstrict
    reg = Registry.from_bytes(limits.read_data("std_registry.json"))
    adv = jsonstrict.parse(limits.read_data("advisories.json"), max_depth=limits.MAX_PCJ_DEPTH, max_bytes=limits.MAX_AUX_FILE_BYTES)
    if not isinstance(adv, dict) or adv.get("advisories_version") != 1 or not isinstance(adv.get("items"), list):
        raise ValueError("advisories.json is malformed")
    return reg.with_advisories(adv["items"])
