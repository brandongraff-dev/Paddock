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
        if path in self.overrides:
            return self._account(path, read_file(self.overrides[path], max_bytes))
        return self._account(path, self.source.read(path, max_bytes))

    def envelope(self) -> bytes:
        from .fetch import FetchError, read_file
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
