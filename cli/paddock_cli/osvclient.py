"""OSV.dev client with an on-disk cache (stdlib only).

Wire format and mapping reuse the SCA engine's pure helpers
(``build_queries`` / ``extract_ids`` / ``map_vuln``); only the transport is
different (urllib instead of aiohttp, so the CLI has no dependencies).

Cache layout (``$PADDOCK_CACHE_DIR`` or ``~/.cache/paddock``)::

    osv/q/<sha256(eco|name|version)>.json {"ts": ..., "ids": [...]}
    osv/v/<vuln id>.json                  {"ts": ..., "vuln": {...OSV record...}}

``--offline`` reads the cache and never touches the network; online mode
refreshes entries older than ``ttl`` and falls back to a stale entry when OSV
is unreachable, saying so in :attr:`OsvResult.notes`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__, engines

OSV_BASE = "https://api.osv.dev"
DEFAULT_TTL_S = 24 * 3600
MAX_BATCH = 1000

Transport = Callable[[str, str, Any], Any]
"""``transport(method, url, json_body) -> parsed JSON`` (raises OSError on failure)."""


def cache_dir() -> Path:
    env = os.environ.get("PADDOCK_CACHE_DIR")
    if env:
        return Path(env)
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "paddock"


def urllib_transport(timeout: float = 20.0) -> Transport:
    def call(method: str, url: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Content-Type": "application/json",
            "User-Agent": f"paddock-cli/{__version__}",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise OSError(f"HTTP {exc.code} from {url}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise OSError(str(exc)) from exc
    return call


@dataclass
class OsvResult:
    # "eco|name|version" -> raw OSV vulnerability records affecting it
    vulns: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    checked: set[str] = field(default_factory=set)     # keys we have an answer for
    unchecked: set[str] = field(default_factory=set)   # keys with no answer (offline / failure)
    notes: list[str] = field(default_factory=list)


def key_of(eco: str, name: str, version: str) -> str:
    return f"{eco}|{name}|{version}"


class OsvClient:
    def __init__(self, *, offline: bool = False, ttl_s: int = DEFAULT_TTL_S,
                 transport: Transport | None = None, base_url: str | None = None,
                 cache: Path | None = None, workers: int = 8) -> None:
        self.offline = offline
        self.ttl_s = ttl_s
        self.base = (base_url or os.environ.get("PADDOCK_OSV_URL") or OSV_BASE).rstrip("/")
        self.transport = transport or urllib_transport()
        self.root = (cache or cache_dir()) / "osv"
        self.workers = workers
        self._network_down = False

    # -- cache ----------------------------------------------------------
    def _read(self, sub: str, name: str) -> dict[str, Any] | None:
        try:
            with open(self.root / sub / f"{name}.json", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def _write(self, sub: str, name: str, payload: dict[str, Any]) -> None:
        try:
            d = self.root / sub
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / f".{name}.{os.getpid()}.tmp"
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, d / f"{name}.json")
        except OSError:
            pass  # a read-only cache must never break a scan

    @staticmethod
    def _qname(eco: str, name: str, version: str) -> str:
        return hashlib.sha256(key_of(eco, name, version).encode()).hexdigest()[:40]

    @staticmethod
    def _vname(vid: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in vid)[:200]

    def _fresh(self, entry: dict[str, Any] | None) -> bool:
        return bool(entry) and (time.time() - float(entry.get("ts", 0))) < self.ttl_s

    # -- public ---------------------------------------------------------
    def query(self, packages: list[tuple[str, str, str]]) -> OsvResult:
        """Vulnerabilities for ``(ecosystem, name, version)`` triples."""
        res = OsvResult()
        uniq = list(dict.fromkeys(p for p in packages if p[1] and p[2]))
        ids_by_key: dict[str, list[str]] = {}
        todo: list[tuple[str, str, str]] = []

        for eco, name, ver in uniq:
            k = key_of(eco, name, ver)
            entry = self._read("q", self._qname(eco, name, ver))
            if entry is not None and (self.offline or self._fresh(entry)):
                ids_by_key[k] = list(entry.get("ids") or [])
            else:
                todo.append((eco, name, ver))

        if todo and not self.offline:
            self._fetch_ids(todo, ids_by_key, res)

        stale_used = 0
        for eco, name, ver in todo:
            k = key_of(eco, name, ver)
            if k in ids_by_key:
                continue
            entry = self._read("q", self._qname(eco, name, ver))
            if entry is not None:  # network failed: stale beats nothing
                ids_by_key[k] = list(entry.get("ids") or [])
                stale_used += 1
        if stale_used:
            res.notes.append(f"OSV unreachable: used cached results for {stale_used} package(s)")

        vuln_ids = list(dict.fromkeys(i for ids in ids_by_key.values() for i in ids))
        details = self._details(vuln_ids, res)

        for eco, name, ver in uniq:
            k = key_of(eco, name, ver)
            if k not in ids_by_key:
                res.unchecked.add(k)
                continue
            res.checked.add(k)
            found = []
            for vid in ids_by_key[k]:
                d = details.get(vid)
                # keep the bare id when the detail could not be fetched
                found.append(d if d else {"id": vid})
            if found:
                res.vulns[k] = found
        if res.unchecked:
            why = "not in the offline cache" if self.offline else "could not be checked"
            res.notes.append(f"{len(res.unchecked)} package(s) {why}")
        return res

    # -- network --------------------------------------------------------
    def _fetch_ids(self, todo: list[tuple[str, str, str]], out: dict[str, list[str]],
                   res: OsvResult) -> None:
        osv = engines.sca_osv()
        for start in range(0, len(todo), MAX_BATCH):
            chunk = todo[start:start + MAX_BATCH]
            try:
                body = osv.build_queries(chunk)
                resp = self.transport("POST", f"{self.base}/v1/querybatch", body)
                per = osv.extract_ids(resp or {})
                results = (resp or {}).get("results") or []
                if len(per) != len(chunk):
                    raise OSError("OSV returned a mismatched batch")
                for i, (eco, name, ver) in enumerate(chunk):
                    ids = list(per[i])
                    token = (results[i] or {}).get("next_page_token")
                    pages = 0
                    while token and pages < 20:  # paginate very vulnerable packages
                        q = {"package": {"ecosystem": eco, "name": name}, "version": ver,
                             "page_token": token}
                        more = self.transport("POST", f"{self.base}/v1/query", q) or {}
                        ids += [v["id"] for v in more.get("vulns") or [] if v.get("id")]
                        token = more.get("next_page_token")
                        pages += 1
                    ids = list(dict.fromkeys(ids))
                    out[key_of(eco, name, ver)] = ids
                    self._write("q", self._qname(eco, name, ver), {"ts": time.time(), "ids": ids})
            except OSError as exc:
                self._network_down = True
                res.notes.append(f"OSV query failed: {exc}")
                return

    def _details(self, ids: list[str], res: OsvResult) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        need: list[str] = []
        for vid in ids:
            entry = self._read("v", self._vname(vid))
            if entry is not None and entry.get("vuln") and (self.offline or self._fresh(entry)):
                out[vid] = entry["vuln"]
            else:
                need.append(vid)
        if not need:
            return out

        def fetch(vid: str) -> tuple[str, dict[str, Any] | None]:
            if self.offline or self._network_down:
                return vid, None
            try:
                data = self.transport("GET", f"{self.base}/v1/vulns/{vid}", None)
            except OSError:
                return vid, None
            return vid, data if isinstance(data, dict) else None

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for vid, data in pool.map(fetch, need):
                if data:
                    out[vid] = data
                    self._write("v", self._vname(vid), {"ts": time.time(), "vuln": data})
                else:
                    stale = self._read("v", self._vname(vid))
                    if stale and stale.get("vuln"):
                        out[vid] = stale["vuln"]
        return out


# --------------------------------------------------------------------------- #
# interpreting OSV records
# --------------------------------------------------------------------------- #

def _norm(ecosystem: str, name: Any) -> str:
    n = str(name or "").lower()
    return re.sub(r"[-_.]+", "-", n) if ecosystem == "PyPI" else n


def fixed_versions(vuln: dict[str, Any], ecosystem: str, name: str) -> list[str]:
    """Every ``fixed`` version OSV lists for this package (git-commit ranges skipped)."""
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or _norm(ecosystem, pkg.get("name")) != _norm(
                ecosystem, name):
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixed = str(ev["fixed"])
                    if ecosystem == "Go" and re.match(r"\d", fixed):
                        fixed = "v" + fixed          # OSV lists Go fixes without the v go.mod needs
                    out.append(fixed)
    return list(dict.fromkeys(out))


_FLAVOR = re.compile(r"-(jre|android)$", re.I)


def nearest_fix(current: str, vulns: list[dict[str, Any]], ecosystem: str, name: str,
                ) -> tuple[str | None, bool]:
    """The lowest version that clears *every* given advisory.

    For each advisory take the nearest ``fixed`` version above ``current``; the
    answer is the highest of those (so one bump fixes them all). Returns
    ``(version, complete)``; ``complete`` is False when some advisory has no
    published fix (the version returned, if any, only clears the others).
    """
    from . import versions as V
    per_vuln: list[str] = []
    complete = True
    flavor = (_FLAVOR.search(current) or [None])[0]   # Guava-style 31.1-jre vs -android builds
    for v in vulns:
        cands = fixed_versions(v, ecosystem, name)
        if flavor:
            cands = [c if c.lower().endswith(flavor.lower()) else c + flavor
                     for c in cands if not _FLAVOR.search(c) or c.lower().endswith(flavor.lower())]
        above = [f for f in cands if V.compare(f, current) > 0]
        if above:
            per_vuln.append(min(above, key=V.sort_key))
        else:
            complete = False
    return (max(per_vuln, key=V.sort_key) if per_vuln else None), complete
