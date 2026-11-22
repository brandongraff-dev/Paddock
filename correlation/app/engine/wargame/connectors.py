"""Read-only config sources that feed the Wargame parsers.

DEFENSIVE and READ-ONLY (``docs/WARGAME.md`` §4 ingest-first, §8). A
:class:`ConfigSource` only *fetches* a configuration export; it never writes,
never applies a change and never probes a target. Its output is the ``raw``
argument of :func:`app.engine.wargame.parsers.parse`.

Contract: ``fetch()`` is READ-ONLY and idempotent. Calling it twice returns
equal data and has no side effects on the system it reads from.

Everything here is pure and stdlib-only. ``boto3`` is optional and imported
lazily, and only inside :meth:`AwsApiConfigSource.from_boto3`; no code path
exercised by the tests touches the network.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol, Union, runtime_checkable

from .parsers import ParseResult, WarningLevel, parse

RawConfig = Union[dict, str]


class ConfigSourceError(Exception):
    """A source could not produce its config (missing file, no client, ...)."""


@runtime_checkable
class ConfigSource(Protocol):
    """Anything that can hand the parsers a raw config export.

    ``vendor`` is the parser key (``"aws"``, ``"cisco_asa"``, ...).
    ``fetch()`` is READ-ONLY and idempotent: it returns the raw config
    (parsed JSON as a dict, or text) and changes nothing.
    """

    vendor: str

    def fetch(self) -> RawConfig:  # pragma: no cover - protocol
        ...


@dataclass
class InMemoryConfigSource:
    """A config already held in memory (tests, API payloads, pasted exports)."""

    vendor: str
    raw: RawConfig

    def fetch(self) -> RawConfig:
        return self.raw


@dataclass
class FileConfigSource:
    """A config export on disk: ``.json`` is decoded, anything else is text."""

    vendor: str
    path: str

    def fetch(self) -> RawConfig:
        p = Path(self.path)
        try:
            if p.suffix.lower() == ".json":
                with p.open("r", encoding="utf-8") as fh:
                    return json.load(fh)
            return p.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ConfigSourceError(f"config file not found: {self.path}") from exc
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            # ValueError covers json.JSONDecodeError.
            raise ConfigSourceError(
                f"cannot read config file {self.path}: {exc}"
            ) from exc


class AwsApiConfigSource:
    """Read-only AWS source: security groups and network ACLs via the EC2 API.

    Least privilege: the credentials need ONLY ``ec2:DescribeSecurityGroups``
    and ``ec2:DescribeNetworkAcls``. This class calls nothing else, and never
    a Create/Modify/Delete/Authorize/Revoke API.

    ``client`` is any object exposing ``describe_security_groups()`` and
    ``describe_network_acls()`` (a boto3 EC2 client, or a stub in tests).
    Build a real one with :meth:`from_boto3`.
    """

    def __init__(self, vendor: str = "aws", client: Optional[Any] = None) -> None:
        self.vendor = vendor
        self.client = client

    @classmethod
    def from_boto3(
        cls,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        vendor: str = "aws",
        **client_kwargs: Any,
    ) -> "AwsApiConfigSource":
        """Build a source around a boto3 EC2 client (lazy, optional import).

        Uses the standard credential chain; supply read-only credentials.
        Not exercised by the tests (it would reach for the network).
        """
        try:
            import boto3  # noqa: PLC0415 - optional dependency, imported lazily
        except ImportError as exc:
            raise ConfigSourceError(
                "boto3 is not installed; install it and supply read-only credentials"
            ) from exc
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            client = session.client("ec2", **client_kwargs)
        except Exception as exc:  # botocore errors: bad profile, region, ...
            raise ConfigSourceError(f"cannot build AWS EC2 client: {exc}") from exc
        return cls(vendor=vendor, client=client)

    def fetch(self) -> dict:
        if self.client is None:
            raise ConfigSourceError(
                "no AWS client supplied; boto3 + read-only credentials required"
            )
        try:
            sgs = self.client.describe_security_groups()
            nacls = self.client.describe_network_acls()
        except Exception as exc:
            raise ConfigSourceError(f"AWS describe call failed: {exc}") from exc
        return {
            "SecurityGroups": list((sgs or {}).get("SecurityGroups", [])),
            "NetworkAcls": list((nacls or {}).get("NetworkAcls", [])),
        }


def _source_id(vendor: str, index: int) -> str:
    return f"{vendor}#{index}"


def collect_map(sources: Iterable[ConfigSource]) -> dict[str, ParseResult]:
    """Parse each source separately, keyed by a stable id ``"<vendor>#<index>"``.

    The index is the source's position in ``sources``, so ids are stable for a
    fixed input order. A source raising :class:`ConfigSourceError` still gets
    an entry: an empty :class:`ParseResult` carrying one UNSUPPORTED warning.
    """
    out: dict[str, ParseResult] = {}
    for i, src in enumerate(sources):
        sid = _source_id(src.vendor, i)
        try:
            out[sid] = parse(src.vendor, src.fetch())
        except ConfigSourceError as exc:
            res = ParseResult(vendor=src.vendor)
            res.add_warning(
                WarningLevel.UNSUPPORTED,
                f"source skipped: {exc}",
                ref=sid,
            )
            out[sid] = res
    return out


def collect(sources: Iterable[ConfigSource]) -> ParseResult:
    """Parse every source and merge into one :class:`ParseResult`.

    Sources are processed in the order given. The combined ``vendor`` is the
    shared vendor when every source has the same one, otherwise ``"multi"``
    (also ``"multi"`` for no sources). A source that raises
    :class:`ConfigSourceError` is skipped and recorded as an UNSUPPORTED
    warning on the merged result; it never aborts the batch. Ruleset ids are
    merged with ``dict.update`` semantics, so a later source overwrites an
    earlier one with the same id.
    """
    per_source = collect_map(sources)
    vendors = {r.vendor for r in per_source.values()}
    merged = ParseResult(vendor=vendors.pop() if len(vendors) == 1 else "multi")
    for res in per_source.values():
        merged.merge(res)
    return merged
