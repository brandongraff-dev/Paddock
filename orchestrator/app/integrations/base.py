"""The connector contract. Every integration implements ``Connector``.

Lifecycle, as the Integrations page shows it:  connect -> test -> sync -> health.

Capabilities (a connector declares one or more):

* ``NOTIFY``  -- push events out (webhook, Slack, Teams, email, SIEM, PagerDuty)
* ``TICKET``  -- create/update tickets AND accept inbound status changes
                 (Jira, ServiceNow, Linear) -- two-way sync
* ``SOURCE``  -- pull context in (cloud inventory, EDR/MDM, CMDB, IdP owners)
* ``ACTION``  -- execute an APPROVED remediation (e.g. quarantine a device on
                 a UniFi/Meraki network). Only ever called by the approve gate.

Rules every connector follows:
1. Never log or return secrets. Secrets arrive decrypted in ``self.secrets``
   and must not be echoed in ``DeliveryResult.detail`` or exceptions.
2. All outbound HTTP goes through ``self.http`` (an ``httpx.AsyncClient``) to
   URLs that passed ``netsafety.validate_outbound_url``.
3. ``deliver`` must be idempotent on ``event.id`` (the dispatcher retries).
4. Map errors to ``DeliveryResult(ok=False, retryable=...)``; don't raise for
   expected remote failures (4xx/5xx/timeouts).
"""
from __future__ import annotations

import uuid
from abc import ABC
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Mapping, Optional


class Capability(str, Enum):
    NOTIFY = "notify"
    TICKET = "ticket"
    SOURCE = "source"
    ACTION = "action"


# The public event catalogue. Integrations subscribe to a subset.
EVENT_TYPES: dict[str, str] = {
    "finding.opened": "A new finding was opened",
    "finding.updated": "A finding's severity/status/owner changed",
    "finding.resolved": "A finding was fixed or verified closed",
    "finding.reopened": "A previously fixed finding came back",
    "finding.accepted": "A finding was risk-accepted or marked false positive",
    "attack_path.opened": "A new attack path to a crown jewel appeared",
    "change.detected": "The attack surface changed (new host, port, cert...)",
    "asset.discovered": "A new asset was discovered",
    "device.behavior": "A Sentry behaviour detector fired",
    "scan.completed": "A scan finished",
    "scan.failed": "A scan failed",
    "report.digest": "The scheduled digest is ready",
    "integration.test": "A test event sent from the Integrations page",
    "finding.verified": "A safe check confirmed (or could not reproduce) a finding",
    "finding.fix_verified": "A fix was verified: the finding could no longer be reproduced",
    "finding.fix_failed": "A fix did not hold: the finding was reproduced and reopened",
    "supplier.grade_changed": "A monitored supplier's passive security grade changed",
    "supplier.dangling_dns": "A monitored supplier has a new dangling DNS record (possible takeover)",
    "supplier.cert_expiring": "A monitored supplier has an expired or expiring certificate",
    "sensor.offline": "A Sentry sensor stopped reporting",
    "sensor.online": "A silent Sentry sensor is reporting again",
}

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Event:
    """A normalized, connector-agnostic event."""

    type: str
    title: str
    summary: str = ""
    severity: Optional[str] = None
    data: Mapping[str, Any] = field(default_factory=dict)
    url: Optional[str] = None                 # deep link into the dashboard
    tenant_id: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))   # idempotency key
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown event type {self.type!r}")
        if self.severity is not None and self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "occurred_at": self.occurred_at.isoformat(),
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "url": self.url,
            "tenant_id": self.tenant_id,
            "data": dict(self.data),
        }


@dataclass
class DeliveryResult:
    ok: bool
    status_code: Optional[int] = None
    external_id: Optional[str] = None      # e.g. Jira issue key, ServiceNow sys_id
    external_url: Optional[str] = None
    detail: str = ""                        # human-readable, NEVER contains secrets
    retryable: bool = True


@dataclass
class HealthResult:
    ok: bool
    detail: str = ""


@dataclass
class InboundUpdate:
    """A change reported BY the external system (two-way sync)."""

    external_id: str
    finding_id: Optional[str] = None
    status: Optional[str] = None             # paddock finding status: open|triaged|fixed|accepted|false_positive
    comment: Optional[str] = None
    actor: Optional[str] = None


@dataclass
class SourceBatch:
    """What a SOURCE connector pulled, in orchestrator bulk-endpoint shapes."""

    assets: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    owners: list[dict[str, Any]] = field(default_factory=list)
    # Additive (schema 031): internet-facing names/addresses the source saw that
    # the customer may want in scope: {"kind", "value", "evidence"}. They are
    # stored as PENDING suggestions; a source never adds scope itself.
    scope_suggestions: list[dict[str, Any]] = field(default_factory=list)


class Connector(ABC):
    """Base class. Subclasses set the ClassVars and override what they support."""

    kind: ClassVar[str]                       # stable id, e.g. "slack"
    display_name: ClassVar[str]               # "Slack"
    category: ClassVar[str] = "other"         # chat|ticketing|siem|webhook|identity|cloud|edr|network|email|paging
    capabilities: ClassVar[frozenset[Capability]] = frozenset()
    # JSON-schema (draft 2020-12) for NON-secret config shown in the UI form.
    config_schema: ClassVar[dict[str, Any]] = {"type": "object", "properties": {}}
    # Names of secret fields (rendered as password inputs, stored encrypted).
    secret_fields: ClassVar[tuple[str, ...]] = ()
    docs_url: ClassVar[Optional[str]] = None

    def __init__(self, config: Mapping[str, Any], secrets: Mapping[str, str], http: Any) -> None:
        self.config = dict(config)
        self.secrets = dict(secrets)
        self.http = http

    # -- every connector --------------------------------------------------- #
    async def test(self) -> HealthResult:
        """Cheap connectivity/credential check, used by the 'Test' button."""
        return HealthResult(ok=False, detail="test not implemented")

    # -- NOTIFY / TICKET --------------------------------------------------- #
    async def deliver(self, event: Event) -> DeliveryResult:
        raise NotImplementedError

    # -- TICKET (inbound half of two-way sync) ----------------------------- #
    async def handle_inbound(self, headers: Mapping[str, str], body: bytes) -> list[InboundUpdate]:
        """Verify the request's signature/secret and translate it. Raise
        ``PermissionError`` on a bad signature."""
        raise NotImplementedError

    # -- SOURCE ------------------------------------------------------------ #
    async def pull(self) -> SourceBatch:
        raise NotImplementedError

    # -- ACTION (only the approve gate calls this) ------------------------- #
    async def act(self, action: Mapping[str, Any]) -> DeliveryResult:
        raise NotImplementedError

    @classmethod
    def describe(cls) -> dict[str, Any]:
        """Catalogue entry for GET /v1/integrations/catalog."""
        return {
            "kind": cls.kind,
            "display_name": cls.display_name,
            "category": cls.category,
            "capabilities": sorted(c.value for c in cls.capabilities),
            "config_schema": cls.config_schema,
            "secret_fields": list(cls.secret_fields),
            "docs_url": cls.docs_url,
        }


REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    """Class decorator: make a connector discoverable."""
    kind = getattr(cls, "kind", None)
    if not kind:
        raise TypeError(f"{cls.__name__} must set `kind`")
    if kind in REGISTRY and REGISTRY[kind] is not cls:
        raise ValueError(f"duplicate connector kind {kind!r}")
    REGISTRY[kind] = cls
    return cls


def get_connector_class(kind: str) -> type[Connector]:
    try:
        return REGISTRY[kind]
    except KeyError:
        raise KeyError(f"unknown integration kind {kind!r}") from None
