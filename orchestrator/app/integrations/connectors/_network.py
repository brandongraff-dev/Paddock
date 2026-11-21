"""Base for network ACTION connectors (Sentry quarantine through the approve gate).

``act(action)`` is called ONLY by ``app.routers.network_actions`` after a human
approved an ``agent_actions`` row (four-eyes, ``apply_for_real``). The action
mapping it receives:

    {"type": "quarantine_device" | "release_device",
     "mac": "aa:bb:cc:dd:ee:ff",
     "dry_run": bool,            # absent -> True (fail safe)
     "action_id": "<uuid>",      # for the audit trail / idempotency
     "reason": "...",
     "revert": {...}}            # release: the plan returned by the quarantine

Guarantees enforced here, independent of the caller:

* only the two action types, only a valid unicast MAC;
* never a MAC listed in ``protected_macs`` (gateways, the Sentry sensor,
  core switches...);
* dry-run performs READ calls only (it confirms the client exists) and
  returns the calls a real run would make;
* every quarantine returns a ``revert`` plan, so release is always possible.
"""
from __future__ import annotations

from typing import Any, Mapping

from ..base import Capability, Connector, DeliveryResult
from ._common import ActionResult, SourceError, is_unicast_mac, normalize_mac

ACTION_TYPES = ("quarantine_device", "release_device")


class NetworkActionConnector(Connector):
    category = "network"
    capabilities = frozenset({Capability.ACTION})

    def _allow_private(self) -> bool:
        return bool(self.config.get("allow_private", False))

    def validate_action(self, action: Mapping[str, Any]) -> tuple[str, str, bool]:
        typ = action.get("type")
        if typ not in ACTION_TYPES:
            raise SourceError(f"unsupported action type {typ!r}", retryable=False)
        mac = normalize_mac(action.get("mac"))
        if not mac or not is_unicast_mac(mac):
            raise SourceError("action needs a valid unicast MAC address", retryable=False)
        protected = {normalize_mac(m) for m in self.config.get("protected_macs") or []}
        if mac in protected:
            raise SourceError(f"{mac} is on this integration's protected list", retryable=False)
        dry_run = action.get("dry_run", True)
        return str(typ), mac, bool(dry_run)

    async def act(self, action: Mapping[str, Any]) -> DeliveryResult:
        dry = bool(action.get("dry_run", True))
        try:
            typ, mac, dry = self.validate_action(action)
            return await self._act(typ, mac, dry, action)
        except SourceError as exc:
            return ActionResult(ok=False, status_code=exc.status_code, detail=str(exc),
                                retryable=exc.retryable, dry_run=dry)

    async def _act(self, typ: str, mac: str, dry_run: bool,
                   action: Mapping[str, Any]) -> ActionResult:  # pragma: no cover - abstract
        raise NotImplementedError
