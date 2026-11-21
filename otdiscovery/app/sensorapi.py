"""Sensor enrollment / heartbeat / idempotent-upload bracket.

otdiscovery is the one address a sensor knows, so it fronts the orchestrator's
sensor API:

* ``POST /enroll`` and ``POST /heartbeat`` are forwarded as-is (the
  orchestrator authenticates the enrollment token / sensor credential, rate
  limits, and owns all state).
* For ``POST /ingest`` the gateway brackets processing with ``claim`` and
  ``done`` so a batch id is applied exactly once and a revoked credential is
  refused on the very next upload. Nothing is cached.

This process stores no sensor state; the orchestrator (Postgres) does.
"""
from __future__ import annotations

from typing import Any

from .orchestrator import OrchestratorClient

SENSOR_PREFIX = "pst_"


class SensorGateway:
    def __init__(self, orch: OrchestratorClient) -> None:
        self.orch = orch

    @staticmethod
    def _fwd(client_ip: str | None) -> dict[str, str]:
        return {"X-Sensor-Client-IP": client_ip} if client_ip else {}

    async def enroll(self, body: dict[str, Any], client_ip: str | None) -> tuple[int, Any]:
        return await self.orch.request("POST", "/v1/sensors/enroll", json_body=body,
                                       headers=self._fwd(client_ip))

    async def heartbeat(self, credential: str, body: dict[str, Any], client_ip: str | None) -> tuple[int, Any]:
        return await self.orch.request("POST", "/v1/sensors/heartbeat", json_body=body,
                                       headers={"X-Sensor-Token": credential, **self._fwd(client_ip)})

    async def claim(self, credential: str, batch_id: str, client_ip: str | None) -> tuple[int, Any]:
        return await self.orch.request(
            "POST", "/v1/sensors/ingest/claim", json_body={"batch_id": batch_id},
            headers={"X-Sensor-Token": credential, **self._fwd(client_ip)})

    async def done(self, credential: str, batch_id: str, *, ok: bool, flows: int) -> tuple[int, Any]:
        return await self.orch.request(
            "POST", "/v1/sensors/ingest/done", json_body={"batch_id": batch_id, "ok": ok, "flows": flows},
            headers={"X-Sensor-Token": credential})
