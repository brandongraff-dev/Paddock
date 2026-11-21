"""Thin HTTP client for the orchestrator fleet API.

Enrollment uses the bootstrap enrollment token in the POST body. Every other
agent call authenticates with the minted agent credential via the
``X-Agent-Token`` header (NOT Authorization: Bearer -- the orchestrator reserves
Bearer for JWTs / pak_ keys, and the agent credential is validated by the fleet
router itself against the stored hash).
"""
from __future__ import annotations

from typing import Any

import httpx


class FleetClientError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class FleetClient:
    def __init__(self, server: str, *, agent_id: str | None = None,
                 agent_token: str | None = None, timeout_s: int = 20,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.base = server.rstrip("/")
        self.agent_id = agent_id
        self.agent_token = agent_token
        self._timeout = timeout_s
        self._transport = transport

    # -- low level ----------------------------------------------------------- #
    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base, timeout=self._timeout, transport=self._transport)

    def _agent_headers(self) -> dict[str, str]:
        if not self.agent_token:
            raise FleetClientError("no agent token; enroll first")
        return {"X-Agent-Token": self.agent_token}

    def _req(self, method: str, path: str, *, json: Any = None,
             headers: dict[str, str] | None = None) -> Any:
        with self._client() as c:
            resp = c.request(method, path, json=json, headers=headers)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:  # noqa: BLE001
                body = resp.text
            raise FleetClientError(
                f"{resp.status_code} on {method} {path}", resp.status_code, body
            )
        if resp.content:
            return resp.json()
        return None

    # -- enrollment ---------------------------------------------------------- #
    def enroll(self, *, hostname: str, platform: str, token: str,
               agent_version: str | None = None, labels: list[str] | None = None,
               capabilities: list[str] | None = None) -> dict[str, Any]:
        body = {
            "hostname": hostname, "platform": platform, "token": token,
            "agent_version": agent_version, "labels": labels or [],
            "capabilities": capabilities or ["inventory", "block", "quarantine"],
        }
        out = self._req("POST", "/v1/fleet/enroll", json=body)
        self.agent_id = out["id"]
        self.agent_token = out["agent_token"]
        return out

    # -- agent-authenticated ------------------------------------------------- #
    def heartbeat(self, *, agent_version: str | None = None) -> dict[str, Any]:
        return self._req(
            "POST", f"/v1/fleet/{self.agent_id}/heartbeat",
            json={"agent_version": agent_version}, headers=self._agent_headers(),
        )

    def post_inventory(self, inventory: dict[str, Any]) -> dict[str, Any]:
        return self._req(
            "POST", f"/v1/fleet/{self.agent_id}/inventory",
            json=inventory, headers=self._agent_headers(),
        )

    def post_result(self, action_id: str, *, status: str, output: dict[str, Any],
                    revert: dict[str, Any] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"status": status, "output": output}
        if revert is not None:
            body["revert"] = revert
        return self._req(
            "POST", f"/v1/fleet/actions/{action_id}/result",
            json=body, headers=self._agent_headers(),
        )

    # -- operator (read / propose; uses the ambient operator credential) ----- #
    def list_actions(self, *, agent: str | None = None, status: str | None = None,
                     operator_headers: dict[str, str] | None = None) -> dict[str, Any]:
        params = []
        if agent:
            params.append(f"agent={agent}")
        if status:
            params.append(f"status={status}")
        qs = ("?" + "&".join(params)) if params else ""
        return self._req("GET", f"/v1/fleet/actions{qs}", headers=operator_headers)

    def get_agent(self, agent_id: str, *, operator_headers: dict[str, str] | None = None) -> dict[str, Any]:
        return self._req("GET", f"/v1/fleet/agents/{agent_id}", headers=operator_headers)
