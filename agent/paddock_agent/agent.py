"""The agent: enrollment + the heartbeat/inventory run loop + action handling.

Run loop (default): heartbeat and inventory on an interval. On each heartbeat
the server returns the approved, real (dry_run=false) actions this agent should
carry out. For each, the agent:
  * re-validates it is host-local and allowed,
  * applies it via the platform enforcer (or SIMULATES if the agent is running
    dry, or the action is still dry_run),
  * reports the result (incl. a revert plan) back to the server.

The agent NEVER applies an action the server has not marked ``approved``, and
NEVER applies anything when running dry. Reverts arrive as first-class
``revert`` actions and are handled the same gated way.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Any

from . import __version__
from .actions import Action, Outcome, apply_action, revert_action
from .client import FleetClient, FleetClientError
from .config import AgentConfig, Credentials, load_credentials, save_credentials
from .inventory import collect_inventory
from .platform_block import BaseEnforcer, detect_platform, get_enforcer

log = logging.getLogger("paddock-agent")


class Agent:
    def __init__(self, cfg: AgentConfig, *, client: FleetClient | None = None,
                 enforcer: BaseEnforcer | None = None) -> None:
        self.cfg = cfg
        self.platform = detect_platform(cfg.platform_name)
        self.creds = load_credentials(cfg.cred_path)
        self.client = client or FleetClient(
            cfg.server,
            agent_id=self.creds.agent_id if self.creds else None,
            agent_token=self.creds.agent_token if self.creds else None,
            timeout_s=cfg.timeout_s,
        )
        self.enforcer = enforcer or get_enforcer(
            self.platform, quarantine_dir=cfg.quarantine_dir
        )
        self._stop = False

    # ------------------------------------------------------------------ #
    # enrollment
    # ------------------------------------------------------------------ #
    def enroll(self, token: str, *, hostname: str | None = None) -> Credentials:
        host = hostname or socket.gethostname()
        out = self.client.enroll(
            hostname=host, platform=self.platform, token=token,
            agent_version=__version__,
        )
        creds = Credentials(
            agent_id=out["id"], agent_token=out["agent_token"],
            server=self.cfg.server, hostname=host,
        )
        save_credentials(self.cfg.cred_path, creds)
        self.creds = creds
        log.info("enrolled as agent %s (%s)", creds.agent_id, host)
        return creds

    def _require_enrolled(self) -> None:
        if not self.creds or not self.client.agent_token:
            raise FleetClientError("agent is not enrolled; run `paddock enroll` first")

    # ------------------------------------------------------------------ #
    # inventory
    # ------------------------------------------------------------------ #
    def send_inventory(self) -> dict[str, Any]:
        self._require_enrolled()
        inv = collect_inventory()
        return self.client.post_inventory(inv)

    # ------------------------------------------------------------------ #
    # heartbeat + action handling
    # ------------------------------------------------------------------ #
    def heartbeat(self) -> dict[str, Any]:
        self._require_enrolled()
        hb = self.client.heartbeat(agent_version=__version__)
        for raw in hb.get("pending_actions", []):
            try:
                self.handle_action(Action.from_server(raw))
            except Exception:  # noqa: BLE001 -- one bad action never stops the loop
                log.exception("failed handling action %s", raw.get("id"))
        return hb

    def handle_action(self, action: Action) -> Outcome:
        """Apply (or revert) one server-approved action under the safety gate."""
        if action.action_type == "revert":
            outcome = revert_action(action, self.enforcer, agent_dry_run=self.cfg.dry_run)
        else:
            outcome = apply_action(action, self.enforcer, agent_dry_run=self.cfg.dry_run)

        # Report only terminal real outcomes to the server. A simulation on the
        # run loop changes no server state (operators drive simulations via the
        # CLI), so we log it and move on.
        if outcome.status == "simulated":
            log.info("simulated %s %s (dry-run): %s",
                     action.action_type, action.target, outcome.output)
            return outcome
        self.client.post_result(
            action.id, status=outcome.status, output=outcome.output, revert=outcome.revert,
        )
        log.info("reported %s for action %s (%s %s)",
                 outcome.status, action.id, action.action_type, action.target)
        return outcome

    # ------------------------------------------------------------------ #
    # run loop
    # ------------------------------------------------------------------ #
    def run(self, *, max_iterations: int | None = None, sleep=time.sleep) -> None:
        self._require_enrolled()
        log.info("agent run loop starting (platform=%s, dry_run=%s)",
                 self.platform, self.cfg.dry_run)
        last_inv = 0.0
        i = 0
        while not self._stop:
            now = time.monotonic()
            try:
                self.heartbeat()
                if now - last_inv >= self.cfg.inventory_interval_s:
                    self.send_inventory()
                    last_inv = now
            except FleetClientError as exc:
                log.warning("server round-trip failed: %s", exc)
            i += 1
            if max_iterations is not None and i >= max_iterations:
                break
            sleep(self.cfg.heartbeat_interval_s)

    def stop(self) -> None:
        self._stop = True
