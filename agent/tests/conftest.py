"""Shared fakes: an in-memory enforcer that records what it did (so 'dry-run
never mutates' and 'revert restores' are assertable without touching the host)."""
from __future__ import annotations

from typing import Any

import pytest

from paddock_agent.platform_block import BaseEnforcer, RevertRefused


class RecordingEnforcer(BaseEnforcer):
    """A fully in-memory enforcer. Tracks a 'host state' set of active blocks so
    tests can prove apply mutates, dry-run does not, and revert restores."""
    name = "fake"
    can_apply = True

    def __init__(self) -> None:
        super().__init__()
        self.state: set[str] = set()          # active blocks (the "host state")
        self.calls: list[tuple[str, Any]] = []

    def _key(self, action_type: str, target: str) -> str:
        return f"{action_type}:{target}"

    def _plan(self, action_type: str, target: str) -> dict[str, Any]:
        return {"mechanism": "fake", "key": self._key(action_type, target)}

    def simulate(self, action_type: str, target: str) -> dict[str, Any]:
        self.calls.append(("simulate", self._key(action_type, target)))
        return {"would": self._plan(action_type, target), "dry_run": True}

    def validate_revert(self, plan: Any, ledger: Any = None) -> dict[str, Any]:
        # The fake knows exactly one plan shape; anything else is refused like the real enforcer does.
        if not isinstance(plan, dict) or plan.get("mechanism") != "fake" or not isinstance(plan.get("key"), str):
            raise RevertRefused("not a plan this fake could have produced")
        return {"mechanism": "fake", "key": plan["key"]}

    def simulate_revert(self, plan: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("simulate_revert", plan.get("key")))
        return {"would_revert": plan, "dry_run": True}

    def apply(self, action_type: str, target: str) -> dict[str, Any]:
        key = self._key(action_type, target)
        self.calls.append(("apply", key))
        self.state.add(key)
        return {"output": {"blocked": key}, "revert": {"mechanism": "fake", "key": key}}

    def revert(self, plan: dict[str, Any]) -> dict[str, Any]:
        key = plan.get("key")
        self.calls.append(("revert", key))
        self.state.discard(key)
        return {"restored": key}


@pytest.fixture
def enforcer() -> RecordingEnforcer:
    return RecordingEnforcer()
