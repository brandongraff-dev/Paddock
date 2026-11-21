"""Action state machine + the core safety rails, agent-side."""
from __future__ import annotations

import pytest

from paddock_agent.actions import (
    Action,
    ActionError,
    Status,
    apply_action,
    revert_action,
)


def _action(**kw):
    base = dict(id="a1", action_type="block_ip", target="203.0.113.10",
                status="approved", dry_run=False)
    base.update(kw)
    return Action(**base)


# RAIL #2: proposed (unapproved) can't apply -----------------------------------

def test_proposed_cannot_apply(enforcer):
    a = _action(status="proposed")
    with pytest.raises(ActionError):
        apply_action(a, enforcer, agent_dry_run=False)
    assert enforcer.state == set()          # nothing mutated
    assert ("apply", "block_ip:203.0.113.10") not in enforcer.calls


def test_denied_cannot_apply(enforcer):
    for bad in ("denied", "applied", "failed", "reverted"):
        with pytest.raises(ActionError):
            apply_action(_action(status=bad), enforcer, agent_dry_run=False)
    assert enforcer.state == set()


# RAIL #3: dry-run never mutates -----------------------------------------------

def test_action_dry_run_only_simulates(enforcer):
    a = _action(dry_run=True)               # approved but server-side dry_run
    out = apply_action(a, enforcer, agent_dry_run=False)
    assert out.status == "simulated"
    assert out.applied is False
    assert out.dry_run is True
    assert enforcer.state == set()          # <- no mutation
    assert [c[0] for c in enforcer.calls] == ["simulate"]


def test_agent_dry_run_forces_simulation_even_when_server_real(enforcer):
    a = _action(dry_run=False)              # server approved for real...
    out = apply_action(a, enforcer, agent_dry_run=True)   # ...but agent is dry
    assert out.status == "simulated"
    assert enforcer.state == set()


# Happy path: approved + real -> applied, with a revert plan -------------------

def test_approved_real_applies_and_records_revert(enforcer):
    a = _action(dry_run=False)
    out = apply_action(a, enforcer, agent_dry_run=False)
    assert out.status == "applied"
    assert out.applied is True
    assert out.revert and out.revert.get("key") == "block_ip:203.0.113.10"
    assert "block_ip:203.0.113.10" in enforcer.state


# RAIL #5: revert restores -----------------------------------------------------

def test_revert_restores_previous_state(enforcer):
    a = _action(dry_run=False)
    out = apply_action(a, enforcer, agent_dry_run=False)
    assert enforcer.state == {"block_ip:203.0.113.10"}

    revert = Action(id="r1", action_type="revert", target="203.0.113.10",
                    status="approved", dry_run=False,
                    revert_of="a1", result={"revert": out.revert})
    rout = revert_action(revert, enforcer, agent_dry_run=False)
    assert rout.status == "applied"
    assert enforcer.state == set()          # fully restored


def test_revert_is_dry_run_safe(enforcer):
    enforcer.state.add("block_ip:203.0.113.10")
    revert = Action(id="r1", action_type="revert", target="203.0.113.10",
                    status="approved", dry_run=False,
                    result={"revert": {"mechanism": "fake", "key": "block_ip:203.0.113.10"}})
    rout = revert_action(revert, enforcer, agent_dry_run=True)
    assert rout.status == "simulated"
    assert enforcer.state == {"block_ip:203.0.113.10"}   # untouched


# RAIL #6: only allowed actions -----------------------------------------------

def test_disallowed_action_type_refused(enforcer):
    a = _action(action_type="scan_network")
    with pytest.raises(ActionError):
        apply_action(a, enforcer, agent_dry_run=False)
    assert enforcer.state == set()
