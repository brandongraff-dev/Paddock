"""SAFETY RAIL #1: an action can only ever target the LOCAL host. There is no
remote-host parameter, and remote-looking targets are refused."""
from __future__ import annotations

import inspect

import pytest

from palantir_agent import actions
from palantir_agent.actions import Action, HostLocalError, apply_action, assert_host_local


# Valid host-local targets normalise cleanly --------------------------------- #

@pytest.mark.parametrize("atype,target,expected", [
    ("block_ip", "203.0.113.10", "203.0.113.10"),
    ("block_ip", "2001:db8::1", "2001:db8::1"),
    ("block_domain", "Evil.Example", "evil.example"),
    ("quarantine_file", "/tmp/x/evil.bin", "/tmp/x/evil.bin"),
    ("firewall_rule", "IN:TCP:22", "in:tcp:22"),
])
def test_valid_host_local_targets(atype, target, expected):
    assert assert_host_local(atype, target) == expected


# Remote-looking / malformed targets are refused ----------------------------- #

@pytest.mark.parametrize("atype,target", [
    ("block_ip", "203.0.113.10:8080"),           # not a bare IP
    ("block_ip", "not-an-ip"),
    ("block_domain", "http://evil.example/x"),   # URL scheme -> remote-ish
    ("block_domain", "user@evil.example"),       # user@host -> remote-ish
    ("quarantine_file", "relative/path"),        # must be absolute local path
    ("quarantine_file", "/etc/../etc/passwd"),   # path traversal
    ("quarantine_file", "scp://host/evil"),      # remote transport
    ("firewall_rule", "ssh://10.0.0.1:22"),      # remote reference
    ("firewall_rule", "tcp"),                     # malformed port spec
])
def test_remote_or_malformed_targets_refused(atype, target):
    with pytest.raises(HostLocalError):
        assert_host_local(atype, target)


def test_no_remote_host_parameter_anywhere_in_action_or_apply():
    """There is structurally no way to tell the agent to act on another host:
    neither the Action model nor apply_action accepts a host/remote/target-host
    field."""
    action_fields = set(getattr(Action, "__dataclass_fields__", {}).keys())
    for forbidden in ("host", "remote_host", "target_host", "exec_host", "node", "address_of"):
        assert forbidden not in action_fields

    sig = inspect.signature(apply_action)
    for forbidden in ("host", "remote_host", "target_host", "exec_host"):
        assert forbidden not in sig.parameters

    # from_server ignores any stray 'host' a compromised server might send.
    a = Action.from_server({
        "id": "x", "action_type": "block_ip", "target": "203.0.113.10",
        "status": "approved", "dry_run": True, "host": "some-other-box",
    })
    assert not hasattr(a, "host")
    assert a.target == "203.0.113.10"


def test_enforcer_apply_signature_takes_only_type_and_target():
    """The enforcer's whole vocabulary is (action_type, target) on THIS host —
    there is no destination/host argument to route a block elsewhere."""
    from palantir_agent.platform_block import LinuxEnforcer
    sig = inspect.signature(LinuxEnforcer.apply)
    params = [p for p in sig.parameters if p != "self"]
    assert params == ["action_type", "target"]


def test_apply_rejects_remote_target_before_touching_enforcer(enforcer):
    a = Action(id="a1", action_type="block_domain", target="http://evil.example",
               status="approved", dry_run=False)
    with pytest.raises(HostLocalError):
        apply_action(a, enforcer, agent_dry_run=False)
    assert enforcer.state == set()
    assert enforcer.calls == []
