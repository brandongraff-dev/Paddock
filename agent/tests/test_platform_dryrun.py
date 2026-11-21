"""Platform abstraction: dry-run/simulate touches nothing, and the Windows /
macOS stubs can simulate but never apply."""
from __future__ import annotations

import pytest

from paddock_agent.platform_block import (
    LinuxEnforcer,
    MacEnforcer,
    NotSupportedError,
    WindowsEnforcer,
    detect_platform,
    get_enforcer,
)


class _BoomRunner:
    """A command runner that fails the test if anything tries to execute."""
    def __call__(self, cmd):  # pragma: no cover - should never be called
        raise AssertionError(f"enforcer executed a command during simulate: {cmd}")


def test_linux_simulate_runs_no_commands():
    enf = LinuxEnforcer(runner=_BoomRunner())
    for atype, target in [("block_ip", "203.0.113.10"),
                          ("block_domain", "evil.example"),
                          ("firewall_rule", "in:tcp:22"),
                          ("quarantine_file", "/tmp/suspShared.bin")]:
        plan = enf.simulate(atype, target)
        assert plan["dry_run"] is True
        assert "would" in plan
    # _BoomRunner never raised -> simulate executed nothing.


def test_linux_plan_shapes_are_reversible():
    enf = LinuxEnforcer(runner=_BoomRunner())
    plan = enf.simulate("block_ip", "203.0.113.10")["would"]
    assert plan["mechanism"] == "iptables"
    assert plan["add"][2] == "INPUT" and plan["remove"][2] == "INPUT"
    # the remove command is the inverse (-D) of the add (-I)
    assert "-I" in plan["add"] and "-D" in plan["remove"]


def test_windows_and_macos_are_dry_run_only():
    for enf in (WindowsEnforcer(), MacEnforcer()):
        assert enf.can_apply is False
        # simulate works (describes the plan)...
        sim = enf.simulate("block_ip", "203.0.113.10")
        assert sim["dry_run"] is True
        # ...but apply is a hard NotImplemented.
        with pytest.raises(NotSupportedError):
            enf.apply("block_ip", "203.0.113.10")
        with pytest.raises(NotSupportedError):
            enf.revert({"mechanism": "x"})


def test_detect_and_factory():
    assert detect_platform("Linux") == "linux"
    assert detect_platform("Darwin") == "macos"
    assert isinstance(get_enforcer("linux"), LinuxEnforcer)
    assert isinstance(get_enforcer("windows"), WindowsEnforcer)
    assert isinstance(get_enforcer("macos"), MacEnforcer)
    # unknown platform -> a never-apply stub, never a Linux enforcer
    assert get_enforcer("plan9").can_apply is False


def test_linux_quarantine_moves_never_deletes(tmp_path):
    victim = tmp_path / "evil.bin"
    victim.write_text("payload")
    qdir = tmp_path / "q"
    enf = LinuxEnforcer(quarantine_dir=str(qdir))
    res = enf.apply("quarantine_file", str(victim))
    assert not victim.exists()                       # moved out
    dest = res["output"]["moved"]["dest"]
    assert (qdir / dest.split("/")[-1]).exists()     # still exists in quarantine
    # revert restores it exactly
    enf.revert(res["revert"])
    assert victim.exists() and victim.read_text() == "payload"
