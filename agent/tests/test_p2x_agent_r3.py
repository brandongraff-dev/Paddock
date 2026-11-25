"""Round-3 regression tests for the agent (finding K2-2) and the docs (K2-2, K2-3).

Each test here failed against the round-2 tree for the reason named in its docstring.
"""
from __future__ import annotations

import logging
import os
import re
import uuid

from tests.test_agent import _server_action
from tests.test_p2x_agent import _linux_rig

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _doc(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_a_dead_man_report_refused_with_409_is_recorded_loudly_not_dropped_silently(tmp_path, caplog):
    """K2-2: the server already held the action as 'applied' (the ack of the applied result was lost), so the
    dead-man 'failed' report got 409 and the agent dropped it without a trace: the server kept 'applied' with a
    revert plan for a rule that was gone, and nothing on the host said so."""
    r, runner, _enf = _linux_rig(tmp_path)
    real = r.fleet.handle
    mode = {"v": "down"}
    refused = []

    def handle(m, p, h, b):
        if "/actions/" in p:
            if mode["v"] == "down":
                raise ConnectionResetError("cut off")
            if mode["v"] == "applied":
                refused.append(p)
                return 409, {}, {"detail": "action must be 'approved' to report a result (is 'applied')"}
        return real(m, p, h, b)
    r.fleet.handle = handle
    aid = str(uuid.uuid4())
    r.fleet.pending_actions = [_server_action(id=aid, action_type="block_ip", target="203.0.113.10")]
    r.agent.heartbeat()
    assert len(r.state.outbox) == 1 and len(runner.rules) == 2
    r.clock.t += 11 * 60
    r.agent.step()
    assert runner.rules == []                                 # the timer removed the block
    mode["v"] = "applied"                                     # the server holds it as 'applied': 409 on the report
    r.clock.t += 60
    with caplog.at_level(logging.ERROR, logger="paddock-agent"):
        r.agent.step()
    assert refused, "the dead-man report was never sent"
    rec = r.state.load_handled()[aid]
    assert rec["status"] == "failed" and rec["output"]["error"] == "deadman_reverted"
    assert rec.get("reported") is False                       # never claimed as delivered
    conflict = rec.get("report_conflict")
    assert isinstance(conflict, dict) and conflict.get("http_status") == 409, rec
    assert "applied" in conflict.get("detail", "")
    assert any(aid in m and "409" in m for m in caplog.messages), caplog.messages
    assert len(r.state.outbox) == 0
    # it never turns into a success claim, and it is not re-posted forever
    n = len(refused)
    r.clock.t += 60
    r.agent.step()
    assert len(refused) == n
    assert not any(p[1]["status"] == "applied" for p in r.fleet.results if p[0] == aid)


def test_docs_say_the_dead_man_report_can_be_refused_when_the_server_holds_the_action_as_applied():
    """K2-2: AGENT_V2.md claimed 'exactly the case the timer fires in'; the lost-ack case also exists."""
    text = _doc("docs", "AGENT_V2.md")
    assert "exactly the case the timer fires in" not in text
    assert "report_conflict" in text and "409" in text


def test_docs_do_not_call_the_missing_cap_net_raw_an_owner_decision():
    """K2-3: the contract (ASSURANCE_P2.md section 8) only says the bounding set is limited to what the P2
    collectors need; it records no decision about CAP_NET_RAW or legacy iptables."""
    for parts in (("docs", "AGENT_V2.md"), ("agent", "README.md"), ("docs", "FLEET_WIRING.md")):
        text = _doc(*parts)
        for para in re.split(r"\n\s*\n", text):
            if "CAP_NET_RAW" in para:
                # stating that NO decision is recorded is fine; presenting one as taken is not
                assert not re.search(r"(?<!no )(?<!not a recorded )owner\s+decision", para, re.I), (parts, para[:200])
