"""`paddock` -- the operator CLI for the paddock host agent.

    paddock enroll   --server URL --token ENROLL_TOKEN
    paddock status
    paddock inventory               # collect (and with --send, upload) inventory
    paddock actions                 # list this host's actions (proposed/approved/...)
    paddock simulate TYPE TARGET    # DRY-RUN preview of a host-local action
    paddock apply ACTION_ID         # apply a SERVER-APPROVED action, after confirm
    paddock run                     # start the heartbeat/inventory run loop

Safety:
  * ``simulate`` never mutates -- it prints the plan the enforcer WOULD run.
  * ``apply`` refuses unless the server has the action in status 'approved' with
    dry_run=false, and the operator confirms interactively. The CLI NEVER
    applies an action the server has not approved.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

from . import __version__
from .actions import Action, HostLocalError, assert_host_local
from .agent import Agent
from .client import FleetClientError
from .config import AgentConfig
from .platform_block import get_enforcer


def _operator_headers() -> dict[str, str]:
    """Operator credential for read/propose calls (separate from the agent token)."""
    tok = os.environ.get("PADDOCK_OPERATOR_TOKEN")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _cmd_enroll(args: argparse.Namespace, agent: Agent) -> int:
    creds = agent.enroll(args.token, hostname=args.hostname)
    _print({"enrolled": True, "agent_id": creds.agent_id, "hostname": creds.hostname,
            "server": creds.server, "credential_stored": agent.cfg.cred_path})
    return 0


def _cmd_status(args: argparse.Namespace, agent: Agent) -> int:
    if not agent.creds:
        _print({"enrolled": False, "platform": agent.platform,
                "dry_run": agent.cfg.dry_run, "server": agent.cfg.server})
        return 0
    status: dict[str, Any] = {
        "enrolled": True, "agent_id": agent.creds.agent_id,
        "hostname": agent.creds.hostname, "platform": agent.platform,
        "dry_run": agent.cfg.dry_run, "can_apply": agent.enforcer.can_apply,
        "server": agent.cfg.server,
    }
    try:
        detail = agent.client.get_agent(agent.creds.agent_id, operator_headers=_operator_headers())
        status["server_view"] = {"status": detail.get("status"),
                                 "last_seen": detail.get("last_seen"),
                                 "action_counts": detail.get("action_counts", {})}
    except FleetClientError as exc:
        status["server_view_error"] = str(exc)
    _print(status)
    return 0


def _cmd_inventory(args: argparse.Namespace, agent: Agent) -> int:
    from .inventory import collect_inventory
    inv = collect_inventory(include_packages=not args.no_packages)
    if args.send:
        out = agent.send_inventory()
        _print({"sent": True, "result": out})
    else:
        _print(inv)
    return 0


def _cmd_actions(args: argparse.Namespace, agent: Agent) -> int:
    if not agent.creds:
        print("not enrolled", file=sys.stderr)
        return 2
    out = agent.client.list_actions(
        agent=agent.creds.agent_id, status=args.status,
        operator_headers=_operator_headers(),
    )
    _print(out)
    return 0


def _cmd_simulate(args: argparse.Namespace, agent: Agent) -> int:
    """DRY-RUN preview of a host-local action. Touches nothing."""
    try:
        target = assert_host_local(args.action_type, args.target)
    except HostLocalError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    enforcer = agent.enforcer if agent else get_enforcer(None)
    plan = enforcer.simulate(args.action_type, target)
    _print({"simulate": True, "dry_run": True, "action_type": args.action_type,
            "target": target, "plan": plan})
    return 0


def _find_action(agent: Agent, action_id: str) -> dict[str, Any] | None:
    out = agent.client.list_actions(agent=agent.creds.agent_id,
                                     operator_headers=_operator_headers())
    for a in out.get("items", []):
        if str(a.get("id")) == action_id:
            return a
    return None


def _cmd_apply(args: argparse.Namespace, agent: Agent) -> int:
    """Apply a SERVER-APPROVED action after an interactive confirm."""
    if not agent.creds:
        print("not enrolled", file=sys.stderr)
        return 2
    srv = _find_action(agent, args.action_id)
    if srv is None:
        print(f"action {args.action_id} not found for this host", file=sys.stderr)
        return 2
    if srv.get("status") != "approved":
        print(f"REFUSED: action status is '{srv.get('status')}', not 'approved'. "
              "The CLI never applies an unapproved action.", file=sys.stderr)
        return 3
    if srv.get("dry_run"):
        print("REFUSED: action is still dry_run=true. An admin must approve it "
              "for real (apply_for_real) before it can be applied.", file=sys.stderr)
        return 3
    if not agent.enforcer.can_apply:
        print(f"REFUSED: platform '{agent.platform}' is dry-run only (not implemented).",
              file=sys.stderr)
        return 3
    print(f"About to APPLY on THIS host ({agent.creds.hostname}):")
    print(f"  {srv.get('action_type')}  {srv.get('target')}")
    if not args.yes:
        reply = input("Proceed? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("aborted")
            return 1
    outcome = agent.handle_action(Action.from_server(srv))
    _print({"applied": outcome.applied, "status": outcome.status, "output": outcome.output})
    return 0 if outcome.status == "applied" else 4


def _cmd_run(args: argparse.Namespace, agent: Agent) -> int:
    agent.run(max_iterations=args.iterations)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="paddock", description="paddock host agent")
    p.add_argument("--version", action="version", version=f"paddock {__version__}")
    p.add_argument("--server", help="orchestrator base URL (default env PADDOCK_SERVER)")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="force dry-run (simulate only; never mutate)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("enroll", help="enroll this host with the orchestrator")
    pe.add_argument("--token", required=True, help="enrollment bootstrap token")
    pe.add_argument("--hostname", help="override reported hostname")
    pe.set_defaults(func=_cmd_enroll)

    ps = sub.add_parser("status", help="show agent + server status")
    ps.set_defaults(func=_cmd_status)

    pi = sub.add_parser("inventory", help="collect (and optionally send) inventory")
    pi.add_argument("--send", action="store_true", help="upload to the orchestrator")
    pi.add_argument("--no-packages", action="store_true", help="skip the package list")
    pi.set_defaults(func=_cmd_inventory)

    pa = sub.add_parser("actions", help="list this host's actions")
    pa.add_argument("--status", help="filter by status (proposed/approved/applied/...)")
    pa.set_defaults(func=_cmd_actions)

    psim = sub.add_parser("simulate", help="dry-run preview of a host-local action")
    psim.add_argument("action_type", choices=sorted(
        {"block_ip", "block_domain", "quarantine_file", "firewall_rule"}))
    psim.add_argument("target")
    psim.set_defaults(func=_cmd_simulate)

    pap = sub.add_parser("apply", help="apply a server-approved action (confirm required)")
    pap.add_argument("action_id")
    pap.add_argument("--yes", action="store_true", help="skip the interactive confirm")
    pap.set_defaults(func=_cmd_apply)

    pr = sub.add_parser("run", help="start the heartbeat/inventory run loop")
    pr.add_argument("--iterations", type=int, default=None, help="stop after N loops (testing)")
    pr.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=os.environ.get("PADDOCK_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = AgentConfig().with_server(args.server)
    if getattr(args, "dry_run", False):
        cfg.dry_run = True
    agent = Agent(cfg)
    try:
        return int(args.func(args, agent))
    except FleetClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
