"""`paddock` -- the operator CLI for the paddock host agent.

    paddock enroll                  # token from $PADDOCK_ENROLL_TOKEN or stdin; NEVER argv
    paddock status
    paddock collect                 # collect the signed-posture payload locally and print it (no network)
    paddock posture                 # collect, sign and send one posture envelope now
    paddock rotate-key              # new signing key, signed over by the current one
    paddock inventory               # v1 (unsigned) inventory; --send uploads it
    paddock actions                 # list this host's actions (proposed/approved/...)
    paddock simulate TYPE TARGET    # DRY-RUN preview of a host-local action
    paddock apply ACTION_ID         # apply a SERVER-APPROVED action, after confirm
    paddock run                     # the signed heartbeat/posture loop

Exit status: 0 ok, 1 no posture produced / aborted, 2 usage / not enrolled / refused target, 3 refused by a
safety rail, 4 apply failed,
5 server error, 6 unusable state directory, 7 the server said, explicitly, that this agent is revoked or must
re-enroll (do not auto-restart). A bare 401/403/404 never causes exit 7: the daemon keeps retrying.

``rotate-key`` can run beside the daemon: it changes the key under the state-directory lock and sends the
running daemon SIGHUP so it reloads at once (a 401 would make it reload anyway). ``enroll`` needs the daemon
stopped.

Safety:
  * ``simulate`` never mutates -- it prints the plan the enforcer WOULD run.
  * ``apply`` refuses unless the server has the action in status 'approved' with dry_run=false, and the
    operator confirms interactively. The CLI NEVER applies an action the server has not approved.
  * The enrollment token is a secret: argv is world-readable in ``ps``, so ``--token`` is refused.
"""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import signal
import sys
from typing import Any, Dict, List, Optional

from . import __version__, signing
from .actions import Action, ActionError, HostLocalError, assert_host_local
from .agent import (
    EXIT_ACTION_FAILED,
    EXIT_NOT_ENROLLED,
    EXIT_RE_ENROLL,
    EXIT_REFUSED,
    EXIT_SERVER,
    EXIT_STATE,
    Agent,
    AgentError,
    Fatal,
)
from .client import FleetClientError
from .config import AgentConfig
from .platform_block import EnforcerError
from .state import StateError

TOKEN_ENV = "PADDOCK_ENROLL_TOKEN"


def _operator_headers() -> Dict[str, str]:
    """Operator credential for read/propose calls (separate from the agent token)."""
    tok = os.environ.get("PADDOCK_OPERATOR_TOKEN")
    return {"Authorization": "Bearer %s" % tok} if tok else {}


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def read_enroll_token(*, from_stdin: bool, environ=None, stdin=None) -> str:
    """The enrollment token from the environment or stdin (a prompt on a terminal). Never from argv."""
    environ = os.environ if environ is None else environ
    stdin = sys.stdin if stdin is None else stdin
    token = environ.get(TOKEN_ENV, "").strip()
    if token:
        try:
            del environ[TOKEN_ENV]           # do not hand the secret to child processes
        except (KeyError, TypeError):
            pass
        return token
    if from_stdin or not stdin.isatty():
        line = stdin.readline()
        return line.strip()
    return getpass.getpass("Enrollment token (input hidden): ").strip()


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def _cmd_enroll(args: argparse.Namespace, agent: Agent) -> int:
    token = read_enroll_token(from_stdin=args.token_stdin)
    if not token:
        print("no enrollment token: set %s or pipe it on stdin (it is never accepted as an argument)"
              % TOKEN_ENV, file=sys.stderr)
        return EXIT_NOT_ENROLLED
    creds = agent.enroll(token, hostname=args.hostname, force=args.force)
    _print({"enrolled": True, "agent_id": creds.agent_id, "tenant_id": creds.tenant_id,
            "hostname": creds.hostname, "server": creds.server, "key_id": creds.key_id,
            "state_dir": agent.state.dir})
    return 0


def _cmd_status(args: argparse.Namespace, agent: Agent) -> int:
    base: Dict[str, Any] = {"platform": agent.platform, "dry_run": agent.cfg.dry_run,
                            "server": agent.cfg.server or None, "state_dir": agent.state.dir,
                            "ed25519_backend": signing.backend_name(), "version": __version__}
    creds = agent.creds
    if not creds:
        _print(dict(base, enrolled=False))
        return 0
    status = dict(base, enrolled=True, agent_id=creds.agent_id, tenant_id=creds.tenant_id,
                  hostname=creds.hostname, server=agent.cfg.server or creds.server,
                  can_apply=agent.enforcer.can_apply, key_id=agent.key_id,
                  seq=agent.state.current_seq(), outbox_items=len(agent.state.outbox),
                  pending_key=agent.state.load_pending_key() is not None)
    try:
        detail = agent.client.get_agent(creds.agent_id, operator_headers=_operator_headers())
        status["server_view"] = {"status": detail.get("status"),
                                 "last_seen": detail.get("last_seen"),
                                 "action_counts": detail.get("action_counts", {})}
    except (FleetClientError, AgentError) as exc:
        status["server_view_error"] = str(exc)
    _print(status)
    return 0


def _cmd_collect(args: argparse.Namespace, agent: Agent) -> int:
    from .runner import Ctx
    ctx = Ctx(agent.cfg.state_dir, __version__, enable_imds=agent.cfg.enable_imds)
    payload, raw = agent.collect_payload(0, ctx=ctx)
    if args.raw:
        sys.stdout.write(raw.decode("utf-8") + "\n")
    else:
        _print(payload)
    return 0


def _cmd_posture(args: argparse.Namespace, agent: Agent) -> int:
    out = agent.send_posture()
    if out is None:
        print("error: no posture was produced (a collector failed; see the log). Nothing was sent.",
              file=sys.stderr)
        return 1
    _print({"sent": True, "seq": agent.state.current_seq(), "result": out})
    return 0


def _cmd_rotate(args: argparse.Namespace, agent: Agent) -> int:
    kid = agent.rotate_key()
    pid = agent.notify_daemon()
    _print({"rotated": True, "key_id": kid, "daemon_notified": pid})
    if pid is None and agent.state.daemon_pid() is not None:
        print("note: a running agent could not be signalled; it reloads the new key on its next refused "
              "request, or restart it: systemctl restart paddock-agent", file=sys.stderr)
    return 0


def _cmd_inventory(args: argparse.Namespace, agent: Agent) -> int:
    from .inventory import collect_inventory
    inv = collect_inventory(include_packages=not args.no_packages)
    if args.send:
        out = agent.send_inventory()
        _print({"sent": True, "unsigned": True, "result": out})
    else:
        _print(inv)
    return 0


def _cmd_actions(args: argparse.Namespace, agent: Agent) -> int:
    creds = agent.creds
    if not creds:
        print("not enrolled", file=sys.stderr)
        return EXIT_NOT_ENROLLED
    out = agent.client.list_actions(agent=creds.agent_id, status=args.status,
                                    operator_headers=_operator_headers())
    _print(out)
    return 0


def _cmd_simulate(args: argparse.Namespace, agent: Agent) -> int:
    """DRY-RUN preview of a host-local action. Touches nothing."""
    try:
        target = assert_host_local(args.action_type, args.target)
        plan = agent.enforcer.simulate(args.action_type, target)
    except (HostLocalError, EnforcerError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return EXIT_NOT_ENROLLED
    _print({"simulate": True, "dry_run": True, "action_type": args.action_type,
            "target": target, "plan": plan})
    return 0


def _find_action(agent: Agent, action_id: str) -> Optional[Dict[str, Any]]:
    out = agent.client.list_actions(agent=agent.creds.agent_id,  # type: ignore[union-attr]
                                    operator_headers=_operator_headers())
    for a in out.get("items", []):
        if str(a.get("id")) == action_id:
            return a
    return None


def _cmd_apply(args: argparse.Namespace, agent: Agent) -> int:
    """Apply a SERVER-APPROVED action after an interactive confirm."""
    creds = agent.creds
    if not creds:
        print("not enrolled", file=sys.stderr)
        return EXIT_NOT_ENROLLED
    srv = _find_action(agent, args.action_id)
    if srv is None:
        print("action %s not found for this host" % args.action_id, file=sys.stderr)
        return EXIT_NOT_ENROLLED
    if srv.get("status") != "approved":
        print("REFUSED: action status is '%s', not 'approved'. "
              "The CLI never applies an unapproved action." % srv.get("status"), file=sys.stderr)
        return EXIT_REFUSED
    if srv.get("dry_run"):
        print("REFUSED: action is still dry_run=true. An admin must approve it "
              "for real (apply_for_real) before it can be applied.", file=sys.stderr)
        return EXIT_REFUSED
    if not agent.enforcer.can_apply:
        print("REFUSED: platform '%s' is dry-run only (not implemented)." % agent.platform,
              file=sys.stderr)
        return EXIT_REFUSED
    print("About to APPLY on THIS host (%s):" % creds.hostname)
    print("  %s  %s" % (srv.get("action_type"), srv.get("target")))
    if not args.yes:
        reply = input("Proceed? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("aborted")
            return 1
    try:
        action = Action.from_server(srv)
    except ActionError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return EXIT_REFUSED
    outcome = agent.handle_action(action)
    _print({"applied": outcome.applied, "status": outcome.status, "output": outcome.output})
    return 0 if outcome.status == "applied" else EXIT_ACTION_FAILED


def _cmd_run(args: argparse.Namespace, agent: Agent) -> int:
    def _stop(_signum, _frame):
        agent.stop()

    def _reload(_signum, _frame):
        agent.request_reload()           # `paddock rotate-key` changed the key on disk
    for sig, handler in ((signal.SIGTERM, _stop), (signal.SIGINT, _stop),
                         (getattr(signal, "SIGHUP", None), _reload)):
        if sig is None:
            continue
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):  # not the main thread
            pass
    return agent.run(max_iterations=args.iterations)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="paddock", description="paddock host agent")
    p.add_argument("--version", action="version", version="paddock %s" % __version__)
    p.add_argument("--server", help="orchestrator base URL (default env PADDOCK_SERVER)")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="force dry-run (simulate only; never mutate)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("enroll", help="enroll this host (token from $%s or stdin)" % TOKEN_ENV)
    pe.add_argument("--token", help=argparse.SUPPRESS)      # refused: secrets never go on argv
    pe.add_argument("--token-stdin", action="store_true", help="read the token from stdin")
    pe.add_argument("--hostname", help="override reported hostname")
    pe.add_argument("--force", action="store_true",
                    help="re-enroll an already enrolled / wiped host (needs an admin's re-key token)")
    pe.set_defaults(func=_cmd_enroll)

    ps = sub.add_parser("status", help="show agent + server status")
    ps.set_defaults(func=_cmd_status)

    pc = sub.add_parser("collect", help="collect the posture payload locally and print it (no network)")
    pc.add_argument("--raw", action="store_true", help="print the exact canonical bytes that get signed")
    pc.set_defaults(func=_cmd_collect)

    pp = sub.add_parser("posture", help="collect, sign and send one posture envelope now")
    pp.set_defaults(func=_cmd_posture)

    pk = sub.add_parser("rotate-key", help="rotate the signing key")
    pk.set_defaults(func=_cmd_rotate)

    pi = sub.add_parser("inventory", help="collect (and optionally send) the v1 unsigned inventory")
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

    pr = sub.add_parser("run", help="start the signed heartbeat/posture run loop")
    pr.add_argument("--iterations", type=int, default=None, help="stop after N loops (testing)")
    pr.set_defaults(func=_cmd_run)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=os.environ.get("PADDOCK_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "token", None):
        print("error: enrollment tokens are never accepted on the command line (argv is visible to "
              "every local user). Set %s or pipe the token on stdin." % TOKEN_ENV, file=sys.stderr)
        return EXIT_NOT_ENROLLED
    cfg = AgentConfig().with_server(args.server)
    if getattr(args, "dry_run", False):
        cfg.dry_run = True
    agent = Agent(cfg)
    try:
        return int(args.func(args, agent))
    except Fatal as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_RE_ENROLL
    except AgentError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_NOT_ENROLLED
    except StateError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_STATE
    except FleetClientError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_SERVER
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
