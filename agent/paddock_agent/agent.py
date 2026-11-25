"""The agent: enrollment, the signed heartbeat/posture run loop, key rotation and action handling.

Run loop. Every tick (``heartbeat_interval_s``, jittered): flush the outbox (oldest first), send a
signed ``heartbeat`` envelope (the reply lists approved, real actions to carry out), and when due
(``posture_interval_s``) collect, sign and send a ``posture`` envelope. A network blip never kills the
loop: every transport error is a :class:`FleetClientError`, the loop backs off (jittered exponential,
capped at 300 s) and tries again. Only an explicit, structured verdict from the server ("this agent may not
talk to the server any more": a JSON body carrying ``agent_revoked`` or ``re_enroll_required``) ends it, with
exit status 7. A bare 401/403/404 (a WAF, an ingress, a captive portal, a key rotated by another process) is
never terminal: the agent re-reads its key and credentials from disk (a 401 may just mean `paddock rotate-key`
ran), retries once, and otherwise keeps retrying at the capped backoff.

Sequence numbers are reserved write-ahead (:meth:`state.State.next_seq`) before anything is signed, so a
crash can skip a number but never reuse one. An envelope that could not be delivered is re-sent
byte-for-byte (same seq, so the server treats an identical retry as idempotent) for as long as it is
fresh enough for the server's 600 s clock window; after that it is dropped (the next posture replaces it).

Actions. The agent NEVER applies an action the server has not marked ``approved``, and NEVER applies
anything when running dry. It re-validates every target as host-local, reports a real outcome (with a
revert plan) back to the server, and remembers what it already did, so a lost reply can never make it
apply the same action twice. A revert plan from the server is untrusted data (see ``platform_block``).

Every real apply writes an *intent* record (status ``applying``) to ``handled.json`` before the first change
to the host and finalises it afterwards, and the enforcer's changes are idempotent per action id, so a crash
anywhere in between re-runs to the same end state. The records are also the agent's ledger: a revert is
accepted only for a rule this agent applied and has not yet reverted. A block that is never confirmed by a
later successful round trip with the server is removed by the dead-man timer (``deadman_minutes``).

The state directory is exclusive: one daemon at a time (``.instance.lock``), and every read-modify-write of
the counter, the key files and ``handled.json`` runs under ``.state.lock``, so a CLI command can run beside
the daemon without reusing a sequence number. After `paddock rotate-key` the CLI sends the daemon SIGHUP
(reload); a 401 also makes the daemon re-read its key and credentials from disk before it counts a failure.
"""
from __future__ import annotations

import contextlib
import logging
import os
import random
import re
import signal
import socket
import threading
import time
import urllib.request
import uuid
from typing import Any, Callable, Dict, Optional

from . import __version__, envelope, signing
from .actions import (
    Action,
    ActionError,
    HostLocalError,
    Outcome,
    SelfGuard,
    apply_action,
    revert_action,
)
from .client import FleetClient, FleetClientError, backoff_delay, normalize_server
from .config import AgentConfig
from .inventory import collect_inventory
from .platform_block import BaseEnforcer, detect_platform, get_enforcer
from .state import Credentials, InstanceBusy, State, StateError

log = logging.getLogger("paddock-agent")

EXIT_OK = 0
EXIT_NOT_ENROLLED = 2
EXIT_REFUSED = 3
EXIT_ACTION_FAILED = 4
EXIT_SERVER = 5
EXIT_STATE = 6
EXIT_RE_ENROLL = 7

CAPABILITIES = ["block", "inventory", "posture", "quarantine"]
MAX_AUTH_FAILURES = 10          # consecutive 401/403/404 answers after which the log says so loudly (never terminal)
TERMINAL_CODES = frozenset({"agent_revoked", "re_enroll_required"})   # explicit structured server verdicts
MAX_RESULT_AGE_S = 24 * 3600     # a queued action result older than this is dropped (the server re-offers the action)
MAX_ITEM_ATTEMPTS = 8            # failed re-sends of one queued item before it is dropped (it cannot block the rest)
MAX_ACTIONS_PER_HEARTBEAT = 50
DEADMAN = "dead-man timer"       # handled.json ``reverted_by`` of a block the agent removed on its own
MAX_OUTBOX_AGE_S = 480           # the server accepts |now - issued_at| <= 600 s; stay well inside it
FORCE_FULL_MANIFEST_EVERY_S = 24 * 3600
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AgentError(RuntimeError):
    """An operator-facing problem (not enrolled, bad hostname, already enrolled, ...)."""


class Fatal(AgentError):
    """The server will not talk to this agent any more; re-enrollment is required."""


def _manifest_sha(payload: Any) -> Optional[str]:
    """The package-manifest digest inside a posture payload, if the patch collector produced one."""
    try:
        sub = payload["sections"]["patch"]["v"]["manifest"]
        if sub.get("state") == "ok" and _SHA256_RE.match(str(sub.get("sha256"))):
            return str(sub["sha256"])
    except (KeyError, TypeError, AttributeError):
        pass
    return None


class Agent:
    def __init__(self, cfg: AgentConfig, *, client: Optional[FleetClient] = None,
                 enforcer: Optional[BaseEnforcer] = None, state: Optional[State] = None,
                 collect_fn: Optional[Callable[[Any], Any]] = None,
                 encode_fn: Optional[Callable[[Any], bytes]] = None,
                 ctx_factory: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 rand: Optional[Callable[[], float]] = None,
                 resolver: Optional[Callable[..., Any]] = None) -> None:
        self.cfg = cfg
        self.platform = detect_platform(cfg.platform_name)
        self.state = state or State(cfg.state_dir, cfg.outbox_max_bytes)
        self._client = client
        self._enforcer = enforcer
        self._collect_fn = collect_fn
        self._encode_fn = encode_fn
        self._ctx_factory = ctx_factory
        self._clock = clock
        self._mono = monotonic
        self._rand = rand or random.random
        self._resolver = resolver or socket.getaddrinfo      # resolves the server for the self-lockout guard
        self._owns_client = client is None
        self._reload_requested = threading.Event()
        self._item_attempts: Dict[str, int] = {}
        self._unconfirmed = True       # blocks applied earlier may still await a successful round trip
        self._retry_now = False
        self._ctx_forced = False
        self._creds: Optional[Credentials] = None
        self._creds_loaded = False
        self._seed: Optional[bytes] = None
        self._stop = threading.Event()
        self._auth_failures = 0
        self._known_manifest: Optional[str] = None
        self._force_full_at = 0.0
        self._last_posture: Optional[float] = None
        self._last_inv: Optional[float] = None
        self.stats: Dict[str, int] = {"expired": 0, "dropped": 0, "posture_ok": 0, "heartbeat_ok": 0}

    # ------------------------------------------------------------------ #
    # lazily built collaborators (so `simulate` and `status` need no server or state)
    # ------------------------------------------------------------------ #
    @property
    def creds(self) -> Optional[Credentials]:
        if not self._creds_loaded:
            self._creds = self.state.load_credentials()
            self._creds_loaded = True
        return self._creds

    @property
    def enforcer(self) -> BaseEnforcer:
        if self._enforcer is None:
            self._enforcer = get_enforcer(self.platform, quarantine_dir=self.cfg.quarantine_dir,
                                          protected_paths=[self.cfg.state_dir])
        return self._enforcer

    @property
    def client(self) -> FleetClient:
        if self._client is not None:
            creds = self.creds
            if creds is not None and not self._client.agent_token:     # an injected, anonymous client
                self._client.agent_id, self._client.agent_token = creds.agent_id, creds.agent_token
        else:
            server = self.cfg.server or (self.creds.server if self.creds else "")
            if not server:
                raise AgentError("no server configured: set PADDOCK_SERVER or pass --server")
            if self.creds and self.creds.server and self.cfg.server:
                try:
                    differs = (normalize_server(self.cfg.server).lower()
                               != normalize_server(self.creds.server).lower())
                except FleetClientError as exc:
                    raise AgentError(str(exc))
                if differs:
                    raise AgentError(
                        "the configured server (%s) differs from the server this host enrolled with (%s); the "
                        "agent credential and signed postures are only ever sent to the enrolled server. Fix "
                        "PADDOCK_SERVER / --server, or re-enroll with `paddock enroll --force`"
                        % (self.cfg.server, self.creds.server))
            self._client = FleetClient(
                server, agent_id=self.creds.agent_id if self.creds else None,
                agent_token=self.creds.agent_token if self.creds else None,
                timeout_s=self.cfg.timeout_s, ca_file=self.cfg.ca_file)
        return self._client

    def _require_enrolled(self) -> Credentials:
        creds = self.creds
        if creds is None or not creds.agent_token:
            raise AgentError("this host is not enrolled; run `paddock enroll` with a one-time token")
        return creds

    def _signing_seed(self) -> bytes:
        if self._seed is None:
            seed = self.state.load_key()
            if seed is None:
                raise AgentError("no signing key in %s; this host must be re-enrolled with a new "
                                 "one-time token" % self.state.keys_dir)
            self._seed = seed
        return self._seed

    @property
    def key_id(self) -> str:
        return signing.key_id(signing.public_key(self._signing_seed()))

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ #
    # another process changed our key / credentials on disk
    # ------------------------------------------------------------------ #
    def request_reload(self) -> None:
        """Ask the loop to re-read its key and credentials at the next tick (the SIGHUP handler calls this)."""
        self._reload_requested.set()

    def notify_daemon(self) -> Optional[int]:
        """Tell the daemon holding this state directory (if any) to reload; returns its pid or ``None``."""
        pid = self.state.daemon_pid()
        hup = getattr(signal, "SIGHUP", None)
        if not pid or hup is None:                           # no daemon (or no SIGHUP on this platform)
            return None
        try:
            os.kill(pid, hup)
        except OSError as exc:
            log.warning("could not signal the running agent (pid %s): %s", pid, exc)
            return None
        return pid

    def _reload_from_disk(self) -> bool:
        """Re-read the key and credentials from disk. True when either changed (so a refused request is worth
        retrying: `paddock rotate-key` or `enroll --force` ran in another process)."""
        try:
            seed = self.state.load_key()
            creds = self.state.load_credentials()
        except StateError as exc:
            log.error("cannot re-read the key / credentials from disk: %s", exc)
            return False
        changed = False
        if seed is not None and self._seed is not None and seed != self._seed:
            changed = True
        if seed is not None:
            self._seed = seed
        old = self._creds if self._creds_loaded else None
        if creds is not None:
            if old is not None and (old.agent_token != creds.agent_token or old.agent_id != creds.agent_id
                                    or old.tenant_id != creds.tenant_id or old.server != creds.server):
                changed = True
            self._creds, self._creds_loaded = creds, True
            if self._client is not None:
                if old is not None and old.server != creds.server and self._owns_client:
                    self._client = None                      # rebuilt lazily for the new server
                else:
                    self._client.agent_id, self._client.agent_token = creds.agent_id, creds.agent_token
        if changed:
            log.warning("the key or credentials on disk changed (rotated or re-enrolled elsewhere); "
                        "reloaded them")
            self._auth_failures = 0
            self._drop_queued_postures()
        return changed

    def _drop_queued_postures(self) -> None:
        """Queued postures were signed by a key that may no longer be active: the server would refuse them."""
        for path in self.state.outbox.files():
            item = self.state.outbox.read(path)
            if item is not None and item.get("kind") == "posture":
                self.state.outbox.delete(path)

    @contextlib.contextmanager
    def _hold_instance(self, what: str):
        """This process owns the state directory exclusively (no daemon, no second command) for the block."""
        owned = self.state._instance_fd is None
        if owned:
            try:
                self.state.acquire_instance()
            except InstanceBusy as exc:
                raise AgentError("%s; stop it first (systemctl stop paddock-agent) before %s" % (exc, what))
        try:
            yield
        finally:
            if owned:
                self.state.release_instance()

    # ------------------------------------------------------------------ #
    # enrollment
    # ------------------------------------------------------------------ #
    def enroll(self, token: str, *, hostname: Optional[str] = None, force: bool = False) -> Credentials:
        """Enroll this host: new key, proof of possession, one-time token. The token is never persisted.

        With ``force`` the host re-enrolls (a wiped state dir, or a re-key token from an admin): a NEW key
        is always generated; the previous key is replaced only after the server accepted the new one.
        """
        if self.creds is not None and not force:
            raise AgentError("this host is already enrolled as agent %s; to re-enroll it (wiped state, "
                             "lost key) get a re-key token from an admin and pass --force"
                             % self.creds.agent_id)
        with self._hold_instance("enrolling"), self.state.exclusive():
            return self._enroll_locked(token, hostname=hostname, force=force)

    def _enroll_locked(self, token: str, *, hostname: Optional[str], force: bool) -> Credentials:
        host = hostname or socket.gethostname()
        if not _HOSTNAME_RE.match(host):
            raise AgentError("hostname %r is not acceptable to the server (letters, digits, . _ : -); "
                             "pass --hostname" % host)
        try:
            prefix = envelope.token_prefix(token)
        except envelope.EnvelopeError as exc:
            raise AgentError(str(exc))
        server = self.cfg.server
        if not server:
            raise AgentError("no server configured: set PADDOCK_SERVER or pass --server")
        client = self._client or FleetClient(server, timeout_s=self.cfg.timeout_s, ca_file=self.cfg.ca_file)

        seed = signing.generate_seed()
        pub = signing.public_key(seed)
        kid = signing.key_id(pub)
        self.state.ensure_dir()
        self.state.save_pending_key(seed)         # on disk BEFORE the token is spent
        try:
            out = client.enroll(
                token=token, hostname=host, public_key_b64=envelope.b64u(pub),
                proof_b64=envelope.enroll_proof(seed, prefix, host), agent_version=__version__,
                capabilities=CAPABILITIES)
            agent_id = _need_uuid(out, "agent_id")
            tenant_id = _need_uuid(out, "tenant_id")
            agent_token = out.get("agent_token")
            if not isinstance(agent_token, str) or not agent_token.startswith("fat_"):
                raise AgentError("the server did not return an agent credential")
            if "key_id" in out and out["key_id"] != kid:
                raise AgentError("the server registered a different key id than the one sent")
        except BaseException:
            self.state.discard_pending_key()
            raise
        creds = Credentials(agent_id=agent_id, agent_token=agent_token, tenant_id=tenant_id,
                            server=server.rstrip("/"), hostname=host, key_id=kid,
                            enrolled_at=envelope.issued_at_iso(self._clock()))
        self.state.save_credentials(creds)
        self.state.promote_pending_key()
        self._creds, self._creds_loaded, self._seed = creds, True, None
        client.agent_id, client.agent_token = agent_id, agent_token
        self._client = client
        self._auth_failures = 0
        log.info("enrolled as agent %s (%s) with key %s", agent_id, host, kid)
        return creds

    # ------------------------------------------------------------------ #
    # envelope plumbing
    # ------------------------------------------------------------------ #
    def _machine_salt(self) -> bytes:
        return ("paddock-machine/v1:%s" % (self.creds.tenant_id if self.creds else "")).encode("utf-8")

    def _build(self, kind: str, payload: bytes, payload_type: str, seq: int,
               collectors: Dict[str, str], seed: Optional[bytes] = None) -> Dict[str, Any]:
        creds = self._require_enrolled()
        return envelope.build_envelope(
            seed or self._signing_seed(), agent_id=creds.agent_id, tenant_id=creds.tenant_id, kind=kind,
            seq=seq, issued_at=int(self._clock()), payload=payload, payload_type=payload_type,
            collectors=collectors)

    def _send(self, method: str, env: Dict[str, Any]) -> Any:
        """Deliver one envelope. On failure the exception carries ``verdict``."""
        try:
            out = getattr(self.client, method)(env)
        except FleetClientError as exc:
            if (exc.status == 401 and not (exc.structured_codes() & TERMINAL_CODES)
                    and self._reload_from_disk()):
                # the key / credentials changed on disk: this envelope was signed with a retired key. Not an
                # auth failure; the tick is retried at once with what is on disk now.
                exc.verdict = "retry"  # type: ignore[attr-defined]
                exc.stale_key = True  # type: ignore[attr-defined]
                self._retry_now = True
                raise
            exc.verdict = self._verdict(exc)  # type: ignore[attr-defined]
            raise
        self._auth_failures = 0
        self._confirm_blocks()
        return out

    def _verdict(self, exc: FleetClientError) -> str:
        """``retry`` (transient), ``drop`` (the bytes can never be accepted), ``auth`` or ``fatal``."""
        if exc.transient:
            return "retry"
        if exc.status in (401, 403, 404):          # 404: the server no longer knows this agent id
            verdict = exc.structured_codes() & TERMINAL_CODES
            if verdict:
                # only the server's own, explicit, structured answer is terminal
                log.error("the server says this agent may not talk to it any more (%s); stopping",
                          ", ".join(sorted(verdict)))
                return "fatal"
            self._auth_failures += 1
            if self._auth_failures >= MAX_AUTH_FAILURES:
                log.error("server keeps refusing this agent (HTTP %s, %d in a row) without saying it is "
                          "revoked: a gateway or proxy in the way? still retrying at the capped backoff; "
                          "if this host was revoked the server will say so explicitly",
                          exc.status, self._auth_failures)
            else:
                log.error("server refused this agent's credentials (HTTP %s, %d in a row): a gateway in the "
                          "way, a revoked agent or a key rotated elsewhere; retrying",
                          exc.status, self._auth_failures)
            return "auth"
        if exc.status == 409:
            expected = exc.body.get("expected_min") if isinstance(exc.body, dict) else None
            if self.state.fast_forward(expected):
                log.warning("sequence behind the server's (409); continuing from %s", expected)
            else:
                log.warning("server answered 409 (replay or already claimed); dropping that envelope")
            return "drop"
        if exc.status == 422:
            now = exc.body.get("server_now") if isinstance(exc.body, dict) else None
            log.error("server rejected the envelope (422); this host's clock may be off (server_now=%s)", now)
            return "drop"
        log.error("server rejected the request permanently (HTTP %s); dropping it", exc.status)
        return "drop"

    # ------------------------------------------------------------------ #
    # heartbeat (signed) + action handling
    # ------------------------------------------------------------------ #
    def heartbeat(self) -> Dict[str, Any]:
        """Send one signed heartbeat and carry out the approved actions it returns."""
        self._require_enrolled()
        seq = self.state.next_seq()
        payload = envelope.canon({"agent_version": __version__, "status": "ok"})
        env = self._build(envelope.KIND_HEARTBEAT, payload, envelope.PAYLOAD_TYPE_HEARTBEAT, seq,
                          {"agent": __version__})
        hb = self._send("heartbeat", env)
        self.stats["heartbeat_ok"] += 1
        if not isinstance(hb, dict):
            return {}
        pending = hb.get("pending_actions")
        if isinstance(pending, list):
            for raw in pending[:MAX_ACTIONS_PER_HEARTBEAT]:
                try:
                    self.handle_action(Action.from_server(raw))
                except ActionError as exc:
                    log.warning("refused an action from the server: %s", exc)
                except Exception:  # noqa: BLE001 -- one bad action never stops the loop
                    log.exception("failed handling action %s",
                                  raw.get("id") if isinstance(raw, dict) else "?")
        return hb

    # -- the ledger: what this agent applied (handled.json) ------------------ #
    @staticmethod
    def _rule_of(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The typed rule a handled record stands for, while it is still in force on the host."""
        if not isinstance(rec, dict) or rec.get("reverted"):
            return None
        rule = rec.get("rule")
        if isinstance(rule, dict):
            if rule.get("reverted") or not isinstance(rule.get("action_type"), str) \
                    or not isinstance(rule.get("target"), str):
                return None
            return rule
        # records written before the ledger existed: an applied action keeps its own revert plan
        rv = rec.get("revert")
        if rec.get("status") == "applied" and isinstance(rv, dict) and isinstance(rv.get("action_type"), str) \
                and isinstance(rv.get("target"), str):
            return {"action_type": rv["action_type"], "target": rv["target"],
                    "tag": rv.get("tag") if isinstance(rv.get("tag"), str) else None}
        return None

    def _ledger_find(self, handled: Dict[str, Any], action_type: str, target: str, tag: Optional[str] = None):
        """``(id, record, rule)`` of the newest unreverted record of applying exactly this, or ``None``. With a
        ``tag`` only the record whose rule carries exactly that tag counts (so an older block of the same
        target is reverted by its own action, whatever newer blocks exist)."""
        best = None
        for aid, rec in handled.items():
            rule = self._rule_of(rec)
            if rule is None or rule["action_type"] != action_type or rule["target"] != target:
                continue
            if tag is not None and rule.get("tag") != tag:
                continue
            if best is None or rec.get("at", 0) >= best[1].get("at", 0):
                best = (aid, rec, rule)
        return best

    def _ledger(self, handled: Dict[str, Any]):
        def lookup(action_type: str, target: str, tag: Optional[str] = None) -> Optional[Dict[str, Any]]:
            hit = self._ledger_find(handled, action_type, target, tag)
            return hit[2] if hit else None
        return lookup

    def _guard(self) -> SelfGuard:
        """The self-lockout guard for one action: the server, every proxy the environment names (whether or not
        no_proxy would bypass it: refusing more is the safe side) and the addresses the client really reached."""
        try:
            proxies = [v for k, v in urllib.request.getproxies().items() if k != "no" and isinstance(v, str)]
        except Exception:  # noqa: BLE001 -- an unreadable proxy configuration must not disable the guard
            proxies = []
        return SelfGuard(self.client.base, resolver=self._resolver, proxies=proxies,
                         peers=tuple(getattr(self.client, "peers", ()) or ()))

    def handle_action(self, action: Action) -> Outcome:
        """Apply (or revert) one server-approved action under the safety gate; report real outcomes."""
        with self.state.exclusive():
            done = self._handle_locked(action)
        if isinstance(done, Outcome):
            return done
        outcome, record = done
        self._report(action.id, record)
        log.info("carried out %s for action %s (%s %s)", outcome.status, action.id,
                 action.action_type, action.target)
        return outcome

    def _handle_locked(self, action: Action):
        handled = self.state.load_handled()
        prior = handled.get(action.id)
        if isinstance(prior, dict) and prior.get("status") in ("applied", "failed") and not self.cfg.dry_run:
            # Already carried out (our reply was lost). Never apply twice: just re-send the result.
            log.info("action %s was already carried out (%s); re-sending its result", action.id,
                     prior.get("status"))
            outcome = Outcome(status=prior["status"], dry_run=False, applied=prior["status"] == "applied",
                              output=prior.get("output") or {}, revert=prior.get("revert"))
            return outcome, prior
        # (a prior status of "applying" is a crash between the intent record and the final one: the enforcer's
        # changes are idempotent per action id, so applying again converges on the same end state)

        def intent(action_type: str, target: str) -> None:
            rule = {"action_type": action_type, "target": target, "applied_at": int(self._clock()),
                    "confirmed": False, "reverted": False}
            if action_type in ("block_ip", "firewall_rule") and getattr(self.enforcer, "tags_rules", False):
                rule["tag"] = "paddock:%s" % action.id
            handled[action.id] = {"at": int(self._clock()), "status": "applying", "output": {}, "revert": None,
                                  "reported": False, "rule": rule}
            self.state.save_handled(handled)

        try:
            if action.action_type == "revert":
                outcome = revert_action(action, self.enforcer, agent_dry_run=self.cfg.dry_run,
                                        ledger=self._ledger(handled))
            else:
                outcome = apply_action(action, self.enforcer, agent_dry_run=self.cfg.dry_run,
                                       guard=self._guard(), intent=intent)
        except HostLocalError as exc:
            # An approved action whose target is not host-local can never succeed: say so (once), or the
            # server would offer it again on every heartbeat. A dry run never changes server state.
            if self.cfg.dry_run or action.dry_run:
                log.warning("refused %s %r (dry-run): %s", action.action_type, action.target, exc)
                return Outcome(status="simulated", dry_run=True, applied=False,
                               output={"dry_run": True, "refused": "not_host_local", "detail": str(exc)})
            outcome = Outcome(status="failed", dry_run=False, applied=False,
                              output={"error": "not_host_local", "detail": str(exc)})

        # Report only terminal real outcomes to the server. A simulation on the run loop changes no
        # server state (operators drive simulations via the CLI), so log it and move on.
        if outcome.status == "simulated":
            log.info("simulated %s %s (dry-run): %s", action.action_type, action.target, outcome.output)
            return outcome
        record = {"at": int(self._clock()), "status": outcome.status, "output": outcome.output,
                  "revert": outcome.revert, "reported": False}
        if action.action_type == "revert":
            if outcome.status == "applied" and outcome.rule:
                hit = self._ledger_find(handled, outcome.rule["action_type"], outcome.rule["target"],
                                        outcome.rule.get("tag"))
                if hit is not None:                      # this rule is no longer in force on the host
                    hit[1]["reverted"] = True
                    hit[1]["reverted_by"] = action.id
                    if isinstance(hit[1].get("rule"), dict):
                        hit[1]["rule"]["reverted"] = True
        elif outcome.rule is not None and (outcome.status == "applied" or outcome.revert):
            # applied, or a partial apply whose rollback failed: either way a rule is in force on the host
            prev = handled.get(action.id, {}).get("rule") if isinstance(handled.get(action.id), dict) else None
            rule = dict(prev) if isinstance(prev, dict) else {"applied_at": int(self._clock()),
                                                                 "confirmed": False, "reverted": False}
            rule.update(outcome.rule)
            if outcome.status != "applied":
                rule["partial"] = True
            record["rule"] = rule
            self._unconfirmed = True
        handled[action.id] = record
        self.state.save_handled(handled)          # before the reply: a lost reply must not mean a re-apply
        return outcome, record

    def _report(self, action_id: str, record: Dict[str, Any]) -> bool:
        """Post a result; on a transient failure queue it (durably) for the next tick."""
        try:
            self.client.post_result(action_id, status=record["status"], output=record.get("output") or {},
                                    revert=record.get("revert"))
        except FleetClientError as exc:
            if exc.transient:
                self.state.outbox.put({"kind": "result", "action_id": action_id, "status": record["status"],
                                       "output": record.get("output") or {}, "revert": record.get("revert"),
                                       "issued": int(self._clock())})
                log.warning("could not report action %s (%s); queued for retry", action_id, exc)
            else:
                log.error("server refused the result of action %s (%s); not retrying", action_id, exc)
            return False
        self._mark_reported(action_id)
        self._confirm_blocks()
        return True

    def _mark_reported(self, action_id: str) -> None:
        with self.state.exclusive():
            handled = self.state.load_handled()
            if action_id in handled:
                handled[action_id]["reported"] = True
                self.state.save_handled(handled)

    # -- dead-man timer ------------------------------------------------------ #
    def _confirm_blocks(self) -> None:
        """A successful round trip with the server after a block was applied proves the block did not cut the
        agent off: from now on the dead-man timer leaves it alone."""
        if not self._unconfirmed:
            return
        with self.state.exclusive():
            handled = self.state.load_handled()
            now, changed = int(self._clock()), False
            for rec in handled.values():
                rule = rec.get("rule") if isinstance(rec, dict) else None
                if isinstance(rule, dict) and not rule.get("confirmed") and not rule.get("reverted") \
                        and int(rule.get("applied_at", 0)) <= now:
                    rule["confirmed"] = True
                    changed = True
            if changed:
                self.state.save_handled(handled)
        self._unconfirmed = False

    def _queue_deadman_result(self, action_id: str, rec: Dict[str, Any]) -> None:
        """Make sure a truthful (failed) result for ``action_id`` is queued unless one already waits."""
        box = self.state.outbox
        try:
            for path in box.files():
                item = box.read(path)
                if isinstance(item, dict) and item.get("kind") == "result" and item.get("action_id") == action_id:
                    return          # flush_outbox substitutes the recorded truth for whatever it carries
            box.put({"kind": "result", "action_id": action_id, "status": rec["status"], "output": rec["output"],
                     "revert": None, "issued": int(self._clock())})
        except OSError as exc:
            log.error("dead-man timer: could not queue the report for action %s (%s); the server will be told "
                      "when it offers the action again", action_id, exc)

    def _recorded_truth(self, action_id: str):
        """``(status, output)`` this host recorded for an action whose block its dead-man timer removed, else
        ``None``: a queued result written before that must not say 'applied'."""
        try:
            rec = self.state.load_handled().get(action_id)
        except StateError:
            return None
        if isinstance(rec, dict) and rec.get("reverted_by") == DEADMAN and rec.get("status") == "failed":
            return rec["status"], rec.get("output") or {}
        return None

    def _deadman_tick(self) -> None:
        """Remove a network block that the server never heard about again within ``deadman_minutes``."""
        minutes = getattr(self.cfg, "deadman_minutes", 0)
        if not minutes or not self._unconfirmed:
            return
        now = int(self._clock())
        with self.state.exclusive():
            handled = self.state.load_handled()
            due = [(aid, rec) for aid, rec in handled.items()
                   if isinstance(rec, dict) and isinstance(rec.get("rule"), dict)
                   and rec["rule"].get("action_type") in ("block_ip", "firewall_rule")
                   and not rec["rule"].get("confirmed") and self._rule_of(rec) is not None
                   and now - int(rec["rule"].get("applied_at", now)) >= minutes * 60]
            for aid, rec in due:
                rule = rec["rule"]
                plan = {"mechanism": "iptables", "action_type": rule["action_type"], "target": rule["target"]}
                if isinstance(rule.get("tag"), str):
                    plan["tag"] = rule["tag"]            # remove exactly this action's rule, not a newer twin
                try:
                    safe = self.enforcer.validate_revert(plan, ledger=self._ledger(handled))
                    self.enforcer.revert(safe)
                except Exception as exc:  # noqa: BLE001 -- keep trying every tick; never stop the loop
                    log.error("dead-man timer: could not remove %s %s (action %s): %s", rule["action_type"],
                              rule["target"], aid, exc)
                    continue
                rec["reverted"] = rule["reverted"] = True
                rec["reverted_by"] = DEADMAN
                rule["deadman_reverted_at"] = now
                # The record of what this host did is now the truth, and it is what any later report carries:
                # the block is gone, so the server must never be told it is "applied". It is reported through
                # the existing result route as a failed apply (the action is still 'approved' there: the
                # result that would have confirmed it never got through, which is why the timer fired).
                rec["status"] = "failed"
                rec["revert"] = None
                rec["output"] = {"error": "deadman_reverted",
                                 "detail": "the block was removed by the agent's dead-man timer: no round trip "
                                           "with the server succeeded within %d minutes of applying it" % minutes,
                                 "action_type": rule["action_type"], "target": rule["target"],
                                 "deadman_reverted_at": now}
                rec["reported"] = False
                self.state.save_handled(handled)
                self._queue_deadman_result(aid, rec)
                log.error("dead-man timer: %s %s (action %s) was applied %d minutes ago and the server has not "
                          "been reached since; REMOVED it so the host cannot be cut off for good",
                          rule["action_type"], rule["target"], aid, minutes)
            if not any(isinstance(r, dict) and isinstance(r.get("rule"), dict)
                       and not r["rule"].get("confirmed") and not r["rule"].get("reverted")
                       and r["rule"].get("action_type") in ("block_ip", "firewall_rule")
                       for r in handled.values()):
                self._unconfirmed = False

    # ------------------------------------------------------------------ #
    # posture (signed)
    # ------------------------------------------------------------------ #
    def _make_ctx(self, seq: int) -> Any:
        self._require_enrolled()
        if self._ctx_factory is not None:
            ctx = self._ctx_factory(seq=seq, key_id=self.key_id)
        else:
            from .runner import Ctx
            ctx = Ctx(self.cfg.state_dir, __version__, seq=seq, key_id=self.key_id,
                      machine_salt=self._machine_salt(), clock_skew_ms=self.client.clock_skew_ms,
                      enable_imds=self.cfg.enable_imds)
        ctx.known_manifest_sha = self._known_manifest
        ctx.force_full_manifest = self._ctx_forced = self._mono() >= self._force_full_at
        return ctx

    def collect_payload(self, seq: int = 0, ctx: Any = None) -> Any:
        """Collect once. Returns ``(payload_dict, payload_bytes)`` (the exact bytes that get signed)."""
        if self._collect_fn is not None:
            collect, encode = self._collect_fn, self._encode_fn
        else:
            from .collectors import collect_all, payload_bytes
            collect, encode = collect_all, self._encode_fn or payload_bytes
        if encode is None:
            from .collectors import payload_bytes
            encode = payload_bytes
        ctx = ctx or self._make_ctx(seq)
        payload = collect(ctx)
        return payload, encode(payload)

    def send_posture(self) -> Any:
        """Collect, sign and send one posture envelope. Returns the server's reply (``None`` when nothing was sent).

        Anything that goes wrong before signing (a collector crash, an oversize payload) sends NOTHING:
        silence is what the server turns into UNKNOWN; a partial or invented posture would not be.
        """
        self._require_enrolled()
        seq = self.state.next_seq()                    # write-ahead; also what the payload reports
        self._ctx_forced = False
        try:
            payload, raw = self.collect_payload(seq)
            collectors = dict(_collector_versions())
            collectors["agent"] = __version__
            env = self._build(envelope.KIND_POSTURE, raw, envelope.PAYLOAD_TYPE_POSTURE, seq, collectors)
        except Exception:  # noqa: BLE001 -- a collector/encoding bug must not slow the heartbeat down
            log.exception("could not build a posture; sending none (the server will see silence)")
            self.stats["posture_errors"] = self.stats.get("posture_errors", 0) + 1
            return None
        sha = _manifest_sha(payload)
        forced = self._ctx_forced
        try:
            out = self._send("post_posture", env)
        except FleetClientError as exc:
            if getattr(exc, "verdict", "") == "retry" and not getattr(exc, "stale_key", False):
                self.state.outbox.put({"kind": "posture", "envelope": env, "seq": seq,
                                       "issued": int(self._clock()), "manifest_sha": sha, "forced": forced})
            raise
        self.stats["posture_ok"] += 1
        if sha:
            self._known_manifest = sha
        if forced:                      # the full-manifest refresh really went out: now the 24 h clock restarts
            self._force_full_at = self._mono() + FORCE_FULL_MANIFEST_EVERY_S
        return out

    # ------------------------------------------------------------------ #
    # outbox
    # ------------------------------------------------------------------ #
    def flush_outbox(self, limit: int = 50) -> str:
        """Re-send queued items oldest first. Returns ``ok``, ``retry``, ``auth`` or ``fatal``.

        A queued POSTURE must go out before anything newer (its sequence number is older than the next
        heartbeat's), so one that fails ends the flush. A queued action RESULT carries no sequence number: one
        that fails is skipped (and dropped after ``MAX_ITEM_ATTEMPTS`` failures or ``MAX_RESULT_AGE_S``), so
        a poisoned item can never stop the heartbeat; the server re-offers the action and the agent re-sends
        the result from ``handled.json``."""
        box = self.state.outbox
        for path in box.files()[:limit]:
            item = box.read(path)
            if item is None:
                continue
            key = os.path.basename(path)
            kind = item.get("kind")
            try:
                if kind == "posture":
                    if self._clock() - int(item.get("issued", 0)) > MAX_OUTBOX_AGE_S:
                        self.stats["expired"] += 1
                        log.info("dropping posture seq %s: too old for the server's clock window",
                                 item.get("seq"))
                        box.delete(path)
                        continue
                    self._send("post_posture", item["envelope"])
                    if item.get("manifest_sha"):
                        self._known_manifest = item["manifest_sha"]
                    if item.get("forced"):
                        self._force_full_at = self._mono() + FORCE_FULL_MANIFEST_EVERY_S
                elif kind == "result":
                    issued = item.get("issued")
                    if isinstance(issued, int) and self._clock() - issued > MAX_RESULT_AGE_S:
                        self.stats["expired"] += 1
                        log.warning("dropping the queued result of action %s: too old", item.get("action_id"))
                        box.delete(path)
                        continue
                    status, output, revert = item["status"], item.get("output") or {}, item.get("revert")
                    truth = self._recorded_truth(item["action_id"])
                    if truth is not None:               # the dead-man timer removed it since this was queued
                        (status, output), revert = truth, None
                    self.client.post_result(item["action_id"], status=status, output=output, revert=revert)
                    self._mark_reported(item["action_id"])
                    self._confirm_blocks()
                else:
                    box.delete(path)
                    continue
            except FleetClientError as exc:
                verdict = getattr(exc, "verdict", None) or ("retry" if exc.transient else "drop")
                if verdict == "retry":
                    tries = self._item_attempts[key] = self._item_attempts.get(key, 0) + 1
                    if tries >= MAX_ITEM_ATTEMPTS:
                        log.error("dropping queued %s after %d failed attempts: %s", kind, tries, exc)
                        self.stats["dropped"] += 1
                        self._item_attempts.pop(key, None)
                        box.delete(path)
                        continue
                    if kind == "result":
                        continue                    # no ordering constraint: do not let it hold up the rest
                    return "retry"
                if verdict in ("auth", "fatal"):
                    return verdict
                self.stats["dropped"] += 1
                self._item_attempts.pop(key, None)
                box.delete(path)
                continue
            except (KeyError, TypeError, ValueError, RecursionError):
                box.delete(path)
                continue
            self._item_attempts.pop(key, None)
            box.delete(path)
        return "ok"

    # ------------------------------------------------------------------ #
    # v1 inventory (unsigned; Fleet page only)
    # ------------------------------------------------------------------ #
    def send_inventory(self) -> Dict[str, Any]:
        self._require_enrolled()
        return self.client.post_inventory(collect_inventory())

    # ------------------------------------------------------------------ #
    # key rotation
    # ------------------------------------------------------------------ #
    def rotate_key(self) -> str:
        """Generate a new key, prove possession of it, and have the CURRENT key sign the hand-over.

        Returns the new key id. If the server's answer is lost the outcome is unknown: the new key stays
        on disk as *pending* and :meth:`resolve_pending_key` settles it (it probes with the new key).
        """
        with self.state.exclusive():          # no other process (the daemon) changes keys or takes a seq meanwhile
            return self._rotate_key_locked()

    def _rotate_key_locked(self) -> str:
        creds = self._require_enrolled()
        if self.resolve_pending_key() != "ok":
            raise AgentError("a previous key change is unresolved and the server is unreachable; retry later")
        old_seed = self._signing_seed()
        old_kid = self.key_id
        new_seed = signing.generate_seed()
        new_kid = signing.key_id(signing.public_key(new_seed))
        self.state.save_pending_key(new_seed)
        seq = self.state.next_seq()
        env = self._build(envelope.KIND_ROTATE, envelope.rotate_payload(new_seed, creds.agent_id, old_kid),
                          envelope.PAYLOAD_TYPE_ROTATE, seq, {"agent": __version__}, seed=old_seed)
        try:
            self._send("rotate_key", env)
        except FleetClientError as exc:
            if not exc.transient:                    # the server said no: the new key was never accepted
                self.state.discard_pending_key()
            raise
        self._adopt_pending_key(new_kid)
        log.info("rotated signing key %s -> %s", old_kid, new_kid)
        return new_kid

    def _adopt_pending_key(self, new_kid: str) -> None:
        self.state.promote_pending_key()
        self._seed = None
        creds = self.creds
        if creds is not None:
            creds.key_id = new_kid
            self.state.save_credentials(creds)
        # Queued envelopes were signed by the retired key: the server would refuse them.
        for path in self.state.outbox.files():
            item = self.state.outbox.read(path)
            if item is not None and item.get("kind") == "posture":
                self.state.outbox.delete(path)

    def resolve_pending_key(self) -> str:
        """Settle an enrollment/rotation that was interrupted. Returns ``ok`` or ``retry``.

        With only a pending key the enrollment finished (credentials exist): promote it. With both keys the
        server may or may not have switched, so ask it: a heartbeat signed by the pending key is accepted
        only if the server activated that key.
        """
        with self.state.exclusive():
            return self._resolve_pending_key_locked()

    def _resolve_pending_key_locked(self) -> str:
        pend = self.state.load_pending_key()
        if pend is None:
            return "ok"
        if self.state.load_key() is None:
            self.state.promote_pending_key()
            self._seed = None
            return "ok"
        new_kid = signing.key_id(signing.public_key(pend))
        seq = self.state.next_seq()
        env = self._build(envelope.KIND_HEARTBEAT, envelope.canon({"agent_version": __version__, "status": "ok"}),
                          envelope.PAYLOAD_TYPE_HEARTBEAT, seq, {"agent": __version__}, seed=pend)
        try:
            self._send("heartbeat", env)
        except FleetClientError as exc:
            verdict = getattr(exc, "verdict", "retry")
            if exc.status == 401:                    # kid is not an active key: the switch never happened
                log.warning("server does not know key %s; discarding the pending key", new_kid)
                self.state.discard_pending_key()
                self._auth_failures = 0
                return "ok"
            if verdict == "fatal":
                raise Fatal("the server refuses this agent; re-enroll it")
            return "retry"
        self._adopt_pending_key(new_kid)
        log.info("the pending key %s is active on the server; adopted", new_kid)
        return "ok"

    # ------------------------------------------------------------------ #
    # run loop
    # ------------------------------------------------------------------ #
    def _due(self, last: Optional[float], interval: int) -> bool:
        return bool(interval) and (last is None or self._mono() - last >= interval)

    def step(self) -> str:
        """One tick: settle a pending key, flush the outbox, heartbeat, and (when due) posture and the v1
        inventory. Returns the worst verdict: ``ok``, ``retry``, ``auth`` or ``fatal``. Never raises on
        network trouble."""
        self._retry_now = False
        verdict = self._step_once()
        if verdict == "retry" and self._retry_now:
            # a 401 made us reload a key/credential another process changed: that is not a failure, try the
            # whole tick again once with what is on disk now (a second 401 then counts)
            self._retry_now = False
            verdict = self._step_once()
        return verdict

    def _step_once(self) -> str:
        worst = "ok"
        order = {"ok": 0, "drop": 0, "retry": 1, "auth": 2, "fatal": 3}
        try:
            if self._reload_requested.is_set():
                self._reload_requested.clear()
                self._reload_from_disk()
            self._deadman_tick()
            if self.resolve_pending_key() != "ok":
                return "retry"
            flushed = self.flush_outbox()
            if flushed != "ok":
                return flushed
            for name, call in (("heartbeat", self.heartbeat), ("posture", self.send_posture),
                               ("inventory", self.send_inventory)):
                if name == "posture":
                    if not self._due(self._last_posture, self.cfg.posture_interval_s):
                        continue
                    self._last_posture = self._mono()     # an attempt counts (a failure is queued)
                elif name == "inventory":
                    if not self._due(self._last_inv, self.cfg.inventory_interval_s):
                        continue
                    self._last_inv = self._mono()
                try:
                    call()
                except FleetClientError as exc:
                    v = getattr(exc, "verdict", None) or ("retry" if exc.transient else "drop")
                    log.warning("%s failed: %s", name, exc)
                    if name != "inventory" and order.get(v, 1) > order[worst]:   # inventory is cosmetic
                        worst = v
                    if name == "heartbeat" and v in ("retry", "auth", "fatal"):
                        break                  # server down or refusing: do not also run the collectors
        except Fatal:
            return "fatal"
        except (StateError, AgentError) as exc:
            log.error("cannot proceed: %s", exc)
            return "retry"
        except Exception:  # noqa: BLE001 -- a bug must not kill the daemon; it is logged loudly
            log.exception("unexpected error in the run loop")
            return "retry"
        return worst

    def run(self, *, max_iterations: Optional[int] = None,
            sleep: Optional[Callable[[float], Any]] = None) -> int:
        """Run until stopped. Returns a process exit status (0 stopped, 7 re-enrollment required)."""
        self._require_enrolled()
        try:
            self.state.acquire_instance()       # one daemon per state directory
        except InstanceBusy as exc:
            raise AgentError(str(exc))
        try:
            return self._run_loop(max_iterations, sleep)
        finally:
            self.state.release_instance()

    def _run_loop(self, max_iterations: Optional[int], sleep: Optional[Callable[[float], Any]]) -> int:
        log.info("agent run loop starting (platform=%s, dry_run=%s, key=%s)", self.platform,
                 self.cfg.dry_run, self._safe_key_id())
        wait = sleep or self._stop.wait
        self._force_full_at = self._mono() + FORCE_FULL_MANIFEST_EVERY_S
        fails = 0
        i = 0
        while not self._stop.is_set():
            verdict = self.step()
            if verdict == "fatal":
                log.error("giving up: the server said this agent may not talk to it any more (revoked or "
                          "must re-enroll); re-enroll it with a new one-time token")
                return EXIT_RE_ENROLL
            if verdict == "ok":
                fails = 0
                delay = self.cfg.heartbeat_interval_s * (0.9 + 0.2 * self._rand())
            else:
                fails += 1
                delay = backoff_delay(fails, base=float(max(5, self.cfg.heartbeat_interval_s)),
                                      rand=self._rand)
            i += 1
            if max_iterations is not None and i >= max_iterations:
                break
            wait(delay)
        return EXIT_OK

    def _safe_key_id(self) -> str:
        try:
            return self.key_id
        except (AgentError, StateError):
            return "?"


def _need_uuid(out: Dict[str, Any], name: str) -> str:
    try:
        return str(uuid.UUID(str(out[name])))
    except (KeyError, ValueError, TypeError):
        raise AgentError("the server's enrollment reply lacks a valid %s (the one-time token may have "
                         "been consumed; ask an admin for a re-key token)" % name)


def _collector_versions() -> Dict[str, str]:
    try:
        from .collectors import COLLECTOR_VERSIONS
        return dict(COLLECTOR_VERSIONS)
    except Exception:  # noqa: BLE001
        return {}

