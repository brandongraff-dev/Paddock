"""``paddockctl`` -- the Paddock API command line.

(The host agent CLI is ``paddock``; this one talks to the orchestrator API.)

    paddockctl login --url https://paddock.internal --api-key pak_...
    paddockctl scope list
    paddockctl scope add domain example.com --auth-doc-ref "SOW-2026-14"
    paddockctl scan run full_recon example.com --wait
    paddockctl findings list --severity critical -o json
    paddockctl findings accept <id> --reason "compensating control: WAF rule 4411"
    paddockctl export sarif --out paddock.sarif
    paddockctl integrations list

Global flags: ``--profile NAME``, ``-o/--output table|json``.
Exit codes: 0 ok, 1 API/transport error, 2 usage error, 3 endpoint not
available on this server.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from typing import Any, Callable, Sequence

from . import __version__
from ._core import APIError, NotFound, PaddockError, TransportError
from .client import PaddockClient
from .config import Config, Profile

EXIT_OK, EXIT_API, EXIT_USAGE, EXIT_UNSUPPORTED = 0, 1, 2, 3
_TERMINAL_SCAN = {"completed", "failed", "cancelled"}


class CLIError(Exception):
    def __init__(self, msg: str, code: int = EXIT_USAGE) -> None:
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def _cell(v: Any, width: int = 60) -> str:
    if v is None:
        return "-"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str, separators=(",", ":"))
    s = str(v).replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def render_table(rows: Sequence[dict[str, Any]], columns: Sequence[str]) -> str:
    if not rows:
        return "(no results)"
    cells = [[_cell(r.get(c)) for c in columns] for r in rows]
    widths = [max(len(c), *(len(row[i]) for row in cells)) for i, c in enumerate(columns)]
    head = "  ".join(c.upper().ljust(widths[i]) for i, c in enumerate(columns))
    sep = "  ".join("-" * w for w in widths)
    body = ["  ".join(row[i].ljust(widths[i]) for i in range(len(columns))).rstrip() for row in cells]
    return "\n".join([head.rstrip(), sep, *body])


class Out:
    def __init__(self, fmt: str, stream=None) -> None:
        self.fmt = fmt
        self.stream = stream or sys.stdout

    def emit(self, data: Any, columns: Sequence[str] | None = None) -> None:
        if self.fmt == "json" or columns is None:
            self.stream.write(json.dumps(data, indent=2, default=str, sort_keys=True) + "\n")
            return
        rows = data if isinstance(data, list) else [data]
        self.stream.write(render_table(rows, columns) + "\n")

    def kv(self, data: dict[str, Any]) -> None:
        if self.fmt == "json":
            self.emit(data)
            return
        w = max((len(k) for k in data), default=0)
        for k, v in data.items():
            self.stream.write(f"{k.ljust(w)}  {_cell(v, 100)}\n")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def _client(args: argparse.Namespace) -> PaddockClient:
    if getattr(args, "_client", None) is not None:
        return args._client
    prof = args._config.profile(args.profile)
    return PaddockClient(prof.url, api_key=prof.api_key, token=prof.token,
                         verify=prof.verify_tls, transport=getattr(args, "_transport", None))


def cmd_login(args, out: Out) -> int:
    cfg: Config = args._config
    name = args.profile or cfg.current or "default"
    prof = Profile(name=name, url=args.url.rstrip("/"), verify_tls=not args.insecure)
    client = PaddockClient(prof.url, api_key=args.api_key or "", token="", verify=prof.verify_tls,
                           transport=getattr(args, "_transport", None))
    if args.api_key:
        prof.api_key = args.api_key
    elif args.username:
        password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Password: ")
        res = client.login_with_password(args.username, password)
        prof.token = res.get("access_token")
        print(f"note: JWTs are short-lived ({res.get('expires_in', '?')}s); prefer an API key for automation",
              file=sys.stderr)
    else:
        raise CLIError("login needs --api-key or --username")
    client.api_key, client.token = prof.api_key, prof.token
    me = client.me()
    cfg.set_profile(prof)
    cfg.save()
    out.kv({"profile": name, "url": prof.url, "actor": me.get("actor"), "role": me.get("role"),
            "config": str(cfg.path)})
    return EXIT_OK


def cmd_logout(args, out: Out) -> int:
    cfg: Config = args._config
    name = args.profile or cfg.current
    if cfg.profiles.pop(name, None) is None:
        raise CLIError(f"no profile {name!r}")
    if cfg.current == name:
        cfg.current = next(iter(cfg.profiles), "default")
    cfg.save()
    out.kv({"removed": name})
    return EXIT_OK


def cmd_config_show(args, out: Out) -> int:
    out.kv(args._config.profile(args.profile).redacted() | {"config": str(args._config.path)})
    return EXIT_OK


def cmd_config_profiles(args, out: Out) -> int:
    cfg: Config = args._config
    rows = [{"current": "*" if n == cfg.current else "", **cfg.profile(n).redacted()} for n in sorted(cfg.profiles)]
    out.emit(rows, ["current", "name", "url", "api_key", "token"])
    return EXIT_OK


def cmd_config_use(args, out: Out) -> int:
    cfg: Config = args._config
    if args.name not in cfg.profiles:
        raise CLIError(f"no profile {args.name!r}")
    cfg.current = args.name
    cfg.save()
    out.kv({"current": args.name})
    return EXIT_OK


def cmd_whoami(args, out: Out) -> int:
    out.kv(_client(args).me())
    return EXIT_OK


SCOPE_COLS = ["id", "kind", "value", "active", "added_by", "auth_doc_ref", "expires_at"]


def cmd_scope_list(args, out: Out) -> int:
    c = _client(args)
    rows = list(c.paginate(c.list_scope, page_size=500, active_only=not args.all))
    out.emit(rows, SCOPE_COLS)
    return EXIT_OK


def cmd_scope_add(args, out: Out) -> int:
    c = _client(args)
    body: dict[str, Any] = {"kind": args.kind, "value": args.value, "added_by": args.added_by or _actor(c)}
    for k in ("auth_doc_ref", "notes", "expires_at"):
        if getattr(args, k):
            body[k] = getattr(args, k)
    out.emit(c.add_scope(body), SCOPE_COLS)
    return EXIT_OK


def cmd_scope_remove(args, out: Out) -> int:
    out.emit(_client(args).deactivate_scope(args.id), SCOPE_COLS)
    return EXIT_OK


def cmd_scope_check(args, out: Out) -> int:
    res = _client(args).check_scope({"target": args.target, "worker": "paddockctl", "reason": "cli check"})
    out.kv(res)
    return EXIT_OK if res.get("allow") else EXIT_API


def cmd_scope_verify(args, out: Out) -> int:
    out.kv(_client(args).scope_verify(args.id) or {"id": args.id, "verified": True})
    return EXIT_OK


def _actor(c: PaddockClient) -> str:
    try:
        return str(c.me().get("actor") or "paddockctl")
    except PaddockError:
        return "paddockctl"


SCAN_COLS = ["id", "kind", "target", "status", "priority", "queued_at", "finished_at", "error"]


def cmd_scan_run(args, out: Out) -> int:
    c = _client(args)
    body: dict[str, Any] = {"kind": args.kind, "target": args.target, "priority": args.priority}
    if args.config:
        body["config"] = json.loads(args.config)
    scan = c.create_scan(body)
    if args.wait:
        deadline = time.monotonic() + args.timeout
        while scan.get("status") not in _TERMINAL_SCAN:
            if time.monotonic() > deadline:
                out.emit(scan, SCAN_COLS)
                raise CLIError(f"timed out after {args.timeout}s waiting for scan {scan['id']}", EXIT_API)
            time.sleep(args.poll)
            scan = c.get_scan(scan["id"])
    out.emit(scan, SCAN_COLS)
    return EXIT_API if scan.get("status") == "failed" else EXIT_OK


def cmd_scan_status(args, out: Out) -> int:
    out.emit(_client(args).get_scan(args.id), SCAN_COLS)
    return EXIT_OK


def cmd_scan_list(args, out: Out) -> int:
    c = _client(args)
    out.emit(list(c.paginate(c.list_scans, max_items=args.limit, status=args.status)), SCAN_COLS)
    return EXIT_OK


FINDING_COLS = ["id", "severity", "status", "title", "asset_value", "rule_id", "last_seen"]


def cmd_findings_list(args, out: Out) -> int:
    c = _client(args)
    rows = list(c.paginate(
        c.list_findings_paged, page_size=min(500, args.limit or 500), max_items=None if args.all else args.limit,
        severity=args.severity, status=args.status, q=args.q, kev=args.kev,
    ))
    out.emit(rows, FINDING_COLS)
    return EXIT_OK


def cmd_findings_show(args, out: Out) -> int:
    out.emit(_client(args).get_finding(args.id))
    return EXIT_OK


def cmd_findings_accept(args, out: Out) -> int:
    status = "false_positive" if args.false_positive else "accepted_risk"
    res = _client(args).patch_finding(args.id, {"status": status, "notes": args.reason})
    out.emit(res, FINDING_COLS)
    return EXIT_OK


def cmd_export(args, out: Out) -> int:
    query = {}
    for kv in args.param or []:
        if "=" not in kv:
            raise CLIError(f"--param expects key=value, got {kv!r}")
        k, v = kv.split("=", 1)
        query[k] = v
    data = _client(args).export_format(args.format, **query)
    text = data if isinstance(data, str) else json.dumps(data, indent=2, default=str)
    if args.out and args.out != "-":
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return EXIT_OK


INTEGRATION_COLS = ["id", "kind", "name", "enabled", "min_severity", "events", "last_ok_at", "last_error"]


def cmd_integrations_list(args, out: Out) -> int:
    data = _client(args).integrations_list()
    rows = data.get("items", data) if isinstance(data, dict) else data
    out.emit(rows, INTEGRATION_COLS)
    return EXIT_OK


def cmd_license_show(args, out: Out) -> int:
    lic = _client(args).get_license()
    if out.fmt == "json":
        out.emit(lic)
    else:
        out.kv({k: lic.get(k) for k in ("edition", "status", "licensed_edition", "license_id", "licensee",
                                         "expires_at", "days_remaining", "limits", "features", "error")})
    return EXIT_OK


def cmd_license_upload(args, out: Out) -> int:
    key = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    lic = _client(args).upload_license({"key": key.strip()})
    out.kv({k: lic.get(k) for k in ("edition", "status", "license_id", "expires_at", "features")})
    return EXIT_OK


def cmd_usage(args, out: Out) -> int:
    u = _client(args).get_usage()
    if out.fmt == "json":
        out.emit(u)
        return EXIT_OK
    rows = [{"metric": k, "value": u.get(k)} for k in (
        "edition", "monitored_assets", "total_assets", "sites", "sensors", "fleet_agents",
        "users", "scans_this_month", "integrations")]
    for name, st in (u.get("limits") or {}).items():
        rows.append({"metric": f"limit.{name}", "value": f"{st.get('used')} / {st.get('limit') or 'unlimited'}"
                     + (" OVER" if st.get("over") else "")})
    out.emit(rows, ["metric", "value"])
    for n in u.get("notes") or []:
        print(f"note: {n}", file=sys.stderr)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", default=argparse.SUPPRESS, help="config profile to use")
    common.add_argument("-o", "--output", choices=("table", "json"), default=argparse.SUPPRESS)

    p = argparse.ArgumentParser(prog="paddockctl", description="Command line for the Paddock /v1 API.",
                                parents=[common])
    p.add_argument("--version", action="version", version=f"paddockctl {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def add(parent, name: str, fn: Callable, help_: str):
        sp = parent.add_parser(name, help=help_, parents=[common])
        sp.set_defaults(fn=fn)
        return sp

    lg = add(sub, "login", cmd_login, "store credentials for a server in a profile")
    lg.add_argument("--url", required=True)
    g = lg.add_mutually_exclusive_group()
    g.add_argument("--api-key")
    g.add_argument("--username")
    lg.add_argument("--password-stdin", action="store_true")
    lg.add_argument("--insecure", action="store_true", help="skip TLS verification (lab use only)")
    add(sub, "logout", cmd_logout, "forget a profile's credentials")
    add(sub, "whoami", cmd_whoami, "show the authenticated principal")

    cfg = sub.add_parser("config", help="show/switch profiles").add_subparsers(dest="sub", required=True)
    add(cfg, "show", cmd_config_show, "show the active profile (secrets redacted)")
    add(cfg, "profiles", cmd_config_profiles, "list profiles")
    use = add(cfg, "use", cmd_config_use, "make a profile current")
    use.add_argument("name")

    sc = sub.add_parser("scope", help="authorized-scope allowlist").add_subparsers(dest="sub", required=True)
    sl = add(sc, "list", cmd_scope_list, "list scope entries")
    sl.add_argument("--all", action="store_true", help="include inactive entries")
    sa = add(sc, "add", cmd_scope_add, "add a scope entry (admin)")
    sa.add_argument("kind", choices=("domain", "subdomain_wildcard", "ipv4_cidr", "ipv6_cidr", "asn"))
    sa.add_argument("value")
    sa.add_argument("--auth-doc-ref", help="reference to the authorization document")
    sa.add_argument("--notes")
    sa.add_argument("--expires-at", help="ISO-8601 timestamp")
    sa.add_argument("--added-by")
    sr = add(sc, "remove", cmd_scope_remove, "deactivate a scope entry (admin)")
    sr.add_argument("id", type=int)
    sk = add(sc, "check", cmd_scope_check, "would TARGET be allowed? (exit 1 when denied)")
    sk.add_argument("target")
    sv = add(sc, "verify", cmd_scope_verify, "run proof-of-control verification for an entry")
    sv.add_argument("id")

    sn = sub.add_parser("scan", help="scans").add_subparsers(dest="sub", required=True)
    sru = add(sn, "run", cmd_scan_run, "queue a scan")
    sru.add_argument("kind")
    sru.add_argument("target")
    sru.add_argument("--priority", type=int, default=5)
    sru.add_argument("--config", help="JSON object of scan options")
    sru.add_argument("--wait", action="store_true")
    sru.add_argument("--timeout", type=float, default=900)
    sru.add_argument("--poll", type=float, default=3)
    sst = add(sn, "status", cmd_scan_status, "show one scan")
    sst.add_argument("id")
    sli = add(sn, "list", cmd_scan_list, "list scans")
    sli.add_argument("--status")
    sli.add_argument("--limit", type=int, default=50)

    fi = sub.add_parser("findings", help="findings").add_subparsers(dest="sub", required=True)
    fl = add(fi, "list", cmd_findings_list, "list findings")
    fl.add_argument("--severity", choices=("info", "low", "medium", "high", "critical"))
    fl.add_argument("--status")
    fl.add_argument("--q", help="text search")
    fl.add_argument("--kev", action="store_true", default=None, help="only KEV-listed")
    fl.add_argument("--limit", type=int, default=100)
    fl.add_argument("--all", action="store_true", help="fetch every page")
    fs = add(fi, "show", cmd_findings_show, "show one finding with its asset and chains")
    fs.add_argument("id")
    fa = add(fi, "accept", cmd_findings_accept, "risk-accept (or mark false positive) a finding")
    fa.add_argument("id")
    fa.add_argument("--reason", required=True)
    fa.add_argument("--false-positive", action="store_true")

    ex = add(sub, "export", cmd_export, "export findings/SBOM (needs a server with /v1/export/*)")
    ex.add_argument("format", choices=("sarif", "sbom", "ocsf"))
    ex.add_argument("--out", help="file to write (default stdout)")
    ex.add_argument("--param", action="append", help="extra query parameter key=value")

    it = sub.add_parser("integrations", help="integrations").add_subparsers(dest="sub", required=True)
    add(it, "list", cmd_integrations_list, "list configured integrations")

    li = sub.add_parser("license", help="edition / license").add_subparsers(dest="sub", required=True)
    add(li, "show", cmd_license_show, "show the effective license")
    lu = add(li, "upload", cmd_license_upload, "upload a license key file (admin)")
    lu.add_argument("file", help="path to the key, or - for stdin")
    add(sub, "usage", cmd_usage, "usage vs license limits")
    return p


def main(argv: Sequence[str] | None = None, *, config: Config | None = None,
         client: PaddockClient | None = None, transport: Any = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.profile = getattr(args, "profile", None)
    out = Out(getattr(args, "output", None) or "table")
    args._config = config or Config.load()
    args._client = client
    args._transport = transport
    try:
        return args.fn(args, out)
    except CLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except NotFound as exc:
        print(f"error: {exc.detail}", file=sys.stderr)
        unsupported = isinstance(exc.detail, str) and "does not provide" in exc.detail
        return EXIT_UNSUPPORTED if unsupported else EXIT_API
    except APIError as exc:
        detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail, default=str)
        print(f"error: HTTP {exc.status}: {detail}", file=sys.stderr)
        return EXIT_API
    except TransportError as exc:
        print(f"error: cannot reach server: {exc}", file=sys.stderr)
        return EXIT_API
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE



if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
