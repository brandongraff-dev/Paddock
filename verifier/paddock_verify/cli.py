# SPDX-License-Identifier: Apache-2.0
"""The ``paddock-verify`` command line (spec/07 section 4).

Exit codes: 0 accepted, 1 rejected, 2 unverifiable, 64 usage or configuration error. ``argparse`` is patched so
that its own exit status 2 can never be mistaken for "unverifiable": a bad command line is always 64. Any
unexpected exception exits 2 (``internal.error``), never 0.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from . import SPEC_VERSION, __version__, checks, codes, fetch, keys as keys_mod, limits, model, policy as policy_mod, timefmt
from .dns import doh, resolver as dns_resolver, txtparse
from .dns.filefix import FixtureError
from .state import State, StateError


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:                          # argparse would exit 2: reserved for "unverifiable"
        raise UsageError(message)

    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        if message:
            sys.stderr.write(message)
        raise SystemExit(status if status == 0 else 64)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="paddock-verify", description="Verify a Paddock containment attestation (spec 1.0). "
                "Exit codes: 0 accepted, 1 rejected, 2 unverifiable, 64 usage error.", allow_abbrev=False)
    a = p.add_argument
    a("target", nargs="?", help="a domain, an https:// base URL, an envelope file or a bundle directory")
    a("--policy", metavar="F", help="acceptance policy (JSON, or the YAML subset)")
    a("--max-age", metavar="D", help="maximum age of issued_at and snapshot.at, such as 48h")
    a("--min-coverage", metavar="P", help="coverage threshold for every disclosed HOLDS, such as 0.95")
    a("--require", metavar="ID[:TIER]", action="append", default=[], help="require an invariant to hold (repeatable)")
    a("--offline", action="store_true", help="never use the network")
    a("--dns-resolver", metavar="SPEC", action="append", default=[], help="doh:<url>, udp:<ip>[:port], system or file:<path> (repeatable)")
    a("--dns-min-resolvers", metavar="N", type=int, help="resolvers that must answer (default 2 for the default DoH set, else 1)")
    a("--dns-record", metavar="TXT", help="an operator supplied TXT record (offline; reported as asserted by the operator)")
    a("--roots", metavar="F", help="trust roots file replacing the built-in roots")
    a("--add-roots", metavar="F", help="trust roots file added to the built-in roots")
    a("--std-registry", metavar="F", help="standard-invariant registry replacing the built-in one")
    a("--state-file", metavar="F", help="rollback state file (default ~/.paddock/verify-state.json)")
    a("--no-state", action="store_true", help="neither read nor write a state file")
    a("--history", choices=["required", "if_available", "off"], help="override the policy's history mode")
    a("--history-depth", metavar="N", type=int, default=1, help="how many earlier statements to link-check (default 1)")
    a("--anchor-file", metavar="F", help="an independent copy of the audit anchor to compare with")
    a("--max-anchor-age", metavar="D", help="maximum gap between anchor and statement (default 2h)")
    a("--proofs-dir", metavar="D", help="directory with inclusion proofs (D/<seq>/<tree>.json)")
    a("--keys", metavar="F", help="keys.json to use instead of the bundle's")
    a("--revoked", metavar="F", help="revoked.json to use instead of the bundle's")
    a("--now", metavar="T", help="override the clock (YYYY-MM-DDTHH:MM:SSZ)")
    a("--allow-private", action="store_true", help="allow loopback, private and link-local addresses when fetching")
    a("--timeout", metavar="S", type=float, default=10.0, help="network timeout in seconds")
    a("--json", action="store_true", help="print the JSON report")
    a("--quiet", action="store_true", help="print only the headline")
    a("--no-color", action="store_true", help="accepted for compatibility: no colour is ever printed")
    a("--explain", metavar="CODE", help="explain a reason code and exit")
    a("--print-roots", action="store_true", help="print the trust roots in use and exit")
    a("--version", action="store_true", help="print the version and exit")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return _main(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except UsageError as e:
        sys.stderr.write("paddock-verify: %s (%s)\n" % (e, "config.usage"))
        return codes.EXIT_USAGE
    except Exception:
        sys.stderr.write("paddock-verify: internal.error: the verifier failed internally; no decision.\n")
        return codes.EXIT_UNVERIFIABLE


def _fail(msg: str) -> UsageError:
    return UsageError(msg)


def _read_small(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            data = fh.read(limits.MAX_AUX_FILE_BYTES + 1)
    except OSError as e:
        raise _fail("cannot read %s: %s" % (what, e.strerror or "error")) from None
    if len(data) > limits.MAX_AUX_FILE_BYTES:
        raise _fail("%s is over %d bytes" % (what, limits.MAX_AUX_FILE_BYTES))
    return data


def _load_roots(args: argparse.Namespace) -> keys_mod.TrustRoots:
    try:
        roots = keys_mod.parse_roots(_read_small(args.roots, "--roots"), custom=True) if args.roots else keys_mod.load_default_roots()
        if args.add_roots:
            roots = roots.merged(keys_mod.parse_roots(_read_small(args.add_roots, "--add-roots"), custom=True))
    except keys_mod.ConfigError as e:
        raise _fail(str(e)) from None
    return roots


def _load_registry(args: argparse.Namespace) -> model.Registry:
    default = model.load_default_registry()
    if not args.std_registry:
        return default
    try:
        custom = model.Registry.from_bytes(_read_small(args.std_registry, "--std-registry"))
    except ValueError as e:
        raise _fail(str(e)) from None
    shipped = [a for a in default.advisories]
    return custom.with_advisories(shipped)


def _load_policy(args: argparse.Namespace) -> policy_mod.Policy:
    try:
        pol = policy_mod.load_policy_file(args.policy) if args.policy else policy_mod.baseline()
        return policy_mod.apply_overrides(pol, args.max_age, args.min_coverage, args.require, args.history)
    except policy_mod.PolicyError as e:
        sys.stderr.write("paddock-verify: config.policy_invalid: %s\n" % e)
        raise SystemExit(codes.EXIT_USAGE)


def _resolvers(args: argparse.Namespace) -> Optional[dns_resolver.ResolverSet]:
    try:
        rs = dns_resolver.parse_specs(args.dns_resolver) if args.dns_resolver else doh.default_resolvers()
    except (ValueError, FixtureError) as e:
        raise _fail("--dns-resolver: %s" % e) from None
    if args.offline:
        rs = dns_resolver.offline_safe(rs)
    if not rs:
        return None
    if args.dns_min_resolvers is not None and args.dns_min_resolvers < 1:
        raise _fail("--dns-min-resolvers must be at least 1")
    return dns_resolver.ResolverSet(rs, args.dns_min_resolvers)


def _default_state_path() -> Optional[str]:
    env = os.environ.get("PADDOCK_VERIFY_STATE")
    if env:
        return env
    home = os.path.expanduser("~")
    return os.path.join(home, ".paddock", "verify-state.json") if home and home != "~" else None


def _proof_loader(directory: str):
    def load(seq: int) -> Optional[Dict[str, bytes]]:
        d = os.path.join(directory, str(seq))
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".json"))[:64]
        except OSError:
            return None
        out = {}  # type: Dict[str, bytes]
        for n in names:
            try:
                with open(os.path.join(d, n), "rb") as fh:
                    out[n] = fh.read(limits.MAX_AUX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(out[n]) > limits.MAX_AUX_FILE_BYTES:
                out[n] = b""                                   # an oversized proof parses as invalid
        return out or None
    return load


def _acquire(args: argparse.Namespace, resolvers: Optional[dns_resolver.ResolverSet]):
    """(bundle, expected domain)."""
    target = args.target
    kw = {"timeout": args.timeout, "allow_private": args.allow_private}
    try:
        if target.startswith("https://"):
            if args.offline:
                raise _fail("--offline cannot fetch an https:// target")
            return fetch.locate(target, args.keys, args.revoked, **kw), None
        if os.path.exists(target) or target.startswith(("/", ".", "~")) or "/" in target or target.lower().startswith("http://"):
            return fetch.locate(target, args.keys, args.revoked, **kw), None
        domain = target.lower()
        if not fetch.looks_like_domain(domain):
            return model.Bundle.failed("input.not_found", "not a file, directory, URL or domain", label=target), None
        if args.offline:
            raise _fail("--offline needs a file or directory TARGET, not a domain")
        base = fetch.default_base(domain)
        if resolvers is not None:
            q = resolvers.lookup("_paddock-attest." + domain, min(args.timeout, 5.0))
            if q.error is None:
                for rec in txtparse.parse_rrset([[r] for r in q.records]).records:
                    hint = fetch.base_from_keys_hint(rec.keys) if rec.keys else None
                    if rec.status == txtparse.STATUS_OK and hint:
                        base = hint
                        break
        return fetch.locate(base, args.keys, args.revoked, **kw), domain
    except fetch.FetchError as e:
        return model.Bundle.failed(e.code, e.detail, label=target), None


def _main(argv: Optional[List[str]]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        sys.stdout.write("paddock-verify %s (containment attestation spec %s)\n" % (__version__, SPEC_VERSION))
        return 0
    if args.explain is not None:
        text = codes.explain(args.explain)
        if text is None:
            raise _fail("unknown reason code")
        sys.stdout.write(text + "\n")
        return 0
    roots = _load_roots(args)
    if args.print_roots:
        sys.stdout.write(_roots_text(roots))
        return 0
    if args.target is None:
        raise _fail("a TARGET is required")
    now = None
    if args.now is not None:
        try:
            now = timefmt.parse(args.now)
        except timefmt.TimeError:
            raise _fail("--now must be YYYY-MM-DDTHH:MM:SSZ") from None
    max_anchor = limits.DEFAULT_MAX_ANCHOR_AGE_SECONDS
    if args.max_anchor_age is not None:
        try:
            max_anchor = timefmt.parse_duration(args.max_anchor_age)
        except timefmt.TimeError:
            raise _fail("--max-anchor-age is a duration such as 2h") from None
    if args.history_depth < 1:
        raise _fail("--history-depth must be at least 1")
    if args.timeout <= 0:
        raise _fail("--timeout must be positive")
    pol = _load_policy(args)
    registry = _load_registry(args)
    resolvers = _resolvers(args)
    anchor_bytes = _read_small(args.anchor_file, "--anchor-file") if args.anchor_file else None
    proofs = _proof_loader(args.proofs_dir) if args.proofs_dir else None
    state = None  # type: Any
    state_path = None
    default_dir = False
    if not args.no_state:
        state_path = args.state_file or _default_state_path()
        default_dir = not args.state_file and not os.environ.get("PADDOCK_VERIFY_STATE")      # only ~/.paddock is ours to create
        if state_path:
            try:
                state = State.load(state_path)
            except StateError as e:
                state = e
    bundle, expected = _acquire(args, resolvers)
    report = checks.verify(bundle, pol, now=now, resolver=resolvers, state=state, roots=roots, registry=registry,
                           expected_domain=expected, dns_record=args.dns_record, max_anchor_age_s=max_anchor,
                           history_depth=args.history_depth, proofs=proofs, anchor_bytes=anchor_bytes, dns_timeout=min(args.timeout, 5.0))
    report.target = args.target
    if isinstance(state, State) and report.state_update:
        try:
            state.apply(report.state_update)
            state.save(state_path, make_dir=default_dir)
        except (StateError, OSError):
            sys.stderr.write("paddock-verify: warning: the state file could not be written, rollback protection is not in force\n")
    if args.json:
        sys.stdout.write(report.to_json())
    else:
        sys.stdout.write(report.to_text(quiet=args.quiet))
    return report.exit


def _roots_text(roots: keys_mod.TrustRoots) -> str:
    lines = []
    if not roots.roots:
        lines.append("no trust roots are built into this verifier; pass --roots FILE")
    for r in roots.roots:
        lines.append("%s %s valid %s to %s" % (r.kid, r.usage, timefmt.format(r.not_before), timefmt.format(r.not_after)))
    for kid in sorted(roots.revoked_issuers):
        lines.append("%s issuer revoked by this release" % kid)
    if roots.custom:
        lines.append("custom trust roots in use")
    return "\n".join(lines) + "\n"
