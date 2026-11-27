"""``paddock assurance scopes list|suggest|set|clear``: declare what a Sentry sensor can actually see.

A sensor covers a host for the reach graph only when every address of that host is inside a network its operator
declared (``/v1/assurance/sensor-scopes``). Until now the operator had to guess those networks. This command shows what
each sensor saw in the last 7 days, suggests a scope from it, and sets or clears one, always with a reason that goes
into the audit log (docs/ASSURANCE_P2_1.md 6.5, D37).

* ``list``: every sensor, its declared scope, and what it observed (including what lies outside the scope);
* ``suggest SENSOR``: prints the evidence and a ready-to-edit ``set`` command. It never changes anything;
* ``set SENSOR --cidr C ... --why TEXT [--allow-wide]``: declares (replaces) the scope. A prefix shorter than /16 (IPv4)
  or /48 (IPv6) needs ``--allow-wide`` AND a reason of at least 20 characters; the server enforces the same rule;
* ``clear SENSOR --why TEXT``: removes the declaration; the sensor then covers nothing.

The API key is read from ``PADDOCK_API_KEY`` only (never from argv, never printed, never saved), exactly like
``paddock upload``. Standard library only. A scope is an accountability record, not proof: observed coverage means "no
such traffic was seen", never "impossible".
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import uuid
from typing import Any
from urllib.parse import quote

from . import upload

EXIT_OK, EXIT_ERROR = 0, 2
WIDE_V4, WIDE_V6 = 16, 48
WIDE_WHY_MIN = 20
_BASE = "/v1/assurance/sensor-scopes"


class ScopesError(Exception):
    """Something the operator must fix; printed as ``error: ...``, exit 2."""


# --------------------------------------------------------------------------- #
# talking to the server
# --------------------------------------------------------------------------- #
def _explain(exc: upload.UploadError) -> str:
    """The server's own words when it sent a structured 4xx (``{"detail": {"error", "message"}}`` or a list)."""
    body = getattr(exc, "body", "") or ""
    try:
        detail = json.loads(body).get("detail")
    except (ValueError, AttributeError):
        return str(exc)
    if isinstance(detail, dict) and (detail.get("error") or detail.get("message")):
        return f"{detail.get('error', 'refused')}: {detail.get('message', '')}".rstrip(": ")
    if isinstance(detail, list):
        msgs = [str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail]
        return f"HTTP {exc.status}: " + "; ".join(msgs)[:300]
    if isinstance(detail, str):
        return f"HTTP {exc.status}: {detail}"[:300]
    return str(exc)


def _call(method: str, server: str, path: str, key: str, body: Any = None) -> Any:
    try:
        return upload._request(method, f"{server}{path}", key, body)
    except upload.UploadError as exc:
        if getattr(exc, "status", None):
            raise ScopesError(_explain(exc)) from exc
        raise ScopesError(str(exc)) from exc


def _listing(server: str, key: str) -> dict[str, Any]:
    data = _call("GET", server, _BASE, key)
    if not isinstance(data, dict):
        raise ScopesError("the server answered something that is not a sensor-scope listing")
    return data


def _all(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [*(data.get("items") or []), *(data.get("unscoped_sensors") or [])]


def _resolve(data: dict[str, Any], ref: str) -> dict[str, Any]:
    """The sensor named by id or by name (exact, then case-insensitive). Ambiguity is an error, never a guess."""
    rows = _all(data)
    by_id = [r for r in rows if str(r.get("sensor_id", "")).lower() == ref.lower()]
    if len(by_id) == 1:
        return by_id[0]
    for same in (lambda r: r.get("name") == ref, lambda r: str(r.get("name", "")).lower() == ref.lower()):
        hits = [r for r in rows if same(r)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            ids = ", ".join(f"{r.get('sensor_id')} (site {r.get('site')})" for r in hits)
            raise ScopesError(f"sensor name {ref!r} is ambiguous: {ids}; use the id")
    raise ScopesError(f"no sensor {ref!r} (see `paddock assurance scopes list`)")


def _sensor_id(server: str, key: str, ref: str) -> str:
    """A UUID is used as given (the server answers 404 for an unknown one); a name needs the listing."""
    try:
        return str(uuid.UUID(ref))
    except ValueError:
        return str(_resolve(_listing(server, key), ref)["sensor_id"])


# --------------------------------------------------------------------------- #
# input checks (the server enforces the same; this saves a round trip and a slip)
# --------------------------------------------------------------------------- #
def _parse_cidrs(raw: list[str]) -> list[str]:
    out: list[str] = []
    for item in raw:
        for part in item.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                net = ipaddress.ip_network(part, strict=True)
            except ValueError as exc:
                raise ScopesError(f"{part!r} is not a network address (write 10.20.0.0/24, not 10.20.0.5/24): {exc}") from exc
            out.append(str(net))
    if not out:
        raise ScopesError("give at least one --cidr")
    return list(dict.fromkeys(out))


def _is_wide(cidr: str) -> bool:
    net = ipaddress.ip_network(cidr)
    if net.version == 6 and net.subnet_of(ipaddress.ip_network("::ffff:0:0/96")):
        # a v4-mapped network means the IPv4 network (the server's builder reads it that way): judge that one
        net = ipaddress.ip_network((net.network_address.ipv4_mapped, net.prefixlen - 96))
    return net.prefixlen < (WIDE_V4 if net.version == 4 else WIDE_V6)


def _why(text: str | None) -> str:
    why = (text or "").strip()
    if not why:
        raise ScopesError("--why is required: say why (it goes into the audit log)")
    return why


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def _session(a: argparse.Namespace) -> tuple[str, str]:
    return upload.resolve_server(getattr(a, "server", None)), upload.api_key()


def _seen_line(o: Any, s: dict[str, Any]) -> str:
    obs = s.get("observed") or {}
    pre = obs.get("prefixes") or []
    private = [p for p in pre if p.get("private", True)]
    if not pre:
        return "saw no flows in the last %s days" % obs.get("window_days", 7)
    more = "+" if obs.get("truncated") else ""
    return f"saw {len(private)}{more} private /24 network(s), {len(pre) - len(private)} public"


def _sensor_head(o: Any, s: dict[str, Any]) -> str:
    st = o.so
    state = s.get("status") or "?"
    online = "online" if s.get("online") else "offline"
    return (f"  {st.bold(str(s.get('name') or '?'))}  {st.dim(str(s.get('sensor_id')))}  "
            f"{st.dim(str(s.get('site') or ''))}  {st.dim(state + ', ' + online)}")


def cmd_list(a: argparse.Namespace, o: Any) -> int:
    server, key = _session(a)
    data = _listing(server, key)
    if a.json:
        o.p(json.dumps(data, indent=2))
        return EXIT_OK
    st = o.so
    items, unscoped = data.get("items") or [], data.get("unscoped_sensors") or []
    if not items and not unscoped:
        o.p("  no sensors are enrolled.")
        return EXIT_OK
    o.p()
    o.p(f"  {st.bold('SENSOR SCOPES')}  {st.dim('what each sensor may claim to see')}")
    o.p()
    for s in items:
        o.p(_sensor_head(o, s))
        o.p(f"      scope   {', '.join(s.get('cidrs') or [])}")
        if s.get("set_by"):
            o.p(st.dim(f"              declared by {s['set_by']} on {str(s.get('set_at') or '')[:10]}: "
                       f"{s.get('justification') or ''}"))
        o.p(f"      {_seen_line(o, s)}")
        if s.get("observed_outside_scope"):
            o.p(f"      {st.yellow('outside the scope:')} {', '.join(s['observed_outside_scope'][:8])}")
        if s.get("declared_but_unobserved"):
            o.p(f"      {st.yellow('declared but never seen:')} {', '.join(s['declared_but_unobserved'][:8])}")
        for n in s.get("advisory_notes") or []:
            o.p(st.dim(f"      note: {n}"))
        o.p()
    if unscoped:
        o.p(f"  {st.bold('NO DECLARED SCOPE')}  {st.dim('these sensors cover nothing until a scope is declared')}")
        o.p()
        for s in unscoped:
            o.p(_sensor_head(o, s))
            o.p(f"      no declared scope: covers nothing; {_seen_line(o, s)}")
            if s.get("suggested_cidrs"):
                o.p(st.dim(f"      try: paddock assurance scopes suggest {s.get('name') or s.get('sensor_id')}"))
            o.p()
    return EXIT_OK


def cmd_suggest(a: argparse.Namespace, o: Any) -> int:
    server, key = _session(a)
    s = _resolve(_listing(server, key), a.sensor)
    st = o.so
    obs = s.get("observed") or {}
    pre = obs.get("prefixes") or []
    o.p()
    o.p(_sensor_head(o, s))
    if s.get("status") not in (None, "active"):
        o.p(f"  {st.yellow('!')} this sensor is {s.get('status')}: a revoked sensor covers nothing")
    elif s.get("online") is False:
        o.p(f"  {st.yellow('!')} this sensor is offline: it covers nothing while it is offline")
    if not pre:
        o.p(f"  It saw no flows in the last {obs.get('window_days', 7)} days: nothing to suggest "
            "(is it online and mirroring the right port?).")
        o.p()
        return EXIT_OK
    o.p(f"  Seen in the last {obs.get('window_days', 7)} days (busiest first):")
    for p in pre[:10]:
        tag = "" if p.get("private", True) else st.dim("  public, never suggested")
        o.p(f"      {p['prefix']:<20} {p['flows']:>6} flow(s){tag}")
    if obs.get("truncated") or len(pre) > 10:
        o.p(st.dim("      ... more were seen than listed"))
    if s.get("cidrs"):
        o.p(f"  Declared now:   {', '.join(s['cidrs'])}")
        if s.get("observed_outside_scope"):
            o.p(f"  {st.yellow('Seen outside the declared scope:')} {', '.join(s['observed_outside_scope'][:10])}")
        if s.get("declared_but_unobserved"):
            o.p(f"  {st.yellow('Declared but never seen:')} {', '.join(s['declared_but_unobserved'][:10])}")
    for n in s.get("advisory_notes") or []:
        o.p(st.dim(f"  note: {n}"))
    sugg = s.get("suggested_cidrs") or []
    if not sugg:
        o.p("  Only public addresses were seen: there is no private network to suggest.")
        o.p()
        return EXIT_OK
    o.p()
    o.p(f"  {st.bold('Suggested scope:')} {', '.join(sugg)}")
    o.p(st.dim("  A suggestion from traffic, not a fact about the network: declare only what this sensor's"))
    o.p(st.dim("  mirror or SPAN port really carries. Review, edit, then run:"))
    o.p()
    cidrs = " ".join(f"--cidr {c}" for c in sugg)
    o.p(f"    paddock assurance scopes set {s['sensor_id']} {cidrs} --why \"<what this sensor mirrors>\"")
    o.p()
    return EXIT_OK


def cmd_set(a: argparse.Namespace, o: Any) -> int:
    cidrs = _parse_cidrs(a.cidr or [])
    why = _why(a.why)
    wide = [c for c in cidrs if _is_wide(c)]
    if wide and not a.allow_wide:
        raise ScopesError(f"{', '.join(wide)}: shorter than /{WIDE_V4} (IPv4) or /{WIDE_V6} (IPv6). A scope that wide "
                          f"claims 'no such traffic was seen' for a whole network: pass --allow-wide and a --why "
                          f"of at least {WIDE_WHY_MIN} characters if you mean it")
    if a.allow_wide and wide and len(why) < WIDE_WHY_MIN:
        raise ScopesError(f"--allow-wide needs a --why of at least {WIDE_WHY_MIN} characters (it goes into the audit log)")
    server, key = _session(a)
    sid = _sensor_id(server, key, a.sensor)
    body: dict[str, Any] = {"cidrs": cidrs, "justification": why}
    if a.allow_wide:
        body["allow_wide"] = True
    res = _call("PUT", server, f"{_BASE}/{quote(sid)}", key, body) or {}
    if a.json:
        o.p(json.dumps(res, indent=2))
        return EXIT_OK
    st = o.so
    scope = res.get("scope") or {}
    verb = "declared" if res.get("changed") else "unchanged"
    o.p(f"  {st.green(st.ok)} scope {verb} for {sid}: {', '.join(scope.get('cidrs') or cidrs)}")
    for w in res.get("warnings") or []:
        o.p(f"    {st.yellow('!')} {w}")
    return EXIT_OK


def cmd_clear(a: argparse.Namespace, o: Any) -> int:
    why = _why(a.why)
    server, key = _session(a)
    sid = _sensor_id(server, key, a.sensor)
    res = _call("DELETE", server, f"{_BASE}/{quote(sid)}?justification={quote(why, safe='')}", key) or {}
    if a.json:
        o.p(json.dumps(res, indent=2))
        return EXIT_OK
    st = o.so
    o.p(f"  {st.green(st.ok)} scope removed for {sid} (was {', '.join(res.get('previous') or []) or 'empty'}); "
        "the sensor now covers nothing")
    return EXIT_OK


_COMMANDS = {"list": cmd_list, "suggest": cmd_suggest, "set": cmd_set, "clear": cmd_clear}


def run(a: argparse.Namespace, o: Any) -> int:
    """Dispatch ``a.scopes_cmd``; every operator-fixable problem is one ``error:`` line and exit 2."""
    try:
        return _COMMANDS[a.scopes_cmd](a, o)
    except (ScopesError, upload.UploadError) as exc:
        return o.fail(str(exc))


# --------------------------------------------------------------------------- #
# argparse
# --------------------------------------------------------------------------- #
def register(parent: argparse.ArgumentParser, handler: Any) -> None:
    """Add ``list|suggest|set|clear`` under ``paddock assurance scopes``; every leaf runs ``handler``."""
    sub = parent.add_subparsers(dest="scopes_cmd", required=True, metavar="ACTION")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--server", metavar="URL", help="Paddock server (or PADDOCK_SERVER / `paddock login`)")
        p.add_argument("--json", action="store_true", help="machine-readable output on stdout")
        p.add_argument("--no-color", action="store_true", help="disable colour (also: NO_COLOR=1)")
        p.set_defaults(fn=handler)

    p = sub.add_parser("list", help="every sensor, its declared scope and what it actually saw")
    common(p)
    p = sub.add_parser("suggest", help="print what a sensor saw and a scope to review (changes nothing)")
    p.add_argument("sensor", help="sensor id or name")
    common(p)
    p = sub.add_parser("set", help="declare (replace) the networks a sensor can see")
    p.add_argument("sensor", help="sensor id or name")
    p.add_argument("--cidr", action="append", metavar="CIDR",
                   help="a network the sensor can see (repeatable, or comma separated)")
    p.add_argument("--why", metavar="TEXT", required=True, help="why (audited)")
    p.add_argument("--allow-wide", action="store_true",
                   help=f"accept a prefix shorter than /{WIDE_V4} (IPv4) or /{WIDE_V6} (IPv6); needs a "
                        f"{WIDE_WHY_MIN}+ character --why")
    common(p)
    p = sub.add_parser("clear", help="remove a sensor's declared scope (it then covers nothing)")
    p.add_argument("sensor", help="sensor id or name")
    p.add_argument("--why", metavar="TEXT", required=True, help="why (audited)")
    common(p)
