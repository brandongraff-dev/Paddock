"""``paddock wargame``: Wargame's "aha", locally, from a ``wargame.toml`` and your config exports.

``check`` works backward from the crown jewels and prints every route that reaches one, each hop
labelled with the evidence behind it, plus the cheapest set of changes that cuts every route.
``plan`` evaluates a ``terraform show -json`` plan against the same model (the CI change gate).

This module is a thin shell: parsing, the solver, the fix-set optimiser and the change gate are the
engine's (``correlation/app/engine/wargame``, loaded through :mod:`paddock_cli.engines`). The one
rule it adds is the brand's: conditional and inferred hops are always shown as *unproven*, and a
closure figure is never printed without its coverage caveat.
"""
from __future__ import annotations

import argparse
import difflib
import ipaddress
import json
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import __version__, engines, ui

EXIT_OK, EXIT_OPEN, EXIT_ERROR = 0, 1, 2
DEFAULT_FILE = "wargame.toml"
SCHEMA_CHECK = "paddock.wargame.check/1"
SCHEMA_PLAN = "paddock.wargame.plan/1"

_TOP_KEYS = ("project", "segment", "source", "zones", "subnets", "edge", "flows")
_SEGMENT_KEYS = ("id", "cidrs", "role", "jewel_kind", "reason")
_SOURCE_KEYS = ("vendor", "path", "id_prefix", "sg_members")
_EDGE_KEYS = ("from", "to", "ruleset", "port", "evidence", "note")
_FLOW_FORMATS = ("auto", "generic", "zeek", "firewall")
_FIREWALL_VENDORS = ("fortinet", "cisco_asa", "paloalto")
_SOURCE_VENDORS = (*_FIREWALL_VENDORS, "aws", "aws_routes")


class WargameError(Exception):
    """Bad input: reported as ``error: ...`` and exit code 2."""


# --------------------------------------------------------------------------- #
# engine access (lazy: `paddock scan` never pays for this)
# --------------------------------------------------------------------------- #
class _E:
    """Namespace of the engine modules this command uses (public entry points only)."""

    def __init__(self) -> None:
        m = engines.module
        self.model = m("wargame", "model")
        self.fabric = m("wargame", "fabric")
        self.topology = m("wargame", "topology")
        self.parsers = m("wargame", "parsers")
        self.pbase = m("wargame", "parsers.base")
        self.tf = m("wargame", "parsers.terraform")
        self.env = m("wargame", "environment")
        self.mincut = m("wargame", "mincut")
        self.report = m("wargame", "report")
        self.gate = m("wargame", "changegate")
        self.ingest = m("wargame", "ingest")
        self.routing = m("wargame", "routing")


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
class _Out:
    def __init__(self, args: argparse.Namespace) -> None:
        no_color = bool(getattr(args, "no_color", False))
        self.out, self.err = sys.stdout, sys.stderr
        self.so = ui.Style(ui.color_enabled(self.out, no_color), ui.unicode_ok(self.out))
        self.se = ui.Style(ui.color_enabled(self.err, no_color), ui.unicode_ok(self.err))

    def p(self, text: str = "") -> None:
        print(text, file=self.out)

    def e(self, text: str = "") -> None:
        print(text, file=self.err)

    def fail(self, text: str) -> int:
        self.e(f"{self.se.red('error:')} {text}")
        return EXIT_ERROR


# --------------------------------------------------------------------------- #
# the project: wargame.toml + config exports -> an Environment
# --------------------------------------------------------------------------- #
@dataclass
class Note:
    """One thing the model could not prove or had to assume."""

    source: str
    level: str
    message: str
    ref: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"source": self.source, "level": self.level, "message": self.message, "ref": self.ref}


@dataclass
class Project:
    path: Path
    name: str
    env: Any                                   # engine Environment
    notes: list[Note] = field(default_factory=list)
    flows: list[Any] = field(default_factory=list)
    flows_source: str = ""
    sources: list[str] = field(default_factory=list)
    conditional_rules: int = 0
    # candidate id -> (src, dst, ruleset id or "")
    fix_targets: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    fabric: Any = None                         # RoutingFabric when an aws_routes source is given


def _suggest(word: str, options: tuple[str, ...] | list[str]) -> str:
    near = difflib.get_close_matches(str(word), list(options), n=1)
    return f" (did you mean {near[0]!r}?)" if near else ""


def _check_keys(table: dict, allowed: tuple[str, ...], where: str) -> None:
    for k in table:
        if k not in allowed:
            raise WargameError(
                f"{where}: unknown key {k!r}{_suggest(k, allowed)}; allowed: {', '.join(allowed)}")


def _need_str(table: dict, key: str, where: str) -> str:
    v = table.get(key)
    if not isinstance(v, str) or not v.strip():
        raise WargameError(f"{where}: {key!r} is required and must be a non-empty string")
    return v.strip()


def _read_text(path: Path, what: str) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise WargameError(f"{what} not found: {path}") from None
    except IsADirectoryError:
        raise WargameError(f"{what} is a directory, not a file: {path}") from None
    except OSError as exc:
        raise WargameError(f"cannot read {what} {path}: {exc.strerror or exc}") from None


def _port(spec: str, where: str, e: _E):
    """``tcp/8080`` | ``8080`` | ``udp/53`` | ``tcp/1000-2000`` | ``any``."""
    s = spec.strip().lower()
    if s in ("", "any", "*"):
        return e.model.PortRange.any()
    proto_s, _, rest = s.rpartition("/")
    proto_s = proto_s or "tcp"
    try:
        proto = e.model.Proto(proto_s)
        lo_s, _, hi_s = rest.partition("-")
        lo = int(lo_s)
        hi = int(hi_s) if hi_s else lo
        return e.model.PortRange(proto, lo, hi)
    except ValueError:
        raise WargameError(
            f"{where}: bad port {spec!r}; use e.g. \"tcp/5432\", \"udp/53\", \"tcp/8000-8100\" or \"any\"") from None


def _segments(doc: dict, e: _E) -> list:
    raw = doc.get("segment")
    if not isinstance(raw, list) or not raw:
        raise WargameError(
            "no [[segment]] entries: describe at least one entry and one crown_jewel "
            "(run `paddock wargame init` for an example)")
    out, seen = [], set()
    roles = [r.value for r in e.model.NodeRole]
    for i, t in enumerate(raw, 1):
        if not isinstance(t, dict):
            raise WargameError(f"[[segment]] #{i}: expected a table")
        _check_keys(t, _SEGMENT_KEYS, f"[[segment]] #{i}")
        sid = _need_str(t, "id", f"[[segment]] #{i}")
        where = f"segment {sid!r}"
        if sid in seen:
            raise WargameError(f"{where}: duplicate id")
        seen.add(sid)
        role_s = str(t.get("role", "intermediate")).strip().lower()
        if role_s not in roles:
            raise WargameError(f"{where}: unknown role {role_s!r}{_suggest(role_s, roles)}; use one of {', '.join(roles)}")
        cidrs = t.get("cidrs")
        if not isinstance(cidrs, list) or not cidrs or not all(isinstance(c, str) for c in cidrs):
            raise WargameError(f"{where}: 'cidrs' must be a non-empty list of CIDR strings, e.g. [\"10.1.0.0/24\"]")
        norm = []
        for c in cidrs:
            try:
                norm.append(str(ipaddress.ip_network(c.strip(), strict=False)))
            except ValueError:
                raise WargameError(f"{where}: {c!r} is not a valid CIDR (e.g. 10.1.0.0/24)") from None
        for key in ("jewel_kind", "reason"):
            if key in t and not isinstance(t[key], str):
                raise WargameError(f"{where}: {key!r} must be a string")
        out.append(e.fabric.SegmentSpec(
            id=sid, cidrs=tuple(norm), role=e.model.NodeRole(role_s),
            reason=t.get("reason", ""), jewel_kind=t.get("jewel_kind", "")))
    if not any(s.role is e.model.NodeRole.ENTRY for s in out):
        raise WargameError('no segment has role = "entry": nothing can start a route')
    if not any(s.role is e.model.NodeRole.CROWN_JEWEL for s in out):
        raise WargameError('no segment has role = "crown_jewel": there is nothing to protect')
    return out


def _load_sources(doc: dict, base: Path, e: _E, proj: Project):
    """Parse every [[source]]; return (rulesets, bindings, route_oracle)."""
    raw = doc.get("source", [])
    if not isinstance(raw, list):
        raise WargameError("[[source]] must be an array of tables")
    rulesets: dict[str, Any] = {}
    owner: dict[str, str] = {}
    bindings: list = []
    oracle = None
    fabric_obj = None
    for i, t in enumerate(raw, 1):
        if not isinstance(t, dict):
            raise WargameError(f"[[source]] #{i}: expected a table")
        _check_keys(t, _SOURCE_KEYS, f"[[source]] #{i}")
        vendor = _need_str(t, "vendor", f"[[source]] #{i}").lower()
        if vendor not in _SOURCE_VENDORS:
            raise WargameError(
                f"[[source]] #{i}: unknown vendor {vendor!r}{_suggest(vendor, _SOURCE_VENDORS)}; "
                f"use one of {', '.join(_SOURCE_VENDORS)}")
        rel = _need_str(t, "path", f"[[source]] #{i}")
        path = (base / rel)
        label = rel
        text = _read_text(path, f"{vendor} source")
        proj.sources.append(f"{vendor}:{rel}")
        data: Any = text
        if vendor in ("aws", "aws_routes"):
            try:
                data = json.loads(text)
            except ValueError as exc:
                raise WargameError(f"{rel}: not valid JSON ({exc}); expected `aws ec2 describe-*` output") from None
        if vendor == "aws_routes":
            if fabric_obj is not None:
                raise WargameError(f"{rel}: only one aws_routes source is supported")
            if not isinstance(data, dict) or not isinstance(data.get("RouteTables"), list):
                raise WargameError(f"{rel}: no \"RouteTables\" array; expected `aws ec2 describe-route-tables` output")
            fabric_obj = e.routing.from_aws(data)
            oracle = fabric_obj.reachable
            continue
        opts: dict[str, Any] = {}
        if "sg_members" in t:
            if vendor != "aws" or not isinstance(t["sg_members"], dict):
                raise WargameError(f"[[source]] #{i}: sg_members is a table of sg-id = [cidrs], aws sources only")
            opts["sg_members"] = {str(k): list(v) for k, v in t["sg_members"].items()}
        res = e.parsers.parse(vendor, data, **opts)
        if not res.rulesets:
            hint = ("; is this a `describe-security-groups` / `describe-network-acls` export?"
                    if vendor == "aws" else f"; is this really a {vendor} export?")
            raise WargameError(f"{rel}: the {vendor} parser found no rules{hint}")
        prefix = str(t.get("id_prefix", "")).strip()
        if prefix:
            rename = {rid: f"{prefix}:{rid}" for rid in res.rulesets}
            res.rulesets = {rename[rid]: replace_ruleset(rs, rename[rid]) for rid, rs in res.rulesets.items()}
            res.bindings = [replace(b, ruleset_id=rename.get(b.ruleset_id, b.ruleset_id)) for b in res.bindings]
        for rid in res.rulesets:
            if rid in rulesets:
                raise WargameError(
                    f"rule set {rid!r} is defined by both {owner[rid]} and {rel}; "
                    f"set id_prefix = \"...\" on one of the sources to tell them apart")
            owner[rid] = rel
        rulesets.update(res.rulesets)
        bindings.extend(res.bindings)
        proj.conditional_rules += res.conditional_count()
        for w in res.warnings:
            proj.notes.append(Note(label, w.level.value, w.message, w.ref))
    proj.fabric = fabric_obj
    return rulesets, bindings, oracle


def replace_ruleset(rs, new_id: str):
    rs.id = new_id
    return rs


def _edges(doc: dict, segs: list, rulesets: dict, e: _E) -> list:
    raw = doc.get("edge", [])
    if not isinstance(raw, list):
        raise WargameError("[[edge]] must be an array of tables")
    ids = [s.id for s in segs]
    out = []
    for i, t in enumerate(raw, 1):
        where = f"[[edge]] #{i}"
        if not isinstance(t, dict):
            raise WargameError(f"{where}: expected a table")
        _check_keys(t, _EDGE_KEYS, where)
        src, dst = _need_str(t, "from", where), _need_str(t, "to", where)
        where = f"edge {src} -> {dst}"
        for end, v in (("from", src), ("to", dst)):
            if v not in ids:
                raise WargameError(f"{where}: {end!r} names unknown segment {v!r}{_suggest(v, ids)}; segments: {', '.join(ids)}")
        rs = t.get("ruleset")
        if rs is not None:
            if not isinstance(rs, str) or rs not in rulesets:
                avail = sorted(rulesets)
                raise WargameError(
                    f"{where}: ruleset {rs!r} is not defined by any [[source]]{_suggest(str(rs), avail)}; "
                    f"available: {', '.join(avail) or '(none)'}")
        port = _port(str(t["port"]), where, e) if "port" in t else None
        ev = str(t.get("evidence", "inferred")).lower()
        if ev not in ("inferred", "observed"):
            raise WargameError(f"{where}: evidence must be \"inferred\" or \"observed\", not {ev!r}")
        labels = frozenset({e.model.EvidenceLabel.OBSERVED}) if (ev == "observed" and rs is None) else frozenset()
        out.append(e.fabric.EdgeSpec(src=src, dst=dst, rule_set_id=rs, port=port, base_labels=labels))
    return out


def _mapping(doc: dict, key: str, segs: list) -> dict[str, str]:
    t = doc.get(key, {})
    if not isinstance(t, dict):
        raise WargameError(f"[{key}] must be a table of name = \"segment-id\"")
    ids = [s.id for s in segs]
    for k, v in t.items():
        if not isinstance(v, str) or v not in ids:
            raise WargameError(f"[{key}] {k} = {v!r}: not a known segment{_suggest(str(v), ids)}; segments: {', '.join(ids)}")
    return dict(t)


def _load_flows(path: Path, fmt: str, e: _E, proj: Project, label: str) -> list:
    text = _read_text(path, "flows file")
    flows, stats = e.ingest.parse_flows_detailed(text, fmt)
    if not flows:
        raise WargameError(
            f"{label}: no usable flows found in {path.name} "
            f"({stats.skipped} row(s) skipped{': ' + stats.reasons[0] if stats.reasons else ''}); "
            "expected Zeek conn.log JSON lines, a firewall allow log, or generic JSON")
    if stats.skipped:
        proj.notes.append(Note(label, "info", f"{stats.skipped} flow row(s) could not be read and were skipped",
                               stats.reasons[0] if stats.reasons else ""))
    return flows


def _assign_fix_ids(env, proj: Project) -> None:
    """Every edge is a cuttable element: a rule change on a governed edge, a new control on an
    ungoverned one. (The cost of each is worked out in :func:`_candidate_of`.)"""
    edges = []
    for edge in env.edges:
        cid = edge.fix_candidate_id
        if not cid:
            cid = f"cut:{edge.src}->{edge.dst}" + (f":{edge.rule_set_id}" if edge.rule_set_id else "")
            edge = replace(edge, fix_candidate_id=cid)
        proj.fix_targets.setdefault(cid, (edge.src, edge.dst, edge.rule_set_id or ""))
        edges.append(edge)
    env.edges = edges


def load_project(file: str | Path, e: _E, flows_override: str | None = None) -> Project:
    path = Path(file)
    if not path.is_file():
        hint = "run `paddock wargame init` to create an example" if path.name == DEFAULT_FILE else "check --file"
        raise WargameError(f"{path} not found; {hint}")
    try:
        doc = tomllib.loads(_read_text(path, "project file"))
    except tomllib.TOMLDecodeError as exc:
        raise WargameError(f"{path}: invalid TOML: {exc}") from None
    for k in doc:
        if k not in _TOP_KEYS:
            raise WargameError(f"{path}: unknown section {k!r}{_suggest(k, _TOP_KEYS)}; allowed: {', '.join(_TOP_KEYS)}")
    base = path.resolve().parent
    proj_t = doc.get("project", {})
    name = str(proj_t.get("name") or base.name) if isinstance(proj_t, dict) else base.name
    proj = Project(path=path, name=name, env=None)

    segs = _segments(doc, e)
    rulesets, bindings, oracle = _load_sources(doc, base, e, proj)
    edges = _edges(doc, segs, rulesets, e)
    spec = e.fabric.TopologySpec(
        segments=segs, edges=edges,
        zone_to_segment=_mapping(doc, "zones", segs), subnet_to_segment=_mapping(doc, "subnets", segs))

    flows_t = doc.get("flows", {})
    if not isinstance(flows_t, dict):
        raise WargameError("[flows] must be a table with file = \"...\"")
    flows_file, label = flows_override, "--flows"
    fmt = "auto"
    if flows_file is None and flows_t.get("file"):
        flows_file, label = str(flows_t["file"]), "[flows]"
        flows_file = str(base / flows_file)
        fmt = str(flows_t.get("format", "auto")).lower()
        if fmt not in _FLOW_FORMATS:
            raise WargameError(f"[flows]: format must be one of {', '.join(_FLOW_FORMATS)}")
    if flows_file is not None:
        proj.flows = _load_flows(Path(flows_file), fmt, e, proj, label)
        proj.flows_source = flows_file

    topo = e.topology.build_topology(
        spec, rulesets, bindings=bindings, observed_flows=proj.flows, route_reachable=oracle)
    for w in topo.warnings:
        proj.notes.append(Note("model", "info", w.message, w.ref))
    _assign_fix_ids(topo.environment, proj)
    proj.env = topo.environment
    return proj


def _finish_notes(proj: Project) -> None:
    """Routing assumptions are recorded while the solver queries the oracle, so read them last."""
    if proj.fabric is not None:
        for a in proj.fabric.assumptions():
            proj.notes.append(Note("routing", "assumption", a))


# --------------------------------------------------------------------------- #
# presentation helpers
# --------------------------------------------------------------------------- #
_LABEL_TEXT = {
    "imported": "imported pentest result", "proved_replica": "proved on a replica",
    "proved_live_safe_check": "proved by a safe check", "observed": "observed traffic",
    "tested_probe": "probe crossed", "proved_config": "proved by config",
    "conditional": "conditional", "inferred": "inferred", "unknown": "unknown",
}
_UNPROVEN_WHY = {
    "conditional": "depends on runtime state the config cannot prove (FQDN, App-ID, unresolved object)",
    "inferred": "no rule proves this hop; it is assumed from the declared topology",
    "unknown": "outside the model",
}


def _labels_sorted(labels, e: _E) -> list[str]:
    strength = e.model.LABEL_STRENGTH
    return [lb.value for lb in sorted(labels, key=lambda x: (-strength[x], x.value))]


def _unproven(label_value: str) -> bool:
    return label_value in _UNPROVEN_WHY


def _port_text(port) -> str:
    if port is None:
        return ""
    if port.low == 0 and port.high == 65535:
        return f"{port.proto.value}/any" if port.proto.value != "any" else "any port"
    rng = str(port.low) if port.low == port.high else f"{port.low}-{port.high}"
    return f"{port.proto.value}/{rng}"


def _route_dict(route, e: _E) -> dict[str, Any]:
    hops = []
    for h in route.hops:
        weakest = h.weakest.value
        hops.append({
            "src": h.src, "dst": h.dst, "labels": _labels_sorted(h.labels, e), "weakest": weakest,
            "proven": not _unproven(weakest), "port": _port_text(h.port) or None,
            "rule": h.rule_ref or None, "fix_candidates": sorted(h.fix_candidate_ids)})
    weakest = route.weakest_label.value
    return {"entry": route.entry, "jewel": route.jewel, "weakest": weakest,
            "proven": not _unproven(weakest), "path": [route.entry, *[h.dst for h in route.hops]],
            "hops": hops}


def _route_order(route, e: _E):
    return (-e.model.LABEL_STRENGTH[route.weakest_label], route.length,
            tuple((h.src, h.dst) for h in route.hops))


def _render_route(o: _Out, rd: dict[str, Any], indent: str = "      ") -> None:
    st = o.so
    width = max(len(h["src"]) for h in rd["hops"])
    width2 = max(len(h["dst"]) for h in rd["hops"])
    for h in rd["hops"]:
        ev = " + ".join(_LABEL_TEXT.get(lb, lb) for lb in h["labels"])
        extra = "  ".join(x for x in (h["port"], h["rule"]) if x)
        line = f"{indent}{h['src']:<{width}} {st.arrow} {h['dst']:<{width2}}  "
        if h["proven"]:
            line += st.green(ev)
        else:
            line += st.yellow(f"{ev.upper()}, UNPROVEN")
        o.p(line + (st.dim(f"   {extra}") if extra else ""))
        if not h["proven"]:
            o.p(st.dim(f"{indent}  {st.arrow} {_UNPROVEN_WHY[h['weakest']]}"))


def _wrap(o: _Out, text: str, indent: int) -> str:
    return o.so.wrap(text, indent)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def cmd_init(a: argparse.Namespace) -> int:
    from .wargame_example import FILES
    o = _Out(a)
    root = Path(a.path)
    if not root.is_dir():
        return o.fail(f"{a.path} is not a directory")
    existing = [rel for rel in FILES if (root / rel).exists()]
    if existing and not a.force:
        o.e(f"{o.se.red('error:')} {', '.join(existing)} already exist{'s' if len(existing) == 1 else ''}; "
            "nothing written (use --force to overwrite)")
        return EXIT_ERROR
    st = o.so
    for rel, content in FILES.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        o.p(f"  {st.green(st.ok)} {rel}")
    cd = "" if root == Path(".") else f"cd {root} && "
    o.p()
    o.p(st.dim(f"    try it:  {cd}paddock wargame check"))
    o.p(st.dim(f"             {cd}paddock wargame plan wargame/example-plan.json"))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #
@dataclass
class Analysis:
    proj: Project
    result: Any
    scorecard: Any
    fix: Any
    cands: dict
    open_routes: list


def analyse(proj: Project, e: _E) -> Analysis:
    result = proj.env.reachability()
    cands = {}
    for edge in proj.env.edges:
        cid = edge.fix_candidate_id
        if cid and cid not in cands:
            cands[cid] = _candidate_of(proj, cid, e)
    sc = e.report.build_scorecard(result)
    # Verified: the fix set is applied to the model and the search re-run, so
    # "cuts every route" also holds for routes the enumeration caps never listed.
    fix = e.mincut.verified_fix_set(proj.env.nodes, proj.env.edges, proj.env.rulesets,
                                    cands, result=result)
    open_routes = sorted((r for r in result.routes if r.pair in result.open_pairs),
                         key=lambda r: (r.pair, _route_order(r, e)))
    return Analysis(proj, result, sc, fix, cands, open_routes)


def _candidate_of(proj: Project, cid: str, e: _E):
    src, dst, rs = proj.fix_targets[cid]
    env = proj.env
    if rs and rs in env.rulesets and env.rulesets[rs].rules:
        cost_class = min(env.rulesets[rs].rules, key=lambda r: (r.order, r.id)).cost_class
        desc = f"tighten rule set {rs} so {src} can no longer reach {dst}"
    elif rs:
        cost_class, desc = "network_rule", f"fix rule set {rs} on {src} -> {dst}"
    else:
        cost_class = "segment_move"
        desc = f"put a control between {src} and {dst} (today an ungoverned adjacency)"
    return e.model.FixCandidate(cid, "edge", cost_class, desc, e.mincut.cost_for(cost_class))


def _check_dict(an: Analysis, e: _E) -> dict[str, Any]:
    proj, sc, fix = an.proj, an.scorecard, an.fix
    c = sc.closure
    routes = [_route_dict(r, e) for r in an.open_routes]
    uses: dict[str, int] = {}
    for r in an.open_routes:
        for cid in r.fix_elements:
            uses[cid] = uses.get(cid, 0) + 1
    selected = []
    for cid in fix.selected:
        cand = an.cands[cid]
        src, dst, rs = proj.fix_targets[cid]
        refs = sorted({h.rule_ref for r in an.open_routes for h in r.hops
                       if cid in h.fix_candidate_ids and h.rule_ref})
        selected.append({
            "id": cid, "description": cand.description, "from": src, "to": dst, "ruleset": rs or None,
            "rules": refs, "cost_class": cand.cost_class, "cost": cand.cost,
            "cuts_routes": uses.get(cid, 0)})
    return {
        "schema": SCHEMA_CHECK,
        "tool": {"name": "paddock-cli", "version": __version__},
        "project": proj.name,
        "file": str(proj.path),
        "verdict": "open" if c.open_pairs else "closed",
        "board_line": sc.board_line,
        "closure": {
            "pairs": c.total_pairs, "open": c.open_pairs, "closed": c.closed_pairs,
            "conditional": c.conditional_pairs, "closure_pct": round(c.closure_pct, 1),
            "open_by_weakest_label": c.by_weakest_label},
        "coverage": {"pct": sc.coverage.coverage_pct, "note": sc.coverage.note,
                     "blind_spots": sc.coverage.blind_spots},
        "routes": routes,
        "closed_pairs": [{"entry": p[0], "jewel": p[1]} for p in sorted(
            set(an.result.closed_pairs) - set(an.result.open_pairs))],
        "fix": {
            "selected": selected, "total_cost": fix.total_cost, "cuts_every_route": bool(fix.cuts_all),
            "optimality": fix.optimality,
            "uncut_routes": [_uncut_dict(fix.routes[i], e) for i in fix.uncut_routes
                             if i < len(fix.routes)],
            "uncuttable_pairs": [{"entry": p[0], "jewel": p[1]}
                                 for p in sorted(fix.uncuttable_pairs)]},
        "unproven": _unproven_summary(proj),
        "model": {"segments": sorted(n for n in proj.env.nodes), "rule_sets": sorted(proj.env.rulesets),
                  "edges": len(proj.env.edges), "sources": proj.sources,
                  "observed_flows": len(proj.flows)},
    }


def _uncut_dict(r: Any, e: _E) -> dict[str, Any]:
    # fix.uncut_routes indexes the verified fix set's own route list.
    return {"entry": r.entry, "jewel": r.jewel, "path": _route_dict(r, e)["path"]}


def _unproven_summary(proj: Project) -> dict[str, Any]:
    return {"conditional_rules": proj.conditional_rules, "notes": [n.as_dict() for n in proj.notes]}


def _render_unproven(o: _Out, proj: Project, *, cap: int = 12) -> None:
    st = o.so
    notable = [n for n in proj.notes if n.level != "info" or (
        n.source in ("model", "routing") and not n.message.startswith("auto-wired"))]
    infos = [n for n in proj.notes if n not in notable]
    if not (proj.conditional_rules or notable or infos):
        return
    o.p("  " + st.bold("WHAT WE COULDN'T PROVE"))
    if proj.conditional_rules:
        n = proj.conditional_rules
        o.p(f"   {st.yellow('!')} {n} rule{'s' if n != 1 else ''} depend{'' if n != 1 else 's'} on runtime state "
            "(FQDN, App-ID, unresolved objects).")
        o.p(st.dim("     We treat them as reachable, so they can never count toward \"closed\"."))
    shown = 0
    for n in notable:
        if shown >= cap:
            break
        shown += 1
        msg = f"{n.message}" + (f" ({n.ref})" if n.ref else "")
        o.p(f"   {st.yellow('-')} {st.dim(n.source + ':')} {msg}")
    if len(notable) > cap:
        o.p(st.dim(f"     ... and {len(notable) - cap} more (see --json)"))
    if infos:
        o.p(st.dim(f"   {len(infos)} informational parser note{'s' if len(infos) != 1 else ''} (see --json)"))
    o.p()


def cmd_check(a: argparse.Namespace) -> int:
    o = _Out(a)
    try:
        e = _E()
        proj = load_project(a.file, e, a.flows)
        an = analyse(proj, e)
        _finish_notes(proj)
    except WargameError as exc:
        return o.fail(str(exc))
    except engines.EngineUnavailable as exc:
        return o.fail(str(exc))
    d = _check_dict(an, e)
    code = EXIT_OPEN if d["closure"]["open"] else EXIT_OK
    if a.json:
        o.p(json.dumps(d, indent=2))
        return code
    st = o.so
    c = d["closure"]
    o.p()
    o.p(f"  {st.bold('paddock wargame check')} {st.dim(__version__)}")
    o.p(st.dim(f"  {proj.name}: {len(proj.env.nodes)} segments, {len(proj.env.rulesets)} rule sets, "
               f"{len(proj.env.edges)} edges, {len(proj.flows)} observed flows"))
    o.p()
    o.p(_wrap(o, d["board_line"], 2))
    o.p()
    if c["open"] == 0:
        o.p(f"  {st.green(st.ok)} No open route reaches a crown jewel in this model.")
        o.p(st.dim(_wrap(o, d["coverage"]["note"], 4)))
        o.p()
        _render_unproven(o, proj)
        return code

    n_routes, n_pairs = len(d["routes"]), c["open"]
    o.p(f"  {st.bold('OPEN ROUTES')} " + st.dim(f"({n_routes} across {_plural(n_pairs, 'entry/jewel pair')})"))
    by_pair: dict[tuple[str, str], list[dict]] = {}
    for r in d["routes"]:
        by_pair.setdefault((r["entry"], r["jewel"]), []).append(r)
    n = 0
    for (entry, jewel), rs in by_pair.items():
        for r in rs[:3]:
            n += 1
            path = f" {st.arrow} ".join(r["path"])
            tag = st.green("proved") if r["proven"] else st.yellow("UNPROVEN")
            o.p(f"   {n:>2}. {st.bold(path)}   {tag}")
            _render_route(o, r)
        if len(rs) > 3:
            o.p(st.dim(f"       ... {len(rs) - 3} more route{'s' if len(rs) - 3 != 1 else ''} "
                       f"from {entry} to {jewel} (see --json)"))
    o.p()
    if d["closed_pairs"]:
        o.p(st.dim("  closed: " + ", ".join(f"{p['entry']} {st.arrow} {p['jewel']}" for p in d["closed_pairs"])))
        o.p()
    unproven_routes = [r for r in d["routes"] if not r["proven"]]
    if unproven_routes:
        o.p(st.dim(_wrap(o, "UNPROVEN means a hop rests on a conditional rule or an inferred adjacency. "
                            "Wargame cannot prove those closed, so the route counts as open.", 2)))
        o.p()

    fx = d["fix"]
    o.p(f"  {st.bold('CHEAPEST FIX SET')} " + st.dim(f"(cost {fx['total_cost']:g}, {fx['optimality']} search)"))
    for i, s in enumerate(fx["selected"], 1):
        o.p(f"   {i:>2}. {s['description']}")
        bits = [f"cuts {s['cuts_routes']} of {len(d['routes'])} open route{'s' if len(d['routes']) != 1 else ''}",
                s["cost_class"]]
        if s["rules"]:
            bits.append("rule " + ", ".join(s["rules"]))
        o.p(st.dim("       " + " · ".join(bits)))
    for u in fx["uncut_routes"]:
        o.p(f"   {st.red(st.bad)} no modelled control to change on {' '.join([u['path'][0], st.arrow, u['path'][-1]])}"
            f" via {', '.join(u['path'][1:-1]) or 'a direct link'}")
    cuts = "yes" if fx["cuts_every_route"] else "no"
    o.p(f"       {st.bold('cuts every route:')} {st.green(cuts) if fx['cuts_every_route'] else st.red(cuts)}")
    if fx["optimality"] != "exact":
        o.p(st.dim("       (greedy search: a good set, not guaranteed minimal)"))
    o.p()
    _render_unproven(o, proj)
    o.e(f"{o.se.red(o.se.bad)} {_plural(c['open'], 'crown-jewel route pair')} open: failing (exit {EXIT_OPEN})")
    return code


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #
def _flow_dict(fi) -> dict[str, Any]:
    f = fi.flow
    return {"src": f.src_ip, "dst": f.dst_ip, "proto": f.proto.value, "port": f.dst_port,
            "ruleset": fi.ruleset_id}


def _flow_text(fd: dict[str, Any]) -> str:
    return f"{fd['src']} -> {fd['dst']} {fd['proto']}/{fd['port']} at {fd['ruleset']}"


def _summary(verdict: str, impact, flows_given: bool) -> str:
    jewels = sorted({d.pair[1] for d in impact.routes_opened})
    entries = sorted({d.pair[0] for d in impact.routes_opened})
    n_broken = len(impact.newly_denied_flows)
    opens = f"This change opens a route to {', '.join(jewels)}" + (
        f" (from {', '.join(entries)})" if entries else "")
    breaks = f"This change would break {_plural(n_broken, 'live flow')}"
    if verdict == "opens_and_breaks":
        return f"{opens}, and would break {_plural(n_broken, 'live flow')}."
    if verdict == "opens_route_to_crown_jewel":
        return f"{opens}."
    if verdict == "breaks_live_flows":
        return f"{breaks}."
    return "This change is safe by the model: no route to a crown jewel opens" + (
        " and no live flow breaks." if flows_given else ".")


def _split_ops(env, change, e: _E):
    """Apply ops one at a time so an op the model cannot place is reported, not fatal."""
    good, unmodelled = [], []
    for op in change.ops:
        try:
            e.env.apply_change(env, e.env.ProposedChange(ops=[op]))
            good.append(op)
        except e.env.ChangeError as exc:
            unmodelled.append({"change": op.description or op.kind.value, "reason": str(exc)})
    return e.env.ProposedChange(ops=good, title=change.title, source=change.source), unmodelled


def cmd_plan(a: argparse.Namespace) -> int:
    o = _Out(a)
    if a.json and a.markdown:
        return o.fail("--json and --markdown both write to stdout; choose one")
    try:
        e = _E()
        plan_text = _read_text(Path(a.plan), "plan file")
        try:
            plan = json.loads(plan_text)
        except ValueError as exc:
            raise WargameError(
                f"{a.plan}: not valid JSON ({exc}); create it with "
                "`terraform plan -out tfplan && terraform show -json tfplan > plan.json`") from None
        if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes", []), list):
            raise WargameError(f"{a.plan}: not a `terraform show -json` plan (no \"resource_changes\" array)")
        if "resource_changes" not in plan:
            raise WargameError(f"{a.plan}: no \"resource_changes\"; is this `terraform show -json` output of a plan "
                               "(not `terraform show -json` of state)?")
        proj = load_project(a.file, e, a.flows)
        parsed = e.tf.parse_plan_detailed(plan)
        change, unmodelled = _split_ops(proj.env, parsed.change, e)
        impact = e.gate.evaluate_change(proj.env, change, flows=proj.flows)
        _finish_notes(proj)
    except WargameError as exc:
        return o.fail(str(exc))
    except engines.EngineUnavailable as exc:
        return o.fail(str(exc))

    verdict = impact.verdict
    flows_given = bool(proj.flows)
    summary = _summary(verdict, impact, flows_given)
    gaps = len(unmodelled) + len(parsed.skipped)
    safe = verdict == "safe"
    strict_fail = bool(a.strict and gaps)
    d = {
        "schema": SCHEMA_PLAN,
        "tool": {"name": "paddock-cli", "version": __version__},
        "project": proj.name, "file": str(proj.path), "plan": str(a.plan),
        "verdict": verdict, "safe": safe and not strict_fail, "summary": summary,
        "routes_opened": [{"entry": r.pair[0], "jewel": r.pair[1],
                           "example_route": _route_dict(r.example_route, e) if r.example_route else None}
                          for r in impact.routes_opened],
        "routes_closed": [{"entry": r.pair[0], "jewel": r.pair[1]} for r in impact.routes_closed],
        "newly_denied_flows": [_flow_dict(f) for f in impact.newly_denied_flows],
        "newly_allowed_flows": [_flow_dict(f) for f in impact.newly_allowed_flows],
        "affected_boundaries": impact.affected_boundaries,
        "change": {"title": change.title, "operations": [op.description for op in change.ops]},
        "not_modelled": {
            "operations": unmodelled,
            "skipped_resources": [{"address": ad, "reason": why} for ad, why in parsed.skipped]},
        "flows_checked": len(proj.flows),
        "unproven": _unproven_summary(proj),
    }
    code = EXIT_OK if d["safe"] else EXIT_OPEN
    if a.json:
        o.p(json.dumps(d, indent=2))
    elif a.markdown:
        o.p(_plan_markdown(d, flows_given))
    else:
        _plan_text(o, d, flows_given)
    if code and not a.json and not a.markdown:
        why = "unsafe change" if not safe else "--strict and parts of the plan are not modelled"
        o.e(f"{o.se.red(o.se.bad)} {why}: failing (exit {EXIT_OPEN})")
    return code


def _plan_text(o: _Out, d: dict[str, Any], flows_given: bool) -> None:
    st = o.so
    safe = d["verdict"] == "safe"
    o.p()
    o.p(f"  {st.bold('paddock wargame plan')} {st.dim(__version__)}")
    o.p(st.dim(f"  {d['plan']} against {d['project']}"))
    o.p()
    o.p(f"  {st.green(st.ok) if safe else st.red(st.bad)} {st.bold(d['summary'])}")
    o.p()
    if d["routes_opened"]:
        o.p(f"  {st.bold('ROUTES OPENED')}")
        for r in d["routes_opened"]:
            ex = r["example_route"]
            o.p(f"   {st.red('+')} {r['entry']} {st.arrow} {r['jewel']}")
            if ex:
                _render_route(o, ex, indent="       ")
        o.p()
    if d["newly_denied_flows"]:
        o.p(f"  {st.bold('LIVE FLOWS THIS WOULD BREAK')} {st.dim('(allowed today, denied after)')}")
        for f in d["newly_denied_flows"]:
            o.p(f"   {st.red('!')} {_flow_text(f)}")
        o.p()
    if d["newly_allowed_flows"]:
        o.p(f"  {st.bold('TRAFFIC THIS WOULD NEWLY ALLOW')}")
        for f in d["newly_allowed_flows"]:
            o.p(f"   {st.yellow('+')} {_flow_text(f)}")
        o.p()
    if d["routes_closed"]:
        o.p(f"  {st.bold('ROUTES CLOSED')}")
        for r in d["routes_closed"]:
            o.p(f"   {st.green('-')} {r['entry']} {st.arrow} {r['jewel']}")
        o.p()
    nm = d["not_modelled"]
    gaps = nm["operations"], nm["skipped_resources"]
    if any(gaps) or not flows_given:
        o.p("  " + st.bold("WHAT WE COULDN'T PROVE"))
        for op in nm["operations"]:
            o.p(f"   {st.yellow('-')} not in the model: {op['change']} ({op['reason']})")
        for s in nm["skipped_resources"]:
            o.p(f"   {st.yellow('-')} not analysed: {s['address']} ({s['reason']})")
        if not flows_given:
            o.p(f"   {st.yellow('-')} no observed flows given, so broken live flows were not checked "
                f"(add [flows] to wargame.toml or pass --flows FILE)")
        o.p()
    o.p(st.dim(_wrap(o, f"Judged against the environment in {Path(d['file']).name} only; anything outside it is not seen.", 2)))
    o.p()


def _plan_markdown(d: dict[str, Any], flows_given: bool) -> str:
    safe = d["verdict"] == "safe"
    L = [f"### Paddock Wargame: {'safe' if safe else 'not safe to merge'}", "", f"**{d['summary']}**", ""]
    if d["routes_opened"]:
        L += ["**Routes opened**", ""]
        for r in d["routes_opened"]:
            L.append(f"- `{r['entry']}` -> `{r['jewel']}`")
            ex = r["example_route"]
            if ex:
                for h in ex["hops"]:
                    ev = ", ".join(_LABEL_TEXT.get(x, x) for x in h["labels"])
                    flag = "" if h["proven"] else " **(unproven)**"
                    extra = " ".join(x for x in (h["port"], h["rule"]) if x)
                    L.append(f"  - `{h['src']}` -> `{h['dst']}`: {ev}{flag}" + (f" ({extra})" if extra else ""))
        L.append("")
    if d["newly_denied_flows"]:
        L += ["**Live flows this would break**", ""] + [f"- `{_flow_text(f)}`" for f in d["newly_denied_flows"]] + [""]
    if d["newly_allowed_flows"]:
        L += ["**Traffic this would newly allow**", ""] + [f"- `{_flow_text(f)}`" for f in d["newly_allowed_flows"]] + [""]
    if d["routes_closed"]:
        L += ["**Routes closed**", ""] + [f"- `{r['entry']}` -> `{r['jewel']}`" for r in d["routes_closed"]] + [""]
    nm = d["not_modelled"]
    gaps = [f"- not in the model: {o['change']} ({o['reason']})" for o in nm["operations"]]
    gaps += [f"- not analysed: {s['address']} ({s['reason']})" for s in nm["skipped_resources"]]
    if not flows_given:
        gaps.append("- no observed flows given, so broken live flows were not checked")
    if gaps:
        L += ["**What we couldn't prove**", ""] + gaps + [""]
    L.append("<sub>Judged against the modelled environment only. Generated locally by "
             f"`paddock wargame plan` {__version__}; nothing was sent anywhere.</sub>")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# argparse wiring
# --------------------------------------------------------------------------- #
def add_parser(sub: argparse._SubParsersAction) -> None:
    w = sub.add_parser("wargame", help="map routes to your crown jewels from your configs, and gate changes")
    ws = w.add_subparsers(dest="wcmd", required=True, metavar="SUBCOMMAND")

    i = ws.add_parser("init", help="write an example wargame.toml (and sample configs) to try")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--force", action="store_true", help="overwrite existing files")
    i.add_argument("--no-color", action="store_true")
    i.set_defaults(fn=cmd_init)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--file", "-f", default=DEFAULT_FILE, metavar="FILE",
                       help=f"project file (default: {DEFAULT_FILE})")
        p.add_argument("--flows", metavar="FILE", help="observed flows (overrides [flows] in the project file)")
        p.add_argument("--json", action="store_true", help="machine-readable output on stdout")
        p.add_argument("--no-color", action="store_true", help="disable colour (also: NO_COLOR=1)")

    c = ws.add_parser("check", help="list open routes to crown jewels and the cheapest fix set")
    common(c)
    c.set_defaults(fn=cmd_check)

    pl = ws.add_parser("plan", help="would this Terraform plan open a route or break live flows? (CI gate)")
    pl.add_argument("plan", metavar="PLAN.json", help="output of `terraform show -json`")
    common(pl)
    pl.add_argument("--markdown", action="store_true", help="a PR-comment sized markdown report on stdout")
    pl.add_argument("--strict", action="store_true",
                    help="also exit 1 when part of the plan cannot be placed in the model")
    pl.set_defaults(fn=cmd_plan)
