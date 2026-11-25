"""Tables -> paddock_assurance graph document. Owned by the store work package (section 5).

``load_graph_doc`` is READ-ONLY and deterministic: the same rows always give the same document
(sorted nodes, edges and coverage facts), so a verdict digest is stable. The document is the
format of docs/ASSURANCE_P1.md section 3 and loads with ``paddock_assurance.ReachGraph.from_dict``.

Host facts (docs/ASSURANCE_P2.md section 5): ``reach_node_facts`` rows become
``nodes[].facts.<collector> = {status, tier, observed_at, signed, source, key_id, seq, evidence_ref,
conf, partial, [reason], [conflict], data}`` (``store.FactOut`` documents the stored shape). A node
with any fact row is auto-tagged ``agent`` (a metadata default: a declared ``agent`` label, even
``false``, overrides it). A stored entry the document cannot carry (malformed, over a cap, or
rejected by the library's own fact parser) is DROPPED and counted in ``LoadDiagnostics``: that
collector is then unknown on the host, which the evaluator reads as UNKNOWN, whereas passing it
through would make the library refuse the whole graph and every invariant UNKNOWN. Two sources
claiming the same collector on one node are both dropped (which one is right?).

Where the stored facts are coarser than the document can say, the loader widens rather than
narrows (a false HOLDS is the worst bug): an edge port range that touches port 0 becomes
``1-hi`` (or the full range when it is only port 0), and no edge is ever dropped. Coverage is
never given to the internet node.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .refs import INTERNET, KINDS, is_valid_ref
from . import store
from .store import Zone, ZoneIndex, _zone

#: label values that explicitly turn a tag off (e.g. un-mark a metadata-derived crown jewel).
_FALSE_VALUES = frozenset({"false", "no", "0", "off"})
_SPECIAL_TAGS = frozenset({"zone", "class", "kind"})
_SOURCE_RANK = {"declared": 3, "connector": 2, "metadata": 1}
_IP_KEYS = ("ips", "public_ips", "private_ips", "ip")
#: Tag every node that has host facts (any source) gets, unless a declared label says otherwise.
AGENT_TAG = "agent"

_ASSET_SQL = (
    "SELECT id, kind, value, jsonb_build_object("
    "'crown_jewel', metadata->'crown_jewel', 'ips', metadata->'ips', "
    "'public_ips', metadata->'public_ips', 'private_ips', metadata->'private_ips', "
    "'ip', metadata->'ip') AS md FROM assets WHERE id = ANY($1::uuid[])"
)


#: Most edges the CIDR expansion may add to one document. Past it a destination keeps its CIDR
#: edge but cannot list who is inside the CIDR, so the document UNDER-approximates the graph.
#: Withdrawing the destination's inbound coverage is not enough to make that safe (an unknown
#: edge needs the SOURCE to be blind outbound too, and a source covered outbound loses its edge
#: outright), so the loader reports ``LoadDiagnostics.cidr_overflow`` and the runner marks every
#: invariant UNKNOWN (``graph_incomplete:cidr_expansion_overflow``) instead of evaluating it.
MAX_EXPANDED_EDGES = 400_000


@dataclass
class LoadDiagnostics:
    """Facts about the load that are not part of the document."""
    graph_version: int = 0
    #: destinations whose CIDR sources could not be expanded (cap hit): inbound coverage withdrawn.
    cidr_unexpanded: list[str] = field(default_factory=list)
    #: True iff the cap was hit: the document is INCOMPLETE and must not be evaluated.
    cidr_overflow: bool = False
    #: node id -> zone names its addresses resolved into (a multi-homed node in two zones).
    zone_conflicts: dict[str, list[str]] = field(default_factory=dict)
    #: ``agent:<uuid>`` nodes whose zone rests ONLY on the addresses the host claims about itself (no declared
    #: label, no address the server observed): an unverified placement, see :func:`_agent_zone`. Each is emitted
    #: with ``zone_unknown: true`` (its ``zone`` is kept as a best guess for display only).
    zone_from_claim: list[str] = field(default_factory=list)
    #: ``agent:<uuid>`` nodes with NO zone at all (no declared label, no usable observed address, a claim that
    #: matches no zone). Each is emitted with ``zone_unknown: true``: the library treats the node as a POSSIBLE member
    #: of every zone selector (as source and as target), so a zone-selected invariant is UNKNOWN, never HOLDS, where
    #: the node could change the verdict (review finding hostfw-1, Z-1).
    zone_unplaced: list[str] = field(default_factory=list)

    @property
    def zone_unknown(self) -> list[str]:
        """Every node the document marks ``zone_unknown`` (sorted)."""
        return sorted({*self.zone_from_claim, *self.zone_unplaced})
    #: host-fact entries (or whole rows) left out of the document because they were invalid; the
    #: affected collectors read as unknown. ``fact_issues`` keeps the first few reasons.
    facts_dropped: int = 0
    fact_issues: list[str] = field(default_factory=list)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat()


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() not in _FALSE_VALUES and v.strip() != ""
    return bool(v)


def _ports(proto: str, lo: int, hi: int) -> Optional[str]:
    """``'lo-hi'`` (library-parsable: 1..65535). ``None`` for icmp (no ports)."""
    if proto == "icmp":
        return None
    lo, hi = max(1, int(lo)), min(65535, int(hi))
    if hi < lo:                       # only port 0 / nonsense: widen, never narrow
        lo, hi = 1, 65535
    return f"{lo}-{hi}"


_ORIGINS = frozenset({"internet"})
_FACT_PROTOS = frozenset({"icmp", "tcp", "udp"})


def _add_qualifiers(fact: dict[str, str], detail: Any) -> bool:
    """Copy a builder's ``detail.origin`` / ``detail.proto`` onto the coverage fact.

    A scan that looked from the internet over TCP is not coverage against internal sources or UDP
    (the library only applies a qualified fact where it speaks). A qualifier the library does not
    know would make it reject the whole graph, so such a fact is dropped instead (False): a node
    left blind is the safe outcome.
    """
    if not isinstance(detail, dict):
        return True
    origin, proto = detail.get("origin"), detail.get("proto")
    if origin is not None:
        if origin not in _ORIGINS or fact["direction"] != "in":
            return False
        fact["origin"] = origin
    if proto is not None:
        if proto not in _FACT_PROTOS:
            return False
        fact["proto"] = proto
    return True


def _default_kind(ref: str) -> str:
    return {"internet": "internet", "ip": "ip", "cidr": "cidr"}.get(ref.partition(":")[0], "host")


def _ips_of(*sources: Any) -> list[str]:
    """Flatten ip-ish values (str or list) from several dict/obj sources, order-stable."""
    out: list[str] = []
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in _IP_KEYS:
            v = src.get(k)
            for item in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
                if isinstance(item, str) and item not in out:
                    out.append(item)
    return out


def _loads(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def doc_sha(doc: dict[str, Any]) -> str:
    """sha256 (hex) of the canonical graph document, for "did the INPUT of the evaluation change?".

    ``graph_version`` only moves when builders, zones or labels change; node ``attrs`` (addresses
    that decide a node's zone and which CIDR rules include it) and ``assets.metadata`` (the
    crown-jewel tag, addresses) feed the document without moving it. Hashing what the evaluator
    actually reads closes that gap.

    The document's own ``now`` and the coverage ``observed_at`` stamps are left out on purpose:
    both change on every refresh without changing what the graph says, and re-evaluating on each
    would make the loop spin. A refreshed ``observed_at`` can only make evidence fresher; the
    freshness limit itself is tracked by ``valid_until`` and the backstop. Host facts follow the
    same rule (``store.digest_view``: ``observed_at``, ``seq`` and ``evidence_ref`` of each
    entry, ``*_at`` inside a conflict record, and the provenance the ``host_agent`` summary repeats in its
    ``data``); every other part of a fact is in the hash, so a
    changed value, ``signed``, ``key_id``, ``conf``, ``partial``, ``status``, ``conflict`` or tier
    re-evaluates.
    """
    def strip_fact(name: str, f: Any) -> Any:
        return store.digest_view(name, f)

    def strip(node: Any) -> Any:
        if not isinstance(node, dict) or ("coverage" not in node and "facts" not in node):
            return node
        node = dict(node)
        if "coverage" in node:
            cov = node["coverage"]
            if isinstance(cov, list):
                cov = [{k: v for k, v in c.items() if k != "observed_at"} if isinstance(c, dict) else c
                       for c in cov]
            elif isinstance(cov, dict):
                cov = {k: v for k, v in cov.items() if k != "observed_at"}
            node["coverage"] = cov
        if isinstance(node.get("facts"), dict):
            node["facts"] = {name: strip_fact(name, f) for name, f in node["facts"].items()}
        return node

    canon = {k: v for k, v in doc.items() if k != "now"}
    if isinstance(canon.get("nodes"), list):
        canon["nodes"] = [strip(n) for n in canon["nodes"]]
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


async def _fetch(conn) -> dict[str, Any]:
    return {
        "state": await conn.fetchrow("SELECT graph_version FROM assurance_state"),
        "nodes": await conn.fetch("SELECT node_ref, kind, asset_id, attrs FROM reach_nodes ORDER BY node_ref"),
        "edges": await conn.fetch(
            "SELECT src_ref, dst_ref, proto, port_lo, port_hi, basis, source FROM reach_edges "
            "ORDER BY src_ref, dst_ref, proto, port_lo, port_hi, source, basis"),
        "cov": await conn.fetch(
            "SELECT node_ref, direction, tier, observed_at, source, detail FROM reach_coverage "
            "ORDER BY node_ref, direction, source"),
        "facts": await conn.fetch(
            "SELECT node_ref, source, tier, observed_at, facts FROM reach_node_facts ORDER BY node_ref, source"),
        "labels": await conn.fetch("SELECT node_ref, tag, value, source FROM asset_labels ORDER BY node_ref, tag"),
        "zones": await conn.fetch("SELECT * FROM zones ORDER BY name"),
    }


async def _fetch_snapshot(conn) -> dict[str, Any]:
    """One consistent snapshot when we own the transaction; inside a caller's, just read."""
    if conn.is_in_transaction():
        return await _fetch(conn)
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        return await _fetch(conn)


def _labels_by_node(rows: list[Any]) -> dict[str, dict[str, tuple[int, str]]]:
    by: dict[str, dict[str, tuple[int, str]]] = {}
    for r in rows:
        by.setdefault(r["node_ref"], {})[r["tag"]] = (_SOURCE_RANK.get(r["source"], 1), r["value"] or "")
    return by


def _node_doc(ref: str, kind: str, labels: dict[str, tuple[int, str]], md: dict[str, Any],
              zone: Optional[str], cov: list[dict[str, str]],
              facts: Optional[dict[str, dict[str, Any]]] = None, has_agent: bool = False,
              zone_unknown: bool = False) -> dict[str, Any]:
    """Labels: ``declared`` rows override metadata-derived defaults (crown jewel, data store, and
    the ``agent`` tag a node with host facts gets)."""
    tags: set[str] = set()
    cls: Optional[str] = None
    if has_agent:
        tags.add(AGENT_TAG)
    if _truthy(md.get("crown_jewel")):
        tags.add("crown-jewel")
    if kind == "cloud_db":
        cls = "data_store"
    for tag, (_rank, value) in labels.items():
        if tag == "class":
            if value:
                cls = value
        elif tag == "kind":
            if value in KINDS:
                kind = value
        elif tag != "zone":
            if value.strip().lower() in _FALSE_VALUES:
                tags.discard(tag)
            else:
                tags.add(tag)
    doc: dict[str, Any] = {"id": ref, "kind": kind}
    if zone:
        doc["zone"] = zone
    if zone_unknown:                 # only ever written when true: a document without such a node is unchanged
        doc["zone_unknown"] = True
    if cls:
        doc["class"] = cls
    doc["tags"] = sorted(tags)
    if cov:
        doc["coverage"] = cov
    if facts:
        doc["facts"] = facts
    return doc


def _hint_ips(attrs: Any, key: str) -> list[str]:
    """Textual addresses under ``attrs[key]`` (a list the builder wrote), nothing else."""
    raw = attrs.get(key) if isinstance(attrs, dict) else None
    return [v for v in raw if isinstance(v, str)][:64] if isinstance(raw, list) else []


def _agent_zone(ref: str, attrs: Any, zone_index: ZoneIndex, diag: "LoadDiagnostics",
                weak: Optional[str] = None) -> tuple[Optional[str], bool]:
    """``(zone, zone_unknown)`` of an uncorroborated ``agent:<uuid>`` node WITHOUT a declared zone label.

    ``attrs.ips`` is empty for these nodes on purpose (the host is "address unknown": it is inside every CIDR
    expansion, D6). Both hints about where the host sits are only EVIDENCE: the addresses it CLAIMS (its own signed
    listener table; a host can write any address there, review finding hostfw-1) and the address the SERVER
    OBSERVED (``observed_ips``: the direct, unique private source of the connection; a host that tunnels its agent
    traffic through a machine in another zone, or sits behind a header-less NAT/VPN with one agent, shows that
    machine's address, review finding Z2-2). Neither is allowed to override the other:

    * the claim and the observation resolve to the SAME zone: two independent hints agree, the host is placed;
    * they disagree (different zones, or a claim spread over several zones), or there is only one of them (no claim,
      or a claim that matches no zone): the host is NOT placed by either. A platform-written (non-declared) zone
      label ``weak`` still places it; otherwise the claim is kept as a best guess for display and the node is
      ``zone_unknown`` (the library treats it as a POSSIBLE member of every zone selector, so a zone-selected
      invariant is UNKNOWN, never HOLDS); a node with no usable claim is unplaced (``zone None``, ``zone_unknown``).

    A declared zone label is handled by the caller and always wins. Every non-placed node is listed in the
    diagnostics; a disagreement is also recorded in ``zone_conflicts``."""
    observed = _hint_ips(attrs, "observed_ips")
    claimed = _hint_ips(attrs, "claimed_ips")
    ours, ours_conflict = zone_index.resolve(observed) if observed else (None, [])
    theirs, theirs_conflict = zone_index.resolve(claimed) if claimed else (None, [])
    if ours is not None and theirs is not None:
        if ours == theirs and not ours_conflict and not theirs_conflict:
            return ours, False
        diag.zone_conflicts[ref] = sorted({ours, theirs, *ours_conflict, *theirs_conflict})
    if weak is not None:
        return weak, False
    if claimed:
        zone, conflict = theirs, theirs_conflict
        if conflict:
            diag.zone_conflicts[ref] = conflict
        if zone is not None:
            diag.zone_from_claim.append(ref)
            return zone, True
    diag.zone_unplaced.append(ref)
    return None, True


def _declared_zone_label(labels: dict[str, tuple[int, str]]) -> tuple[Optional[str], Optional[str]]:
    """``(declared zone, weaker non-declared zone)`` from the node's labels."""
    rank, value = labels.get("zone", (0, ""))
    if not value:
        return None, None
    return (value, None) if rank >= _SOURCE_RANK["declared"] else (None, value)


def _node_addrs(ref: str, attrs: Any, md: Any) -> list[Any]:
    """The addresses a node is known by (``[]`` = unknown, which may be anywhere)."""
    if ref.startswith("agent:"):
        return []         # a managed host is known by no address it claims (hostfw-1): possibly in any CIDR (D6)
    raw = [ref.partition(":")[2]] if ref.startswith("ip:") else _ips_of(attrs, md)
    out: list[Any] = []
    for v in raw:
        try:
            out.append(ipaddress.ip_address(str(v).strip()))
        except ValueError:
            continue
    return out


def _expand_cidr_sources(nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
                         addrs: dict[str, list[Any]]) -> list[str]:
    """Make ``cidr:<net> -> dst`` mean what it says: every node inside ``net`` may connect to ``dst``.

    A security group rule "allow 10.0.0.0/8" is stored as an edge from the node ``cidr:10.0.0.0/8``,
    which is connected to nothing else in the graph. Without this step a guest laptop at 10.20.0.5
    (known only from Sentry) has no edge to that server, the server is covered inbound by its
    configuration, and "guest cannot reach the server" would HOLD although the rule admits it.
    A node whose addresses are unknown may be inside any CIDR, so it is included (D6). The
    ``internet`` node is never inside a CIDR (world-open rules on addressable nodes are already
    ``internet`` edges). Returns the destinations that could not be expanded within the cap; their
    inbound coverage is withdrawn from the document.
    """
    by_dst: dict[str, list[dict[str, Any]]] = {}
    for e in edges:
        if e["src"].startswith("cidr:"):
            by_dst.setdefault(e["dst"], []).append(e)
    if not by_dst:
        return []
    have = {(e["src"], e["dst"], e["proto"], e.get("ports"), e["basis"], e["source"]) for e in edges}
    members: dict[str, list[str]] = {}
    candidates = sorted(r for r in addrs if r != INTERNET and not r.startswith("cidr:"))
    added: list[dict[str, Any]] = []
    unexpanded: list[str] = []
    for dst in sorted(by_dst):
        new: list[dict[str, Any]] = []
        for e in by_dst[dst]:
            net = e["src"][len("cidr:"):]
            if net not in members:
                try:
                    n = ipaddress.ip_network(net, strict=False)
                except ValueError:
                    n = None
                members[net] = candidates if n is None else [
                    r for r in candidates if not addrs[r] or any(a.version == n.version and a in n for a in addrs[r])]
            for r in members[net]:
                if r == dst:
                    continue
                key = (r, dst, e["proto"], e.get("ports"), e["basis"], e["source"])
                if key not in have:
                    have.add(key)
                    new.append({**e, "src": r})
        if len(added) + len(new) > MAX_EXPANDED_EDGES:
            unexpanded.append(dst)
            continue
        added.extend(new)
    edges.extend(added)
    edges.sort(key=lambda d: (d["src"], d["dst"], d["proto"], d.get("ports", ""), d["source"], d["basis"]))
    if unexpanded:
        bad = set(unexpanded)
        for n in nodes:
            if n["id"] in bad and n.get("coverage"):
                n["coverage"] = [c for c in n["coverage"] if c["direction"] != "in"]
                if not n["coverage"]:
                    del n["coverage"]
    return unexpanded


async def load_graph_doc_with_diagnostics(conn, now: dt.datetime) -> tuple[dict[str, Any], LoadDiagnostics]:
    """Build the graph document and the side facts a runner may want to record.

    The queries run on ``conn``; everything CPU-bound (zone resolution, CIDR expansion, document
    assembly) runs in a worker thread so a large tenant cannot stall the event loop that also
    serves the API.
    """
    snap = await _fetch_snapshot(conn)
    asset_ids = _asset_ids(snap)
    assets: dict[str, dict[str, Any]] = {}
    if asset_ids:
        for r in await conn.fetch(_ASSET_SQL, sorted(set(asset_ids.values()))):
            md = _loads(r["md"]) or {}
            if r["kind"] in ("ipv4", "ipv6"):
                md = dict(md, ip=r["value"])
            assets[str(r["id"])] = md
    return await asyncio.to_thread(_assemble, snap, assets, now)


def _asset_ids(snap: dict[str, Any]) -> dict[str, str]:
    """node ref -> asset uuid, for every node that stands for an asset."""
    asset_ids: dict[str, str] = {}
    refs: set[str] = set()
    for r in snap["nodes"]:
        refs.add(r["node_ref"])
        if r["asset_id"]:
            asset_ids[r["node_ref"]] = str(r["asset_id"])
    for e in snap["edges"]:
        refs.update((e["src_ref"], e["dst_ref"]))
    for ref in sorted(refs):                       # asset:<uuid> refs carry their own id
        if ref.startswith("asset:"):
            try:
                asset_ids.setdefault(ref, str(uuid.UUID(ref[len("asset:"):])))
            except ValueError:
                pass
    return asset_ids


def _lib_fact_parser() -> Any:
    """The library's own fact parser (``paddock_assurance.hostfacts``), or ``None``: the loader
    must not break where the library is absent or older. Used only to DROP what the library would
    refuse, never to change a fact."""
    try:
        from paddock_assurance import hostfacts  # noqa: PLC0415
        return hostfacts.parse_fact, hostfacts.new_budget
    except Exception:  # noqa: BLE001
        return None


def _fact_entry_doc(name: str, e: dict[str, Any], row: Any) -> dict[str, Any]:
    """One stored entry -> the document's fact. The row's tier / observed_at are ceilings: an
    entry may only be weaker / older."""
    tier = row["tier"]
    if e.get("tier") and store._BASIS_RANK[e["tier"]] < store._BASIS_RANK[tier]:
        tier = e["tier"]
    seen = row["observed_at"]
    if e.get("observed_at"):
        seen = min(seen, store._parse_ts(e["observed_at"]) or seen)
    d: dict[str, Any] = {
        "status": e["status"], "tier": tier, "observed_at": _iso(seen), "signed": e["signed"],
        "source": row["source"], "key_id": e["key_id"], "seq": e["seq"], "evidence_ref": e["evidence_ref"],
        "conf": e["conf"], "partial": e["partial"]}
    if e.get("reason"):
        d["reason"] = e["reason"]
    if "conflict" in e:
        d["conflict"] = e["conflict"]
    d["data"] = e["data"]
    return d


def _note_fact_issue(diag: LoadDiagnostics, text: str) -> None:
    diag.facts_dropped += 1
    if len(diag.fact_issues) < 50:
        diag.fact_issues.append(text[:300])


def _assemble_facts(rows: list[Any], diag: LoadDiagnostics) -> tuple[dict[str, dict[str, dict[str, Any]]], set[str]]:
    """``(node_ref -> collector -> fact document, refs that have any fact row)``. Pure; rows are
    sorted by (node_ref, source), so the output (and which fact the document budget cuts) is
    deterministic. Invalid material is dropped and counted, never passed on."""
    lib = _lib_fact_parser()
    have: set[str] = set()
    by_node: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for row in rows:
        ref = row["node_ref"]
        have.add(ref)
        if row["tier"] not in store.BASES or not is_valid_ref(ref) or ref == INTERNET:
            _note_fact_issue(diag, f"{ref}: bad fact row (tier/ref)")
            continue
        raw = _loads(row["facts"])
        if not isinstance(raw, dict) or len(raw) > store.MAX_FACT_COLLECTORS:
            _note_fact_issue(diag, f"{ref}: facts of {row['source']!r} are not a collector object within the cap")
            continue
        for name in sorted(raw):
            try:
                if not isinstance(name, str) or not store.FACT_COLLECTOR_RE.fullmatch(name):
                    raise store.FactInvalid(f"bad collector name {str(name)[:40]!r}")
                entry = _fact_entry_doc(name, store.normalise_fact_entry(name, raw[name]), row)
                if lib is not None:
                    try:
                        lib[0](name, entry, ref, lib[1]())
                    except ValueError as exc:                # the library's FactError
                        raise store.FactInvalid(f"rejected by the assurance library: {exc}") from exc
                    except Exception:  # noqa: BLE001 - a parser we cannot call: our own checks stand
                        lib = None
            except store.FactInvalid as exc:
                _note_fact_issue(diag, f"{ref} {str(name)[:40]}: {exc}")
                continue
            by_node.setdefault(ref, {}).setdefault(name, []).append(entry)
    out: dict[str, dict[str, dict[str, Any]]] = {}
    budget = store.MAX_FACT_TOTAL_ELEMENTS
    for ref in sorted(by_node):
        merged: dict[str, dict[str, Any]] = {}
        for name in sorted(by_node[ref]):
            entries = by_node[ref][name]
            if len(entries) > 1:
                _note_fact_issue(diag, f"{ref} {name}: {len(entries)} sources claim this collector; none is trusted")
                continue
            merged[name] = entries[0]
        if len(merged) > store.MAX_FACT_COLLECTORS:
            _note_fact_issue(diag, f"{ref}: more than {store.MAX_FACT_COLLECTORS} collectors across sources")
            continue
        cost = sum(store.count_fact_elements(f["data"]) + store.count_fact_elements(f.get("conflict")) for f in merged.values())
        if cost > budget:
            _note_fact_issue(diag, f"{ref}: the graph document's fact budget is exhausted")
            continue
        budget -= cost
        if merged:
            out[ref] = merged
    return out, have


def _assemble(snap: dict[str, Any], assets: dict[str, dict[str, Any]],
              now: dt.datetime) -> tuple[dict[str, Any], LoadDiagnostics]:
    """Pure: rows -> (document, diagnostics). No I/O, so it can run off the event loop."""
    zone_index = ZoneIndex(_zone(r) for r in snap["zones"])    # CIDRs parsed once for the whole load
    labels = _labels_by_node(snap["labels"])
    diag = LoadDiagnostics(graph_version=int(snap["state"]["graph_version"]) if snap["state"] else 0)

    kinds: dict[str, str] = {}
    attrs: dict[str, dict[str, Any]] = {}
    for r in snap["nodes"]:
        kinds[r["node_ref"]] = r["kind"] if r["kind"] in KINDS else _default_kind(r["node_ref"])
        a = _loads(r["attrs"])
        attrs[r["node_ref"]] = a if isinstance(a, dict) else {}
    for e in snap["edges"]:
        for ref in (e["src_ref"], e["dst_ref"]):
            kinds.setdefault(ref, _default_kind(ref))
    host_facts, has_facts = _assemble_facts(list(snap.get("facts") or ()), diag)
    for ref in sorted(has_facts):
        if ref != INTERNET:
            kinds.setdefault(ref, _default_kind(ref))
    kinds[INTERNET] = "internet"
    # docs/ASSURANCE_P2.md E5: a node DECLARED a server is part of the graph even when no builder emitted it
    # (an on-prem host, an asset no connector draws edges for). Without this the label would be ignored and the
    # std host invariants would silently leave that server out of scope; with it the node reaches the library
    # as a `server` with no agent facts, which is UNKNOWN (no_agent), never a pass.
    for ref, lab in labels.items():
        value = (lab.get("server") or (0, "false"))[1]
        if ref != INTERNET and "server" in lab and value.strip().lower() not in _FALSE_VALUES:
            kinds.setdefault(ref, _default_kind(ref))
    asset_ids = _asset_ids(snap)

    cov_by: dict[str, list[dict[str, str]]] = {}
    for r in snap["cov"]:
        if r["node_ref"] == INTERNET:
            continue                              # the internet is never covered
        fact = {"direction": r["direction"], "tier": r["tier"],
                "observed_at": _iso(r["observed_at"]), "source": r["source"]}
        if not _add_qualifiers(fact, _loads(r["detail"])):
            continue                              # a qualifier we do not understand: no coverage
        cov_by.setdefault(r["node_ref"], []).append(fact)

    nodes: list[dict[str, Any]] = []
    for ref in sorted(kinds):
        lab = labels.get(ref, {})
        md = assets.get(asset_ids.get(ref, ""), {})
        zone_unknown = False
        if ref == INTERNET:
            zone: Optional[str] = INTERNET
        else:
            declared, weak = _declared_zone_label(lab)
            zone = declared
            if zone is None:
                if ref.startswith("agent:"):
                    zone, zone_unknown = _agent_zone(ref, attrs.get(ref), zone_index, diag, weak)
                else:
                    if ref.startswith("ip:") or ref.startswith("cidr:"):
                        addrs = [ref.partition(":")[2]]
                    else:
                        addrs = _ips_of(attrs.get(ref), md)
                    zone, conflict = zone_index.resolve(addrs)
                    if conflict:
                        diag.zone_conflicts[ref] = conflict
                if zone is None and not zone_unknown:
                    zone = weak
        nodes.append(_node_doc(ref, kinds[ref], lab, md, zone,
                               sorted(cov_by.get(ref, []), key=lambda c: (c["direction"], c["source"], c["tier"]))
                               if ref != INTERNET else [],
                               host_facts.get(ref), ref in has_facts and ref != INTERNET, zone_unknown))

    edges: list[dict[str, Any]] = []
    for e in sorted(snap["edges"], key=lambda r: (r["src_ref"], r["dst_ref"], r["proto"], r["port_lo"],
                                                   r["port_hi"], r["source"], r["basis"])):
        d: dict[str, Any] = {"src": e["src_ref"], "dst": e["dst_ref"], "proto": e["proto"]}
        ports = _ports(e["proto"], e["port_lo"], e["port_hi"])
        if ports is not None:
            d["ports"] = ports
        d["basis"] = e["basis"]
        d["source"] = e["source"]
        edges.append(d)

    addrs = {ref: _node_addrs(ref, attrs.get(ref), assets.get(asset_ids.get(ref, ""), {})) for ref in kinds}
    diag.cidr_unexpanded = _expand_cidr_sources(nodes, edges, addrs)
    diag.cidr_overflow = bool(diag.cidr_unexpanded)
    doc = {"version": 1, "now": _iso(now), "nodes": nodes, "edges": edges}
    return doc, diag


async def load_graph_doc(conn, now: dt.datetime) -> dict[str, Any]:
    """The tenant's reach graph as a section-3 document (see module docstring)."""
    doc, _ = await load_graph_doc_with_diagnostics(conn, now)
    return doc
