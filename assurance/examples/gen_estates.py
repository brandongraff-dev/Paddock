"""Regenerates the two example estates. Run from anywhere: python examples/gen_estates.py"""
import json
from pathlib import Path

NOW = "2026-12-01T09:00:00Z"
SEEN = "2026-12-01T08:30:00Z"


def node(id_, zone, kind="host", cls=None, tags=(), tier="observed", seen=SEEN, source="sensor"):
    n = {"id": id_, "kind": kind, "zone": zone, "tags": list(tags)}
    if cls:
        n["class"] = cls
    if tier:
        n["coverage"] = {"tier": tier, "observed_at": seen, "source": source}
    return n


def edge(src, dst, ports, proto="tcp", basis="observed", source="flows"):
    return {"src": src, "dst": dst, "proto": proto, "ports": ports, "basis": basis, "source": source}


def estate(violated: bool) -> dict:
    nodes = [
        node("internet", "internet", kind="internet", source="external_scan"),
        node("lb-1", "dmz", source="aws_sg"),
        node("web-1", "dmz"),
        node("app-1", "prod", tags=["app-tier"]),
        node("db-1", "prod", cls="data_store", tags=["crown-jewel"]),
        node("guest-ap", "guest", kind="access_point", source="sentry"),
        node("guest-laptop", "guest", kind="device", source="sentry"),
        node("printer-1", "office", kind="device", source="sentry"),
        node("pos-1", "pos", kind="device", tags=["cardholder-data"], source="sentry"),
        node("pos-hub", "pos", source="sentry"),
    ]
    edges = [
        edge("internet", "lb-1", "80,443", source="external_scan"),
        edge("lb-1", "web-1", "8080"),
        edge("web-1", "app-1", "9000"),
        edge("app-1", "db-1", "5432"),
        edge("guest-laptop", "guest-ap", "1-65535"),
        edge("guest-laptop", "printer-1", "9100"),       # guests may print
        edge("pos-1", "pos-hub", "443"),
        edge("pos-hub", "app-1", "9000"),
    ]
    if violated:
        edges += [
            edge("printer-1", "pos-1", "445"),             # the planted lateral path
            edge("internet", "web-1", "22", source="external_scan"),  # SSH open to the internet
            edge("internet", "db-1", "5432", source="external_scan"),  # database open to the world
        ]
    return {"version": 1, "now": NOW, "nodes": nodes, "edges": edges}


here = Path(__file__).parent
for name, v in (("estate-clean.json", False), ("estate-violated.json", True)):
    (here / name).write_text(json.dumps(estate(v), indent=2) + "\n")
    print("wrote", name)
