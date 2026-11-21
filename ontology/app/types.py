"""The ontology type system + the pure projection mapping.

This module is deliberately free of any I/O so the mapping is unit-testable in
isolation (asset row -> Host object, finding -> Vulnerability, edge -> link).
``projector.py`` consumes these helpers and does the bulk DB work.

Object types model the Entities an analyst reasons about; link types model the
verbs between them. Every object carries its provenance (``backing_table`` +
``backing_id``) so the projection is deterministic and idempotent: re-running
it never duplicates, and rows whose backing source vanished are pruned.
"""
from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
# Object types: name -> display / icon / color / source table / property schema
# Colors are drawn from the dashboard's asset-kind palette (tokens.css) so the
# Explore view stays visually consistent with the Graph.
# --------------------------------------------------------------------------- #

OBJECT_TYPES: dict[str, dict[str, Any]] = {
    "Host": {
        "display": "Host",
        "icon": "server",
        "color": "#4ea3ff",
        "source": "assets",
        "property_schema": {
            "kind": "string", "canonical": "string", "confidence": "int",
            "source": "string", "env": "string",
        },
    },
    "Service": {
        "display": "Service",
        "icon": "plug",
        "color": "#ffb86b",
        "source": "assets",
        "property_schema": {
            "kind": "string", "canonical": "string", "port": "string",
            "protocol": "string", "confidence": "int",
        },
    },
    "Technology": {
        "display": "Technology",
        "icon": "chip",
        "color": "#c7a7ff",
        "source": "assets",
        "property_schema": {
            "canonical": "string", "product": "string", "version": "string",
            "confidence": "int",
        },
    },
    "Vulnerability": {
        "display": "Vulnerability",
        "icon": "alert-triangle",
        "color": "#ff4d6d",
        "source": "findings",
        "property_schema": {
            "rule_id": "string", "rule_source": "string", "severity": "string",
            "status": "string", "cvss": "float", "epss": "float",
        },
    },
    "Repository": {
        "display": "Repository",
        "icon": "git-branch",
        "color": "#e6edf7",
        "source": "assets",
        "property_schema": {
            "canonical": "string", "url": "string", "source": "string",
        },
    },
    "Secret": {
        "display": "Secret",
        "icon": "key",
        "color": "#ff4d6d",
        "source": "assets",
        "property_schema": {
            "kind": "string", "canonical": "string", "detector": "string",
            "confidence": "int",
        },
    },
    "Package": {
        "display": "Package",
        "icon": "package",
        "color": "#58d68d",
        "source": "sbom_components",
        "property_schema": {
            "ecosystem": "string", "name": "string", "version": "string",
            "purl": "string", "direct": "bool", "depth": "int",
        },
    },
    "Certificate": {
        "display": "Certificate",
        "icon": "certificate",
        "color": "#f78da7",
        "source": "assets",
        "property_schema": {
            "canonical": "string", "subject": "string", "issuer": "string",
        },
    },
    "Team": {
        "display": "Team",
        "icon": "users",
        "color": "#c084fc",
        "source": "tickets",
        "property_schema": {"name": "string"},
    },
    "Ticket": {
        "display": "Ticket",
        "icon": "ticket",
        "color": "#f0b429",
        "source": "tickets",
        "property_schema": {
            "status": "string", "severity": "string", "system": "string",
            "owner_team": "string", "sla_due": "string", "breached": "bool",
        },
    },
    "AttackPath": {
        "display": "Attack Path",
        "icon": "route",
        "color": "#ff7a45",
        "source": "attack_paths",
        "property_schema": {
            "severity": "string", "exploitability": "float", "length": "int",
            "kev_on_path": "bool",
        },
    },
}

# --------------------------------------------------------------------------- #
# Link types: name -> display / from_type / to_type / cardinality
# AFFECTS nominally targets Host but is also projected onto Technology/Service
# objects (a finding points at whatever asset it was raised on); the DB does
# not constrain link endpoints to the declared types.
# --------------------------------------------------------------------------- #

LINK_TYPES: dict[str, dict[str, str]] = {
    "RESOLVES_TO": {"display": "resolves to", "from_type": "Host", "to_type": "Host", "cardinality": "many_to_many"},
    "RUNS": {"display": "runs", "from_type": "Host", "to_type": "Service", "cardinality": "one_to_many"},
    "AFFECTS": {"display": "affects", "from_type": "Vulnerability", "to_type": "Host", "cardinality": "many_to_many"},
    "DECLARES": {"display": "declares", "from_type": "Repository", "to_type": "Package", "cardinality": "one_to_many"},
    "CONTAINS": {"display": "contains", "from_type": "Repository", "to_type": "Secret", "cardinality": "one_to_many"},
    "ON_PATH": {"display": "on path", "from_type": "Host", "to_type": "AttackPath", "cardinality": "many_to_many"},
    "OWNED_BY": {"display": "owned by", "from_type": "Host", "to_type": "Team", "cardinality": "many_to_one"},
    "TRACKS": {"display": "tracks", "from_type": "Ticket", "to_type": "Vulnerability", "cardinality": "one_to_one"},
    "SECURES": {"display": "secures", "from_type": "Certificate", "to_type": "Host", "cardinality": "many_to_many"},
}

# Which asset.kind projects to which object type. Kinds not listed (org,
# endpoint, cloud_account, cloud_resource) have no typed entity yet and are
# skipped — including any finding/edge that only touches them.
ASSET_KIND_TO_TYPE: dict[str, str] = {
    "domain": "Host",
    "subdomain": "Host",
    "ipv4": "Host",
    "ipv6": "Host",
    "port": "Service",
    "service": "Service",
    "technology": "Technology",
    "certificate": "Certificate",
    "repository": "Repository",
    "secret_candidate": "Secret",
}


def _meta(row: dict[str, Any]) -> dict[str, Any]:
    m = row.get("metadata")
    return m if isinstance(m, dict) else {}


def _clean(props: dict[str, Any]) -> dict[str, Any]:
    """Drop None-valued properties so the stored JSON stays tight."""
    return {k: v for k, v in props.items() if v is not None}


# --------------------------------------------------------------------------- #
# Object mappers (pure). Each returns a dict with the ontology_objects shape,
# or None when the row has no typed projection.
# --------------------------------------------------------------------------- #

def asset_to_object(row: dict[str, Any]) -> dict[str, Any] | None:
    """Project an ``assets`` row to a typed object (Host/Service/...)."""
    otype = ASSET_KIND_TO_TYPE.get(row["kind"])
    if otype is None:
        return None
    meta = _meta(row)
    base = {
        "kind": row.get("kind"),
        "canonical": row.get("canonical"),
        "confidence": row.get("confidence"),
    }
    if otype == "Host":
        props = {**base, "source": row.get("source"), "env": meta.get("env")}
    elif otype == "Service":
        props = {**base, "port": meta.get("port"), "protocol": meta.get("protocol")}
    elif otype == "Technology":
        props = {
            "canonical": row.get("canonical"),
            "product": meta.get("product") or meta.get("name"),
            "version": meta.get("version"),
            "confidence": row.get("confidence"),
        }
    elif otype == "Repository":
        props = {
            "canonical": row.get("canonical"),
            "url": meta.get("url") or row.get("value"),
            "source": row.get("source"),
        }
    elif otype == "Secret":
        props = {
            "kind": row.get("kind"),
            "canonical": row.get("canonical"),
            "detector": meta.get("detector") or meta.get("rule"),
            "confidence": row.get("confidence"),
        }
    elif otype == "Certificate":
        props = {
            "canonical": row.get("canonical"),
            "subject": meta.get("subject") or row.get("value"),
            "issuer": meta.get("issuer"),
        }
    else:  # pragma: no cover - map above is exhaustive for ASSET_KIND_TO_TYPE
        props = base
    return {
        "object_type": otype,
        "title": row.get("value") or row.get("canonical") or str(row["id"]),
        "properties": _clean(props),
        "backing_table": "assets",
        "backing_id": str(row["id"]),
        "classification": row.get("classification") or "internal",
    }


def finding_to_object(row: dict[str, Any]) -> dict[str, Any]:
    """Project a ``findings`` row to a Vulnerability object."""
    cvss = row.get("cvss")
    epss = row.get("epss")
    props = _clean({
        "rule_id": row.get("rule_id"),
        "rule_source": row.get("rule_source"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "cvss": float(cvss) if cvss is not None else None,
        "epss": float(epss) if epss is not None else None,
    })
    return {
        "object_type": "Vulnerability",
        "title": row.get("title") or row.get("rule_id") or str(row["id"]),
        "properties": props,
        "backing_table": "findings",
        "backing_id": str(row["id"]),
        "classification": row.get("classification") or "internal",
    }


def package_to_object(row: dict[str, Any]) -> dict[str, Any]:
    """Project an ``sbom_components`` row to a Package object."""
    props = _clean({
        "ecosystem": row.get("ecosystem"),
        "name": row.get("name"),
        "version": row.get("version"),
        "purl": row.get("purl"),
        "direct": row.get("direct"),
        "depth": row.get("depth"),
    })
    title = f"{row.get('name')}@{row.get('version')}"
    return {
        "object_type": "Package",
        "title": title,
        "properties": props,
        "backing_table": "sbom_components",
        "backing_id": str(row["id"]),
        "classification": "internal",
    }


def ticket_to_object(row: dict[str, Any]) -> dict[str, Any]:
    """Project a ``tickets`` row to a Ticket object."""
    due = row.get("sla_due")
    props = _clean({
        "status": row.get("status"),
        "severity": row.get("severity"),
        "system": row.get("system"),
        "owner_team": row.get("owner_team"),
        "sla_due": due.isoformat() if hasattr(due, "isoformat") else due,
        "breached": row.get("breached"),
    })
    return {
        "object_type": "Ticket",
        "title": row.get("title") or str(row["id"]),
        "properties": props,
        "backing_table": "tickets",
        "backing_id": str(row["id"]),
        "classification": "internal",
    }


def team_to_object(team: str) -> dict[str, Any]:
    """Project a distinct ticket ``owner_team`` to a Team object.

    Backed by a synthetic ``team`` provenance table keyed by the team name.
    """
    return {
        "object_type": "Team",
        "title": team,
        "properties": {"name": team},
        "backing_table": "team",
        "backing_id": team,
        "classification": "internal",
    }


def attackpath_to_object(row: dict[str, Any]) -> dict[str, Any]:
    """Project an ``attack_paths`` row to an AttackPath object."""
    expl = row.get("exploitability")
    props = _clean({
        "severity": row.get("severity"),
        "exploitability": float(expl) if expl is not None else None,
        "length": row.get("length"),
        "kev_on_path": row.get("kev_on_path"),
    })
    return {
        "object_type": "AttackPath",
        "title": row.get("title") or f"path:{row['id']}",
        "properties": props,
        "backing_table": "attack_paths",
        "backing_id": str(row["id"]),
        "classification": "internal",
    }


# --------------------------------------------------------------------------- #
# Edge classification (pure). Decides which link an asset_edge becomes, from
# the object types of its endpoints + the raw edge kind.
# --------------------------------------------------------------------------- #

def classify_edge(
    src_type: str | None, dst_type: str | None, edge_kind: str
) -> tuple[str, str | None] | None:
    """Return ``(link_type, from_type)`` for an asset_edge, or None to skip.

    ``from_type`` names the endpoint that should be the link's ``from_object``
    (so the caller can orient src/dst canonically); ``None`` means keep the
    stored src -> dst direction.
    """
    if src_type is None or dst_type is None:
        return None
    pair = {src_type, dst_type}
    if pair == {"Host"} and edge_kind == "resolves_to":
        # subdomain/domain -> ip, as the passive worker stores it.
        return ("RESOLVES_TO", None)
    if pair == {"Host", "Service"}:
        return ("RUNS", "Host")
    if pair == {"Certificate", "Host"}:
        return ("SECURES", "Certificate")
    if pair == {"Repository", "Secret"}:
        return ("CONTAINS", "Repository")
    # Host<->Host 'contains' (domain/subdomain), Service<->Service 'runs',
    # Technology<->Service 'has_version', etc. have no typed link (yet).
    return None
