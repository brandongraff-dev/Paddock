"""Tests for the pure Wargame assessment assembler (no DB).

Builds a small Environment with one open route (internet -> dmz -> db) and one
closed boundary (guest, which has no path to db). Asserts that a signed
certificate is produced for the closed+pass boundary and never for the open
one, that a fix set is present, and that the bundle shape is sane.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.engine.wargame import certificate
from app.engine.wargame.assess import DEMO_SIGNING_KEY, assess_environment
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action,
    Edge,
    EvidenceLabel,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)


def _env() -> Environment:
    env = Environment()
    env.add_node(Node("internet", NodeRole.ENTRY, ("203.0.113.0/24",), reason="internet"))
    env.add_node(Node("guest", NodeRole.ENTRY, ("10.9.0.0/24",), reason="guest wifi"))
    env.add_node(Node("dmz", NodeRole.INTERMEDIATE, ("10.2.0.0/24",)))
    env.add_node(
        Node("db", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",), jewel_kind="cardholder_data")
    )

    # A security group that allows the DMZ into the DB on tcp/5432.
    env.add_ruleset(
        RuleSet(
            "sg-db",
            [
                Rule(
                    "allow_dmz",
                    Action.ALLOW,
                    10,
                    ("10.2.0.0/24",),
                    ("10.1.0.0/24",),
                    (PortRange.single(Proto.TCP, 5432),),
                    vendor="aws",
                    cost_class="cloud_policy",
                ),
            ],
            default_action=Action.DENY,
            vendor="aws",
        )
    )

    # Open route: internet -> dmz (observed) -> db (proved by the SG).
    env.add_edge(
        Edge(
            "internet",
            "dmz",
            base_labels=frozenset({EvidenceLabel.OBSERVED}),
            fix_candidate_id="edge:internet->dmz",
        )
    )
    env.add_edge(
        Edge(
            "dmz",
            "db",
            rule_set_id="sg-db",
            port=PortRange.single(Proto.TCP, 5432),
            fix_candidate_id="sg-db:allow_dmz",
        )
    )
    # guest has no outgoing edges, so (guest, db) is a closed pair.
    return env


def _bundle():
    issued = datetime(2026, 11, 22, tzinfo=timezone.utc)
    return assess_environment(
        _env(), label="twin", config_hashes=["cfg-abc"], issued_at=issued
    )


def test_certifies_closed_pass_boundary_only() -> None:
    bundle = _bundle()

    cert_pairs = {(c["boundary_src"], c["boundary_dst"]) for c in bundle.certificates}
    assert ("guest", "db") in cert_pairs          # closed + pass is certified
    assert ("internet", "db") not in cert_pairs   # open / fail_open never is
    assert len(bundle.certificates) == 1


def test_certificate_is_signed_and_honest() -> None:
    bundle = _bundle()
    cert = bundle.certificates[0]

    assert cert["status"] == "valid"
    assert cert["fingerprint"]                         # was signed
    assert cert["config_hashes"] == ["cfg-abc"]        # pinned to the config
    keys = {a["key"] for a in cert["assumptions"]}
    assert "no_unmodelled_links" in keys
    # No protected-side sensor -> the absence-of-evidence limit is made explicit.
    assert "observation_side" in keys


def test_signature_verifies_with_demo_key() -> None:
    # Re-run the signing path over an object to confirm the demo key verifies.
    issued = datetime(2026, 11, 22, tzinfo=timezone.utc)
    cert = certificate.build_certificate(
        boundary_src="guest",
        boundary_dst="db",
        port=None,
        config_hashes=("cfg-abc",),
        assumptions=[certificate.Assumption("no_unmodelled_links", "x")],
        corroboration=certificate.Corroboration(0, 30, sensor_on_protected_side=False),
        issued_at=issued,
        ttl_hours=24,
    )
    certificate.sign(cert, key=DEMO_SIGNING_KEY)
    assert certificate.verify(cert, key=DEMO_SIGNING_KEY)
    assert not certificate.verify(cert, key=b"wrong")


def test_boundary_verdicts() -> None:
    bundle = _bundle()
    verdicts = {
        (b["boundary_src"], b["boundary_dst"]): b["verdict"] for b in bundle.boundaries
    }
    assert verdicts[("guest", "db")] == "pass"
    assert verdicts[("internet", "db")] == "fail_open"


def test_fix_set_present_and_cuts_open_route() -> None:
    bundle = _bundle()
    assert bundle.fix_set is not None
    assert bundle.fix_set["selected"]            # at least one change chosen
    assert bundle.fix_set["cuts_all"] is True
    # The chosen candidate is one of the two cuttable elements on the route.
    chosen = {s["id"] for s in bundle.fix_set["selected"]}
    assert chosen <= {"edge:internet->dmz", "sg-db:allow_dmz"}
    assert chosen


def test_bundle_shape_is_sane() -> None:
    bundle = _bundle()
    a = bundle.assessment
    assert a["label"] == "twin"
    assert a["crownjewel_total"] == 2            # (internet, db) + (guest, db)
    assert a["crownjewel_open"] == 1
    assert a["crownjewel_closed"] == 1
    assert a["coverage_pct"] is None             # not measured here
    # The open route internet -> dmz -> db is recorded.
    assert any(r["entry"] == "internet" and r["jewel"] == "db" for r in bundle.routes)
