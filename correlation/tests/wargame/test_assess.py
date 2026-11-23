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
    # No probe was run: config-proved closed, NOT "pass" (which would claim
    # an active probe agreed). The model's own reachability is never a probe.
    assert verdicts[("guest", "db")] == "proved_config"
    assert verdicts[("internet", "db")] == "fail_open"
    notes = {(b["boundary_src"], b["boundary_dst"]): b["note"] for b in bundle.boundaries}
    assert "probe agree" not in notes[("guest", "db")]


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


# ---------------------------------------------------------------------------
# Honesty: probe evidence, conditional pairs, multi-hop pairs, signing
# ---------------------------------------------------------------------------

from app.engine.wargame import agreement, signing  # noqa: E402
from app.engine.wargame.model import Certificate  # noqa: E402

_ISSUED = datetime(2026, 11, 22, tzinfo=timezone.utc)
_TENANT = "00000000-0000-0000-0000-00000000000a"


def _cert(bundle, pair=("guest", "db")):
    return next(c for c in bundle.certificates
                if (c["boundary_src"], c["boundary_dst"]) == pair)


def _keys(c):
    return {a["key"] for a in c["assumptions"]}


def test_config_only_certificate_states_its_basis():
    c = _cert(_bundle())
    assert "proof_basis" in _keys(c)       # no-packet proof, no probe behind it
    assert "coverage" in _keys(c)          # coverage unmeasured, said so


def test_real_probe_upgrades_to_pass():
    bundle = assess_environment(
        _env(), label="twin", config_hashes=["cfg-abc"], issued_at=_ISSUED,
        probes={("guest", "db"): False},           # a real probe was blocked
    )
    v = {(b["boundary_src"], b["boundary_dst"]): b["verdict"] for b in bundle.boundaries}
    assert v[("guest", "db")] == "pass"
    assert "proof_basis" not in _keys(_cert(bundle))


def test_real_probe_that_crossed_blocks_the_certificate():
    bundle = assess_environment(
        _env(), label="twin", config_hashes=["cfg-abc"], issued_at=_ISSUED,
        probes={("guest", "db"): True},
    )
    v = {(b["boundary_src"], b["boundary_dst"]): b["verdict"] for b in bundle.boundaries}
    assert v[("guest", "db")] == "fail_open"
    assert bundle.certificates == []


def _conditional_env() -> Environment:
    """guest -> dmz is allowed only by a CONDITIONAL rule (App-ID-like)."""
    env = _env()
    env.add_ruleset(RuleSet("fw-guest", [Rule(
        "app_id", Action.ALLOW, 10, ("10.9.0.0/24",), ("10.2.0.0/24",),
        (PortRange.single(Proto.TCP, 5432),), conditional=True,
    )], default_action=Action.DENY))
    env.add_edge(Edge("guest", "dmz", rule_set_id="fw-guest",
                      port=PortRange.single(Proto.TCP, 5432)))
    return env


def test_conditional_pair_is_never_certified():
    env = _conditional_env()
    bundle = assess_environment(env, label="twin", config_hashes=["c"], issued_at=_ISSUED)
    v = {(b["boundary_src"], b["boundary_dst"]): b["verdict"] for b in bundle.boundaries}
    # guest -> dmz (conditional) -> db: the route rests on runtime state.
    assert v[("guest", "db")] == "conditional"
    assert ("guest", "db") not in {
        (c["boundary_src"], c["boundary_dst"]) for c in bundle.certificates
    }


def test_conditional_verdict_on_a_closed_pair_is_still_not_certified(monkeypatch):
    # Even if agreement ever returned "conditional" for a pair the search
    # calls closed, no certificate is issued for it.
    real = agreement.from_reachability

    def fake(rr, entry, jewel, **kw):
        rep = real(rr, entry, jewel, **kw)
        if (entry, jewel) == ("guest", "db"):
            rep.verdict = "conditional"
        return rep

    monkeypatch.setattr(agreement, "from_reachability", fake)
    bundle = _bundle()
    assert bundle.certificates == []


def test_multi_hop_open_pair_uses_the_route_not_a_direct_edge():
    # (internet, db) has NO direct edge; its config verdict must come from
    # the route internet -> dmz -> db, i.e. open.
    env = _env()
    assert env.find_edge("internet", "db") is None
    bundle = assess_environment(env, label="twin", config_hashes=[], issued_at=_ISSUED)
    b = next(b for b in bundle.boundaries
             if (b["boundary_src"], b["boundary_dst"]) == ("internet", "db"))
    assert b["verdict"] == "fail_open"
    assert "config says open" in b["disagreements"]


def test_no_key_configured_marks_certificates_unsigned_dev():
    c = _cert(_bundle())
    assert c["key_id"] == signing.DEV_KEY_ID
    assert "unsigned_dev_signature" in _keys(c)
    assert _bundle().assessment["metadata"]["signing"] == "unsigned-dev"


def _as_cert(d) -> Certificate:
    from app.engine.wargame.model import Assumption, Corroboration
    return Certificate(
        claim=d["claim"], boundary_src=d["boundary_src"], boundary_dst=d["boundary_dst"],
        port=None, config_hashes=tuple(d["config_hashes"]),
        assumptions=[Assumption(a["key"], a["text"]) for a in d["assumptions"]],
        corroboration=Corroboration(**d["corroboration"]),
        issued_at=d["issued_at"], expires_at=d["expires_at"], status=d["status"],
        fingerprint=d["fingerprint"], key_id=d["key_id"],
    )


def test_configured_key_signs_per_tenant_with_key_id():
    ring = signing.Keyring.from_strings("k" * 40)
    bundle = assess_environment(
        _env(), label="twin", config_hashes=["cfg-abc"], issued_at=_ISSUED,
        signing_key=ring.signing_key(_TENANT),
    )
    d = _cert(bundle)
    assert d["key_id"].startswith("wg1-") and d["key_id"] == signing.key_id(b"k" * 40)
    assert "unsigned_dev_signature" not in _keys(d)
    cert = _as_cert(d)
    assert certificate.signature_status(cert, ring, _TENANT) == "signed"
    # Another tenant's key does not verify it; nor does the public demo key.
    assert certificate.signature_status(cert, ring, "00000000-0000-0000-0000-00000000000b") == "invalid"
    assert not certificate.verify(cert, DEMO_SIGNING_KEY)
    assert bundle.assessment["metadata"]["signing"] == "signed"


def test_stored_certificate_round_trips_and_says_no_probe():
    ring = signing.Keyring.from_strings("k" * 40)
    bundle = assess_environment(
        _env(), label="twin", config_hashes=["cfg-abc"], issued_at=_ISSUED,
        signing_key=ring.signing_key(_TENANT),
    )
    d = _cert(bundle)
    assert d["corroboration"] == {
        "observed_flows": 0, "window_days": 0,        # nothing was observed
        "sensor_on_protected_side": False, "probe_tested": False,
    }
    # Postgres hands timestamps back as datetimes: still verifies.
    from app.engine.wargame.store import _ts
    cert = _as_cert(d)
    cert.issued_at, cert.expires_at = _ts(d["issued_at"]), _ts(d["expires_at"])
    assert certificate.verify_with(cert, ring, _TENANT)


def test_unproven_environment_never_counts_no_route_as_closed():
    from app.engine.wargame.assess import assess_unproven_environment

    bundle = assess_unproven_environment(_env(), label="auto")
    a = bundle.assessment
    assert a["crownjewel_total"] == 2
    assert a["crownjewel_closed"] == 0            # (guest, db) has no route: unproven
    assert a["closure_pct"] == 0.0
    assert a["metadata"]["unproven_pairs"] == 1
    assert "unproven" in a["board_line"] and "not proof of closure" in a["board_line"]
    assert bundle.certificates == [] and bundle.boundaries == []
