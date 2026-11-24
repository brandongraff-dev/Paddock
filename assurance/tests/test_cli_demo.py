import json
from pathlib import Path

import pytest

from paddock_assurance.cli import main

EX = Path(__file__).resolve().parent.parent / "examples"
STD = ["std:no-internet-to-datastore", "std:guest-cannot-reach-pos", "std:public-ports-allowlist"]


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_clean_estate_all_hold_exit_0(capsys):
    code, out, _ = run(capsys, "test", *STD, "--graph", str(EX / "estate-clean.json"))
    assert code == 0 and out.count("HOLDS") == 3 and "VIOLATED" not in out


def test_planted_paths_are_found_exit_1(capsys):
    code, out, _ = run(capsys, "test", *STD, "--graph", str(EX / "estate-violated.json"))
    assert code == 1
    assert "guest-laptop -[tcp/9100 observed]-> printer-1 -[tcp/445 observed]-> pos-1" in out
    assert "internet -[tcp/5432 observed]-> db-1" in out
    assert "not allowed: 22" in out


def test_removing_the_planted_edge_flips_to_holds(capsys, tmp_path):
    doc = json.loads((EX / "estate-violated.json").read_text())
    doc["edges"] = [e for e in doc["edges"] if not (e["src"] == "printer-1" and e["dst"] == "pos-1")]
    p = tmp_path / "fixed.json"
    p.write_text(json.dumps(doc))
    code, out, _ = run(capsys, "test", "std:guest-cannot-reach-pos", "--graph", str(p))
    assert code == 0 and "HOLDS" in out


def test_json_output_is_stable_and_complete(capsys):
    args = ["test", *STD, "--graph", str(EX / "estate-violated.json"), "--json"]
    _, a, _ = run(capsys, *args)
    _, b, _ = run(capsys, *args)
    assert a == b
    doc = json.loads(a)
    assert doc["evaluated_at"] == "2026-12-01T09:00:00Z"
    by = {r["invariant"]: r for r in doc["results"]}
    assert by["std:guest-cannot-reach-pos"]["verdict"] == "VIOLATED"
    assert by["std:guest-cannot-reach-pos"]["digest"].startswith("sha256:")
    assert by["std:no-internet-to-datastore"]["witnesses"][0]["hops"][0]["basis"] == "observed"


def test_stale_clock_makes_everything_unknown_exit_2(capsys):
    code, out, _ = run(capsys, "test", *STD, "--graph", str(EX / "estate-clean.json"),
                       "--now", "2026-12-10T00:00:00Z")
    assert code == 2 and "UNKNOWN" in out and "stale" in out


def test_explain_shows_plan_and_resolution(capsys):
    code, out, _ = run(capsys, "explain", "std:guest-cannot-reach-pos", "--graph",
                       str(EX / "estate-violated.json"))
    assert code == 0
    assert "REACH" in out and "zone=guest" in out and "guest-ap, guest-laptop" in out
    assert "digest   sha256:" in out and "not run in P0" in out


def test_lint_ok_and_errors(capsys, tmp_path):
    code, out, _ = run(capsys, "lint", *STD)
    assert code == 0 and out.count("ok  ") == 3
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: paddock.dev/invariant/v1\nid: nope\n")
    code, _, err = run(capsys, "lint", str(bad))
    assert code == 3 and "id:" in err


@pytest.mark.parametrize("argv", [
    ["lint", "std:nope"],
    ["lint", "/does/not/exist.yaml"],
    ["test", "std:guest-cannot-reach-pos", "--graph", "/does/not/exist.json"],
    ["test", "std:guest-cannot-reach-pos", "std:guest-cannot-reach-pos", "--graph", str(EX / "estate-clean.json")],
    ["test", "std:guest-cannot-reach-pos", "--graph", str(EX / "estate-clean.json"), "--now", "yesterday"],
    ["test", "std:guest-cannot-reach-pos", "--graph", str(EX / "estate-clean.json"), "--now", "2026-12-01T00:00:00"],
])
def test_input_errors_exit_3(capsys, argv):
    code, _, err = run(capsys, *argv)
    assert code == 3 and err.startswith("error:")


def test_std_lists_three(capsys):
    code, out, _ = run(capsys, "std")
    assert code == 0 and out.split() == sorted(STD)
