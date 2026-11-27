# SPDX-License-Identifier: Apache-2.0
"""The verifier against the committed end-to-end corpus (``vectors/cases``).

Every case is run in process through the real command line (the same argument vector the language-neutral runner
builds), then compared on exit code, decision, the exact ordered list of reject and unverifiable codes, warnings,
primary reason and profile, and every printed byte is scanned for the forbidden vocabulary. The corpus is written by
``tools/gen_cases.py``, an independent implementation, with every expectation stated by hand from the spec.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from paddock_verify import cli, codes

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs" / "spec" / "containment-attestation-v1"
CASES = SPEC / "vectors" / "cases"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


runner = _load(SPEC / "conformance" / "run.py", "conformance_run")
CASE_IDS = sorted(p.name for p in CASES.iterdir() if (p / "case.json").is_file())


def _static():
    w = runner.wording()
    limits = (SPEC / "registry" / "limits-v1.txt").read_text(encoding="ascii")
    return w, [w["templates"]["W-FOOTER"]["text"], limits] + [ln for ln in limits.splitlines() if ln]


WORDING, STATIC_REMOVE = _static()


def run_in_process(case_id, tmp_path, monkeypatch):
    case_dir = str(CASES / case_id)
    case = runner.load_json(os.path.join(case_dir, "case.json"))
    work = str(tmp_path / "w")
    os.makedirs(work)
    root = runner.materialise(case_dir, case, work)
    cmd = runner.build_command("paddock-verify", case_dir, case, root, work, str(SPEC / "vectors" / "test-roots.json"))
    monkeypatch.chdir(work)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = cli.main(cmd[1:])
    return case, root, status, out.getvalue(), err.getvalue()


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_case(case_id, tmp_path, monkeypatch):
    case, root, status, out, err = run_in_process(case_id, tmp_path, monkeypatch)
    exp = case["expect"]
    assert status == exp["exit"], (status, err, out[:300])
    report = json.loads(out)
    got_codes, got_warn = runner.report_codes(report)
    assert report["decision"] == exp["decision"]
    assert got_codes == exp["codes"]
    assert sorted(got_warn) == sorted(exp["warnings"])
    assert report["primary"] == exp["primary"]
    assert report["profile"] == exp["profile"]
    assert report["exit"] == exp["exit"]
    hits = runner.forbidden_hits(out + "\n" + err, STATIC_REMOVE + runner.harvest_inputs(root), WORDING["forbidden_words"])
    assert hits == []
    assert err == "" or case["expect"]["exit"] in (0, 1, 2)          # nothing but the report on stderr unless something warned


def test_the_corpus_is_the_size_the_contract_asks_for_and_every_case_states_everything():
    assert len(CASE_IDS) >= 110
    for cid in CASE_IDS:
        case = json.loads((CASES / cid / "case.json").read_text(encoding="ascii"))
        assert case["id"] == cid
        for k in ("exit", "decision", "codes", "warnings", "primary", "profile"):
            assert k in case["expect"], (cid, k)
        assert case["expect"]["forbidden_terms"] is True


def test_every_reason_code_is_exercised_except_the_ones_a_path_target_cannot_express():
    seen = set()
    for cid in CASE_IDS:
        e = json.loads((CASES / cid / "case.json").read_text(encoding="ascii"))["expect"]
        seen.update(e["codes"])
        seen.update(e["warnings"])
    missing = set(codes.CODES) - seen
    # a path TARGET cannot name an https URL, a network failure or a verifier bug, and exit 64 prints no report: those codes are
    # exercised by test_checks, test_fetch and test_exit_codes instead, and the manifest says so
    assert missing == {"input.fetch_failed", "input.insecure_transport", "internal.error", "config.policy_invalid", "config.usage"}
    manifest = json.loads((SPEC / "vectors" / "MANIFEST.json").read_text(encoding="ascii"))
    assert set(manifest["codes_not_expressible_by_the_runner"]) | {"config.policy_invalid", "config.usage"} == missing


def test_manifest_lists_every_file_with_its_hash_and_the_spec_version():
    m = json.loads((SPEC / "vectors" / "MANIFEST.json").read_text(encoding="ascii"))
    assert m["spec_version"] == "1.0" and m["cases"] == len(CASE_IDS)
    on_disk = {}
    vec = SPEC / "vectors"
    for p in vec.rglob("*"):
        if p.is_file() and p.name != "MANIFEST.json":
            on_disk[p.relative_to(vec).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    assert m["files"] == on_disk


def test_generators_are_up_to_date():
    gen = _load(SPEC / "tools" / "gen_cases.py", "gen_cases_check")
    files = gen.generate()
    vec = SPEC / "vectors"
    for rel, data in files.items():
        assert (vec / rel).read_bytes() == data, rel
    have = set(p.relative_to(vec).as_posix() for p in (vec / "cases").rglob("*") if p.is_file())
    assert have <= set(files)


def test_case_files_match_the_vector_case_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SPEC / "schema" / "vector-case.schema.json").read_text(encoding="ascii"))
    pred = json.loads((SPEC / "schema" / "predicate.schema.json").read_text(encoding="ascii"))
    from referencing import Registry, Resource
    reg = Registry().with_resources([(pred["$id"], Resource.from_contents(pred)), (schema["$id"], Resource.from_contents(schema))])
    v = jsonschema.Draft202012Validator(schema, registry=reg)
    for cid in CASE_IDS:
        v.validate(json.loads((CASES / cid / "case.json").read_text(encoding="ascii")))


def test_the_language_neutral_runner_passes_end_to_end_as_a_subprocess():
    env = dict(os.environ, PYTHONPATH=str(ROOT / "verifier"))
    p = subprocess.run([sys.executable, str(SPEC / "conformance" / "run.py"), "--impl", "%s -m paddock_verify" % sys.executable, "--filter", "wording"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)
    text = p.stdout.decode("utf-8")
    assert p.returncode == 0, text + p.stderr.decode("utf-8")
    assert "0 failed" in text and "MANIFEST sha256" in text
