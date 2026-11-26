#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Language-neutral conformance runner for containment attestation verifiers (spec v1). Standard library only.

Level A (mandatory) drives a command line verifier over every case of ``vectors/cases``:

    run.py --impl "paddock-verify" [--filter TAG] [--case ID] [--list] [--json]

For each case the runner copies the case's bundle into a temporary directory, expands the recipes (huge inputs
are built here so the repository stays small), writes the policy, DNS, state and roots files and runs

    <impl> --json --offline --now <T> --roots <test roots> [--dns-resolver file:<f>]... [--state-file <f> | --no-state]
           [--policy <f>] [--anchor-file <f>] [--std-registry <f>] <case args> <target>

It compares the exit code, the decision, the EXACT ORDERED list of reject and unverifiable reason codes, the
warnings, the primary reason and the profile, then scans every byte the implementation printed for the forbidden
vocabulary (spec/09-human-wording.md). Level B (optional) feeds the primitive vectors to an adapter module:

    run.py --primitives-adapter ./my_adapter.py        # see conformance/README.md for the functions

Exit status: 0 everything passed, 1 at least one mismatch, 2 the runner itself could not run. An implementation may
claim conformance only against a named ``spec_version`` plus the MANIFEST hash this runner prints.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_DIR = os.path.dirname(HERE)
VECTORS = os.path.join(SPEC_DIR, "vectors")
REGISTRY = os.path.join(SPEC_DIR, "registry")
SPEC_VERSION = "1.0"

INVARIANT_ID = re.compile(r"[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}")
SUBJECT_NAME = re.compile(r"dns:([a-z0-9][a-z0-9.-]{0,251}[a-z0-9])")
WORD = re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+)*")
B64_CHUNK = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


# ----------------------------------------------------------------------------------------- helpers
def load_json(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def wording():
    return load_json(os.path.join(REGISTRY, "wording-v1.json"))


def forbidden_hits(text, remove, words):
    """Whole-word, case-insensitive; a hyphenated compound counts when it or one of its parts is listed."""
    banned = set(w.lower() for w in words)
    for r in remove:
        if r:
            text = text.replace(r, " ")
    hits = set()
    for token in WORD.findall(text.lower()):
        if token in banned:
            hits.add(token)
        for part in token.split("-"):
            if part in banned:
                hits.add(part)
    return sorted(hits)


def harvest_inputs(root):
    """Invariant ids and domains the input itself contains (the scan removes exactly these)."""
    found = set()

    def scan(text):
        found.update(INVARIANT_ID.findall(text))
        for m in SUBJECT_NAME.finditer(text):
            found.add(m.group(1))
            found.add(m.group(0))

    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    raw = fh.read(4 << 20)
            except OSError:
                continue
            text = raw.decode("latin-1")
            scan(text)
            for chunk in B64_CHUNK.findall(text):
                try:
                    scan(base64.b64decode(chunk + "=" * (-len(chunk) % 4)).decode("latin-1"))
                except Exception:
                    pass
    return sorted(found, key=len, reverse=True)


# ------------------------------------------------------------------------------------------ level A
class CaseResult(object):
    def __init__(self, case_id):
        self.id = case_id
        self.ok = True
        self.problems = []
        self.exit = None

    def fail(self, msg):
        self.ok = False
        self.problems.append(msg)


def materialise(case_dir, case, work):
    """Copy ``bundle/`` and apply the recipes. Returns the directory the target path is relative to."""
    root = os.path.join(work, "case")
    src = os.path.join(case_dir, "bundle")
    if os.path.isdir(src):
        shutil.copytree(src, root)
    else:
        os.makedirs(root)
    for r in case.get("recipes") or []:
        op = r.get("op")
        path = os.path.join(root, r["file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fill = r.get("fill", " ").encode("ascii")
        if op == "pad_file":
            size = os.path.getsize(path) if os.path.exists(path) else 0
            if size > r["bytes"]:
                raise ValueError("pad_file: %s is already larger than %d" % (r["file"], r["bytes"]))
            with open(path, "ab") as fh:
                fh.write(fill * (r["bytes"] - size))
        elif op == "write_file":
            head, tail = r.get("head", "").encode("ascii"), r.get("tail", "").encode("ascii")
            with open(path, "wb") as fh:
                fh.write(head + fill * (r["bytes"] - len(head) - len(tail)) + tail)
        else:
            raise ValueError("unknown recipe op %r" % (op,))
    return root


def build_command(impl, case_dir, case, root, work, roots_file):
    cmd = shlex.split(impl) + ["--json", "--offline", "--now", case["now"]]
    if case.get("roots", "test") == "test":
        cmd += ["--roots", roots_file]
    elif case.get("roots") not in (None, "none"):
        cmd += ["--roots", os.path.join(case_dir, case["roots"])]
    dns = case.get("dns")
    if dns is not None:
        fixtures = dns["resolvers"] if isinstance(dns, dict) and "resolvers" in dns else [dns]
        for i, fx in enumerate(fixtures):
            p = os.path.join(work, "dns-%d.json" % i)
            with open(p, "w") as fh:
                json.dump(fx, fh)
            cmd += ["--dns-resolver", "file:" + p]
    state = case.get("state")
    if state is None:
        cmd += ["--no-state"]
    else:
        p = os.path.join(work, "state.json")
        with open(p, "w") as fh:
            json.dump(state, fh)
        cmd += ["--state-file", p]
    policy = case.get("policy")
    if policy is not None:
        if isinstance(policy, dict) and set(policy) == {"yaml"}:
            p, text = os.path.join(work, "policy.yaml"), policy["yaml"]
        else:
            p, text = os.path.join(work, "policy.json"), json.dumps(policy)
        with open(p, "w") as fh:
            fh.write(text)
        cmd += ["--policy", p]
    if case.get("anchor"):
        cmd += ["--anchor-file", os.path.join(root, case["anchor"])]
    if case.get("registry", "default") != "default":
        cmd += ["--std-registry", os.path.join(case_dir, case["registry"])]
    cmd += list(case.get("args") or [])
    target = case["target"]
    cmd.append(os.path.join(root, target["path"]))
    return cmd


def report_codes(report):
    """Reject and unverifiable codes in the order reported, plus the warning codes.

    A report of the wrong shape (not an object, a field of the wrong type, an entry without a string code) raises
    ``ValueError``: the runner reports it as a failed case rather than guessing.
    """
    if not isinstance(report, dict):
        raise ValueError("the report is not a JSON object")
    reasons_in = report.get("reasons", [])
    warnings_in = report.get("warnings", [])
    if not isinstance(reasons_in, list) or not isinstance(warnings_in, list):
        raise ValueError("reasons and warnings must be arrays")
    reasons = []
    for r in reasons_in:
        if not isinstance(r, dict) or not isinstance(r.get("code"), str):
            raise ValueError("a reason is an object with a string code")
        if r.get("class") in ("R", "U"):
            reasons.append(r["code"])
    warnings = []
    for w in warnings_in:
        code = w if isinstance(w, str) else (w.get("code") if isinstance(w, dict) else None)
        if not isinstance(code, str):
            raise ValueError("a warning is a code string or an object with a string code")
        warnings.append(code)
    return reasons, warnings


EXPECT_REQUIRED = ("exit", "decision", "codes", "warnings", "primary")


def run_case(impl, case_dir, roots_file, remove_static, words, timeout):
    case = load_json(os.path.join(case_dir, "case.json"))
    res = CaseResult(case["id"])
    work = tempfile.mkdtemp(prefix="paddock-conf-")
    try:
        root = materialise(case_dir, case, work)
        cmd = build_command(impl, case_dir, case, root, work, roots_file)
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, cwd=work)
        except subprocess.TimeoutExpired:
            res.fail("timed out after %ds" % timeout)
            return res
        except OSError as e:
            res.fail("cannot run the implementation: %s" % e)
            return res
        res.exit = p.returncode
        exp = case["expect"]
        missing = [k for k in EXPECT_REQUIRED if k not in exp]
        if missing:
            res.fail("the case's expect lacks %s (a case states every expectation)" % ", ".join(missing))
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        if p.returncode != exp["exit"]:
            res.fail("exit %s, expected %s" % (p.returncode, exp["exit"]))
        try:
            report = json.loads(out)
        except ValueError:
            report = None
            res.fail("stdout is not a JSON report")
        codes = warns = None
        if report is not None:
            try:
                codes, warns = report_codes(report)
            except ValueError as e:
                res.fail("malformed report: %s" % e)
                report = None
        if report is not None:
            if "decision" in exp and report.get("decision") != exp["decision"]:
                res.fail("decision %r, expected %r" % (report.get("decision"), exp["decision"]))
            if "codes" in exp and codes != exp["codes"]:
                res.fail("codes %s, expected %s" % (codes, exp["codes"]))
            if "warnings" in exp and sorted(warns) != sorted(exp["warnings"]):
                res.fail("warnings %s, expected %s" % (sorted(warns), sorted(exp["warnings"])))
            if "primary" in exp:
                got = report.get("primary")
                got = got.get("code") if isinstance(got, dict) else got
                if got != exp["primary"]:
                    res.fail("primary %r, expected %r" % (got, exp["primary"]))
            if "profile" in exp and report.get("profile") != exp["profile"]:
                res.fail("profile %r, expected %r" % (report.get("profile"), exp["profile"]))
        if exp.get("forbidden_terms", True):
            remove = remove_static + harvest_inputs(root)
            hits = forbidden_hits(out + "\n" + err, remove, words)
            if hits:
                res.fail("forbidden words in the output: %s" % ", ".join(hits))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return res


def list_cases(cases_dir, tag=None, only=None):
    if not os.path.isdir(cases_dir):
        return []
    out = []
    for name in sorted(os.listdir(cases_dir)):
        p = os.path.join(cases_dir, name, "case.json")
        if not os.path.isfile(p):
            continue
        case = load_json(p)
        if only and case["id"] != only:
            continue
        if tag and tag not in case.get("tags", []):
            continue
        out.append((case, os.path.join(cases_dir, name)))
    return out


def run_level_a(args):
    cases = list_cases(os.path.join(VECTORS, "cases"), args.filter, args.case)
    if args.list:
        for case, _d in cases:
            print("%-40s %s" % (case["id"], ",".join(case.get("tags", []))))
        return [], True
    if not cases:
        sys.stderr.write("no cases found under %s\n" % os.path.join(VECTORS, "cases"))
        return [], False
    roots_file = args.roots or os.path.join(VECTORS, "test-roots.json")
    w = wording()
    footer = w["templates"]["W-FOOTER"]["text"]
    with open(os.path.join(REGISTRY, "limits-v1.txt"), "rb") as fh:
        limits = fh.read().decode("ascii")
    static = [footer, limits] + [line for line in limits.splitlines() if line]
    results = []
    for case, d in cases:
        results.append(run_case(args.impl, d, roots_file, static, w["forbidden_words"], args.timeout))
    return results, True


# ------------------------------------------------------------------------------------------ level B
def _raises(fn, *a):
    try:
        fn(*a)
    except Exception:
        return True
    return False


def _unhex(s):
    return bytes.fromhex(s)


def run_level_b(adapter, prim_dir):
    """Return a list of (file, id, ok, detail) for every adapter function that is present."""
    out = []

    def check(file, cid, ok, detail=""):
        out.append((file, cid, bool(ok), detail))

    def has(name):
        return callable(getattr(adapter, name, None))

    def vec(name):
        return load_json(os.path.join(prim_dir, name))

    if has("pae"):
        for c in vec("pae.json")["cases"]:
            got = adapter.pae(c["payload_type"], base64.b64decode(c["payload_b64"]))
            check("pae.json", c["id"], got == base64.b64decode(c["pae_b64"]))
    if has("b64_decode"):
        for c in vec("b64.json")["decode"]:
            if c["valid"]:
                try:
                    check("b64.json", c["id"], adapter.b64_decode(c["input"]) == _unhex(c["decoded_hex"]))
                except Exception as e:
                    check("b64.json", c["id"], False, repr(e))
            else:
                check("b64.json", c["id"], _raises(adapter.b64_decode, c["input"]))
    if has("pcj_parse") or has("pcj_dumps"):
        pc = vec("pcj.json")
        if has("pcj_parse"):
            for c in pc["parse"]:
                if "input_b64" in c:
                    data = base64.b64decode(c["input_b64"])
                else:
                    r = c["recipe"]
                    data = r["head"].encode() + r["fill"].encode() * (r["length"] - len(r["head"]) - len(r["tail"])) + r["tail"].encode()
                if c["result"] == "accept":
                    try:
                        v = adapter.pcj_parse(data)
                        check("pcj.json", c["id"], ("value" not in c) or v == c["value"])
                    except Exception as e:
                        check("pcj.json", c["id"], False, repr(e))
                else:
                    check("pcj.json", c["id"], _raises(adapter.pcj_parse, data))
        if has("pcj_dumps"):
            for c in pc["encode"]:
                if "error" in c:
                    check("pcj.json", "encode-" + c["id"], _raises(adapter.pcj_dumps, c["value"]))
                else:
                    try:
                        check("pcj.json", "encode-" + c["id"], adapter.pcj_dumps(c["value"]) == base64.b64decode(c["pcj_b64"]))
                    except Exception as e:
                        check("pcj.json", "encode-" + c["id"], False, repr(e))
    if has("time_parse"):
        for c in vec("time.json")["parse"]:
            if c["valid"]:
                try:
                    check("time.json", c["id"], adapter.time_parse(c["input"]) == c["epoch"])
                except Exception as e:
                    check("time.json", c["id"], False, repr(e))
            else:
                check("time.json", c["id"], _raises(adapter.time_parse, c["input"]))
    if has("merkle_root") or has("merkle_verify"):
        mv = vec("merkle.json")
        if has("merkle_root"):
            for c in mv["trees"]:
                got = adapter.merkle_root([_unhex(h) for h in c["sorted_leaf_hashes"]])
                check("merkle.json", "tree-n%d" % c["size"], got == _unhex(c["root_hex"]))
        if has("merkle_verify"):
            for c in mv["inclusion"]:
                ok = adapter.merkle_verify(_unhex(c["leaf_hash_hex"]), c["index"], c["size"], [_unhex(p) for p in c["path_hex"]], _unhex(c["root_hex"]))
                check("merkle.json", "incl-n%d-i%d" % (c["size"], c["index"]), ok is True)
            for c in mv["bad_inclusion"]:
                ok = adapter.merkle_verify(_unhex(c["leaf_hash_hex"]), c["index"], c["size"], [_unhex(p) for p in c["path_hex"]], _unhex(c["root_hex"]))
                check("merkle.json", "bad-" + c["id"], ok is False)
    if has("ed25519_verify"):
        for c in vec("ed25519.json")["cases"]:
            try:
                ok = adapter.ed25519_verify(_unhex(c["pub_hex"]), _unhex(c["msg_hex"]), _unhex(c["sig_hex"]))
            except Exception as e:
                check("ed25519.json", c["id"], c["expect"] != "valid", repr(e))
                continue
            check("ed25519.json", c["id"], bool(ok) == (c["expect"] == "valid"))
    return out


def load_adapter(spec):
    if os.path.isfile(spec):
        s = importlib.util.spec_from_file_location("conformance_adapter", spec)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        return mod
    return importlib.import_module(spec)


# --------------------------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--impl", help="command line of the verifier under test, e.g. 'paddock-verify'")
    ap.add_argument("--filter", help="only cases carrying this tag")
    ap.add_argument("--case", help="only the case with this id")
    ap.add_argument("--list", action="store_true", help="list the cases and exit")
    ap.add_argument("--roots", help="test trust roots file (default: vectors/test-roots.json)")
    ap.add_argument("--timeout", type=int, default=60, help="seconds per case")
    ap.add_argument("--primitives-adapter", help="module (path or name) implementing the Level B functions")
    ap.add_argument("--primitives-dir", default=os.path.join(VECTORS, "primitives"))
    ap.add_argument("--json", action="store_true", help="machine readable matrix")
    args = ap.parse_args(argv)
    if not args.impl and not args.primitives_adapter and not args.list:
        ap.error("give --impl (Level A), --primitives-adapter (Level B) or --list")
    matrix, failed = [], 0
    if args.impl or args.list:
        results, ok = run_level_a(args)
        if not ok:
            return 2
        for r in results:
            matrix.append({"level": "A", "id": r.id, "ok": r.ok, "exit": r.exit, "problems": r.problems})
            failed += 0 if r.ok else 1
    if args.primitives_adapter:
        try:
            adapter = load_adapter(args.primitives_adapter)
        except Exception as e:
            sys.stderr.write("cannot load the adapter: %s\n" % e)
            return 2
        for f, cid, ok, detail in run_level_b(adapter, args.primitives_dir):
            matrix.append({"level": "B", "id": "%s:%s" % (f, cid), "ok": ok, "exit": None, "problems": [detail] if detail else []})
            failed += 0 if ok else 1
    manifest = os.path.join(VECTORS, "MANIFEST.json")
    header = {"spec_version": SPEC_VERSION, "manifest_sha256": sha256_file(manifest) if os.path.exists(manifest) else None,
              "total": len(matrix), "failed": failed}
    if args.json:
        print(json.dumps(dict(header, matrix=matrix), indent=2, sort_keys=True))
    else:
        for m in matrix:
            if m["level"] == "A" or not m["ok"]:
                print("%s %-8s %-48s %s" % ("PASS" if m["ok"] else "FAIL", "level " + m["level"], m["id"], "; ".join(m["problems"])))
        print("spec_version %s, MANIFEST sha256 %s" % (header["spec_version"], header["manifest_sha256"]))
        print("%d checks, %d failed" % (header["total"], failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
