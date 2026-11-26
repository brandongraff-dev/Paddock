#!/usr/bin/env python3
"""Write the std-registry of the containment attestation spec from the shipped invariant library.

    python scripts/export_std_registry.py            # (re)write the registry and the verifier's data copies
    python scripts/export_std_registry.py --check    # exit 1 if anything is stale (CI)

The registry is the only place a ``std:`` digest becomes trusted by the open verifier, which cannot recompute
digests (that needs the DSL canonicaliser). It maps every ruleset (a digest over the std ids and their digests)
to the std invariants of that ruleset, using the engine's own ``digest()``. A std YAML that changes without a
registry update fails ``--check``. Older rulesets stay in the file and are marked ``deprecated``; a ruleset
marked ``withdrawn`` by hand is never changed by this script.

It also keeps the four data files inside the verifier package byte-identical to their spec originals:
``registry/{std-registry.json (as std_registry.json), advisories.json, wording-v1.json, limits-v1.txt}``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = ROOT / "docs" / "spec" / "containment-attestation-v1" / "registry"
DATA_DIR = ROOT / "verifier" / "paddock_verify" / "data"
REGISTRY_FILE = REGISTRY_DIR / "std-registry.json"
COPIES = (("advisories.json", "advisories.json"), ("wording-v1.json", "wording-v1.json"),
          ("limits-v1.txt", "limits-v1.txt"), ("std-registry.json", "std_registry.json"))
#: words a registry name must not contain (the verifier prints names inside its own sentences)
NAME_BANNED = {"hardened", "secure", "secured", "safe", "protected", "compliant", "certified", "guaranteed", "clean", "proven"}


def _library():
    sys.path.insert(0, str(ROOT / "assurance"))
    sys.path.insert(0, str(ROOT / "verifier"))
    import paddock_assurance
    from paddock_assurance.stdlib import list_std, load_std
    from paddock_verify import canon, wording
    return paddock_assurance, list_std, load_std, canon, wording


def current_ruleset():
    """(ruleset digest, engine version, {std id: entry}) of the library as shipped."""
    pa, list_std, load_std, canon, wording = _library()
    entries, rows = {}, []
    for std_id in sorted(list_std()):
        plan = load_std(std_id)
        name = plan.invariant.title
        hits = wording.forbidden_hits(name) + [w for w in NAME_BANNED if w in name.lower().split()]
        if hits or not name.isascii() or '"' in name or "`" in name or not 1 <= len(name) <= 120:
            raise SystemExit("%s: the title %r cannot be a registry name (%s)" % (std_id, name, ", ".join(sorted(set(hits))) or "charset"))
        entries[std_id] = {"digest": plan.digest, "assertion": plan.invariant.assert_, "name": name, "status": "current"}
        rows.append({"digest": plan.digest, "id": std_id})
    ruleset = "sha256:" + hashlib.sha256(canon.dumps({"std": rows, "v": 1})).hexdigest()
    return ruleset, pa.__version__, entries


def build_registry(existing):
    ruleset, engine, entries = current_ruleset()
    rulesets = {}
    for rs, body in (existing or {}).get("rulesets", {}).items():
        body = json.loads(json.dumps(body))
        if rs != ruleset:
            for e in body["std"].values():
                if e["status"] == "current":
                    e["status"] = "deprecated"
        rulesets[rs] = body
    first_seen = rulesets.get(ruleset, {}).get("engine", engine)
    rulesets[ruleset] = {"engine": first_seen, "std": entries}
    return {"registry_version": 1, "rulesets": rulesets}


def render(doc) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if the committed files are stale; write nothing")
    args = ap.parse_args(argv)
    existing = json.loads(REGISTRY_FILE.read_text(encoding="ascii")) if REGISTRY_FILE.exists() else None
    want = {REGISTRY_FILE: render(build_registry(existing))}
    for src, dst in COPIES:
        data = want[REGISTRY_FILE] if src == "std-registry.json" else (REGISTRY_DIR / src).read_bytes()
        want[DATA_DIR / dst] = data
    stale = [str(p.relative_to(ROOT)) for p, data in want.items() if not p.exists() or p.read_bytes() != data]
    if args.check:
        if stale:
            sys.stderr.write("stale (run scripts/export_std_registry.py): %s\n" % ", ".join(stale))
            return 1
        print("std registry and verifier data are up to date")
        return 0
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for p, data in want.items():
        if not p.exists() or p.read_bytes() != data:
            p.write_bytes(data)
            print("wrote", p.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
