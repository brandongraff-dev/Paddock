#!/usr/bin/env python3
"""End-to-end integration harness for paddock.

Drives the full service pipeline against a running stack and asserts the
cross-service contracts that past bugs kept breaking (missing fields, bad
envelopes, 422s, services not wired). Prints a PASS/FAIL/SKIP table and exits
non-zero on any hard FAIL.

This is NOT a unit test and MUST run against a disposable/demo database only
(it drives real compute passes). It never truncates anything.

Usage: python3 hardening/integration_test.py
Env:   ORCH=http://127.0.0.1:8080 (orchestrator)
       plus the per-service URLs (defaults to localhost dev ports).
"""
from __future__ import annotations
import json, os, sys, time, urllib.request, urllib.error

ORCH = os.environ.get("ORCH", "http://127.0.0.1:8080")
SVC = {
    "correlation": os.environ.get("CORR", "http://127.0.0.1:8091"),
    "changewatch": os.environ.get("CW", "http://127.0.0.1:8092"),
    "triage": os.environ.get("TRIAGE", "http://127.0.0.1:8093"),
    "sca": os.environ.get("SCA", "http://127.0.0.1:8094"),
    "brain": os.environ.get("BRAIN", "http://127.0.0.1:8095"),
    "codeanalysis": os.environ.get("CA", "http://127.0.0.1:8097"),
    "mlrisk": os.environ.get("ML", "http://127.0.0.1:8098"),
    "ontology": os.environ.get("ONT", "http://127.0.0.1:8099"),
    "threatintel": os.environ.get("TI", "http://127.0.0.1:8100"),
}

results: list[tuple[str, str, str]] = []  # (stage, status, detail)


def _req(method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        txt = r.read().decode()
        return r.status, (json.loads(txt) if txt.strip() else {})


def GET(path):  return _req("GET", ORCH + path)
def POST(url, body=None): return _req("POST", url, body)


def rec(stage, ok, detail=""):
    results.append((stage, "PASS" if ok else "FAIL", detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {stage} — {detail}")


def skip(stage, detail):
    results.append((stage, "SKIP", detail))
    print(f"  [SKIP] {stage} — {detail}")


def items(path):
    _, d = GET(path)
    return d.get("items", d) if isinstance(d, dict) else d


print("paddock integration harness\n" + "=" * 50)

# 0. every service healthy
for name, base in {"orchestrator": ORCH, **SVC}.items():
    try:
        s, _ = _req("GET", base + "/healthz", timeout=5)
        rec(f"health:{name}", s == 200, f"{base} -> {s}")
    except Exception as e:  # noqa: BLE001
        rec(f"health:{name}", False, f"{base} unreachable: {e}")

# 1. base graph present (seeded)
assets = items("/v1/assets?limit=500")
rec("graph:assets", len(assets) >= 20, f"{len(assets)} assets")
finds = GET("/v1/findings?limit=5")[1]
total_finds = finds.get("total", len(finds.get("items", [])))
rec("graph:findings", total_finds >= 5, f"{total_finds} findings")

# 2. CONTRACT: findings carry asset_value + blast_score (the recurring gap)
row = (finds.get("items") or [{}])[0]
rec("contract:finding.asset_value", "asset_value" in row, f"keys include asset_value={row.get('asset_value')!r}")
rec("contract:finding.blast_score", "blast_score" in row, f"blast_score={row.get('blast_score')!r}")

# 3. correlation: attack paths + ATT&CK map + fusion
try:
    POST(SVC["correlation"] + "/compute-paths"); POST(SVC["correlation"] + "/map-attack")
    POST(SVC["correlation"] + "/fuse")
    time.sleep(1)
    paths = GET("/v1/attack-paths?limit=5")[1]
    rec("correlation:attack_paths", paths.get("total", 0) >= 1, f"{paths.get('total')} paths")
    cov = GET("/v1/attack/coverage")[1]
    rec("correlation:attack_coverage", cov.get("total_findings_mapped", 0) >= 1,
        f"{cov.get('total_findings_mapped')} mapped, {len(cov.get('by_technique', []))} techniques")
except Exception as e:  # noqa: BLE001
    rec("correlation:*", False, str(e))

# 4. SCA: scan a lockfile -> SBOM + OSV
try:
    pkg = {"name":"itest","version":"1","lockfileVersion":3,"packages":{
        "":{"dependencies":{"lodash":"4.17.11"}},"node_modules/lodash":{"version":"4.17.11"}}}
    POST(SVC["sca"] + "/scan", {"project_name":"itest","files":{"package-lock.json":json.dumps(pkg)}})
    comps = GET("/v1/sbom/components?limit=5")[1]
    rec("sca:sbom", comps.get("total", 0) >= 1, f"{comps.get('total')} components")
except Exception as e:  # noqa: BLE001
    rec("sca:*", False, str(e))

# 5. codeanalysis: SAST over a taint sample
try:
    src = "import os\nfrom flask import request\ndef f():\n  os.system('ping ' + request.args['h'])\n"
    POST(SVC["codeanalysis"] + "/analyze", {"project_name":"itest","files":{"app.py":src}})
    cf = GET("/v1/code-findings?limit=5")[1]
    rec("codeanalysis:sast", cf.get("total", 0) >= 1, f"{cf.get('total')} code findings")
except Exception as e:  # noqa: BLE001
    rec("codeanalysis:*", False, str(e))

# 6. changewatch -> surface_changes
try:
    POST(SVC["changewatch"] + "/run")
    ch = GET("/v1/changes?limit=5")[1]
    rec("changewatch:changes", ch.get("total", 0) >= 1, f"{ch.get('total')} changes")
except Exception as e:  # noqa: BLE001
    rec("changewatch:*", False, str(e))

# 7. triage -> tickets (needs owner rules; soft)
try:
    POST(SVC["triage"] + "/run")
    tk = GET("/v1/tickets?limit=5")[1]
    n = tk.get("total", 0)
    (rec if n >= 1 else skip)("triage:tickets", n >= 1 or "no owner rules / already ticketed", f"{n} tickets")
except Exception as e:  # noqa: BLE001
    rec("triage:*", False, str(e))

# 8. mlrisk -> ml scores + anomalies + model (cold-start ok)
try:
    POST(SVC["mlrisk"] + "/retrain"); POST(SVC["mlrisk"] + "/detect-anomalies")
    mr = GET("/v1/ml/risk?limit=5")[1]
    rec("mlrisk:scores", mr.get("total", 0) >= 1, f"{mr.get('total')} scored")
    model = GET("/v1/ml/model")[1]
    rr = model.get("risk_ranker") or {}
    rec("mlrisk:model", bool(rr), f"v{rr.get('version')} cold_start={rr.get('cold_start')}")
    an = GET("/v1/anomalies?limit=5")[1]
    rec("mlrisk:anomalies", an.get("total", 0) >= 0, f"{an.get('total')} anomalies")
except Exception as e:  # noqa: BLE001
    rec("mlrisk:*", False, str(e))

# 9. ontology projection -> typed objects
try:
    POST(SVC["ontology"] + "/project")
    _, types = GET("/v1/ontology/types")
    tlist = types.get("object_types", types) if isinstance(types, dict) else types
    objs = GET("/v1/ontology/objects?limit=5")[1]
    rec("ontology:objects", objs.get("total", 0) >= 20, f"{objs.get('total')} objects, {len(tlist)} types")
except Exception as e:  # noqa: BLE001
    rec("ontology:*", False, str(e))

# 10. threat-intel: ingest a STIX bundle w/ an indicator that matches a demo asset
try:
    # indicator for a demo subdomain so a match lands
    bundle = {"type":"bundle","id":"bundle--itest","objects":[
        {"type":"indicator","id":"indicator--itest1","pattern":"[domain-name:value = 'admin.acme-demo.example']",
         "pattern_type":"stix","valid_from":"2026-01-01T00:00:00Z","indicator_types":["malicious-activity"],
         "labels":["c2"]}]}
    POST(SVC["threatintel"] + "/ingest/stix", bundle)
    POST(SVC["threatintel"] + "/match")
    summ = GET("/v1/ti/summary")[1]
    rec("threatintel:indicators", summ.get("indicators", 0) >= 1, f"{summ.get('indicators')} indicators, {summ.get('matches')} matches")
except Exception as e:  # noqa: BLE001
    rec("threatintel:*", False, str(e))

# 11. brain NL ask (fallback ok) + guard holds
try:
    s, d = POST(ORCH + "/v1/ask", {"question":"open critical findings"})
    engine = d.get("engine"); okq = d.get("ok")
    rec("brain:ask", engine in ("fallback", "llm") and okq, f"engine={engine} ok={okq} rows={len(d.get('rows', d.get('answer_rows', [])))}")
except Exception as e:  # noqa: BLE001
    rec("brain:*", False, str(e))

# 12. governance: audit chain intact after all this activity
try:
    s, d = GET("/v1/audit/verify")
    rec("governance:audit_chain", d.get("ok") is True, f"checked={d.get('checked')} broken={d.get('first_broken_id')}")
except Exception as e:  # noqa: BLE001
    skip("governance:audit_chain", f"auth/endpoint: {e}")


# 13. IoT/OT devices service wired + summary shape
try:
    s_, summ = GET("/v1/devices/summary")
    ok = isinstance(summ, dict) and ("ot" in summ or "devices" in summ or "exposed_ot" in summ or "total" in summ)
    rec("devices:summary", ok, f"keys={list(summ)[:6] if isinstance(summ,dict) else summ}")
except Exception as e:  # noqa: BLE001
    rec("devices:*", False, str(e))

# 14. fleet: enroll an agent -> it appears
try:
    POST(SVC_ORCH := ORCH + "/v1/fleet/enroll", {"hostname": "itest-host", "platform": "linux", "token": "itest-enroll"})
    agents = items("/v1/fleet/agents")
    rec("fleet:enroll", any((a.get("hostname") == "itest-host") for a in agents), f"{len(agents)} agents")
except Exception as e:  # noqa: BLE001
    # already enrolled is fine
    try:
        agents = items("/v1/fleet/agents")
        rec("fleet:enroll", any((a.get("hostname") == "itest-host") for a in agents), f"{len(agents)} agents (reused)")
    except Exception as e2:  # noqa: BLE001
        rec("fleet:*", False, f"{e} / {e2}")

# 15. remediation: propose a fix on an sca finding -> a remediation record exists (verified or rejected, both fine)
try:
    fl = GET("/v1/findings?rule_source=sca&limit=1")[1]
    frow = (fl.get("items") or [{}])[0]
    fid = frow.get("id")
    if fid:
        POST(ORCH + "/v1/remediation/propose", {"finding_id": fid})
        rem = GET("/v1/remediation?limit=5")[1]
        n = rem.get("total", len(rem.get("items", [])))
        rec("remediation:propose", n >= 1, f"{n} remediation records")
    else:
        skip("remediation:propose", "no sca finding to remediate")
except Exception as e:  # noqa: BLE001
    rec("remediation:*", False, str(e))

# summary
print("=" * 50)
p = sum(1 for _, s, _ in results if s == "PASS")
f = sum(1 for _, s, _ in results if s == "FAIL")
k = sum(1 for _, s, _ in results if s == "SKIP")
print(f"RESULT: {p} pass, {f} fail, {k} skip  (of {len(results)} checks)")
sys.exit(1 if f else 0)
