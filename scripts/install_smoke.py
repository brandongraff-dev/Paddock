#!/usr/bin/env python3
"""Clean-machine install smoke test (used by .github/workflows/install.yml).

Run it after `make quickstart` (full, dev profile) or `make lite && make
lite-demo` (lite, hardened). It waits for every container to be healthy, then
asserts through the public surface that a first-time user would see data:

  * the API returns the seeded demo assets / findings / chain,
  * the dashboard serves its HTML shell (and SPA routes like /setup) and
    proxies /v1/* to the orchestrator,
  * lite only: auth is enforced, the first-run wizard reports needs_setup,
    optional services report "not enabled", and an unproven scope entry
    never authorises a scan.

Stdlib only. Never talks to anything but localhost.

Usage:  python3 scripts/install_smoke.py --mode full|lite [--compose "docker compose -f ..."]
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8080")
UI = os.environ.get("DASHBOARD_URL", "http://localhost:3000")
DEMO = "acme-demo.example"

failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  ok   {msg}")


def fail(msg: str) -> None:
    print(f"  FAIL {msg}")
    failures.append(msg)


def call(method: str, url: str, body: dict | None = None, headers: dict | None = None,
         timeout: float = 15) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json", **(headers or {})}
    try:
        with urlopen(Request(url, data=data, method=method, headers=h), timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            status = r.status
    except HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status = e.code
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def wait_healthy(compose: list[str], timeout_s: int) -> None:
    """Every container running, and healthy where it has a healthcheck."""
    deadline = time.monotonic() + timeout_s
    last: list[str] = []
    while time.monotonic() < deadline:
        out = subprocess.run(compose + ["ps", "-a", "--format", "json"],
                             capture_output=True, text=True, check=False).stdout
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            rows.extend(parsed if isinstance(parsed, list) else [parsed])
        bad = [
            f"{r['Service']}={r.get('State')}/{r.get('Health') or '-'}"
            for r in rows
            if r.get("State") != "running" or r.get("Health") not in ("", None, "healthy")
        ]
        if rows and not bad:
            ok(f"{len(rows)} containers running/healthy")
            return
        if bad != last:
            print(f"  ..   waiting on: {', '.join(bad) or 'containers'}")
            last = bad
        time.sleep(5)
    fail(f"containers not healthy after {timeout_s}s: {', '.join(last)}")


def check_dashboard() -> None:
    for path in ("/", "/setup", "/graph"):
        status, body = call("GET", UI + path)
        if status == 200 and isinstance(body, str) and '<div id="root">' in body:
            ok(f"dashboard serves HTML at {path}")
        else:
            fail(f"dashboard {path}: HTTP {status}")
    status, body = call("GET", UI + "/v1/does-not-exist")
    if status in (401, 404):
        ok(f"dashboard proxies /v1/* to the orchestrator (HTTP {status})")
    else:
        fail(f"dashboard /v1 proxy: HTTP {status}")


def check_demo(headers: dict) -> None:
    status, assets = call("GET", f"{API}/v1/assets?limit=500", headers=headers)
    values = {a.get("value") for a in assets} if isinstance(assets, list) else set()
    if status == 200 and DEMO in values and f"legacy.{DEMO}" in values:
        ok(f"API returns the seeded demo assets ({len(values)} assets)")
    else:
        fail(f"seeded assets missing: HTTP {status}, {len(values)} assets")
    status, page = call("GET", f"{API}/v1/findings?limit=50", headers=headers)
    total = page.get("total", 0) if isinstance(page, dict) else 0
    titles = {f.get("title", "") for f in page.get("items", [])} if isinstance(page, dict) else set()
    if status == 200 and total >= 8 and any("CVE-2021-43798" in t for t in titles):
        ok(f"API returns the seeded findings (total={total})")
    else:
        fail(f"seeded findings missing: HTTP {status}, total={total}")
    status, chains = call("GET", f"{API}/v1/chains", headers=headers)
    if status == 200 and isinstance(chains, list) and any(
        c.get("chain_rule_id") == "forgotten-box-compromise" for c in chains
    ):
        ok("API returns the seeded attack chain")
    else:
        fail(f"seeded chain missing: HTTP {status}")
    # The same data through the dashboard's proxy (what the browser uses).
    status, page = call("GET", f"{UI}/v1/findings?limit=5", headers=headers)
    if status == 200 and isinstance(page, dict) and page.get("total", 0) >= 8:
        ok("findings reachable through the dashboard proxy")
    else:
        fail(f"findings via dashboard proxy: HTTP {status}")


def login() -> dict:
    password = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD", "")
    status, body = call("POST", f"{API}/v1/auth/login",
                        {"username": "admin", "password": password})
    if status != 200 or not isinstance(body, dict):
        fail(f"admin login failed: HTTP {status}")
        return {}
    ok("admin can sign in with ADMIN_BOOTSTRAP_PASSWORD")
    return {"Authorization": f"Bearer {body['access_token']}"}


def check_lite(h: dict) -> None:
    status, _ = call("GET", f"{API}/v1/assets")
    if status == 401:
        ok("unauthenticated API call is refused (AUTH_MODE=enforce)")
    else:
        fail(f"lite must enforce auth; unauthenticated GET returned {status}")

    status, ob = call("GET", f"{API}/v1/onboarding", headers=h)
    if status == 200 and isinstance(ob, dict) and ob.get("needs_setup") and \
            ob.get("deployment_mode") == "lite" and ob.get("require_scope_proof"):
        ok("first-run wizard: needs_setup, lite mode, proof required")
    else:
        fail(f"onboarding state unexpected: HTTP {status} {ob!r:.200}")

    status, svc = call("GET", f"{API}/v1/system/services", headers=h)
    states = {s["name"]: s["status"] for s in svc.get("services", [])} if isinstance(svc, dict) else {}
    if status == 200 and states and all(v == "not_enabled" for v in states.values()):
        ok(f"optional services report not_enabled ({len(states)})")
    else:
        fail(f"services endpoint: HTTP {status} {states}")

    # Proof-of-control: a fresh, unproven entry must not authorise a scan.
    # (.example never resolves; nothing is contacted.)
    status, entry = call("POST", f"{API}/v1/scope", {
        "kind": "domain", "value": f"proof-check.{DEMO}", "added_by": "install-smoke"}, h)
    if status != 201 or not isinstance(entry, dict):
        fail(f"could not add scope entry: HTTP {status}")
        return
    status, ch = call("POST", f"{API}/v1/scope/{entry['id']}/challenge", headers=h)
    if status == 200 and isinstance(ch, dict) and ch["dns_txt"]["name"] == f"_paddock-challenge.proof-check.{DEMO}":
        ok("challenge issued with the exact TXT record name")
    else:
        fail(f"challenge: HTTP {status}")
    status, body = call("POST", f"{API}/v1/scans",
                        {"kind": "passive_subdomains", "target": f"proof-check.{DEMO}"}, h)
    reason = json.dumps(body)
    if status == 403 and "proof-of-control is pending" in reason:
        ok("scan against an unproven scope entry is refused (403)")
    else:
        fail(f"unproven scope must refuse scans: HTTP {status} {reason:.200}")
    call("DELETE", f"{API}/v1/scope/{entry['id']}", headers=h)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["full", "lite"], required=True)
    ap.add_argument("--compose", default=None, help="compose command (default per mode)")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    compose = shlex.split(args.compose or (
        "docker compose -f docker-compose.lite.yml" if args.mode == "lite" else "docker compose"
    ))

    print(f"==> install smoke ({args.mode})")
    wait_healthy(compose, args.timeout)
    for _ in range(60):
        try:
            with urlopen(f"{API}/healthz", timeout=2):
                break
        except (URLError, HTTPError, OSError):
            time.sleep(2)
    check_dashboard()
    if args.mode == "lite":
        h = login()
        check_demo(h)
        if h:
            check_lite(h)
    else:
        check_demo({})

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall install checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
