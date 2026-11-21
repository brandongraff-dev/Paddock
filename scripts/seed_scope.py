#!/usr/bin/env python3
"""Seed the scope allowlist with safe defaults.

This loads ONLY targets that are explicitly authorized for public testing:
- localhost / 127.0.0.1 — your own machine
- scanme.nmap.org — nmap's official legal scan target
- OWASP Juice Shop at juice-shop.local — a deliberately vulnerable app you
  run locally; you must have set it up yourself.

Add your OWN domains via the Makefile or the dashboard scope page.
"""

from __future__ import annotations

import json
import os
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ORCH = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8080")

SAFE_SEED = [
    {
        "kind": "ipv4_cidr",
        "value": "127.0.0.0/8",
        "notes": "localhost; always safe to point at yourself",
        "auth_doc_ref": "RFC1122",
    },
    {
        "kind": "ipv6_cidr",
        "value": "::1/128",
        "notes": "localhost v6",
        "auth_doc_ref": "RFC4291",
    },
    {
        "kind": "domain",
        "value": "scanme.nmap.org",
        "notes": "nmap's official legal scan target",
        "auth_doc_ref": "https://nmap.org/book/legal-issues.html",
    },
    {
        "kind": "subdomain_wildcard",
        "value": "juice-shop.local",
        "notes": "OWASP Juice Shop on your local network",
        "auth_doc_ref": "local lab setup",
    },
]


def post(path: str, body: dict) -> dict:
    req = Request(
        f"{ORCH}{path}",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def wait_for_orchestrator(max_attempts: int = 60) -> None:
    for i in range(max_attempts):
        try:
            with urlopen(f"{ORCH}/healthz", timeout=2) as r:
                if r.status == 200:
                    return
        except (URLError, HTTPError):
            pass
        time.sleep(1)
    print(f"orchestrator never became healthy at {ORCH}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    print(f"waiting for orchestrator at {ORCH} ...")
    wait_for_orchestrator()
    print("orchestrator up; seeding scope")

    added, skipped = 0, 0
    for entry in SAFE_SEED:
        body = {**entry, "added_by": "seed_scope.py"}
        try:
            result = post("/v1/scope", body)
            print(f"  + {entry['kind']:22} {entry['value']:40}  id={result.get('id')}")
            added += 1
        except HTTPError as e:
            # Duplicate entries are fine; log and keep going.
            if e.code == 409:
                print(f"  = {entry['kind']:22} {entry['value']:40}  (already present)")
                skipped += 1
            else:
                print(f"  ! {entry['kind']:22} {entry['value']:40}  HTTP {e.code}: {e.read().decode()}")
        except Exception as e:  # noqa: BLE001
            print(f"  ! {entry['kind']:22} {entry['value']:40}  {e}")

    print(f"\ndone: {added} added, {skipped} already present")
    print("\n  Remember: this is scope for YOUR OWN TESTING. Add your own domains with:")
    print("     make scope-add KIND=subdomain_wildcard VALUE=yourdomain.example AUTH='your note'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
