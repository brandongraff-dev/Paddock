#!/usr/bin/env python3
"""Seed a representative DEMO attack-surface graph.

So the dashboard isn't empty the first time you open it, this loads a small
but realistic surface for a fictional org — **acme-demo.example** — straight
through the orchestrator's bulk ingest API (the same endpoints the workers
use). It creates assets, the edges between them, a spread of findings across
severities and rule sources, and one multi-finding attack chain.

Everything uses reserved, non-routable identifiers on purpose:
  * ``.example``        — RFC 6761 reserved TLD (never resolves, never routes)
  * ``203.0.113.0/24``  — TEST-NET-3, reserved for documentation (RFC 5737)
Nothing here points at a real host, and no scan is launched — this only writes
demo rows. It is **idempotent**: the bulk endpoints upsert, so re-running it
won't duplicate the graph.

Usage:   python3 scripts/seed_demo.py
Env:     ORCHESTRATOR_URL=http://localhost:8080   (default)

Run it against the DEV profile (``make up``), where AUTH_MODE=dev means the
ingest endpoints accept the synthetic-admin principal. Pair it with
``make seed-scope`` if you also want the safe default scan scope loaded.
"""

from __future__ import annotations

import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ORCH = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8080")

DOMAIN = "acme-demo.example"
SRC = "seed_demo"

# --------------------------------------------------------------------------- #
# The demo surface
# --------------------------------------------------------------------------- #

# (subdomain-label, ipv4, note)
SUBDOMAINS = [
    ("www", "203.0.113.10", "marketing site, behind a CDN"),
    ("api", "203.0.113.20", "public JSON API"),
    ("admin", "203.0.113.20", "internal admin console, accidentally public"),
    ("vpn", "203.0.113.30", "remote-access gateway"),
    ("mail", "203.0.113.40", "mail server"),
    ("dev", "203.0.113.50", "developer sandbox"),
    ("staging", "203.0.113.50", "staging; dangling CNAME (takeover risk)"),
    ("legacy", "203.0.113.60", "forgotten box, exposed .git, weak TLS"),
    ("git", "203.0.113.70", "self-hosted git"),
    ("grafana", "203.0.113.20", "metrics dashboard"),
]

TECHS = [
    ("nginx 1.18.0", "api"),
    ("OpenSSH 7.4", "legacy"),
    ("Grafana 8.3.0", "grafana"),
    ("jQuery 1.12.4", "www"),
]

# findings: (sub, rule_source, rule_id, severity, title, description, extra)
FINDINGS = [
    (
        "legacy", "exposed_file", "exposed-git-dir", "high",
        "Exposed .git directory",
        "The .git directory is publicly readable; source and history are "
        "downloadable, which often leaks credentials and internal logic.",
        {"cvss": 7.5, "blast_score": 72.0,
         "remediation": "Block /.git at the web server or remove it from the webroot."},
    ),
    (
        "legacy", "tls_grade", "tls-weak-grade", "medium",
        "Weak TLS configuration (grade C)",
        "TLS 1.0/1.1 enabled and weak ciphers negotiated. Downgrade-prone.",
        {"blast_score": 40.0,
         "remediation": "Disable TLS < 1.2 and legacy ciphers; prefer TLS 1.3."},
    ),
    (
        "api", "cve_match", "CVE-2021-23017", "high",
        "nginx resolver off-by-one (CVE-2021-23017)",
        "Detected nginx 1.18.0, affected by an off-by-one in the DNS resolver "
        "that can lead to memory corruption.",
        {"cvss": 7.7, "epss": 0.21, "blast_score": 68.0,
         "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
         "remediation": "Upgrade nginx to 1.20.1 or later."},
    ),
    (
        "www", "header_check", "missing-security-headers", "low",
        "Missing security headers",
        "No Content-Security-Policy, Strict-Transport-Security, or "
        "X-Content-Type-Options on responses.",
        {"blast_score": 18.0,
         "remediation": "Add CSP, HSTS, X-Content-Type-Options: nosniff."},
    ),
    (
        "staging", "takeover", "dangling-cname-takeover", "high",
        "Subdomain takeover risk (dangling CNAME)",
        "staging.acme-demo.example points via CNAME to a deprovisioned cloud "
        "bucket. An attacker who claims that name controls this subdomain.",
        {"blast_score": 65.0,
         "remediation": "Remove the dangling DNS record or reclaim the target."},
    ),
    (
        "admin", "nuclei", "exposed-admin-panel", "medium",
        "Admin panel exposed to the internet",
        "An administrative console is reachable without network restriction. "
        "Fingerprint only — no credentials were submitted.",
        {"blast_score": 55.0,
         "remediation": "Put the admin console behind the VPN / an allowlist."},
    ),
    (
        "grafana", "cve_match", "CVE-2021-43798", "critical",
        "Grafana path traversal (CVE-2021-43798, KEV)",
        "Grafana 8.3.0 is vulnerable to unauthenticated arbitrary file read "
        "via plugin path traversal. Listed in CISA KEV.",
        {"cvss": 7.5, "epss": 0.94, "blast_score": 88.0, "kev": True,
         "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-43798"],
         "remediation": "Upgrade Grafana to 8.3.1+."},
    ),
    (
        "www", "sca", "GHSA-jf85-cpcp-j695", "medium",
        "Vulnerable dependency: lodash 4.17.11 (prototype pollution)",
        "The front-end bundle ships lodash 4.17.11, affected by prototype "
        "pollution (CVE-2019-10744).",
        {"cvss": 5.3, "blast_score": 30.0,
         "references": ["https://github.com/advisories/GHSA-jf85-cpcp-j695"],
         "remediation": "Upgrade lodash to >= 4.17.12."},
    ),
]


def _req(method: str, path: str, body: dict | None = None, timeout: int = 20):
    data = json.dumps(body).encode() if body is not None else None
    req = Request(
        f"{ORCH}{path}", data=data, method=method,
        headers={"content-type": "application/json"},
    )
    with urlopen(req, timeout=timeout) as r:
        txt = r.read().decode()
        return r.status, (json.loads(txt) if txt.strip() else {})


def wait_for_orchestrator(max_attempts: int = 60) -> bool:
    for _ in range(max_attempts):
        try:
            with urlopen(f"{ORCH}/healthz", timeout=2) as r:
                if r.status == 200:
                    return True
        except (URLError, HTTPError):
            pass
        time.sleep(1)
    return False


def canonical_sub(label: str) -> str:
    return f"{label}.{DOMAIN}".lower()


def build_assets() -> list[dict]:
    items: list[dict] = []

    # org + apex domain
    items.append({"kind": "org", "value": "Acme Demo Corp", "source": SRC,
                  "metadata": {"note": "fictional demo organization"}})
    items.append({"kind": "domain", "value": DOMAIN, "source": SRC,
                  "metadata": {"registrar": "demo"}})

    seen_ips: set[str] = set()
    for label, ip, note in SUBDOMAINS:
        fqdn = canonical_sub(label)
        items.append({"kind": "subdomain", "value": fqdn, "source": SRC,
                      "metadata": {"note": note}})
        if ip not in seen_ips:
            items.append({"kind": "ipv4", "value": ip, "source": SRC,
                          "metadata": {"note": "TEST-NET-3 (RFC 5737)"}})
            seen_ips.add(ip)

    # a couple of ports + services + a cert + a repo + endpoints
    items.append({"kind": "port", "value": "443", "source": SRC,
                  "canonical": "203.0.113.20:443", "metadata": {"proto": "tcp"}})
    items.append({"kind": "port", "value": "22", "source": SRC,
                  "canonical": "203.0.113.60:22", "metadata": {"proto": "tcp"}})
    items.append({"kind": "service", "value": "https", "source": SRC,
                  "canonical": "203.0.113.20:443/https"})
    items.append({"kind": "service", "value": "ssh", "source": SRC,
                  "canonical": "203.0.113.60:22/ssh"})
    items.append({"kind": "certificate", "value": "*.acme-demo.example", "source": SRC,
                  "metadata": {"issuer": "Demo CA", "expires": "2026-06-01"}})
    items.append({"kind": "repository", "value": "git.acme-demo.example/acme/web", "source": SRC,
                  "metadata": {"visibility": "public-by-mistake"}})
    items.append({"kind": "endpoint", "value": "https://api.acme-demo.example/v1/users",
                  "source": SRC})
    items.append({"kind": "endpoint", "value": "https://admin.acme-demo.example/login",
                  "source": SRC})

    for tech, sub in TECHS:
        items.append({"kind": "technology", "value": tech, "source": SRC,
                      "canonical": f"{tech}@{canonical_sub(sub)}".lower(),
                      "metadata": {"on": canonical_sub(sub)}})
    return items


def build_edges() -> list[dict]:
    """`_edge` sentinel items understood by POST /v1/assets/bulk."""
    edges: list[dict] = []

    def edge(sk, sc, dk, dc, kind):
        edges.append({
            "kind": "_edge", "value": f"{sc}->{dc}", "source": SRC,
            "metadata": {
                "src_kind": sk, "src_canonical": sc.lower(),
                "dst_kind": dk, "dst_canonical": dc.lower(),
                "edge_kind": kind,
            },
        })

    for label, ip, _ in SUBDOMAINS:
        edge("domain", DOMAIN, "subdomain", canonical_sub(label), "has_subdomain")
        edge("subdomain", canonical_sub(label), "ipv4", ip, "resolves_to")
    return edges


def main() -> int:
    print(f"==> waiting for orchestrator at {ORCH}")
    if not wait_for_orchestrator():
        print(f"!! orchestrator never became healthy at {ORCH}", file=sys.stderr)
        print("   bring the stack up first:  make up", file=sys.stderr)
        return 1

    assets = build_assets()
    edges = build_edges()
    print(f"==> seeding {len(assets)} assets + {len(edges)} edges")
    try:
        _, res = _req("POST", "/v1/assets/bulk", {"items": assets + edges})
        print(f"   assets: {res.get('inserted', 0)} inserted, "
              f"{res.get('updated', 0)} updated; "
              f"edges: {res.get('edges_inserted', 0)} inserted, "
              f"{res.get('edges_updated', 0)} updated")
    except HTTPError as e:
        print(f"!! asset seed failed: HTTP {e.code}: {e.read().decode()[:300]}",
              file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"!! asset seed failed: {e}", file=sys.stderr)
        return 1

    find_items = []
    for sub, rsrc, rid, sev, title, desc, extra in FINDINGS:
        meta = {"blast_score": extra.get("blast_score")}
        if extra.get("kev"):
            meta["kev"] = True
        find_items.append({
            "asset_value": canonical_sub(sub),
            "asset_kind": "subdomain",
            "rule_id": rid,
            "rule_source": rsrc,
            "severity": sev,
            "title": title,
            "description": desc,
            "impact": extra.get("impact"),
            "remediation": extra.get("remediation"),
            "cvss": extra.get("cvss"),
            "epss": extra.get("epss"),
            "references": extra.get("references", []),
            "metadata": meta,
        })

    print(f"==> seeding {len(find_items)} findings")
    finding_ids: list[str] = []
    try:
        _, res = _req("POST", "/v1/findings/bulk", {"items": find_items})
        print(f"   findings: {res.get('inserted', 0)} inserted, "
              f"{res.get('updated', 0)} updated")
        finding_ids = [it["id"] for it in res.get("items", []) if it.get("id")]
    except HTTPError as e:
        print(f"!! finding seed failed: HTTP {e.code}: {e.read().decode()[:300]}",
              file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"!! finding seed failed: {e}", file=sys.stderr)
        return 1

    # One demo chain: exposed .git + weak TLS on the same forgotten box.
    # (Indices 0 and 1 are both on `legacy`.)
    if len(finding_ids) >= 2:
        chain = {
            "chain_rule_id": "forgotten-box-compromise",
            "severity": "critical",
            "title": "Forgotten box: source disclosure + weak crypto, no WAF",
            "description": "legacy.acme-demo.example exposes its .git directory "
                           "AND negotiates weak TLS, with no WAF in front. "
                           "Together these let an attacker pull source (and any "
                           "secrets in it) over a downgradable channel.",
            "impact_narrative": "Source + history disclosure escalates every "
                                "other finding on this host: credentials in the "
                                "repo become live, and the weak TLS makes "
                                "interception practical.",
            "blast_radius_score": 84.0,
            "finding_ids": finding_ids[:2],
            "metadata": {"source": SRC},
        }
        try:
            _req("POST", "/v1/findings/chains", chain)
            print("   chain:    1 created (forgotten-box-compromise)")
        except Exception as e:  # noqa: BLE001
            print(f"   chain:    skipped ({e})")

    print("\n==> demo graph seeded for acme-demo.example")
    print("    open the dashboard and start on the Graph page:")
    print("      http://localhost:3000/graph")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
