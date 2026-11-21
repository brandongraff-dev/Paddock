"""Deterministic, realistic demo data for report rendering tests.

``seed_demo(pool, now)`` builds ~60 days of history for the fictional
``acme-demo.example`` surface: findings opened and fixed on believable
timelines, routed tickets with SLA clocks, attack paths that open and close,
surface changes, Sentry device findings, scans, SBOM and TLS grades. All
timestamps are relative to ``now`` and the RNG is seeded, so output is stable.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta

TEAMS = ["Platform", "Web", "Payments", "Corp IT", "OT Engineering"]
SLA_H = {"critical": 24, "high": 72, "medium": 168, "low": 720, "info": 0}

RULES = [
    ("critical", "cve_match", "CVE-2024-3400", "PAN-OS GlobalProtect command injection (KEV)"),
    (
        "critical",
        "exposed_file",
        "exposed-dotenv",
        "Environment file with live credentials exposed",
    ),
    ("critical", "secret_scan", "secret-aws-key", "AWS access key committed to public repository"),
    ("high", "cve_match", "CVE-2023-4966", "Citrix NetScaler session token leak"),
    ("high", "exposed_file", "exposed-dotgit-root", "Exposed .git directory"),
    ("high", "nuclei", "grafana-default-login", "Grafana default login page reachable"),
    ("high", "takeover", "subdomain-takeover", "Dangling CNAME to unclaimed bucket"),
    ("high", "cve_match", "CVE-2024-6387", "OpenSSH regreSSHion (CVE-2024-6387)"),
    ("medium", "tls_check", "tls-weak-protocol", "TLS 1.0 still enabled"),
    ("medium", "header_check", "header-csp-missing", "Content-Security-Policy missing"),
    ("medium", "policy", "cert_expiry_30d", "Certificate expires within 30 days"),
    ("medium", "nuclei", "directory-listing", "Directory listing enabled"),
    ("medium", "policy", "no_public_dev", "Development host publicly reachable"),
    ("low", "header_check", "header-hsts-missing", "Strict-Transport-Security missing"),
    ("low", "header_check", "header-xcto-missing", "X-Content-Type-Options missing"),
    ("low", "nuclei", "server-banner", "Server version disclosed in banner"),
    ("info", "nuclei", "tech-detect", "Technology fingerprint recorded"),
]
FIX_DAYS = {
    "critical": (0.2, 1.3),
    "high": (0.6, 3.6),
    "medium": (1.5, 8),
    "low": (4, 32),
    "info": (5, 30),
}


async def seed_demo(pool, now: datetime) -> dict[str, int]:
    rng = random.Random(7)
    async with pool.acquire() as con:
        async with con.transaction():
            assets: list[tuple] = []
            names = [
                "www",
                "api",
                "app",
                "auth",
                "pay",
                "admin",
                "vpn",
                "mail",
                "status",
                "cdn",
                "grafana",
                "staging",
                "dev",
                "files",
                "sso",
                "shop",
            ]
            for n in names:
                assets.append(("subdomain", f"{n}.acme-demo.example"))
            for i in range(8):
                assets.append(("ipv4", f"203.0.113.{10 + i}"))
            for p in ["/login", "/api/v2", "/admin", "/.git", "/.env", "/graphql"]:
                assets.append(("endpoint", f"https://app.acme-demo.example{p}"))
            assets.append(("repository", "github.com/acme-demo/storefront"))
            ids: dict[str, object] = {}
            for kind, value in assets:
                first = now - timedelta(days=rng.uniform(5, 90))
                ids[value] = await con.fetchval(
                    """INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen, metadata)
                       VALUES ($1,$2,$2,'demo',$3,$4,'{}') RETURNING id""",
                    kind,
                    value,
                    first,
                    now - timedelta(hours=rng.uniform(1, 40)),
                )
            web = [v for k, v in assets if k in ("subdomain", "endpoint", "ipv4")]

            # devices + segments
            segs = {}
            for s in ["10.20.0.0/24 (IoT)", "10.30.0.0/24 (OT cell)", "10.10.0.0/16 (corp)"]:
                segs[s] = await con.fetchval(
                    """INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen)
                       VALUES ('network_segment',$1,$1,'sentry',$2,$3) RETURNING id""",
                    s,
                    now - timedelta(days=50),
                    now - timedelta(hours=1),
                )
            devices = []
            for i, (kind, label) in enumerate(
                [
                    ("iot_device", "axis-cam-lobby"),
                    ("iot_device", "hp-printer-3f"),
                    ("iot_device", "ecobee-thermostat"),
                    ("iot_device", "samsung-tv-board"),
                    ("iot_device", "hikvision-dvr"),
                    ("ot_device", "siemens-s7-1200-line2"),
                    ("ot_device", "schneider-m340"),
                    ("ot_device", "bacnet-ahu-ctrl"),
                ]
            ):
                first = now - timedelta(days=rng.uniform(2, 50))
                did = await con.fetchval(
                    """INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen, metadata)
                       VALUES ($1,$2,$2,'sentry',$3,$4,$5::jsonb) RETURNING id""",
                    kind,
                    label,
                    first,
                    now - timedelta(hours=2),
                    json.dumps({"vendor": label.split("-")[0]}),
                )
                devices.append((kind, label, did))
            seg_ids = list(segs.values())
            for a, b in [(0, 2), (1, 2), (0, 1)]:
                await con.execute(
                    """INSERT INTO asset_edges (src_id, dst_id, kind, first_seen)
                       VALUES ($1,$2,'can_reach_observed',$3)""",
                    seg_ids[a],
                    seg_ids[b],
                    now - timedelta(days=20),
                )

            # findings + tickets
            n_find = 0
            used: set[tuple] = set()
            for _ in range(110):
                sev, src, rule, title = rng.choices(
                    RULES, weights=[2, 1, 1, 3, 2, 2, 1, 2, 4, 5, 3, 3, 2, 6, 6, 4, 3]
                )[0]
                val = rng.choice(web)
                if (val, rule) in used:
                    continue
                used.add((val, rule))
                first = now - timedelta(days=rng.uniform(0, 62) ** 1.0)
                lo, hi = FIX_DAYS[sev]
                fix_at = first + timedelta(days=rng.uniform(lo, hi) * rng.choice([1, 1, 1, 1.6]))
                fixed = fix_at < now and rng.random() < 0.9
                fid = await con.fetchval(
                    """INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description,
                                             first_seen, last_seen)
                       VALUES ($1,$2,$3,$4,$5,$5,$6,$6) RETURNING id""",
                    ids[val],
                    rule,
                    src,
                    sev,
                    title,
                    first,
                )
                n_find += 1
                team = rng.choice(TEAMS[:4])
                due = first + timedelta(hours=SLA_H[sev]) if SLA_H[sev] else None
                await con.execute(
                    """INSERT INTO tickets (finding_id, title, severity, owner_team, sla_hours, sla_due,
                                            opened_at, status, closed_at)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
                    fid,
                    title,
                    sev,
                    team,
                    SLA_H[sev] or None,
                    due,
                    first,
                    "resolved" if fixed else "open",
                    fix_at if fixed else None,
                )
                if fixed:
                    status = "fixed" if rng.random() > 0.08 else "accepted_risk"
                    await con.execute(
                        "UPDATE findings SET status=$2, last_seen=$3 WHERE id=$1",
                        fid,
                        status,
                        fix_at,
                    )
                    await con.execute(
                        "UPDATE finding_resolutions SET resolved_at=$2 WHERE finding_id=$1",
                        fid,
                        fix_at,
                    )

            # Sentry behaviour findings on devices
            beh = [
                (
                    "ot_device",
                    "ot_internet_egress",
                    "high",
                    "PLC initiated a connection to a public address",
                ),
                (
                    "iot_device",
                    "iot_crosses_segment",
                    "medium",
                    "Camera reached the corporate segment on 445/tcp",
                ),
                ("iot_device", "cleartext_management", "medium", "Printer managed over Telnet"),
                (
                    "iot_device",
                    "behavior_drift",
                    "medium",
                    "Thermostat started SSH egress unlike its model",
                ),
                ("ot_device", "ot_it_exposure", "high", "OT cell reachable from corporate IT"),
            ]
            for i, (kind, rule, sev, title) in enumerate(beh):
                dev = [d for d in devices if d[0] == kind][i % 2]
                first = now - timedelta(days=rng.uniform(1, 25))
                await con.execute(
                    """INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description,
                                             first_seen, last_seen, assigned_to)
                       VALUES ($1,$2,'policy',$3,$4,$4,$5,$5,'OT Engineering')""",
                    dev[2],
                    rule,
                    sev,
                    title,
                    first,
                )
                n_find += 1

            # attack paths: open some, close some (ledger via trigger), then backdate
            paths = [
                (
                    "vpn.acme-demo.example → OpenSSH regreSSHion → db-primary",
                    "critical",
                    88.0,
                    True,
                    40,
                    9,
                ),
                ("www → exposed .git → CI token → artifact store", "critical", 81.5, False, 35, 12),
                ("grafana default login → metrics host → payments API", "high", 66.0, False, 26, 4),
                ("dangling CNAME → session cookie scope → app", "high", 58.0, False, 18, None),
                ("dev host → .env secrets → object storage", "critical", 77.0, False, 9, None),
                ("mail → TLS 1.0 downgrade → SSO", "medium", 31.0, False, 6, None),
                ("status page → admin panel → config bucket", "high", 52.0, False, 3, 1),
            ]
            src, dst = ids["vpn.acme-demo.example"], ids["github.com/acme-demo/storefront"]
            for i, (title, sev, expl, kev, opened_ago, closed_ago) in enumerate(paths):
                await con.execute(
                    """INSERT INTO attack_paths (source_asset_id, target_asset_id, hops, length, total_cost,
                         exploitability, severity, title, kev_on_path, fingerprint)
                       VALUES ($1,$2,'[]',3,4.5,$3,$4,$5,$6,$7)""",
                    src,
                    dst,
                    expl,
                    sev,
                    title,
                    kev,
                    f"fp-{i}",
                )
                await con.execute(
                    "UPDATE attack_path_ledger SET opened_at=$2 WHERE fingerprint=$1",
                    f"fp-{i}",
                    now - timedelta(days=opened_ago),
                )
                if closed_ago is not None:
                    await con.execute("DELETE FROM attack_paths WHERE fingerprint=$1", f"fp-{i}")
                    await con.execute(
                        "UPDATE attack_path_ledger SET closed_at=$2 WHERE fingerprint=$1",
                        f"fp-{i}",
                        now - timedelta(days=closed_ago),
                    )

            # surface changes
            ctypes = [
                ("subdomain_discovered", "info"),
                ("port_opened", "medium"),
                ("cert_expiring", "medium"),
                ("tech_version_changed", "low"),
                ("port_closed", "info"),
                ("finding_resolved", "info"),
                ("attack_path_found", "high"),
                ("endpoint_discovered", "low"),
            ]
            for i in range(34):
                ct, sev = rng.choice(ctypes)
                val = rng.choice(web)
                await con.execute(
                    """INSERT INTO surface_changes (change_type, asset_id, asset_value, severity, summary, detected_at)
                       VALUES ($1,$2,$3,$4,$5,$6)""",
                    ct,
                    ids[val],
                    val,
                    sev,
                    f"{ct.replace('_', ' ')} on {val}",
                    now - timedelta(days=rng.uniform(0, 30)),
                )
            # scans, SBOM, TLS
            for i in range(46):
                q = now - timedelta(days=rng.uniform(0, 30))
                st = "failed" if i % 17 == 0 else "completed"
                await con.execute(
                    """INSERT INTO scans (kind, target, status, queued_at, started_at, finished_at)
                       VALUES ('http_probe', 'acme-demo.example', $1, $2, $2, $3)""",
                    st,
                    q,
                    q + timedelta(minutes=4),
                )
            pid = await con.fetchval(
                "INSERT INTO sca_projects (name, last_scanned) VALUES ('storefront', $1) RETURNING id",
                now - timedelta(days=2),
            )
            for i in range(140):
                await con.execute(
                    "INSERT INTO sbom_components (project_id, ecosystem, name, version) VALUES ($1,'npm',$2,'1.0.0')",
                    pid,
                    f"pkg-{i}",
                )
            for i, v in enumerate(web[:9]):
                await con.execute(
                    "INSERT INTO tls_grades (asset_id, host, grade, score) VALUES ($1,$2,$3,$4)",
                    ids[v],
                    v,
                    ["A", "A+", "B", "C", "A", "A", "F", "A", "B"][i],
                    70,
                )
    return {"findings": n_find, "assets": len(assets) + len(devices) + 3}
