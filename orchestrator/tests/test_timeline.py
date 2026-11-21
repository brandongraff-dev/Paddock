"""/v1/timeline returns the per-severity and scan breakdown the dashboard charts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


async def test_timeline_breaks_findings_down_by_severity(client, db_pool):
    now = datetime.now(timezone.utc)
    yday = now - timedelta(days=1)
    async with db_pool.acquire() as con:
        aid = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source, first_seen) "
            "VALUES ('domain', 'a.example', 'a.example', 'test', $1) RETURNING id",
            yday,
        )
        for sev, n in (("critical", 2), ("high", 1)):
            for i in range(n):
                await con.execute(
                    "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, "
                    "description, first_seen) VALUES ($1, $2, 'policy', $3, 't', 'd', $4)",
                    aid, f"r-{sev}-{i}", sev, yday,
                )
        await con.execute(
            "INSERT INTO scans (kind, target, status, queued_at) VALUES ('http_probe', 'a.example', 'completed', $1)",
            yday,
        )
    r = await client.get("/v1/timeline")
    assert r.status_code == 200
    days = {d["day"]: d for d in r.json()["days"]}
    d = days[yday.date().isoformat()]
    assert d["finding_count"] == 3
    assert d["new_findings_by_severity"] == {"critical": 2, "high": 1}
    assert d["scans_run"] == 1
    assert days[now.date().isoformat()]["new_findings_by_severity"] == {}
