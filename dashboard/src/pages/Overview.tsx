import { useMemo } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import StatTile, { BlastMeter } from "../components/StatTile";
import AssetChip from "../components/AssetChip";
import { useAssets } from "../hooks/useAssets";
import { useChains, useFindingsInfinite, useTimeline } from "../hooks/useFindings";
import { useQuery } from "@tanstack/react-query";
import { listScans } from "../api/scans";
import { SEV_COLOR, SEV_ORDER } from "../lib/color";
import type { LiveEvent, Severity } from "../api/types";
import { useStore } from "../state/store";

function fmt(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/** Stable-ish react key for a live/seeded event row. */
function eventStreamKey(e: LiveEvent): string {
  const r = e as unknown as Record<string, unknown>;
  const id = (r.finding_id ?? r.asset_id ?? r.scan_id ?? r.cve_id ?? e.ts ?? "") as string;
  return `${e.event}:${id}`;
}

export default function Overview() {
  const assets = useAssets({ limit: 500 });
  const findings = useFindingsInfinite({ status: "open" });
  const chains = useChains();
  const scans = useQuery({ queryKey: ["scans-overview"], queryFn: () => listScans({ limit: 100 }) });
  const timeline = useTimeline();
  const events = useStore((s) => s.events);

  const allFindings = useMemo(
    () => (findings.data?.pages ?? []).flat(),
    [findings.data],
  );

  const assetCount = assets.data?.length ?? 0;
  const inFlightScans = (scans.data ?? []).filter(
    (s) => s.status === "queued" || s.status === "running",
  ).length;

  const sevBuckets: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of allFindings) sevBuckets[f.severity] = (sevBuckets[f.severity] ?? 0) + 1;

  const kindBuckets = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of assets.data ?? []) m.set(a.kind, (m.get(a.kind) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [assets.data]);

  const sevTrend = useMemo(
    () =>
      (timeline.data ?? []).map((d) => ({
        date: d.date.slice(5),
        info: d.new_findings_by_severity?.info ?? 0,
        low: d.new_findings_by_severity?.low ?? 0,
        medium: d.new_findings_by_severity?.medium ?? 0,
        high: d.new_findings_by_severity?.high ?? 0,
        critical: d.new_findings_by_severity?.critical ?? 0,
      })),
    [timeline.data],
  );

  const newAssetsSpark = (timeline.data ?? []).map((d) => d.new_assets ?? 0);

  const riskyAssets = useMemo(
    () =>
      [...(assets.data ?? [])]
        .filter((a) => (a.blast_score ?? 0) > 0)
        .sort((a, b) => (b.blast_score ?? 0) - (a.blast_score ?? 0))
        .slice(0, 10),
    [assets.data],
  );

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <div className="subtitle">Snapshot of asset surface, open findings, and operational state.</div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile
          label="Assets"
          value={fmt(assetCount)}
          delta={{ value: `${kindBuckets.length} kinds`, dir: undefined }}
          spark={newAssetsSpark}
          accent="#4ea3ff"
        />
        <StatTile
          label="Open — Critical"
          value={sevBuckets.critical}
          accent={SEV_COLOR.critical}
        />
        <StatTile
          label="Open — High"
          value={sevBuckets.high}
          accent={SEV_COLOR.high}
        />
        <StatTile
          label="Chains Active"
          value={chains.data?.length ?? 0}
          accent="#c084fc"
        />
        <StatTile
          label="Scans in flight"
          value={inFlightScans}
          delta={{ value: `${scans.data?.length ?? 0} total`, dir: undefined }}
          accent="#58d68d"
        />
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-h">
            <h2>Severity trend</h2>
            <span style={{ color: "var(--text-2)", fontSize: 11 }}>last {sevTrend.length} days</span>
          </div>
          <div style={{ height: 220 }}>
            <ResponsiveContainer>
              <AreaChart data={sevTrend} margin={{ top: 6, right: 10, bottom: 0, left: 0 }}>
                <CartesianGrid stroke="#1d2430" strokeDasharray="2 4" />
                <XAxis dataKey="date" stroke="#6f7a8c" tick={{ fontSize: 10 }} />
                <YAxis stroke="#6f7a8c" tick={{ fontSize: 10 }} width={28} />
                <Tooltip
                  contentStyle={{
                    background: "#10151d",
                    border: "1px solid #2a3344",
                    borderRadius: 6,
                    fontSize: 11,
                  }}
                />
                {SEV_ORDER.map((sev) => (
                  <Area
                    key={sev}
                    type="monotone"
                    stackId="sev"
                    dataKey={sev}
                    stroke={SEV_COLOR[sev]}
                    fill={SEV_COLOR[sev]}
                    fillOpacity={0.25}
                    isAnimationActive={false}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel">
          <div className="panel-h">
            <h2>Assets by kind</h2>
          </div>
          <div style={{ height: 220 }}>
            <ResponsiveContainer>
              <BarChart
                data={kindBuckets.map(([k, v]) => ({ kind: k, count: v }))}
                margin={{ top: 6, right: 10, bottom: 0, left: 0 }}
                layout="vertical"
              >
                <CartesianGrid stroke="#1d2430" strokeDasharray="2 4" horizontal={false} />
                <XAxis type="number" stroke="#6f7a8c" tick={{ fontSize: 10 }} />
                <YAxis dataKey="kind" type="category" width={100} stroke="#aab4c4" tick={{ fontSize: 10 }} />
                <Tooltip
                  contentStyle={{
                    background: "#10151d",
                    border: "1px solid #2a3344",
                    borderRadius: 6,
                    fontSize: 11,
                  }}
                />
                <Bar dataKey="count" fill="#4ea3ff" fillOpacity={0.75} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-h">
            <h2>Top risky assets</h2>
            <span style={{ color: "var(--text-2)", fontSize: 11 }}>by blast_score</span>
          </div>
          {riskyAssets.length === 0 ? (
            <div className="empty">
              <div className="icon">∅</div>
              No scored assets yet.
            </div>
          ) : (
            <ol className="risky-list">
              {riskyAssets.map((a, i) => (
                <li key={a.id}>
                  <span className="rank mono">{i + 1}</span>
                  <div className="risky-asset">
                    <AssetChip asset={a} />
                  </div>
                  <BlastMeter score={a.blast_score} width={120} showValue />
                </li>
              ))}
            </ol>
          )}
        </div>

        <div className="panel">
          <div className="panel-h">
            <h2>Live event stream</h2>
          </div>
          {events.length === 0 ? (
            <div className="empty"><div className="icon">⌁</div>Awaiting events…</div>
          ) : (
            <ul className="mono" style={{ margin: 0, padding: 0, listStyle: "none", fontSize: 11, maxHeight: 220, overflow: "auto" }}>
              {events.slice(0, 50).map((e, i) => {
                const sev = "severity" in e ? e.severity : undefined;
                const ts = e.ts ?? "";
                // Seeded (historical) rows can span days, so show date+time;
                // live rows show time-of-day only.
                const when = e.seeded
                  ? `${ts.slice(5, 10)} ${ts.slice(11, 16)}`.trim()
                  : ts.slice(11, 19);
                return (
                  <li key={`${eventStreamKey(e)}-${i}`} className={`evrow${e.seeded ? " seeded" : ""}`}>
                    <span className="ev-ts">{when}</span>
                    <span className="ev-name" style={{ color: sev ? SEV_COLOR[sev as Severity] : "var(--accent)" }}>
                      {e.event}
                    </span>
                    <span className="ev-body">
                      {"value" in e ? e.value : "title" in e ? e.title : "target" in e ? e.target : ""}
                    </span>
                    {e.seeded && <span className="ev-past" title="historical / seeded">past</span>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
