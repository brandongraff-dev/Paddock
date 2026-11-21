import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import StatTile, { BlastMeter } from "../components/StatTile";
import AssetChip from "../components/AssetChip";
import SeverityStream, { type SevDay } from "../components/charts/SeverityStream";
import PixelMatrix from "../components/charts/PixelMatrix";
import RankBars from "../components/charts/RankBars";
import { fmtNum } from "../components/charts/kit";
import { useAssets } from "../hooks/useAssets";
import { useChains, useFindingsInfinite, useTimeline } from "../hooks/useFindings";
import { listScans } from "../api/scans";
import { SEV_COLOR } from "../lib/color";
import type { LiveEvent, Severity } from "../api/types";
import { useStore } from "../state/store";
import "../styles/overview.css";

/** Stable-ish react key for a live/seeded event row. */
function eventStreamKey(e: LiveEvent): string {
  const r = e as unknown as Record<string, unknown>;
  const id = (r.finding_id ?? r.asset_id ?? r.scan_id ?? r.cve_id ?? e.ts ?? "") as string;
  return `${e.event}:${id}`;
}

const RANGES = [
  { key: 7, label: "7D" },
  { key: 14, label: "14D" },
  { key: 30, label: "30D" },
] as const;

const SEV_DESC: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_WEIGHT: Record<Severity, number> = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };

/** A 100% strip of open findings by severity, with counts beneath. */
function SeverityStrip({ counts }: { counts: Record<Severity, number> }) {
  const total = SEV_DESC.reduce((s, k) => s + counts[k], 0);
  return (
    <div className="sev-strip-wrap">
      <div className="sev-strip" role="img" aria-label={`Open findings by severity, ${total} total`}>
        {total === 0 ? (
          <span className="sev-strip-empty" />
        ) : (
          SEV_DESC.filter((k) => counts[k] > 0).map((k) => (
            <span
              key={k}
              style={{ flexGrow: counts[k], background: SEV_COLOR[k] }}
              title={`${k}: ${counts[k]}`}
            />
          ))
        )}
      </div>
      <dl className="sev-legend">
        {SEV_DESC.map((k) => (
          <div key={k}>
            <dt>
              <i style={{ background: SEV_COLOR[k] }} />
              {k}
            </dt>
            <dd className="mono">{counts[k]}</dd>
            <dd className="pct mono">{total ? `${Math.round((counts[k] / total) * 100)}%` : "—"}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function Overview() {
  const [range, setRange] = useState<number>(14);
  const assets = useAssets({ limit: 500 });
  const findings = useFindingsInfinite({ status: "open" });
  const chains = useChains();
  const scans = useQuery({ queryKey: ["scans-overview"], queryFn: () => listScans({ limit: 100 }) });
  const timeline = useTimeline(useMemo(() => {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - 29);
    return { from: d.toISOString().slice(0, 10) };
  }, []));
  const events = useStore((s) => s.events);

  const allFindings = useMemo(() => (findings.data?.pages ?? []).flat(), [findings.data]);

  const assetCount = assets.data?.length ?? 0;
  const inFlightScans = (scans.data ?? []).filter(
    (s) => s.status === "queued" || s.status === "running",
  ).length;

  const sevBuckets: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of allFindings) sevBuckets[f.severity] = (sevBuckets[f.severity] ?? 0) + 1;
  const exposure = SEV_DESC.reduce((s, k) => s + sevBuckets[k] * SEV_WEIGHT[k], 0);

  const kindBuckets = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of assets.data ?? []) m.set(a.kind, (m.get(a.kind) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
  }, [assets.data]);

  const days = useMemo(() => (timeline.data ?? []).slice(-range), [timeline.data, range]);

  const sevTrend: SevDay[] = useMemo(
    () =>
      days.map((d) => ({
        date: d.date.slice(5),
        info: d.new_findings_by_severity?.info ?? 0,
        low: d.new_findings_by_severity?.low ?? 0,
        medium: d.new_findings_by_severity?.medium ?? 0,
        high: d.new_findings_by_severity?.high ?? 0,
        critical: d.new_findings_by_severity?.critical ?? 0,
      })),
    [days],
  );

  const matrix = useMemo(
    () => [
      { key: "assets", label: "New assets", values: days.map((d) => d.new_assets ?? 0) },
      {
        key: "findings",
        label: "Findings",
        values: days.map((d) =>
          Object.values(d.new_findings_by_severity ?? {}).reduce((s, v) => s + (v ?? 0), 0),
        ),
      },
      {
        key: "crit",
        label: "Crit + high",
        values: days.map(
          (d) => (d.new_findings_by_severity?.critical ?? 0) + (d.new_findings_by_severity?.high ?? 0),
        ),
      },
      { key: "scans", label: "Scans", values: days.map((d) => d.scans_run ?? 0) },
    ],
    [days],
  );

  const newAssetsSpark = days.map((d) => d.new_assets ?? 0);
  const critSpark = days.map((d) => d.new_findings_by_severity?.critical ?? 0);
  const highSpark = days.map((d) => d.new_findings_by_severity?.high ?? 0);
  const scanSpark = days.map((d) => d.scans_run ?? 0);

  const riskyAssets = useMemo(
    () =>
      [...(assets.data ?? [])]
        .filter((a) => (a.blast_score ?? 0) > 0)
        .sort((a, b) => (b.blast_score ?? 0) - (a.blast_score ?? 0))
        .slice(0, 8),
    [assets.data],
  );

  return (
    <div className="page overview">
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <div className="subtitle">Your attack surface, what is open on it, and what changed.</div>
        </div>
        <div className="seg" role="radiogroup" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.key}
              role="radio"
              aria-checked={range === r.key}
              className={range === r.key ? "on" : ""}
              onClick={() => setRange(r.key)}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="stat-row">
        <StatTile
          label="Exposure index"
          value={fmtNum(exposure)}
          hint="Σ open findings × severity weight"
        />
        <StatTile
          label="Assets"
          value={fmtNum(assetCount)}
          delta={{ value: `${kindBuckets.length} kinds`, dir: undefined }}
          spark={newAssetsSpark}
        />
        <StatTile label="Open — Critical" value={sevBuckets.critical} spark={critSpark} accent={SEV_COLOR.critical} />
        <StatTile label="Open — High" value={sevBuckets.high} spark={highSpark} accent={SEV_COLOR.high} />
        <StatTile label="Chains Active" value={chains.data?.length ?? 0} />
        <StatTile
          label="Scans in flight"
          value={inFlightScans}
          delta={{ value: `${scans.data?.length ?? 0} total`, dir: undefined }}
          spark={scanSpark}
        />
      </div>

      <div className="ov-grid">
        <section className="panel span-2">
          <div className="panel-h">
            <h2>Findings opened</h2>
            <span className="panel-meta mono">last {sevTrend.length} days · by severity</span>
          </div>
          {sevTrend.length === 0 ? (
            <div className="empty">No activity in range yet.</div>
          ) : (
            <SeverityStream data={sevTrend} />
          )}
        </section>

        <section className="panel">
          <div className="panel-h">
            <h2>Open by severity</h2>
            <span className="panel-meta mono">{allFindings.length} open</span>
          </div>
          <SeverityStrip counts={sevBuckets} />
        </section>

        <section className="panel span-2">
          <div className="panel-h">
            <h2>Activity matrix</h2>
            <span className="panel-meta mono">one pixel per day</span>
          </div>
          {days.length === 0 ? (
            <div className="empty">No activity in range yet.</div>
          ) : (
            <PixelMatrix rows={matrix} columns={days.map((d) => d.date.slice(5))} unit="events" />
          )}
        </section>

        <section className="panel">
          <div className="panel-h">
            <h2>Surface composition</h2>
            <span className="panel-meta mono">assets by kind</span>
          </div>
          {kindBuckets.length === 0 ? (
            <div className="empty">No assets discovered yet.</div>
          ) : (
            <RankBars data={kindBuckets} caption="Assets by kind" />
          )}
        </section>

        <section className="panel span-2">
          <div className="panel-h">
            <h2>Top risky assets</h2>
            <span className="panel-meta mono">by blast score</span>
          </div>
          {riskyAssets.length === 0 ? (
            <div className="empty">No scored assets yet.</div>
          ) : (
            <ol className="risky-list">
              {riskyAssets.map((a, i) => (
                <li key={a.id}>
                  <span className="rank mono">{String(i + 1).padStart(2, "0")}</span>
                  <div className="risky-asset">
                    <AssetChip asset={a} />
                  </div>
                  <BlastMeter score={a.blast_score} width={140} showValue />
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="panel">
          <div className="panel-h">
            <h2>Live event stream</h2>
            <span className="panel-meta mono">{events.length} buffered</span>
          </div>
          {events.length === 0 ? (
            <div className="empty">Awaiting events…</div>
          ) : (
            <ul className="evlist mono">
              {events.slice(0, 50).map((e, i) => {
                const sev = "severity" in e ? e.severity : undefined;
                const ts = e.ts ?? "";
                const when = e.seeded ? `${ts.slice(5, 10)} ${ts.slice(11, 16)}`.trim() : ts.slice(11, 19);
                return (
                  <li key={`${eventStreamKey(e)}-${i}`} className={`evrow${e.seeded ? " seeded" : ""}`}>
                    <span className="ev-ts">{when}</span>
                    <i
                      className="ev-dot"
                      style={{ background: sev ? SEV_COLOR[sev as Severity] : "var(--accent)" }}
                      aria-hidden="true"
                    />
                    <span className="ev-name">{e.event}</span>
                    <span className="ev-body">
                      {"value" in e ? e.value : "title" in e ? e.title : "target" in e ? e.target : ""}
                    </span>
                    {e.seeded && (
                      <span className="ev-past" title="historical / seeded">
                        past
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
