import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Severity, TimelineDay } from "../api/types";
import { SEV_COLOR, SEV_ORDER } from "../lib/color";

interface Props {
  days: TimelineDay[];
  onDaySelect?: (date: string) => void;
}

/**
 * Timeline rendering:
 *  - A cumulative area chart at the top.
 *  - Below, one row per day: new assets (blue dots) + per-severity dots
 *    + a muted 'scans' pill.
 */
export default function Timeline({ days, onDaySelect }: Props) {
  // Build a cumulative-count data set for the area chart.
  const chartData = (() => {
    let cumAssets = 0;
    let cumFindings = 0;
    return days.map((d) => {
      cumAssets += d.new_assets ?? 0;
      cumFindings += Object.values(d.new_findings_by_severity ?? {}).reduce(
        (a, b) => a + (b ?? 0),
        0,
      );
      return {
        date: d.date,
        assets: d.cumulative_assets ?? cumAssets,
        findings: d.cumulative_findings ?? cumFindings,
      };
    });
  })();

  return (
    <div>
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ height: 180 }}>
          <ResponsiveContainer>
            <AreaChart data={chartData} margin={{ top: 16, right: 16, bottom: 4, left: 16 }}>
              <defs>
                <linearGradient id="a1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#9fc2d8" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#9fc2d8" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="a2" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#e67350" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#e67350" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(236,226,208,0.07)" strokeDasharray="2 4" />
              <XAxis dataKey="date" stroke="#8a8175" tick={{ fontSize: 10 }} />
              <YAxis stroke="#8a8175" tick={{ fontSize: 10 }} width={32} />
              <Tooltip
                contentStyle={{
                  background: "#191613",
                  border: "1px solid rgba(236,226,208,0.13)",
                  borderRadius: 6,
                  color: "#ece6da",
                  fontSize: 11,
                }}
                labelStyle={{ color: "#b4ab9c" }}
              />
              <Area
                type="monotone"
                dataKey="assets"
                stroke="#9fc2d8"
                strokeWidth={1.2}
                fill="url(#a1)"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="findings"
                stroke="#e67350"
                strokeWidth={1.2}
                fill="url(#a2)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 12 }}>
        <div className="panel-h">
          <h2>Daily ledger</h2>
          <span style={{ color: "var(--text-2)", fontSize: 11 }}>
            click a day to filter other pages
          </span>
        </div>
        {days.length === 0 && (
          <div className="empty">
            <div className="icon">∅</div>No activity in range.
          </div>
        )}
        {days.map((d) => {
          const totalFindings = Object.values(d.new_findings_by_severity ?? {}).reduce(
            (a, b) => a + (b ?? 0),
            0,
          );
          return (
            <div
              key={d.date}
              className="timeline-row"
              onClick={() => onDaySelect?.(d.date)}
              role="button"
              tabIndex={0}
            >
              <div className="timeline-day">{d.date}</div>
              <div className="timeline-dots">
                {Array.from({ length: Math.min(d.new_assets ?? 0, 20) }).map((_, i) => (
                  <span
                    key={`a-${i}`}
                    className="timeline-dot"
                    style={{ background: "#9fc2d8" }}
                    title="new asset"
                  />
                ))}
                {SEV_ORDER.map((sev) =>
                  Array.from({
                    length: Math.min(d.new_findings_by_severity?.[sev as Severity] ?? 0, 20),
                  }).map((_, i) => (
                    <span
                      key={`f-${sev}-${i}`}
                      className="timeline-dot"
                      style={{ background: SEV_COLOR[sev as Severity] }}
                      title={`new ${sev} finding`}
                    />
                  )),
                )}
                {d.scans_run > 0 && (
                  <span
                    style={{
                      marginLeft: 8,
                      padding: "1px 6px",
                      border: "1px solid var(--border)",
                      borderRadius: 999,
                      color: "var(--text-2)",
                      fontFamily: "var(--mono)",
                      fontSize: 10,
                    }}
                  >
                    {d.scans_run} scans
                  </span>
                )}
                <span
                  style={{ marginLeft: "auto", color: "var(--text-2)", fontSize: 11, fontFamily: "var(--mono)" }}
                >
                  {d.new_assets ?? 0} assets · {totalFindings} findings
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
