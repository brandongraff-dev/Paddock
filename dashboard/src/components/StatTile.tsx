import { Area, AreaChart, ResponsiveContainer } from "recharts";
import { blastColor, blastPct } from "../lib/color";

/**
 * Small horizontal blast-score meter (0–100), filled and colored by band
 * (<40 low/blue, 40–70 med/amber, 70+ high/red). Used in the Findings table's
 * BLAST column and the Overview "top risky assets" list.
 */
export function BlastMeter({
  score,
  width = 80,
  showValue = false,
}: {
  score: number | null | undefined;
  width?: number;
  showValue?: boolean;
}) {
  const has = score != null && !Number.isNaN(score);
  const pct = blastPct(score);
  const color = blastColor(score);
  const label = has ? (Math.round(pct * 10) / 10).toString() : "—";
  return (
    <div className="blast-meter" style={{ width }} title={`blast ${label}`}>
      <div className="blast-meter-track">
        <span style={{ width: `${pct}%`, background: has ? color : "transparent" }} />
      </div>
      {showValue && (
        <span className="blast-meter-val mono" style={{ color: has ? color : "var(--text-2)" }}>
          {label}
        </span>
      )}
    </div>
  );
}

interface Props {
  label: string;
  value: number | string;
  delta?: { value: string; dir?: "up" | "down" };
  spark?: number[]; // optional array for sparkline
  accent?: string;
}

export default function StatTile({ label, value, delta, spark, accent }: Props) {
  const data = spark?.map((v, i) => ({ i, v })) ?? [];
  const stroke = accent ?? "var(--accent)";
  return (
    <div className="stat-tile">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {delta && (
        <div className={`delta ${delta.dir ?? ""}`}>
          {delta.dir === "up" ? "+" : delta.dir === "down" ? "−" : ""}
          {delta.value}
        </div>
      )}
      {data.length > 1 && (
        <div className="spark">
          <ResponsiveContainer>
            <AreaChart data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id={`sparkfill-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={stroke} stopOpacity={0.5} />
                  <stop offset="100%" stopColor={stroke} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke={stroke}
                strokeWidth={1.2}
                fill={`url(#sparkfill-${label})`}
                isAnimationActive={false}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
