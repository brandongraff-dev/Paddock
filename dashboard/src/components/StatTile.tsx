import Spark from "./charts/Spark";
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
  spark?: number[]; // optional series for the trend line
  /** Identity colour: shown as a small marker beside the label, never on text. */
  accent?: string;
  /** Optional footnote under the value. */
  hint?: string;
}

export default function StatTile({ label, value, delta, spark, accent, hint }: Props) {
  return (
    <div className="stat-tile">
      <div className="label">
        {accent && <i className="stat-dot" style={{ background: accent }} aria-hidden="true" />}
        {label}
      </div>
      <div className="stat-body">
        <div className="value">{value}</div>
        {spark && spark.length > 1 && (
          <div className="spark">
            <Spark values={spark} />
          </div>
        )}
      </div>
      {(delta || hint) && (
        <div className={`delta ${delta?.dir ?? ""}`}>
          {delta && (
            <>
              {delta.dir === "up" ? "▲ " : delta.dir === "down" ? "▼ " : ""}
              {delta.value}
            </>
          )}
          {hint && <span className="stat-hint">{hint}</span>}
        </div>
      )}
    </div>
  );
}
