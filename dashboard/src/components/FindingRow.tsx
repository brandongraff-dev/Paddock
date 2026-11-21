import type { AssetKind, Finding } from "../api/types";
import SeverityChip from "./Severity";
import AssetChip from "./AssetChip";
import { ClassificationChip } from "./Classification";
import { BlastMeter } from "./StatTile";
import { PriorityScore, SlaBadge } from "./Lifecycle";

interface Props {
  finding: Finding;
  focused?: boolean;
  onClick?: (f: Finding) => void;
}

function fmtDate(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return d.toISOString().slice(0, 10);
}

/**
 * The asset shown on a finding row. Prefer the flattened asset_value/asset_kind
 * columns the orchestrator joins onto every finding; fall back to the hydrated
 * asset object. Rendered as an AssetChip (mono, kind tag, truncated, clickable
 * to open the asset in the DetailDrawer).
 */
function assetFor(finding: Finding) {
  if (finding.asset) return finding.asset;
  if (finding.asset_value) {
    return {
      id: finding.asset_id,
      kind: (finding.asset_kind ?? "domain") as AssetKind,
      value: finding.asset_value,
    };
  }
  return undefined;
}

export default function FindingRow({ finding, focused, onClick }: Props) {
  const score = finding.blast_score ?? finding.asset?.blast_score ?? null;
  const asset = assetFor(finding);

  return (
    <div
      className={`finding-row ${focused ? "focused" : ""}`}
      role="row"
      tabIndex={0}
      onClick={() => onClick?.(finding)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onClick?.(finding);
      }}
    >
      <SeverityChip severity={finding.severity} />
      <div className="title" title={finding.title}>
        <PriorityScore score={finding.priority_score} />
        <span className="t">{finding.title}</span>
        {(finding.source_count ?? 1) > 1 && (
          <span className="dup-count" title="reported by several engines; collapsed into one">
            ×{finding.source_count}
          </span>
        )}
        <SlaBadge finding={finding} compact />
        {finding.kev && (
          <span className="chip chip-sev-critical" style={{ marginLeft: 6 }}>
            KEV
          </span>
        )}
        {finding.classification && (
          <span style={{ marginLeft: 6, display: "inline-flex", verticalAlign: "middle" }}>
            <ClassificationChip c={finding.classification} compact />
          </span>
        )}
      </div>
      <div style={{ minWidth: 0 }}>
        {asset ? (
          <AssetChip asset={asset} dense />
        ) : (
          <span className="mono" style={{ color: "var(--text-2)" }}>—</span>
        )}
      </div>
      <div className="mono" style={{ color: "var(--text-2)" }}>{finding.rule_source}</div>
      <div className="mono" style={{ color: "var(--text-2)" }}>{fmtDate(finding.last_seen)}</div>
      <div>
        <BlastMeter score={score} width={70} />
      </div>
      <div>
        <span className={`chip chip-status chip-status-${finding.status}`}>
          {finding.status}
        </span>
      </div>
    </div>
  );
}
