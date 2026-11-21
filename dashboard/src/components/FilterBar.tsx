import type { ReactNode } from "react";
import type { Severity } from "../api/types";

const SEV_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];

interface Props {
  severity: Severity[];
  onSeverity: (next: Severity[]) => void;
  text?: string;
  onText?: (v: string) => void;
  kevOnly?: boolean;
  onKev?: (b: boolean) => void;
  status?: string;
  onStatus?: (v: string) => void;
  ruleSource?: string;
  onRuleSource?: (v: string) => void;
  extra?: ReactNode;
}

export default function FilterBar({
  severity,
  onSeverity,
  text,
  onText,
  kevOnly,
  onKev,
  status,
  onStatus,
  ruleSource,
  onRuleSource,
  extra,
}: Props) {
  const toggle = (s: Severity) => {
    const on = severity.includes(s);
    onSeverity(on ? severity.filter((x) => x !== s) : [...severity, s]);
  };
  return (
    <div className="filterbar">
      <label>Severity</label>
      {SEV_LIST.map((s) => (
        <label
          key={s}
          className={`checkchip ${severity.includes(s) ? "on" : ""}`}
          style={{
            borderColor: severity.includes(s) ? `var(--sev-${s === "medium" ? "med" : s === "critical" ? "crit" : s})` : undefined,
            color: severity.includes(s)
              ? `var(--sev-${s === "medium" ? "med" : s === "critical" ? "crit" : s})`
              : undefined,
          }}
        >
          <input
            type="checkbox"
            checked={severity.includes(s)}
            onChange={() => toggle(s)}
          />
          {s.toUpperCase()}
        </label>
      ))}

      {onStatus && (
        <>
          <span className="sep" />
          <label>Status</label>
          <select
            value={status ?? ""}
            onChange={(e) => onStatus(e.target.value)}
          >
            <option value="">Any</option>
            <option value="open">Open</option>
            <option value="triaged">Triaged</option>
            <option value="fixed">Fixed</option>
            <option value="accepted">Accepted</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="false_positive">False positive</option>
          </select>
        </>
      )}

      {onRuleSource && (
        <>
          <label>Rule</label>
          <select
            value={ruleSource ?? ""}
            onChange={(e) => onRuleSource(e.target.value)}
          >
            <option value="">Any</option>
            <option value="nuclei">nuclei</option>
            <option value="cve_match">cve_match</option>
            <option value="policy">policy</option>
            <option value="chain">chain</option>
            <option value="secret_scan">secret_scan</option>
            <option value="tls_check">tls_check</option>
            <option value="header_check">header_check</option>
            <option value="exposed_file">exposed_file</option>
            <option value="manual">manual</option>
          </select>
        </>
      )}

      {onKev && (
        <>
          <label
            className={`checkchip ${kevOnly ? "on" : ""}`}
            style={{ marginLeft: 4 }}
          >
            <input
              type="checkbox"
              checked={!!kevOnly}
              onChange={(e) => onKev(e.target.checked)}
            />
            KEV only
          </label>
        </>
      )}

      {onText && (
        <>
          <span className="sep" />
          <input
            placeholder="search title / asset…"
            value={text ?? ""}
            onChange={(e) => onText(e.target.value)}
            style={{ minWidth: 220 }}
          />
        </>
      )}

      {extra}
    </div>
  );
}
