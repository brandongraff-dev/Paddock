/**
 * Finding lifecycle UI (schema 019): explained priority, SLA clock, the
 * accept / false-positive / reopen reason dialog, and the duplicate-sources
 * and history lists. Pure presentational pieces; data comes from
 * hooks/useFindings.
 */

import { useEffect, useId, useRef, useState } from "react";
import type {
  Finding,
  FindingSource,
  FindingStatus,
  StatusHistoryEntry,
  WhyFactor,
} from "../api/types";
import "../styles/lifecycle.css";

/* ------------------------------------------------------------------ */
/* Priority score                                                     */
/* ------------------------------------------------------------------ */

export function priorityBand(score: number): "urgent" | "high" | "medium" | "low" {
  if (score >= 80) return "urgent";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function PriorityScore({ score, large }: { score?: number | null; large?: boolean }) {
  if (score == null) return null;
  const band = priorityBand(score);
  const lit = band === "urgent" ? 4 : band === "high" ? 3 : band === "medium" ? 2 : 1;
  return (
    <span
      className={`prio${large ? " lg" : ""}`}
      data-band={band}
      title={`Priority ${score}/100 — sum of the factors below`}
      aria-label={`priority ${score} of 100`}
    >
      <span className="bars" aria-hidden>
        {[1, 2, 3, 4].map((i) => <i key={i} className={i <= lit ? "on" : ""} />)}
      </span>
      {score}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Why chips                                                          */
/* ------------------------------------------------------------------ */

export function WhyChips({ why, max, dense }: { why?: WhyFactor[]; max?: number; dense?: boolean }) {
  if (!why || why.length === 0) return null;
  const shown = max ? why.slice(0, max) : why;
  const rest = why.length - shown.length;
  return (
    <div className={`why-chips${dense ? " dense" : ""}`} aria-label="why this priority">
      {shown.map((w) => (
        <span
          key={`${w.key}-${w.label}`}
          className="why-chip"
          data-key={w.key}
          data-zero={w.weight === 0 ? "true" : undefined}
          title={w.weight ? `+${w.weight} priority` : "context"}
        >
          {w.label}
          {w.weight > 0 && <span className="w">+{w.weight}</span>}
        </span>
      ))}
      {rest > 0 && <span className="why-chip" data-zero="true">+{rest} more</span>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SLA badge                                                          */
/* ------------------------------------------------------------------ */

function humanSpan(ms: number): string {
  const h = Math.round(Math.abs(ms) / 3_600_000);
  if (h < 1) return "<1h";
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

const CLOCK_RUNS: FindingStatus[] = ["open", "triaged"];

export function slaState(
  f: Pick<Finding, "due_at" | "sla_breached" | "status">,
  now: number = Date.now(),
): { state: "breached" | "soon" | "ok"; label: string } | null {
  if (!f.due_at || !CLOCK_RUNS.includes(f.status)) return null;
  const due = new Date(f.due_at).getTime();
  if (Number.isNaN(due)) return null;
  const left = due - now;
  if (f.sla_breached || left < 0) return { state: "breached", label: `SLA breached · ${humanSpan(left)} over` };
  if (left < 24 * 3_600_000) return { state: "soon", label: `due in ${humanSpan(left)}` };
  return { state: "ok", label: `due in ${humanSpan(left)}` };
}

export function SlaBadge({
  finding,
  compact,
}: {
  finding: Pick<Finding, "due_at" | "sla_breached" | "status">;
  /** Row variant: "overdue 30h" / "due 9h" — leaves room for the title. */
  compact?: boolean;
}) {
  const s = slaState(finding);
  if (!s) return null;
  const label = compact
    ? s.label.replace("SLA breached · ", "overdue ").replace(" over", "").replace("due in ", "due ")
    : s.label;
  return (
    <span
      className="sla"
      data-state={s.state}
      title={finding.due_at ? `${s.label} — due ${finding.due_at.slice(0, 16).replace("T", " ")} UTC` : undefined}
    >
      {label}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Reason dialog                                                      */
/* ------------------------------------------------------------------ */

export type ReasonKind = "accept" | "false_positive" | "reopen";

const COPY: Record<ReasonKind, { title: string; cta: string; help: string; required: boolean }> = {
  accept: {
    title: "Accept risk",
    cta: "Accept risk",
    help: "Recorded in the audit log. With an expiry the finding reopens automatically.",
    required: true,
  },
  false_positive: {
    title: "Mark as false positive",
    cta: "Mark false positive",
    help: "Recorded in the audit log and fed back into detection quality.",
    required: true,
  },
  reopen: {
    title: "Reopen finding",
    cta: "Reopen",
    help: "Moves the finding (and its duplicates) back to open.",
    required: false,
  },
};

export interface ReasonSubmit {
  reason: string;
  accepted_until?: string;
  suppress?: boolean;
}

export function tomorrowISODate(now: Date = new Date()): string {
  const d = new Date(now.getTime() + 24 * 3_600_000);
  return d.toISOString().slice(0, 10);
}

export function ReasonDialog({
  kind,
  findingTitle,
  pending,
  error,
  onCancel,
  onSubmit,
}: {
  kind: ReasonKind;
  findingTitle?: string;
  pending?: boolean;
  error?: string | null;
  onCancel: () => void;
  onSubmit: (v: ReasonSubmit) => void;
}) {
  const copy = COPY[kind];
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [suppress, setSuppress] = useState(false);
  const ref = useRef<HTMLTextAreaElement | null>(null);
  const reasonId = useId();
  const untilId = useId();

  useEffect(() => {
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const trimmed = reason.trim();
  const valid = copy.required ? trimmed.length >= 3 : true;
  const submit = () => {
    if (!valid || pending) return;
    onSubmit({
      reason: trimmed,
      // end of the chosen day, UTC — the server reopens after it
      accepted_until: until ? `${until}T23:59:59Z` : undefined,
      suppress: kind === "false_positive" ? suppress : undefined,
    });
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onCancel()}>
      <div className="modal reason-dialog" role="dialog" aria-modal="true" aria-label={copy.title}>
        <header>{copy.title}</header>
        <div className="body">
          {findingTitle && <div className="help" style={{ color: "var(--text-1)" }}>{findingTitle}</div>}
          <div className="field">
            <label htmlFor={reasonId}>Reason{copy.required ? "" : " (optional)"}</label>
            <textarea
              id={reasonId}
              ref={ref}
              value={reason}
              placeholder={
                kind === "accept"
                  ? "e.g. Compensating WAF rule; patch scheduled for the Q3 window"
                  : kind === "false_positive"
                    ? "e.g. MD5 is used for cache keys, not passwords"
                    : "e.g. Reproduced manually"
              }
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
              }}
            />
          </div>
          {kind !== "reopen" && (
            <div className="row">
              <div className="field">
                <label htmlFor={untilId}>Expires (optional)</label>
                <input
                  id={untilId}
                  type="date"
                  min={tomorrowISODate()}
                  value={until}
                  onChange={(e) => setUntil(e.target.value)}
                />
              </div>
              <span className="help">Reopens automatically after this date.</span>
            </div>
          )}
          {kind === "false_positive" && (
            <label className="check">
              <input type="checkbox" checked={suppress} onChange={(e) => setSuppress(e.target.checked)} />
              Also suppress this rule on this asset at ingest
            </label>
          )}
          <div className="help">{copy.help}</div>
          {error && <div className="err" role="alert">{error}</div>}
        </div>
        <div className="foot">
          <button className="ghost" onClick={onCancel}>Cancel</button>
          <button className="primary" disabled={!valid || pending} onClick={submit}>
            {pending ? "Saving…" : copy.cta}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sources + history                                                  */
/* ------------------------------------------------------------------ */

export function SourcesList({ sources }: { sources?: FindingSource[] }) {
  if (!sources || sources.length < 2) return null;
  return (
    <ul className="lc-list" aria-label="duplicate sources">
      {sources.map((s) => (
        <li key={s.finding_id}>
          <span className="mono" style={{ color: "var(--text-0)" }}>{s.rule_source}</span>
          <span className="mono">{s.rule_id}</span>
          {s.primary && <span className="primary-tag">primary</span>}
          <span className={`chip chip-status chip-status-${s.status}`}>{s.status}</span>
        </li>
      ))}
    </ul>
  );
}

export function HistoryList({ history }: { history?: StatusHistoryEntry[] }) {
  if (!history || history.length === 0) return null;
  return (
    <ul className="lc-list" aria-label="status history">
      {history.map((h) => (
        <li key={h.id} style={{ alignItems: "flex-start" }}>
          <span className="mono" style={{ minWidth: 86 }}>{h.at.slice(0, 16).replace("T", " ")}</span>
          <span>
            <span className="mono" style={{ color: "var(--text-1)" }}>
              {h.from_status ?? "—"} → {h.to_status}
            </span>{" "}
            <span style={{ color: "var(--text-2)" }}>by {h.actor}</span>
            {h.reason && <div style={{ color: "var(--text-1)" }}>{h.reason}</div>}
          </span>
        </li>
      ))}
    </ul>
  );
}
