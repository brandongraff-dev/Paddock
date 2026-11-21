/**
 * Network actions — the approval queue for quarantine / release proposals on
 * UniFi and Meraki networks (Sentry `device_lateral_scan` and operators).
 *
 *   Approval queue   proposed rows (device, reason, evidence, proposer) with
 *                    approve / reject; approved rows waiting to be executed
 *   History          every finished or rejected action and its outcome
 *
 * Safety framing, mirrored from the API: a proposal is always a DRY RUN. An
 * admin approval WITHOUT "Apply for real" can only ever produce a read-only
 * preview; "Apply for real" is the single conscious grant that lets the
 * connector change the network. Approver != proposer (four-eyes). Every
 * decision needs a written reason, which lands in the audit log. All decision
 * controls are admin-only (<Gate need="admin">; the API enforces it too).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import { errorMessages } from "../api/integrations";
import {
  approveNetworkAction,
  executeNetworkAction,
  getActionEvidence,
  listNetworkActions,
  rejectNetworkAction,
  releaseNetworkAction,
  type NetworkAction,
} from "../api/networkActions";
import { useStore } from "../state/store";
import "../styles/cloud-context.css";

/* ------------------------------ helpers -------------------------------- */

export const MIN_REASON = 3;

export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const TYPE_LABEL: Record<string, string> = {
  quarantine_device: "Quarantine",
  release_device: "Release",
  revert: "Release (revert)",
};

/** The one-line outcome of an action, from what the connector reported. */
export function outcomeOf(a: NetworkAction): string {
  const out = a.result.output;
  const preview = a.result.dry_run_preview;
  switch (a.status) {
    case "applied":
      return out?.detail || "Applied";
    case "failed":
      return out?.detail || "Failed";
    case "denied":
      return "Rejected — nothing was changed";
    case "reverted":
      return "Released — the device was restored";
    case "approved":
      return preview ? `Dry-run preview: ${preview.detail}` : a.dry_run ? "Approved as dry run — not run yet" : "Approved for live apply — not run yet";
    default:
      return "Awaiting a decision";
  }
}

function ModeBadge({ dry }: { dry: boolean }) {
  return (
    <span
      className={`cx-badge ${dry ? "dry" : "live"}`}
      title={dry ? "Simulation only: read calls, no network change" : "Live: changes the network"}
    >
      {dry ? "DRY RUN" : "LIVE"}
    </span>
  );
}

const integrationOf = (a: NetworkAction) =>
  a.result.integration_name ?? a.result.integration_kind ?? "network";

/* ------------------------------ evidence ------------------------------- */

function EvidenceView({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["network-evidence", id], queryFn: () => getActionEvidence(id) });
  if (q.isLoading) return <div className="cx-sub cx-pad">Loading evidence…</div>;
  if (q.isError || !q.data) return <div className="cx-sub cx-pad">No evidence could be loaded.</div>;
  const { finding, device } = q.data;
  const ev = finding?.evidence ?? {};
  return (
    <div className="cx-evidence" aria-label="Evidence">
      {finding ? (
        <>
          <div>
            <strong>{finding.title}</strong>{" "}
            <span className="cx-sub mono">{finding.rule_id} · {finding.severity}</span>
          </div>
          {finding.description && <div className="cx-sub">{finding.description}</div>}
          {Object.keys(ev).length > 0 && (
            <dl className="cx-kv">
              {Object.entries(ev).map(([k, v]) => (
                <div key={k}>
                  <dt className="mono">{k}</dt>
                  <dd className="mono">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
        </>
      ) : (
        <div className="cx-sub">Proposed by hand: no Sentry finding is linked.</div>
      )}
      <div className="cx-sub">
        Device{" "}
        {Object.entries(device).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : String(v)}`).join(" · ")}
      </div>
    </div>
  );
}

/* ------------------------------- queue --------------------------------- */

function DecisionForm({ a }: { a: NetworkAction }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const [reason, setReason] = useState("");
  const [live, setLive] = useState(false);
  const ready = reason.trim().length >= MIN_REASON;
  const invalidate = () => qc.invalidateQueries({ queryKey: ["network-actions"] });
  const onErr = (e: unknown) => pushToast({ text: `Refused: ${errorMessages(e)[0]}`, severity: "high" });

  const approve = useMutation({
    mutationFn: () => approveNetworkAction(a.id, reason.trim(), live),
    onSuccess: () => {
      pushToast({ text: live ? "Approved for LIVE apply." : "Approved as a dry run." });
      invalidate();
    },
    onError: onErr,
  });
  const reject = useMutation({
    mutationFn: () => rejectNetworkAction(a.id, reason.trim()),
    onSuccess: () => { pushToast({ text: "Rejected." }); invalidate(); },
    onError: onErr,
  });
  const busy = approve.isPending || reject.isPending;

  return (
    <Gate need="admin" title="Admin-only — approving or rejecting network actions is gated">
      <div className="cx-decide">
        <label className="cx-lbl" htmlFor={`reason-${a.id}`}>Reason (required)</label>
        <textarea
          id={`reason-${a.id}`}
          rows={2}
          value={reason}
          maxLength={2048}
          placeholder="Why approve or reject? This is written to the audit log."
          onChange={(e) => setReason(e.target.value)}
        />
        <label className="cx-live">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          <span>Apply for real (live quarantine)</span>
        </label>
        <div className={`cx-mode ${live ? "live" : "dry"}`} role="status">
          {live
            ? "LIVE: after execution the device loses network access until released."
            : "DRY RUN: approving only allows a read-only preview. No network change."}
        </div>
        <div className="cx-actions">
          <button className={live ? "primary danger" : "primary"} disabled={!ready || busy} onClick={() => approve.mutate()}>
            {live ? "Approve live quarantine" : "Approve dry run"}
          </button>
          <button className="ghost danger" disabled={!ready || busy} onClick={() => reject.mutate()}>
            Reject
          </button>
        </div>
      </div>
    </Gate>
  );
}

function ExecuteControl({ a }: { a: NetworkAction }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const run = useMutation({
    mutationFn: () => executeNetworkAction(a.id),
    onSuccess: (r) => {
      pushToast({
        text: r.ok ? (r.dry_run ? "Dry-run preview ready." : "Applied.") : `Execution failed: ${r.detail}`,
        severity: r.ok ? undefined : "high",
      });
      qc.invalidateQueries({ queryKey: ["network-actions"] });
    },
    onError: (e: unknown) => pushToast({ text: `Refused: ${errorMessages(e)[0]}`, severity: "high" }),
  });
  return (
    <Gate need="admin" title="Admin-only — executing network actions is gated">
      <button className={a.dry_run ? "ghost" : "primary danger"} disabled={run.isPending} onClick={() => run.mutate()}>
        {run.isPending ? "Running…" : a.dry_run ? "Run dry-run preview" : "Execute live quarantine"}
      </button>
    </Gate>
  );
}

function QueueCard({ a }: { a: NetworkAction }) {
  const [showEv, setShowEv] = useState(false);
  const proposed = a.status === "proposed";
  const preview = a.result.dry_run_preview;
  return (
    <article className="cx-card" aria-label={`${TYPE_LABEL[a.action_type] ?? a.action_type} ${a.target}`}>
      <div className="cx-card-main">
        <div className="cx-card-head">
          <span className={`cx-chip cx-st-${a.status}`}>{a.status}</span>
          <span className="cx-type">{TYPE_LABEL[a.action_type] ?? a.action_type}</span>
          <span className="mono cx-device">{a.target}</span>
          {a.result.device && <span className="cx-sub mono">{a.result.device}</span>}
          <ModeBadge dry={a.dry_run} />
        </div>
        <div className="cx-card-meta">
          <span className="cx-reason">{a.reason ?? "No reason given"}</span>
          <span className="cx-sub">via {integrationOf(a)}</span>
          <span className="cx-sub">proposed by <strong>{a.requested_by ?? "—"}</strong> · {relTime(a.created_at)}</span>
          {a.approved_by && <span className="cx-sub">approved by {a.approved_by}</span>}
        </div>
        {a.status === "approved" && <div className="cx-sub">{outcomeOf(a)}</div>}
        {preview && preview.planned.length > 0 && (
          <ul className="cx-planned mono">{preview.planned.map((p) => <li key={p}>{p}</li>)}</ul>
        )}
        <button type="button" className="cx-link" aria-expanded={showEv} onClick={() => setShowEv((v) => !v)}>
          {showEv ? "Hide evidence" : "Show evidence"}
        </button>
        {showEv && <EvidenceView id={a.id} />}
      </div>
      <div className="cx-card-side">
        {proposed ? <DecisionForm a={a} /> : <ExecuteControl a={a} />}
      </div>
    </article>
  );
}

/* ------------------------------ history -------------------------------- */

function HistoryRow({ a }: { a: NetworkAction }) {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const release = useMutation({
    mutationFn: async () => {
      const rev = await releaseNetworkAction(a.id, "released from the network actions screen");
      return executeNetworkAction(rev.id);
    },
    onSuccess: (r) => {
      pushToast({ text: r.ok ? "Device released." : `Release failed: ${r.detail}`, severity: r.ok ? undefined : "high" });
      qc.invalidateQueries({ queryKey: ["network-actions"] });
    },
    onError: (e: unknown) => pushToast({ text: `Refused: ${errorMessages(e)[0]}`, severity: "high" }),
  });
  const canRelease = a.status === "applied" && a.action_type === "quarantine_device" && !a.dry_run;
  return (
    <tr>
      <td><span className={`cx-chip cx-st-${a.status}`}>{a.status}</span></td>
      <td>
        <span className="cx-type">{TYPE_LABEL[a.action_type] ?? a.action_type}</span>
        <div className="mono cx-device">{a.target}</div>
      </td>
      <td><ModeBadge dry={a.dry_run} /></td>
      <td className="cx-detail" title={outcomeOf(a)}>{outcomeOf(a)}</td>
      <td className="cx-sub">
        {a.requested_by ?? "—"}
        {a.approved_by ? <div>→ {a.approved_by}</div> : null}
      </td>
      <td className="mono cx-nowrap" title={a.applied_at ?? a.decided_at ?? a.created_at}>
        {relTime(a.applied_at ?? a.decided_at ?? a.created_at)}
      </td>
      <td>
        {canRelease && (
          <Gate need="admin" title="Admin-only — releasing a device is gated">
            <button className="ghost cx-small" disabled={release.isPending} onClick={() => release.mutate()}>
              {release.isPending ? "Releasing…" : "Release"}
            </button>
          </Gate>
        )}
      </td>
    </tr>
  );
}

/* -------------------------------- page --------------------------------- */

export default function NetworkActionsPage() {
  const q = useQuery({
    queryKey: ["network-actions"],
    queryFn: () => listNetworkActions(),
    refetchInterval: 15_000,
  });
  const items = q.data?.items ?? [];
  const { queue, history, counts } = useMemo(() => {
    const queue = items.filter((a) => a.status === "proposed" || a.status === "approved");
    const history = items.filter((a) => !(a.status === "proposed" || a.status === "approved"));
    return {
      queue,
      history,
      counts: {
        pending: items.filter((a) => a.status === "proposed").length,
        ready: items.filter((a) => a.status === "approved").length,
        live: items.filter((a) => a.status === "applied" && !a.dry_run).length,
        failed: items.filter((a) => a.status === "failed").length,
      },
    };
  }, [items]);

  return (
    <div className="page cx-page">
      <div className="page-header">
        <div>
          <h1>Network actions</h1>
          <div className="subtitle">
            Quarantine and release proposals for devices on UniFi and Meraki networks. A proposal is
            always a <strong>dry run</strong>: approving it only allows a read-only preview unless
            the approver explicitly chooses <strong>Apply for real</strong>. The approver must differ
            from the proposer, every decision needs a written reason, and every quarantine can be
            released.
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Awaiting decision" value={counts.pending} accent="#e3b265" />
        <StatTile label="Approved, not run" value={counts.ready} accent="#9fc2d8" />
        <StatTile label="Live quarantines" value={counts.live} accent="#e67350" />
        <StatTile label="Failed" value={counts.failed} accent="#7d7468" />
      </div>

      <section className="panel">
        <div className="panel-h">
          <h2>Approval queue</h2>
          <span className="panel-sub">{queue.length} open</span>
        </div>
        {q.isLoading ? (
          <div className="cx-sub cx-pad">Loading actions…</div>
        ) : queue.length === 0 ? (
          <EmptyState
            title="Nothing waiting for approval."
            hint="Sentry lateral-scan findings and operators propose quarantines here."
          />
        ) : (
          <div className="cx-cards">{queue.map((a) => <QueueCard key={a.id} a={a} />)}</div>
        )}
      </section>

      <section className="panel">
        <div className="panel-h">
          <h2>History</h2>
          <span className="panel-sub">{history.length} decided or finished</span>
        </div>
        {history.length === 0 ? (
          <EmptyState title="No history yet." hint="Applied, failed, rejected and released actions appear here." />
        ) : (
          <table className="table cx-table">
            <thead>
              <tr><th>Status</th><th>Action</th><th>Mode</th><th>Outcome</th><th>Who</th><th>When</th><th aria-label="actions" /></tr>
            </thead>
            <tbody>{history.map((a) => <HistoryRow key={a.id} a={a} />)}</tbody>
          </table>
        )}
      </section>
    </div>
  );
}
