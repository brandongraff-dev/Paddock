/**
 * Context sync — SOURCE connectors (cloud inventory, EDR, CMDB) and the scope
 * they suggest.
 *
 *   Sources       one row per SOURCE integration: last sync, items imported,
 *                 errors, next run, "Sync now"
 *   Suggestions   internet-facing IPs / domains a source saw. NEVER scope by
 *                 themselves: Accept goes through the normal scope add (and
 *                 its proof-of-control), Dismiss keeps them out of the queue.
 *
 * Mutations sit inside <Gate need="admin">; the API enforces the same rule.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import { errorMessages } from "../api/integrations";
import {
  acceptSuggestion,
  dismissSuggestion,
  getSyncStatus,
  listSuggestions,
  syncNow,
  type AcceptResult,
  type ScopeSuggestion,
  type SyncStatus,
} from "../api/context";
import { useStore } from "../state/store";
import "../styles/cloud-context.css";

/* ------------------------------ helpers -------------------------------- */

export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.round((now - t) / 1000);
  const abs = Math.abs(s);
  if (abs < 60) return s >= 0 ? "just now" : "any moment";
  const txt = abs < 3600 ? `${Math.floor(abs / 60)}m` : abs < 86400 ? `${Math.floor(abs / 3600)}h` : `${Math.floor(abs / 86400)}d`;
  return s >= 0 ? `${txt} ago` : `in ${txt}`;
}

export type SyncHealth = "never" | "running" | "ok" | "degraded" | "error" | "paused";

/** ok-with-warnings is "degraded": the sync landed but part of the inventory is missing. */
export function syncHealth(s: SyncStatus): SyncHealth {
  const r = s.last_run;
  if (!r) return s.enabled ? "never" : "paused";
  if (r.status === "running") return "running";
  if (r.status === "error" || r.status === "abandoned") return "error";
  if ((r.counts?.warnings ?? 0) > 0) return "degraded";
  return s.enabled ? "ok" : "paused";
}

const HEALTH_LABEL: Record<SyncHealth, string> = {
  never: "Not synced yet",
  running: "Syncing",
  ok: "Healthy",
  degraded: "Degraded",
  error: "Failing",
  paused: "Paused",
};

/** Items a run brought in: assets, findings and edges, new or refreshed. */
export function importedCount(counts: Record<string, number> | undefined): number {
  const c = counts ?? {};
  return (c.assets_inserted ?? 0) + (c.assets_updated ?? 0) + (c.assets_merged ?? 0) +
    (c.findings_inserted ?? 0) + (c.findings_updated ?? 0) +
    (c.edges_inserted ?? 0) + (c.edges_updated ?? 0);
}

const KIND_LABEL: Record<string, string> = {
  ipv4_cidr: "IPv4",
  ipv6_cidr: "IPv6",
  domain: "Domain",
  subdomain_wildcard: "Wildcard",
  asn: "ASN",
};

function evidenceLine(ev: Record<string, unknown>): string {
  const parts = [ev.cloud, ev.project ?? ev.subscription, ev.type ?? ev.dns_zone]
    .filter((x) => typeof x === "string" && x)
    .map(String);
  const res = typeof ev.resource === "string" ? ev.resource.split("/").slice(-2).join("/") : "";
  return [...parts, res].filter(Boolean).join(" · ");
}

/* ------------------------------ sources -------------------------------- */

function SourceRow({ s }: { s: SyncStatus }) {
  const qc = useQueryClient();
  const pushToast = useStore((st) => st.pushToast);
  const health = syncHealth(s);
  const run = s.last_run;
  const sync = useMutation({
    mutationFn: () => syncNow(s.integration_id),
    onSuccess: (r) => {
      pushToast({
        text: r.status === "ok" ? `${s.name}: sync finished` : `${s.name}: ${r.status}${r.detail ? ` (${r.detail})` : ""}`,
        severity: r.status === "error" ? "high" : undefined,
      });
      qc.invalidateQueries({ queryKey: ["context-sync"] });
      qc.invalidateQueries({ queryKey: ["context-suggestions"] });
    },
    onError: (e: unknown) => pushToast({ text: `Sync refused: ${errorMessages(e)[0]}`, severity: "high" }),
  });
  const problem = run && (run.status === "error" || run.status === "abandoned" || health === "degraded") ? run.detail : null;

  return (
    <tr>
      <td>
        <div className="cx-name">{s.name}</div>
        <div className="cx-sub mono">{s.kind}</div>
      </td>
      <td>
        <span className={`cx-chip cx-${health}`} aria-label={HEALTH_LABEL[health]}>{HEALTH_LABEL[health]}</span>
      </td>
      <td className="mono cx-nowrap" title={run?.started_at ?? ""}>
        {run ? relTime(run.finished_at ?? run.started_at) : "never"}
        {run && <div className="cx-sub">{run.trigger}</div>}
      </td>
      <td className="mono cx-num">{run ? importedCount(run.counts) : "—"}</td>
      <td className="cx-detail" title={problem ?? ""}>{problem ?? "—"}</td>
      <td className="mono cx-nowrap" title={s.next_run_at ?? ""}>
        {s.enabled && s.next_run_at ? relTime(s.next_run_at) : "—"}
        {s.interval_minutes ? <div className="cx-sub">every {s.interval_minutes}m</div> : null}
      </td>
      <td>
        <Gate need="admin" title="Admin-only — syncing pulls from the customer system">
          <button className="ghost cx-small" disabled={sync.isPending || health === "running"} onClick={() => sync.mutate()}>
            {sync.isPending ? "Syncing…" : "Sync now"}
          </button>
        </Gate>
      </td>
    </tr>
  );
}

/* ---------------------------- suggestions ------------------------------ */

function SuggestionRow({ s, onAccepted }: { s: ScopeSuggestion; onAccepted: (r: AcceptResult) => void }) {
  const qc = useQueryClient();
  const pushToast = useStore((st) => st.pushToast);
  const [docRef, setDocRef] = useState("");
  const [open, setOpen] = useState(false);
  const done = () => {
    qc.invalidateQueries({ queryKey: ["context-suggestions"] });
    qc.invalidateQueries({ queryKey: ["context-sync"] });
    qc.invalidateQueries({ queryKey: ["scope"] });
  };
  const accept = useMutation({
    mutationFn: () => acceptSuggestion(s.id, docRef.trim() ? { auth_doc_ref: docRef.trim() } : {}),
    onSuccess: (r) => { onAccepted(r); done(); },
    onError: (e: unknown) => pushToast({ text: `Scope add refused: ${errorMessages(e)[0]}`, severity: "high" }),
  });
  const dismiss = useMutation({
    mutationFn: () => dismissSuggestion(s.id),
    onSuccess: () => { pushToast({ text: `Dismissed ${s.value}` }); done(); },
    onError: (e: unknown) => pushToast({ text: `Dismiss refused: ${errorMessages(e)[0]}`, severity: "high" }),
  });

  return (
    <tr>
      <td><span className="cx-kind">{KIND_LABEL[s.kind] ?? s.kind}</span></td>
      <td className="mono cx-value">{s.value}</td>
      <td>
        <div>{s.integration_name ?? s.source}</div>
        <div className="cx-sub" title={JSON.stringify(s.evidence)}>{evidenceLine(s.evidence) || s.source}</div>
      </td>
      <td className="mono cx-nowrap" title={s.first_seen}>{relTime(s.last_seen)}</td>
      <td>
        <Gate need="admin" title="Admin-only — changing scope is gated">
          {open ? (
            <div className="cx-accept">
              <input
                aria-label={`Authorization reference for ${s.value}`}
                placeholder="Authorization doc ref (optional)"
                value={docRef}
                onChange={(e) => setDocRef(e.target.value)}
              />
              <button className="primary cx-small" disabled={accept.isPending} onClick={() => accept.mutate()}>
                {accept.isPending ? "Adding…" : "Add to scope"}
              </button>
              <button className="ghost cx-small" onClick={() => setOpen(false)}>Cancel</button>
            </div>
          ) : (
            <>
              <button className="primary cx-small" aria-label={`Accept ${s.value}`} onClick={() => setOpen(true)}>Accept</button>
              <button className="ghost cx-small" aria-label={`Dismiss ${s.value}`} disabled={dismiss.isPending} onClick={() => dismiss.mutate()}>
                Dismiss
              </button>
            </>
          )}
        </Gate>
      </td>
    </tr>
  );
}

function SuggestionsPanel() {
  const q = useQuery({
    queryKey: ["context-suggestions", "pending"],
    queryFn: () => listSuggestions("pending"),
    refetchInterval: 20_000,
  });
  const [accepted, setAccepted] = useState<AcceptResult | null>(null);
  const items = q.data ?? [];

  return (
    <section className="panel cx-suggest">
      <div className="panel-h">
        <h2>Scope suggestions</h2>
        <span className="panel-sub">{items.length} pending · never added automatically</span>
      </div>
      <p className="cx-note">
        Sources report the public IPs and domains they can see. Accepting one adds it to scope
        the same way a manual add does — it must still pass <strong>proof of control</strong> before
        anything is scanned.
      </p>
      {accepted && (
        <div className="cx-accepted" role="status">
          Added <span className="mono">{accepted.scope_entry.value}</span> to scope.{" "}
          <Link to="/scope">Verify ownership in Scope</Link> to enable scanning.
        </div>
      )}
      {q.isLoading ? (
        <div className="cx-sub cx-pad">Loading suggestions…</div>
      ) : items.length === 0 ? (
        <EmptyState title="No pending suggestions." hint="Cloud sources propose public IPs and DNS zones here after a sync." />
      ) : (
        <table className="table cx-table">
          <thead>
            <tr><th>Type</th><th>Value</th><th>Seen by</th><th>Last seen</th><th aria-label="actions" /></tr>
          </thead>
          <tbody>
            {items.map((s) => <SuggestionRow key={s.id} s={s} onAccepted={setAccepted} />)}
          </tbody>
        </table>
      )}
    </section>
  );
}

/* -------------------------------- page --------------------------------- */

export default function ContextSyncPage() {
  const q = useQuery({
    queryKey: ["context-sync"],
    queryFn: getSyncStatus,
    refetchInterval: 15_000,
  });
  const rows = q.data ?? [];
  const bad = rows.filter((r) => ["error", "degraded"].includes(syncHealth(r))).length;
  const imported = rows.reduce((n, r) => n + importedCount(r.last_run?.counts), 0);
  const pending = rows.reduce((n, r) => n + r.pending_suggestions, 0);

  return (
    <div className="page cx-page">
      <div className="page-header">
        <div>
          <h1>Context sync</h1>
          <div className="subtitle">
            Read-only connectors that pull cloud inventory, EDR and CMDB context into the graph.
            They never write to the customer system and never change scope: what they find on the
            internet edge arrives below as a suggestion for a human to accept.
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Sources" value={rows.length} accent="#9fc2d8" />
        <StatTile label="Needs attention" value={bad} accent="#e3b265" />
        <StatTile label="Items last run" value={imported} accent="#8fbf8a" />
        <StatTile label="Pending suggestions" value={pending} accent="#b9a3d6" />
      </div>

      <section className="panel">
        <div className="panel-h">
          <h2>Sources</h2>
          <span className="panel-sub">scheduled pulls · read-only</span>
        </div>
        {q.isLoading ? (
          <div className="cx-sub cx-pad">Loading sources…</div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No source integrations."
            hint={<>Connect AWS, GCP, Azure, CrowdStrike or a CMDB on the <Link to="/integrations">Integrations</Link> page.</>}
          />
        ) : (
          <table className="table cx-table">
            <thead>
              <tr>
                <th>Source</th><th>Status</th><th>Last sync</th>
                <th className="cx-num">Items</th><th>Errors</th><th>Next run</th><th aria-label="actions" />
              </tr>
            </thead>
            <tbody>{rows.map((s) => <SourceRow key={s.integration_id} s={s} />)}</tbody>
          </table>
        )}
      </section>

      <SuggestionsPanel />
    </div>
  );
}
