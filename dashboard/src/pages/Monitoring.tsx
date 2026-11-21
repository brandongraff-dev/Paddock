import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  createSchedule,
  deleteSchedule,
  listSchedules,
  patchSchedule,
  runScheduleNow,
} from "../api/monitoring";
import type { ScanKind, Schedule } from "../api/types";
import { useStore } from "../state/store";

const SCAN_KINDS: ScanKind[] = [
  "passive_full",
  "full_recon",
  "nuclei",
  "tls_grade",
  "takeover_scan",
  "passive_ct_watch",
];

function relFuture(iso: string | null): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.round((t - Date.now()) / 1000);
  if (s <= 0) return "due";
  if (s < 60) return `in ${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `in ${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `in ${h}h`;
  return `in ${Math.round(h / 24)}d`;
}

function statusTone(status: string | null): string {
  switch (status) {
    case "done":
    case "ok":
    case "success":
      return "ok";
    case "failed":
    case "error":
      return "bad";
    case "running":
    case "queued":
      return "run";
    default:
      return "idle";
  }
}

/** A schedule's cadence as a mono string — cron, or "every N min" from config. */
function cadence(s: Schedule): string {
  if (s.cron) return s.cron;
  const n = (s.config as { every_n_minutes?: number })?.every_n_minutes;
  return n ? `every ${n}m` : "—";
}

function ScheduleList() {
  const qc = useQueryClient();
  const pushToast = useStore((st) => st.pushToast);
  const q = useQuery({ queryKey: ["schedules"], queryFn: listSchedules, staleTime: 15_000 });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["schedules"] });

  const toggle = useMutation({
    mutationFn: (p: { id: string; enabled: boolean }) => patchSchedule(p.id, { enabled: p.enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: (id: string) => deleteSchedule(id), onSuccess: invalidate });
  const run = useMutation({
    mutationFn: (id: string) => runScheduleNow(id),
    onSuccess: () => { pushToast({ text: "Scan enqueued." }); invalidate(); },
    onError: () => pushToast({ text: "Could not enqueue scan.", severity: "high" }),
  });

  const rows = q.data ?? [];

  return (
    <div className="panel" style={{ padding: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Schedules</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{rows.length} active</span>
      </div>
      <div className="sched-list">
        <div className="sched-row sched-head">
          <div>On</div>
          <div>Name</div>
          <div>Scan</div>
          <div>Scope</div>
          <div>Cadence</div>
          <div>Next</div>
          <div>Last</div>
          <div />
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading schedules…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load schedules.</div>}
        {!q.isLoading && rows.length === 0 && (
          <EmptyState title="No schedules yet." hint="Create one below to run recurring scans." />
        )}
        {rows.map((s) => (
          <div key={s.id} className={`sched-row${s.enabled ? "" : " disabled"}`}>
            <Gate need="admin">
              <label className="switch" title={s.enabled ? "enabled" : "disabled"}>
                <input type="checkbox" checked={s.enabled} onChange={(e) => toggle.mutate({ id: s.id, enabled: e.target.checked })} />
                <span className="track" />
              </label>
            </Gate>
            <div className="sched-name">{s.name}</div>
            <div className="sched-kind mono">{s.scan_kind}</div>
            <div className="sched-scope mono" title={s.target_scope}>{s.target_scope}</div>
            <div className="sched-cron mono">{cadence(s)}</div>
            <div className="sched-next mono">{relFuture(s.next_run_at)}</div>
            <div>
              <span className={`sched-status status-${statusTone(s.last_status)}`}>{s.last_status ?? "—"}</span>
            </div>
            <Gate need="admin">
              <div className="sched-actions">
                <button className="ghost" disabled={run.isPending} onClick={() => run.mutate(s.id)} title="enqueue now">Run now</button>
                <button className="ghost danger" onClick={() => remove.mutate(s.id)} title="delete schedule">✕</button>
              </div>
            </Gate>
          </div>
        ))}
      </div>
    </div>
  );
}

function CreateSchedule() {
  const qc = useQueryClient();
  const pushToast = useStore((st) => st.pushToast);

  const [name, setName] = useState("");
  const [scanKind, setScanKind] = useState<ScanKind>("passive_full");
  const [scope, setScope] = useState("");
  const [mode, setMode] = useState<"cron" | "every">("cron");
  const [cron, setCron] = useState("0 */6 * * *");
  const [everyN, setEveryN] = useState(60);

  const create = useMutation({
    mutationFn: () =>
      createSchedule({
        name: name.trim(),
        scan_kind: scanKind,
        target_scope: scope.trim(),
        cron: mode === "cron" ? cron.trim() : null,
        config: mode === "every" ? { every_n_minutes: everyN } : {},
        enabled: true,
      }),
    onSuccess: () => {
      pushToast({ text: "Schedule created." });
      setName(""); setScope("");
      qc.invalidateQueries({ queryKey: ["schedules"] });
    },
    onError: () => pushToast({ text: "Could not create schedule.", severity: "high" }),
  });

  const canCreate =
    name.trim().length > 0 &&
    scope.trim().length > 0 &&
    (mode === "cron" ? cron.trim().length > 0 : everyN > 0);

  return (
    <form className="panel rule-form" style={{ marginTop: 0 }} onSubmit={(e) => { e.preventDefault(); if (canCreate) create.mutate(); }}>
      <div className="rule-form-head">New schedule</div>
      <Gate need="admin">
      <div className="rule-form-grid">
        <div className="field">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. nightly TLS sweep" />
        </div>
        <div className="field">
          <label>Scan kind</label>
          <select value={scanKind} onChange={(e) => setScanKind(e.target.value as ScanKind)}>
            {SCAN_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </div>
      </div>
      <div className="field">
        <label>Target scope</label>
        <input className="mono" value={scope} onChange={(e) => setScope(e.target.value)} placeholder="*.example.com" />
      </div>
      <div className="field">
        <label>Cadence</label>
        <div className="sched-cadence">
          <label className={`checkchip ${mode === "cron" ? "on" : ""}`}>
            <input type="radio" name="sched-mode" checked={mode === "cron"} onChange={() => setMode("cron")} style={{ display: "none" }} />
            cron
          </label>
          <label className={`checkchip ${mode === "every" ? "on" : ""}`}>
            <input type="radio" name="sched-mode" checked={mode === "every"} onChange={() => setMode("every")} style={{ display: "none" }} />
            every N min
          </label>
          {mode === "cron" ? (
            <input className="mono" value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 */6 * * *" style={{ minWidth: 160 }} />
          ) : (
            <input type="number" className="mono" value={everyN} onChange={(e) => setEveryN(Number(e.target.value) || 0)} style={{ width: 90 }} />
          )}
        </div>
      </div>
      <div className="rule-form-foot">
        <button type="submit" className="primary" disabled={!canCreate || create.isPending}>
          {create.isPending ? "Creating…" : "Create schedule"}
        </button>
      </div>
      </Gate>
    </form>
  );
}

export default function MonitoringPage() {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Monitoring</h1>
          <div className="subtitle">
            Recurring scans. Schedules feed the Change feed and alerts automatically.
          </div>
        </div>
      </div>

      <ScheduleList />
      <CreateSchedule />
    </div>
  );
}
