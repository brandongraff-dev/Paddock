import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { createScan, listScans } from "../api/scans";
import { useStore } from "../state/store";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import type { Scan, ScanStatus } from "../api/types";

const SCAN_KINDS = [
  "passive_subdomains",
  "active_http_probe",
  "nuclei_scan",
  "naabu_portscan",
  "katana_crawl",
  "tlsx",
  "secret_scan",
];

function statusColor(s: ScanStatus): string {
  switch (s) {
    case "done": return "var(--ok)";
    case "running": return "var(--accent)";
    case "queued": return "var(--text-2)";
    case "failed": return "var(--bad)";
    case "scope_denied": return "var(--sev-high)";
  }
}

function duration(s: Scan): string {
  if (!s.started_at) return "—";
  const start = new Date(s.started_at).getTime();
  const end = s.finished_at ? new Date(s.finished_at).getTime() : Date.now();
  const diff = Math.max(0, end - start);
  if (diff < 1000) return `${diff}ms`;
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ${Math.floor((diff % 60_000) / 1000)}s`;
  return `${Math.floor(diff / 3_600_000)}h ${Math.floor((diff % 3_600_000) / 60_000)}m`;
}

function NewScanModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState(SCAN_KINDS[0]);
  const [target, setTarget] = useState("");
  const [configText, setConfigText] = useState("{}");
  const [err, setErr] = useState<string | null>(null);
  const push = useStore((s) => s.pushToast);
  const mut = useMutation({
    mutationFn: (body: { kind: string; target: string; config?: Record<string, unknown> }) =>
      createScan(body),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      push({ text: `queued scan ${r.scan_id.slice(0, 8)}…` });
      onClose();
    },
    onError: (e: Error) => setErr(e.message),
  });

  const submit = () => {
    setErr(null);
    let config: Record<string, unknown> = {};
    try {
      config = configText.trim() ? JSON.parse(configText) : {};
    } catch (e) {
      setErr(`invalid JSON: ${(e as Error).message}`);
      return;
    }
    mut.mutate({ kind, target: target.trim(), config });
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header>Queue scan</header>
        <div className="body">
          <div className="field">
            <label>Kind</label>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {SCAN_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
          <div className="field">
            <label>Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              autoFocus
            />
          </div>
          <div className="field">
            <label>Config (JSON)</label>
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              rows={6}
              style={{ fontFamily: "var(--mono)", fontSize: 11 }}
            />
          </div>
          {err && <div style={{ color: "var(--bad)", fontSize: 12 }}>{err}</div>}
          <div style={{ color: "var(--text-2)", fontSize: 11 }}>
            Scope is enforced server-side; if the target isn't authorized the scan
            returns <code className="mono">scope_denied</code>.
          </div>
        </div>
        <div className="foot">
          <button onClick={onClose}>Cancel</button>
          <button className="primary" disabled={mut.isPending || !target.trim()} onClick={submit}>
            Queue scan
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScansPage() {
  const openDrawer = useStore((s) => s.openDrawer);
  const [modal, setModal] = useState(false);
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => listScans({ limit: 200 }),
    refetchInterval: 5000,
  });

  // Also re-fetch whenever an SSE scan_* event arrives.
  const events = useStore((s) => s.events);
  const qc = useQueryClient();
  useEffect(() => {
    const last = events[0];
    if (!last) return;
    if (last.event === "scan_started" || last.event === "scan_completed" || last.event === "scan_failed") {
      qc.invalidateQueries({ queryKey: ["scans"] });
    }
  }, [events, qc]);

  const rows = scans.data ?? [];

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Scans</h1>
          <div className="subtitle">Live worker job state. Updates via /v1/events.</div>
        </div>
        <Gate need="triage">
          <button className="primary" onClick={() => setModal(true)}>+ New scan</button>
        </Gate>
      </div>

      <div className="panel" style={{ padding: 0 }}>
        {rows.length === 0 ? (
          <EmptyState title="No scans yet." hint="Queue one with “New scan”, or let the correlation service schedule them." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>kind</th>
                <th>target</th>
                <th>status</th>
                <th>queued_at</th>
                <th>duration</th>
                <th>worker</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} onClick={() => openDrawer({ kind: "scan", id: s.id })}>
                  <td className="mono">{s.kind}</td>
                  <td className="mono">{s.target}</td>
                  <td>
                    <span
                      className="chip"
                      style={{ color: statusColor(s.status), borderColor: statusColor(s.status) }}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td className="mono">{s.queued_at}</td>
                  <td className="mono">{duration(s)}</td>
                  <td className="mono">{s.worker_id ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && <NewScanModal onClose={() => setModal(false)} />}
    </div>
  );
}
