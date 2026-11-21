/**
 * Suppliers: third-party monitoring. Each supplier domain is assessed on a
 * schedule from PUBLIC data only (DNS + certificate-transparency logs): Paddock
 * never sends a packet to the supplier. A grade, its history and the changes
 * between runs are shown; grade drops, new dangling DNS and expiring
 * certificates raise supplier.* events through Integrations.
 */
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import { ApiError } from "../api/client";
import {
  addSupplier,
  assessSupplierNow,
  deleteSupplier,
  errorDetail,
  getSupplier,
  listSuppliers,
  patchSupplier,
  type Criticality,
  type Grade,
  type Supplier,
  type SupplierDetail,
} from "../api/growth";
import "../styles/growth.css";

const CRIT: Criticality[] = ["low", "medium", "high", "critical"];
const INTERVALS = [
  { h: 24, label: "Daily" },
  { h: 168, label: "Weekly" },
  { h: 720, label: "Monthly" },
];

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "not yet");

export function GradePill({ g }: { g: Grade | null }) {
  if (!g) return <span className="gr-grade gr-none" title="Not assessed yet">–</span>;
  return <span className={`gr-grade gr-g-${g}`} aria-label={`Grade ${g}`}>{g}</span>;
}

/** The rows a human wants first: highest severity, then confirmed before possible. */
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export function rankFindings(f: SupplierDetail["findings"]) {
  return [...f].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.title.localeCompare(b.title));
}

function Trend({ d }: { d: SupplierDetail }) {
  const pts = [...d.history].reverse();
  if (pts.length < 2) return <span className="gr-muted">Not enough history yet</span>;
  const w = 220, h = 44;
  const xs = (i: number) => (i / (pts.length - 1)) * (w - 8) + 4;
  const ys = (s: number) => h - 4 - (s / 100) * (h - 8);
  const path = pts.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)} ${ys(p.score).toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} role="img" aria-label={`Score history, ${pts.length} assessments`}>
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.6" />
      {pts.map((p, i) => <circle key={p.id} cx={xs(i)} cy={ys(p.score)} r="2.2" fill="var(--accent)" />)}
    </svg>
  );
}

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["supplier", id], queryFn: () => getSupplier(id) });
  const d = q.data;
  if (!d) return <div className="panel"><div className="gr-muted" role="status">Loading…</div></div>;
  const findings = rankFindings(d.findings);
  return (
    <div className="panel gr-detail" aria-label={`${d.name} detail`}>
      <div className="panel-h">
        <h2>{d.name} <code>{d.domain}</code></h2>
        <button className="ghost" onClick={onClose}>Close</button>
      </div>
      <div className="gr-detail-top">
        <GradePill g={d.last_grade} />
        <div><b>{d.last_score ?? "–"}</b><span className="gr-muted"> / 100</span></div>
        <Trend d={d} />
      </div>
      {d.last_error && <div className="gr-err" role="alert">Last attempt failed: {d.last_error}</div>}

      <h3 className="gr-h3">Changes over time</h3>
      {d.history.length === 0 ? (
        <div className="gr-muted">No assessment has completed yet.</div>
      ) : (
        <ul className="gr-hist">
          {d.history.slice(0, 10).map((h) => (
            <li key={h.id}>
              <span className="mono">{fmt(h.created_at)}</span>
              <GradePill g={h.grade} />
              <span>
                {h.changes.first ? "First assessment" :
                  h.changes.grade_direction === "drop" ? `Dropped from ${h.changes.grade_from}` :
                  h.changes.grade_direction === "improve" ? `Improved from ${h.changes.grade_from}` : "Grade unchanged"}
                {h.changes.new.length > 0 && !h.changes.first && `, ${h.changes.new.length} new finding${h.changes.new.length > 1 ? "s" : ""}`}
                {h.changes.resolved.length > 0 && `, ${h.changes.resolved.length} resolved`}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h3 className="gr-h3">Findings ({findings.length})</h3>
      {findings.length === 0 ? (
        <div className="gr-muted">Nothing found in public data.</div>
      ) : (
        <ul className="gr-find">
          {findings.map((f) => (
            <li key={f.id}>
              <span className={`gr-sev gr-sev-${f.severity}`}>{f.severity}</span>
              <div>
                <div>{f.title}{f.confidence === "possible" && <em className="gr-possible">possible</em>}</div>
                {f.host && <code>{f.host}</code>}
                <div className="gr-muted">{f.detail}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function SuppliersPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["suppliers"], queryFn: listSuppliers, refetchInterval: 15000 });
  const [open, setOpen] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [name, setName] = useState("");
  const [crit, setCrit] = useState<Criticality>("medium");
  const [interval, setIntervalH] = useState(168);
  const [err, setErr] = useState<string | null>(null);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["suppliers"] });
    void qc.invalidateQueries({ queryKey: ["supplier"] });
  };
  const add = useMutation({
    mutationFn: addSupplier,
    onSuccess: () => { setDomain(""); setName(""); setErr(null); refresh(); },
    onError: (e) => {
      const d = errorDetail(e);
      setErr(e instanceof ApiError && e.status === 409 ? "That supplier is already monitored." : d.message ?? "Could not add the supplier.");
    },
  });
  const assess = useMutation({ mutationFn: assessSupplierNow, onSuccess: refresh });
  const toggle = useMutation({ mutationFn: (s: Supplier) => patchSupplier(s.id, { enabled: !s.enabled }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: deleteSupplier, onSuccess: () => { setOpen(null); refresh(); } });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;
    add.mutate({ domain: domain.trim(), name: name.trim() || undefined, criticality: crit, interval_hours: interval });
  };

  const rows = q.data ?? [];
  return (
    <div className="page gr-page">
      <div className="page-header">
        <div>
          <h1>Suppliers</h1>
          <div className="subtitle">
            Third-party risk from public data only (DNS and certificate logs). Nothing is ever sent to a supplier.
            Alerts go through <Link to="/integrations">Integrations</Link>: <code>supplier.grade_changed</code>,{" "}
            <code>supplier.dangling_dns</code>, <code>supplier.cert_expiring</code>.
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-h"><h2>Add supplier</h2></div>
        <Gate need="admin">
          <form className="gr-form" onSubmit={submit} aria-label="add supplier">
            <div className="field">
              <label htmlFor="sp-domain">Domain</label>
              <input id="sp-domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="vendor.com" maxLength={300} />
            </div>
            <div className="field">
              <label htmlFor="sp-name">Name (optional)</label>
              <input id="sp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Vendor Inc." maxLength={120} />
            </div>
            <div className="field">
              <label htmlFor="sp-crit">Criticality</label>
              <select id="sp-crit" value={crit} onChange={(e) => setCrit(e.target.value as Criticality)}>
                {CRIT.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="field">
              <label htmlFor="sp-int">Check</label>
              <select id="sp-int" value={interval} onChange={(e) => setIntervalH(Number(e.target.value))}>
                {INTERVALS.map((i) => <option key={i.h} value={i.h}>{i.label}</option>)}
              </select>
            </div>
            <div className="field" style={{ justifyContent: "flex-end" }}>
              <button className="primary" type="submit" disabled={!domain.trim() || add.isPending}>
                {add.isPending ? "Adding…" : "Add supplier"}
              </button>
            </div>
          </form>
        </Gate>
        {err && <div className="gr-err" role="alert">{err}</div>}
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        {rows.length === 0 && !q.isLoading ? (
          <EmptyState title="No suppliers yet." hint="Add a vendor's domain to start monitoring its public security posture." />
        ) : (
          <table className="table" aria-label="suppliers">
            <thead>
              <tr><th>Supplier</th><th>Grade</th><th>Criticality</th><th>Last assessed</th><th>Next check</th><th /></tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className={s.enabled ? "" : "gr-dim"}>
                  <td>
                    <button className="gr-link" onClick={() => setOpen(open === s.id ? null : s.id)}>{s.name}</button>
                    <div className="mono gr-muted">{s.domain}</div>
                    {s.last_error && <div className="gr-err-inline">{s.last_error}</div>}
                  </td>
                  <td><GradePill g={s.last_grade} /> {s.last_score != null && <span className="mono gr-muted">{s.last_score}</span>}</td>
                  <td><span className={`gr-crit gr-crit-${s.criticality}`}>{s.criticality}</span></td>
                  <td className="mono">{fmt(s.last_assessed_at)}</td>
                  <td className="mono">{s.enabled ? fmt(s.next_run_at) : "paused"}</td>
                  <td>
                    <Gate need="admin">
                      <span style={{ display: "inline-flex", gap: 6 }}>
                        <button onClick={() => assess.mutate(s.id)} disabled={assess.isPending}>Check now</button>
                        <button onClick={() => toggle.mutate(s)} disabled={toggle.isPending}>{s.enabled ? "Pause" : "Resume"}</button>
                        <button
                          className="danger"
                          onClick={() => { if (window.confirm(`Stop monitoring ${s.name}?`)) remove.mutate(s.id); }}
                          disabled={remove.isPending}
                        >
                          Remove
                        </button>
                      </span>
                    </Gate>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {open && <Detail id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
