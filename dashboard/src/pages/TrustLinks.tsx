/**
 * Reports → Share trust page. Admins mint signed, expiring, revocable links
 * to an aggregate-only posture page for insurers and customers. The token is
 * shown ONCE, when the link is created; only its hash is stored.
 */
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import { useStore } from "../state/store";
import {
  TRUST_SECTIONS,
  createTrustLink,
  listTrustLinks,
  revokeTrustLink,
  type TrustLink,
  type TrustLinkCreated,
  type TrustSection,
} from "../api/growth";
import "../styles/growth.css";

export function trustUrl(path: string): string {
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return `${origin}${path}`;
}

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "never");

function StatusChip({ s }: { s: TrustLink["status"] }) {
  return <span className={`gr-chip gr-${s}`}>{s}</span>;
}

export default function TrustLinksPage() {
  const qc = useQueryClient();
  const toast = useStore((s) => s.pushToast);
  const q = useQuery({ queryKey: ["trust-links"], queryFn: listTrustLinks });
  const [label, setLabel] = useState("");
  const [sections, setSections] = useState<TrustSection[]>(["grade", "verified_fixes", "sla"]);
  const [days, setDays] = useState(30);
  const [period, setPeriod] = useState(30);
  const [password, setPassword] = useState("");
  const [created, setCreated] = useState<TrustLinkCreated | null>(null);

  const create = useMutation({
    mutationFn: createTrustLink,
    onSuccess: (r) => {
      setCreated(r);
      setLabel("");
      setPassword("");
      void qc.invalidateQueries({ queryKey: ["trust-links"] });
    },
  });
  const revoke = useMutation({
    mutationFn: revokeTrustLink,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["trust-links"] }),
  });

  const toggle = (k: TrustSection) =>
    setSections((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));
  const valid = label.trim().length > 0 && sections.length > 0 && (!password || password.length >= 8);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    create.mutate({
      label: label.trim(),
      sections,
      expires_in_days: days,
      period_days: period,
      ...(password ? { password } : {}),
    });
  };

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast({ text: "Link copied", severity: "info" });
    } catch {
      toast({ text: "Could not copy. Select the link and copy it manually.", severity: "medium" });
    }
  }

  const rows = q.data ?? [];
  return (
    <div className="page gr-page">
      <div className="page-header">
        <div>
          <h1>Share trust page</h1>
          <div className="subtitle">
            A link for insurers and customers that shows chosen aggregates only: no findings, hosts or
            addresses. Every view is audited. Back to <Link to="/reports">Reports</Link>.
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-h"><h2>New link</h2></div>
        <Gate need="admin">
          <form className="gr-form" onSubmit={submit} aria-label="new trust link">
            <div className="field wide">
              <label htmlFor="tl-label">Label (private, for your records)</label>
              <input id="tl-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Cyber insurance renewal 2027" maxLength={120} />
            </div>
            <fieldset className="field wide gr-sections">
              <legend>Sections to include</legend>
              {TRUST_SECTIONS.map((s) => (
                <label key={s.key} className="gr-check">
                  <input type="checkbox" checked={sections.includes(s.key)} onChange={() => toggle(s.key)} />
                  <span><b>{s.label}</b><em>{s.hint}</em></span>
                </label>
              ))}
            </fieldset>
            <div className="field">
              <label htmlFor="tl-days">Expires after (days)</label>
              <input id="tl-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Math.min(365, Math.max(1, Number(e.target.value) || 1)))} />
            </div>
            <div className="field">
              <label htmlFor="tl-period">Reporting period (days)</label>
              <select id="tl-period" value={period} onChange={(e) => setPeriod(Number(e.target.value))}>
                {[7, 30, 90, 180, 365].map((d) => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
            <div className="field wide">
              <label htmlFor="tl-pw">Password (optional, 8+ characters)</label>
              <input id="tl-pw" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="field" style={{ justifyContent: "flex-end" }}>
              <button className="primary" type="submit" disabled={!valid || create.isPending}>
                {create.isPending ? "Creating…" : "Create link"}
              </button>
            </div>
          </form>
        </Gate>
        {create.isError && <div className="gr-err" role="alert">Could not create the link.</div>}
      </div>

      {created && (
        <div className="panel gr-created" role="status" aria-label="new link">
          <div className="panel-h"><h2>Copy this link now</h2></div>
          <p className="gr-note">It is shown once. Paddock keeps only a hash, so it cannot be shown again. If you lose it, revoke it and create a new one.</p>
          <div className="gr-url">
            <code data-testid="trust-url">{trustUrl(created.path)}</code>
            <button className="primary" onClick={() => copy(trustUrl(created.path))}>Copy</button>
            <button className="ghost" onClick={() => setCreated(null)}>Done</button>
          </div>
        </div>
      )}

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        {rows.length === 0 && !q.isLoading ? (
          <EmptyState title="No trust links yet." hint="Create one above to share your posture with an insurer or customer." />
        ) : (
          <table className="table" aria-label="trust links">
            <thead>
              <tr><th>Label</th><th>Sections</th><th>Status</th><th>Expires</th><th>Views</th><th>Last viewed</th><th /></tr>
            </thead>
            <tbody>
              {rows.map((l) => (
                <tr key={l.id} className={l.status === "active" ? "" : "gr-dim"}>
                  <td>{l.label}{l.password_protected && <span className="gr-chip gr-lock" title="Password protected">locked</span>}</td>
                  <td className="gr-secs">{l.sections.map((s) => <code key={s}>{s.replace("_", " ")}</code>)}</td>
                  <td><StatusChip s={l.status} /></td>
                  <td className="mono">{fmt(l.expires_at)}</td>
                  <td className="mono tabular">{l.view_count}</td>
                  <td className="mono">{fmt(l.last_viewed_at)}</td>
                  <td>
                    <Gate need="admin">
                      {l.status === "active" && (
                        <button
                          className="danger"
                          disabled={revoke.isPending}
                          onClick={() => { if (window.confirm(`Revoke "${l.label}"? The link stops working immediately.`)) revoke.mutate(l.id); }}
                        >
                          Revoke
                        </button>
                      )}
                    </Gate>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
