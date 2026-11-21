/**
 * Suppression rules (schema 019). A rule matches at ingest by rule id (glob),
 * asset pattern (glob) and/or tag, AND-ed. Matching findings are stored but
 * hidden from the default Findings view; the count stays visible there.
 * Every create / toggle / delete is audited server-side.
 */

import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import { useSuppressionMutations, useSuppressions } from "../hooks/useFindings";
import type { Suppression, SuppressionInput } from "../api/types";
import "../styles/lifecycle.css";

const EMPTY = { rule_id: "", asset_pattern: "", tag: "", reason: "", expires: "" };

export function suppressionInput(v: typeof EMPTY): SuppressionInput | null {
  const t = (s: string) => s.trim() || null;
  if (!(t(v.rule_id) || t(v.asset_pattern) || t(v.tag))) return null;
  if (v.reason.trim().length < 3) return null;
  return {
    rule_id: t(v.rule_id),
    asset_pattern: t(v.asset_pattern),
    tag: t(v.tag),
    reason: v.reason.trim(),
    expires_at: v.expires ? `${v.expires}T23:59:59Z` : null,
  };
}

function Match({ s }: { s: Suppression }) {
  return (
    <span className="supp-match">
      {s.rule_id && <code>rule {s.rule_id}</code>}
      {s.rule_source && <code>source {s.rule_source}</code>}
      {s.asset_pattern && <code>asset {s.asset_pattern}</code>}
      {s.tag && <code>tag {s.tag}</code>}
    </span>
  );
}

export default function SuppressionsPage() {
  const q = useSuppressions();
  const m = useSuppressionMutations();
  const [form, setForm] = useState(EMPTY);
  const body = suppressionInput(form);
  const rows = q.data ?? [];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!body) return;
    m.create.mutate(body, { onSuccess: () => setForm(EMPTY) });
  };
  const set = (k: keyof typeof EMPTY) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Suppressions</h1>
          <div className="subtitle">
            Known noise, suppressed at ingest. Suppressed findings are kept and counted, never
            deleted — see them under <Link to="/findings">Findings → Suppressed</Link>.
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-h"><h2>New rule</h2></div>
        <Gate need="triage">
          <form className="supp-form" onSubmit={submit} aria-label="new suppression">
            <div className="field">
              <label htmlFor="supp-rule">Rule id (glob)</label>
              <input id="supp-rule" value={form.rule_id} onChange={set("rule_id")} placeholder="sast:weak-*" />
            </div>
            <div className="field">
              <label htmlFor="supp-asset">Asset pattern (glob)</label>
              <input id="supp-asset" value={form.asset_pattern} onChange={set("asset_pattern")}
                     placeholder="*.staging.example.com" />
            </div>
            <div className="field">
              <label htmlFor="supp-tag">Tag</label>
              <input id="supp-tag" value={form.tag} onChange={set("tag")} placeholder="lab" />
            </div>
            <div className="field">
              <label htmlFor="supp-exp">Expires (optional)</label>
              <input id="supp-exp" type="date" value={form.expires} onChange={set("expires")} />
            </div>
            <div className="field wide">
              <label htmlFor="supp-reason">Reason</label>
              <input id="supp-reason" value={form.reason} onChange={set("reason")}
                     placeholder="Why this is noise — recorded in the audit log" />
            </div>
            <div className="field" style={{ justifyContent: "flex-end" }}>
              <button className="primary" type="submit" disabled={!body || m.create.isPending}>
                {m.create.isPending ? "Saving…" : "Add suppression"}
              </button>
            </div>
          </form>
        </Gate>
        {!body && (form.reason || form.rule_id || form.asset_pattern || form.tag) && (
          <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 8 }}>
            Needs at least one matcher (rule, asset or tag) and a reason.
          </div>
        )}
        {m.create.isError && (
          <div style={{ color: "var(--bad)", fontSize: 12, marginTop: 8 }} role="alert">
            Could not create the suppression.
          </div>
        )}
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        {rows.length === 0 && !q.isLoading ? (
          <EmptyState title="No suppression rules." hint="Mark a finding as a false positive with “suppress” to create one." />
        ) : (
          <table className="table" aria-label="suppression rules">
            <thead>
              <tr>
                <th>Match</th>
                <th>Reason</th>
                <th>Author</th>
                <th>Expires</th>
                <th>Hidden now</th>
                <th>Matched</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className={s.active ? "" : "supp-inactive"}>
                  <td><Match s={s} /></td>
                  <td style={{ maxWidth: 320 }}>{s.reason}</td>
                  <td className="mono">{s.author}</td>
                  <td className="mono">{s.expires_at ? s.expires_at.slice(0, 10) : "never"}</td>
                  <td className="mono tabular">{s.suppressed_now}</td>
                  <td className="mono tabular">{s.match_count}</td>
                  <td>
                    <Gate need="triage">
                      <span style={{ display: "inline-flex", gap: 6 }}>
                        <button onClick={() => m.toggle.mutate(s)} disabled={m.toggle.isPending}>
                          {s.enabled ? "Disable" : "Enable"}
                        </button>
                        <button className="danger" onClick={() => m.remove.mutate(s.id)} disabled={m.remove.isPending}>
                          Delete
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
    </div>
  );
}
