/**
 * MSP console: every customer you hold a grant on, with health, search, sort
 * and paging. "Open" exchanges your MSP session for a short-lived token scoped
 * to that ONE customer (docs/MSP.md) and drops you on its Overview; the topbar
 * then shows which customer you are in and a one-click way back.
 *
 * Provisioning / suspension / usage export need an MSP admin.
 */

import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { downloadUsageCsv, type Customer, type CustomerSort, type CreatedCustomer } from "../api/msp";
import { ApiError } from "../api/client";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import StatTile from "../components/StatTile";
import { useCustomers, useMspMutations, useMspSummary } from "../hooks/useMsp";
import { useMsp } from "../state/msp";
import "../styles/msp.css";

const PAGE = 25;

const SORTS: { value: CustomerSort; label: string; order: "asc" | "desc" }[] = [
  { value: "name", label: "Name", order: "asc" },
  { value: "exposure", label: "Exposure (worst first)", order: "desc" },
  { value: "criticals", label: "Open criticals", order: "desc" },
  { value: "sla_breaches", label: "SLA breaches", order: "desc" },
  { value: "verified_fixes", label: "Verified fixes", order: "desc" },
  { value: "last_scan", label: "Last scan (oldest first)", order: "asc" },
  { value: "assets", label: "Monitored assets", order: "desc" },
  { value: "created", label: "Newest", order: "desc" },
];

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { detail?: unknown } | undefined;
    if (b && typeof b.detail === "string") return b.detail;
    return `${e.status} ${e.message}`;
  }
  return e instanceof Error ? e.message : "request failed";
}

function Licence({ c }: { c: Customer }) {
  const h = c.health;
  if (!h) return <span className="mono">—</span>;
  const seats = h.seats_limit != null ? `${h.seats_used}/${h.seats_limit}` : `${h.seats_used}`;
  const assets = h.assets_limit != null ? `${h.monitored_assets}/${h.assets_limit}` : `${h.monitored_assets}`;
  const over =
    (h.seats_limit != null && h.seats_used > h.seats_limit) ||
    (h.assets_limit != null && h.monitored_assets > h.assets_limit);
  return (
    <span className={`mono${over ? " bad" : ""}`} title="seats used/limit · monitored assets used/limit">
      {seats} · {assets}
    </span>
  );
}

export default function MspConsolePage() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const enter = useMsp((s) => s.enter);
  const acting = useMsp((s) => s.acting);
  const m = useMspMutations();
  const summary = useMspSummary();

  const [search, setSearch] = useState("");
  const [sortIdx, setSortIdx] = useState(0);
  const [offset, setOffset] = useState(0);
  const sort = SORTS[sortIdx];
  const q = useCustomers({ q: search.trim() || undefined, sort: sort.value, order: sort.order, limit: PAGE, offset });
  const page = q.data;
  const items = page?.items ?? [];
  const total = page?.total ?? 0;

  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedCustomer | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const open = (c: Customer) => {
    setErr(null);
    m.switchTo.mutate(c.id, {
      onSuccess: (sw) => {
        enter(sw);
        qc.clear(); // nothing of the MSP view may leak into the customer's
        nav("/");
      },
      onError: (e) => setErr(`Could not open ${c.name}: ${errText(e)}`),
    });
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    m.create.mutate(
      { slug: slug.trim().toLowerCase(), name: name.trim() },
      {
        onSuccess: (c) => {
          setCreated(c);
          setSlug("");
          setName("");
        },
        onError: (e2) => setErr(errText(e2)),
      },
    );
  };
  const slugOk = /^[a-z0-9][a-z0-9-]{1,62}$/.test(slug.trim().toLowerCase());

  const s = summary.data;
  if (acting) {
    return (
      <div className="page msp-page">
        <EmptyState
          title={`You are inside ${acting.customer.name}.`}
          hint="Use “Back to MSP” in the top bar to return to the customer list."
        />
      </div>
    );
  }
  return (
    <div className="page msp-page">
      <div className="page-header">
        <div>
          <h1>Customers</h1>
          <div className="subtitle">
            Every customer you hold an access grant on. Opening one puts you inside it with the role
            of your grant; everything you do there is recorded in both audit logs.
          </div>
        </div>
        <Gate need="admin">
          <button onClick={() => downloadUsageCsv().catch((e) => setErr(errText(e)))}>Export usage CSV</button>
        </Gate>
      </div>

      <div className="stat-row">
        <StatTile label="Customers" value={s?.customers ?? "—"} />
        <StatTile label="Open criticals" value={s?.open_criticals ?? "—"} accent="var(--sev-crit)" />
        <StatTile label="SLA breaches" value={s?.sla_breaches ?? "—"} accent="var(--sev-high)" />
        <StatTile label="Verified fixes (30d)" value={s?.verified_fixes ?? "—"} accent="var(--ok)" />
        <StatTile label="Grade D or F" value={s?.at_risk ?? "—"} accent="var(--warn)" />
      </div>

      <Gate need="admin">
        <div className="panel">
          <div className="panel-h"><h2>New customer</h2></div>
          <form className="msp-new" onSubmit={submit} aria-label="new customer">
            <div className="field">
              <label htmlFor="msp-name">Name</label>
              <input id="msp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Dental" />
            </div>
            <div className="field">
              <label htmlFor="msp-slug">Slug</label>
              <input id="msp-slug" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="acme-dental" />
            </div>
            <div className="field">
              <button className="primary" type="submit" disabled={!name.trim() || !slugOk || m.create.isPending}>
                {m.create.isPending ? "Creating…" : "Create customer"}
              </button>
            </div>
          </form>
          {created && (
            <div className="msp-invite" role="status">
              <strong>{created.name}</strong> created. Give its administrator this one-time invitation
              (shown once; valid for 72 hours) — they redeem it at <code>POST {created.invite.redeem_path}</code>:
              <code>{created.invite.token}</code>
            </div>
          )}
        </div>
      </Gate>

      {err && (
        <div role="alert" style={{ color: "var(--bad)", fontSize: 12, margin: "8px 0" }}>{err}</div>
      )}

      <div className="msp-toolbar">
        <input
          type="search"
          aria-label="search customers"
          placeholder="Search customers…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
        />
        <select
          aria-label="sort customers"
          value={sortIdx}
          onChange={(e) => { setSortIdx(Number(e.target.value)); setOffset(0); }}
        >
          {SORTS.map((o, i) => <option key={o.value} value={i}>{o.label}</option>)}
        </select>
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        {items.length === 0 && !q.isLoading ? (
          <EmptyState
            title={search ? "No customers match." : "No customers yet."}
            hint={search ? "Try a different search." : "Customers appear here once you hold an access grant on them."}
          />
        ) : (
          <table className="table msp-table" aria-label="customers">
            <thead>
              <tr>
                <th>Customer</th>
                <th>Grade</th>
                <th className="num">Exposure</th>
                <th className="num">Criticals</th>
                <th className="num">SLA breaches</th>
                <th className="num">Verified fixes</th>
                <th>Last scan</th>
                <th>Licence use</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((c) => {
                const h = c.health;
                const suspended = c.status === "suspended";
                return (
                  <tr key={c.id} className={suspended ? "suspended" : ""}>
                    <td>
                      <span className="name">
                        <span>{c.name}</span>
                        <small className="mono">{c.slug} · {c.role}{suspended ? " · suspended" : ""}</small>
                      </span>
                    </td>
                    <td><span className="msp-grade" data-grade={h?.grade ?? "none"}>{h?.grade ?? "–"}</span></td>
                    <td className="num mono">{h?.exposure_index ?? "—"}</td>
                    <td className={`num mono${h && h.open_criticals > 0 ? " bad" : ""}`}>{h?.open_criticals ?? "—"}</td>
                    <td className={`num mono${h && h.sla_breaches > 0 ? " bad" : ""}`}>{h?.sla_breaches ?? "—"}</td>
                    <td className="num mono">{h?.verified_fixes ?? "—"}</td>
                    <td className="mono">{ago(h?.last_scan_at)}</td>
                    <td><Licence c={c} /></td>
                    <td>
                      <span className="msp-actions">
                        <button
                          onClick={() => open(c)}
                          disabled={suspended || m.switchTo.isPending}
                          aria-label={`Open ${c.name}`}
                          title={suspended ? "Suspended customers cannot be opened" : "Act inside this customer"}
                        >
                          Open
                        </button>
                        <Gate need="admin">
                          {suspended ? (
                            <button onClick={() => m.status.mutate({ id: c.id, action: "reactivate" })}
                                    disabled={m.status.isPending} aria-label={`Reactivate ${c.name}`}>
                              Reactivate
                            </button>
                          ) : (
                            <button className="danger"
                                    onClick={() => {
                                      if (window.confirm(`Suspend ${c.name}? Its users and your access are blocked until reactivated.`))
                                        m.status.mutate({ id: c.id, action: "suspend" });
                                    }}
                                    disabled={m.status.isPending} aria-label={`Suspend ${c.name}`}>
                              Suspend
                            </button>
                          )}
                        </Gate>
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {total > PAGE && (
          <div className="msp-pager">
            <span>{offset + 1}–{Math.min(offset + PAGE, total)} of {total}</span>
            <span className="btns">
              <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
              <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>Next</button>
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
