import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  createOwner,
  deleteOwner,
  getTicketSummary,
  listOwners,
  listSlaPolicies,
  listTickets,
  patchOwner,
  patchSlaPolicy,
  patchTicket,
  type TicketFilter,
} from "../api/tickets";
import type { AssetKind, Owner, Severity, Ticket } from "../api/types";
import { SEV_COLOR } from "../lib/color";
import { useStore } from "../state/store";

/* ------------------------------ constants ------------------------------ */

const SEV_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["open", "ack", "in_progress", "resolved", "closed", "wontfix"] as const;
const TERMINAL = new Set<string>(["resolved", "closed", "wontfix"]);
const OWNER_KINDS: AssetKind[] = ["subdomain", "domain", "endpoint", "ipv4", "ipv6", "service", "repository", "cloud_resource"];

/* ------------------------------- helpers ------------------------------- */

function relPast(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function fmtDur(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m`;
  const h = s / 3600;
  if (h < 48) return `${Math.round(h)}h`;
  return `${Math.round(h / 24)}d`;
}

type SlaTone = "ok" | "warn" | "breached" | "none";

/**
 * SLA countdown from sla_due vs now: green with >50% of the window left, amber
 * under 50%, a red BREACHED pill once past due (or when the server flags it).
 * Closed/resolved tickets show nothing.
 */
function slaState(t: Ticket): { label: string; tone: SlaTone } {
  if (TERMINAL.has(t.status)) return { label: "—", tone: "none" };
  const due = Date.parse(t.sla_due);
  if (Number.isNaN(due)) return { label: "—", tone: "none" };
  const left = due - Date.now();
  if (left <= 0 || t.breached) return { label: "BREACHED", tone: "breached" };
  const windowMs = (t.sla_hours ?? 0) * 3_600_000;
  const frac = windowMs > 0 ? left / windowMs : 1;
  return { label: `${fmtDur(left)} left`, tone: frac > 0.5 ? "ok" : "warn" };
}

/* ------------------------------ sub-views ------------------------------ */

function HeaderTiles() {
  const q = useQuery({ queryKey: ["ticket-summary"], queryFn: getTicketSummary, staleTime: 20_000 });
  const s = q.data ?? {};
  const teams = s.by_team ? Object.keys(s.by_team).length : 0;
  return (
    <div className="stat-row">
      <StatTile label="Open" value={s.open ?? 0} accent={SEV_COLOR.high} />
      <StatTile label="Breached" value={s.breached ?? 0} accent={SEV_COLOR.critical} />
      <StatTile label="Resolved (7d)" value={s.resolved_7d ?? 0} accent="#58d68d" />
      <StatTile label="Teams" value={teams} accent="#4ea3ff" />
    </div>
  );
}

function SlaCell({ ticket }: { ticket: Ticket }) {
  const { label, tone } = slaState(ticket);
  if (tone === "breached") return <span className="sla-pill mono">BREACHED</span>;
  if (tone === "none") return <span className="sla-cell none mono">—</span>;
  return <span className={`sla-cell ${tone} mono`}>{label}</span>;
}

function TicketQueue() {
  const qc = useQueryClient();
  const openDrawer = useStore((s) => s.openDrawer);
  const summary = useQuery({ queryKey: ["ticket-summary"], queryFn: getTicketSummary, staleTime: 20_000 });

  const [status, setStatus] = useState("");
  const [team, setTeam] = useState("");
  const [sev, setSev] = useState<Severity | "">("");
  const [breachedOnly, setBreachedOnly] = useState(false);

  const filter = useMemo<TicketFilter>(
    () => ({
      status: status || undefined,
      team: team || undefined,
      severity: sev || undefined,
      breached: breachedOnly || undefined,
      limit: 200,
    }),
    [status, team, sev, breachedOnly],
  );

  const q = useQuery({
    queryKey: ["tickets", filter],
    queryFn: () => listTickets(filter),
    staleTime: 10_000,
  });

  const rows = q.data ?? [];
  const teams = useMemo(() => {
    const set = new Set<string>(Object.keys(summary.data?.by_team ?? {}));
    for (const t of rows) if (t.owner_team) set.add(t.owner_team);
    return [...set].sort();
  }, [summary.data, rows]);

  const patch = useMutation({
    mutationFn: (p: { id: string; status: string }) => patchTicket(p.id, { status: p.status }),
    onMutate: async (p) => {
      await qc.cancelQueries({ queryKey: ["tickets"] });
      qc.setQueriesData<Ticket[]>({ queryKey: ["tickets"] }, (old) =>
        (old ?? []).map((t) =>
          t.id === p.id
            ? { ...t, status: p.status, closed_at: TERMINAL.has(p.status) ? new Date().toISOString() : null }
            : t,
        ),
      );
    },
    onError: () => qc.invalidateQueries({ queryKey: ["tickets"] }),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["tickets"] });
      qc.invalidateQueries({ queryKey: ["ticket-summary"] });
    },
  });

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Queue</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{rows.length} tickets</span>
      </div>

      <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label>Status</label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <label>Team</label>
        <select value={team} onChange={(e) => setTeam(e.target.value)}>
          <option value="">Any</option>
          {teams.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <label>Severity</label>
        <select value={sev} onChange={(e) => setSev(e.target.value as Severity | "")}>
          <option value="">Any</option>
          {SEV_LIST.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="sep" />
        <label className={`checkchip ${breachedOnly ? "on" : ""}`} style={breachedOnly ? { borderColor: SEV_COLOR.critical, color: SEV_COLOR.critical } : undefined}>
          <input type="checkbox" checked={breachedOnly} onChange={(e) => setBreachedOnly(e.target.checked)} />
          Breached only
        </label>
      </div>

      <div className="ticket-list">
        <div className="ticket-row ticket-head">
          <div>Sev</div>
          <div>Title</div>
          <div>Team</div>
          <div>SLA</div>
          <div>Status</div>
          <div>System</div>
          <div>Opened</div>
        </div>
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading tickets…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load tickets.</div>}
        {!q.isLoading && rows.length === 0 && <EmptyState title="No tickets match these filters." />}
        {rows.map((t) => (
          <div key={t.id} className={`ticket-row${TERMINAL.has(t.status) ? " done" : ""}`}>
            <div><SeverityChip severity={t.severity} compact /></div>
            <button
              type="button"
              className="ticket-title"
              title={t.title}
              onClick={() => openDrawer({ kind: "finding", id: t.finding_id })}
            >
              {t.title}
            </button>
            <div className="ticket-team mono">{t.owner_team ?? <span className="muted">unassigned</span>}</div>
            <div><SlaCell ticket={t} /></div>
            <div>
              <Gate need="triage">
                <select
                  className="ticket-status-sel"
                  value={t.status}
                  disabled={patch.isPending}
                  onChange={(e) => patch.mutate({ id: t.id, status: e.target.value })}
                >
                  {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </Gate>
            </div>
            <div>
              {t.external_url ? (
                <a className="ticket-system mono" href={t.external_url} target="_blank" rel="noopener noreferrer" title={t.external_url}>
                  {t.system}
                </a>
              ) : (
                <span className="ticket-system mono" title={t.system}>{t.system}</span>
              )}
            </div>
            <div className="ticket-opened mono" title={t.opened_at}>{relPast(t.opened_at)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ownerMatchSummary(o: Owner): string {
  const parts: string[] = [];
  if (o.match.kinds?.length) parts.push(`${o.match.kinds.length} kind${o.match.kinds.length === 1 ? "" : "s"}`);
  if (o.match.value_regex) parts.push(`/${o.match.value_regex}/`);
  if (o.match.metadata_env) parts.push(`env=${o.match.metadata_env}`);
  if (o.match.tag) parts.push(`#${o.match.tag}`);
  if (o.match.cidr) parts.push(o.match.cidr);
  return parts.length ? parts.join(" · ") : "any asset";
}

function OwnershipRules() {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const q = useQuery({ queryKey: ["owners"], queryFn: listOwners, staleTime: 15_000 });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["owners"] });

  const [name, setName] = useState("");
  const [team, setTeam] = useState("");
  const [contact, setContact] = useState("");
  const [kinds, setKinds] = useState<AssetKind[]>([]);
  const [valueRegex, setValueRegex] = useState("");
  const [env, setEnv] = useState("");
  const [tag, setTag] = useState("");
  const [priority, setPriority] = useState(100);

  const create = useMutation({
    mutationFn: () =>
      createOwner({
        name: name.trim(),
        team: team.trim(),
        contact: contact.trim() || null,
        match: {
          kinds: kinds.length ? kinds : undefined,
          value_regex: valueRegex.trim() || undefined,
          metadata_env: env.trim() || undefined,
          tag: tag.trim() || undefined,
        },
        priority,
        enabled: true,
      }),
    onSuccess: () => {
      pushToast({ text: "Ownership rule created." });
      setName(""); setTeam(""); setContact(""); setKinds([]); setValueRegex(""); setEnv(""); setTag(""); setPriority(100);
      invalidate();
    },
    onError: () => pushToast({ text: "Could not create rule.", severity: "high" }),
  });

  const toggle = useMutation({
    mutationFn: (p: { id: string; enabled: boolean }) => patchOwner(p.id, { enabled: p.enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: (id: string) => deleteOwner(id), onSuccess: invalidate });

  const toggleKind = (k: AssetKind) =>
    setKinds((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));

  const canCreate = name.trim().length > 0 && team.trim().length > 0;
  const owners = [...(q.data ?? [])].sort((a, b) => a.priority - b.priority);

  return (
    <div className="panel alert-rules">
      <div className="panel-h">
        <h2>Ownership rules</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{q.data?.length ?? 0} rules</span>
      </div>

      <Gate need="admin">
      <div className="rule-list">
        {owners.length === 0 && !q.isLoading && (
          <div className="muted" style={{ fontSize: 12, padding: "4px 0" }}>No ownership rules yet.</div>
        )}
        {owners.map((o) => (
          <div key={o.id} className={`rule-row${o.enabled ? "" : " disabled"}`}>
            <label className="switch" title={o.enabled ? "enabled" : "disabled"}>
              <input type="checkbox" checked={o.enabled} onChange={(e) => toggle.mutate({ id: o.id, enabled: e.target.checked })} />
              <span className="track" />
            </label>
            <div className="rule-main">
              <div className="rule-name">
                {o.name}
                <span className="rule-channel mono">{o.team}</span>
                <span className="owner-prio mono" title="priority">p{o.priority}</span>
              </div>
              <div className="rule-match mono">{ownerMatchSummary(o)}</div>
            </div>
            <button className="ghost danger" onClick={() => remove.mutate(o.id)} title="delete rule">✕</button>
          </div>
        ))}
      </div>

      <form className="rule-form" onSubmit={(e) => { e.preventDefault(); if (canCreate) create.mutate(); }}>
        <div className="rule-form-head">New rule</div>
        <div className="rule-form-grid">
          <div className="field">
            <label>Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. payments subdomains" />
          </div>
          <div className="field">
            <label>Team</label>
            <input value={team} onChange={(e) => setTeam(e.target.value)} placeholder="e.g. payments-secops" />
          </div>
        </div>
        <div className="field">
          <label>Contact (email or webhook URL)</label>
          <input value={contact} onChange={(e) => setContact(e.target.value)} placeholder="security@… or https://hooks…" />
        </div>
        <div className="field">
          <label>Match kinds (any if none)</label>
          <div className="rule-type-chips">
            {OWNER_KINDS.map((k) => {
              const on = kinds.includes(k);
              return (
                <label key={k} className={`checkchip ${on ? "on" : ""}`}>
                  <input type="checkbox" checked={on} onChange={() => toggleKind(k)} />
                  {k}
                </label>
              );
            })}
          </div>
        </div>
        <div className="rule-form-grid">
          <div className="field">
            <label>Value regex</label>
            <input className="mono" value={valueRegex} onChange={(e) => setValueRegex(e.target.value)} placeholder="^api\\." />
          </div>
          <div className="field">
            <label>Priority</label>
            <input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value) || 0)} />
          </div>
          <div className="field">
            <label>Env</label>
            <input value={env} onChange={(e) => setEnv(e.target.value)} placeholder="prod" />
          </div>
          <div className="field">
            <label>Tag</label>
            <input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="crown-jewel" />
          </div>
        </div>
        <div className="rule-form-foot">
          <button type="submit" className="primary" disabled={!canCreate || create.isPending}>
            {create.isPending ? "Creating…" : "Create rule"}
          </button>
        </div>
      </form>
      </Gate>
    </div>
  );
}

function SlaEditor() {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const q = useQuery({ queryKey: ["sla-policies"], queryFn: listSlaPolicies, staleTime: 30_000 });
  const [draft, setDraft] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: (p: { severity: Severity; hours: number }) => patchSlaPolicy(p.severity, p.hours),
    onSuccess: () => {
      pushToast({ text: "SLA policy updated." });
      qc.invalidateQueries({ queryKey: ["sla-policies"] });
    },
    onError: () => pushToast({ text: "Could not update SLA policy.", severity: "high" }),
  });

  // Merge server policies onto the severity ladder so every row is editable.
  const bySev = new Map((q.data ?? []).map((p) => [p.severity, p.hours]));

  return (
    <div className="panel sla-editor">
      <div className="panel-h">
        <h2>SLA policies</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>hours to breach</span>
      </div>
      <Gate need="admin">
      <div className="sla-grid">
        {SEV_LIST.map((s) => {
          const current = bySev.get(s);
          const val = draft[s] ?? (current != null ? String(current) : "");
          return (
            <div key={s} className="sla-row">
              <SeverityChip severity={s} compact />
              <input
                type="number"
                className="mono"
                value={val}
                placeholder="—"
                onChange={(e) => setDraft((d) => ({ ...d, [s]: e.target.value }))}
              />
              <button
                className="ghost"
                disabled={save.isPending || val === "" || Number(val) === current}
                onClick={() => save.mutate({ severity: s, hours: Number(val) })}
              >
                save
              </button>
            </div>
          );
        })}
      </div>
      </Gate>
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function TicketsPage() {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Tickets</h1>
          <div className="subtitle">Owned, SLA-bound findings — routed by ownership rules, swept for breaches.</div>
        </div>
      </div>

      <HeaderTiles />

      <div className="tickets-grid">
        <TicketQueue />
        <div className="tickets-side">
          <OwnershipRules />
          <SlaEditor />
        </div>
      </div>
    </div>
  );
}
