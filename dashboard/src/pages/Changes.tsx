import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import {
  ackChange,
  createAlertRule,
  deleteAlertRule,
  getChangeSummary,
  listAlertDeliveries,
  listAlertRules,
  listChanges,
  patchAlertRule,
  type ChangeFilter,
} from "../api/changes";
import type {
  AlertChannel,
  AssetKind,
  ChangeType,
  LiveEvent,
  Severity,
  SurfaceChange,
} from "../api/types";
import { SEV_COLOR, SEV_ORDER, changeTypeColor, changeTypeTag } from "../lib/color";
import { useStore } from "../state/store";

/* ------------------------------ constants ------------------------------ */

const SEV_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Types offered in the filter + alert-rule form (order = rough notability). */
const CHANGE_TYPES: ChangeType[] = [
  "secret_found",
  "exposure_increased",
  "finding_opened",
  "finding_resolved",
  "port_opened",
  "tech_detected",
  "cert_added",
  "cert_expiring",
  "subdomain_discovered",
  "endpoint_discovered",
  "ip_discovered",
  "repository_found",
  "asset_removed",
  "chain_detected",
  "attack_path_found",
];

const PAGE = 100;

/* ------------------------------- helpers ------------------------------- */

function relTime(iso: string): string {
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

/** Map a live SSE event onto a provisional feed row (changewatch severity rules). */
function liveEventToChange(e: LiveEvent): SurfaceChange | null {
  if (e.event === "finding_opened") {
    return {
      id: `live:finding:${e.finding_id}`,
      change_type: "finding_opened",
      asset_kind: null,
      asset_value: e.asset_value ?? null,
      severity: e.severity,
      summary: e.title ?? "New finding opened",
      detected_at: e.ts,
      acknowledged: false,
      asset_id: e.asset_id ?? null,
      live: true,
    };
  }
  if (e.event === "asset_added") {
    const map: Partial<Record<AssetKind, ChangeType>> = {
      subdomain: "subdomain_discovered",
      endpoint: "endpoint_discovered",
      ipv4: "ip_discovered",
      ipv6: "ip_discovered",
      port: "port_opened",
      technology: "tech_detected",
      certificate: "cert_added",
      secret_candidate: "secret_found",
      repository: "repository_found",
    };
    const ct = map[e.kind];
    if (!ct) return null;
    const severity: Severity =
      ct === "secret_found" ? "high" : ct === "port_opened" || ct === "tech_detected" ? "medium" : "low";
    return {
      id: `live:asset:${e.asset_id}`,
      change_type: ct,
      asset_kind: e.kind,
      asset_value: e.value,
      severity,
      summary: `${e.kind} ${e.value}`,
      detected_at: e.ts,
      acknowledged: false,
      asset_id: e.asset_id,
      live: true,
    };
  }
  return null;
}

/* --------------------------- velocity chart ---------------------------- */

function ChangeVelocity() {
  const q = useQuery({
    queryKey: ["changes-summary", 7],
    queryFn: () => getChangeSummary(7),
    staleTime: 30_000,
  });

  const data = useMemo(
    () =>
      (q.data?.by_day ?? []).map((d) => ({
        day: d.day.slice(5),
        info: d.info ?? 0,
        low: d.low ?? 0,
        medium: d.medium ?? 0,
        high: d.high ?? 0,
        critical: d.critical ?? 0,
      })),
    [q.data],
  );

  return (
    <div className="panel">
      <div className="panel-h">
        <h2>Change velocity</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {q.data?.total ?? 0} changes · last {data.length} days
        </span>
      </div>
      {data.length === 0 ? (
        <div className="empty" style={{ minHeight: 120 }}>
          <div className="icon">∅</div>
          No change activity in the window.
        </div>
      ) : (
        <div style={{ height: 150 }}>
          <ResponsiveContainer>
            <AreaChart data={data} margin={{ top: 6, right: 10, bottom: 0, left: 0 }}>
              <CartesianGrid stroke="rgba(236,226,208,0.07)" strokeDasharray="2 4" />
              <XAxis dataKey="day" stroke="#8a8175" tick={{ fontSize: 10 }} />
              <YAxis stroke="#8a8175" tick={{ fontSize: 10 }} width={28} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  background: "#191613",
                  border: "1px solid rgba(236,226,208,0.13)",
                  borderRadius: 6,
                  fontSize: 11,
                }}
              />
              {SEV_ORDER.map((sev) => (
                <Area
                  key={sev}
                  type="monotone"
                  stackId="sev"
                  dataKey={sev}
                  stroke={SEV_COLOR[sev]}
                  fill={SEV_COLOR[sev]}
                  fillOpacity={0.22}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

/* ------------------------------- feed ---------------------------------- */

function ChangeRow({
  change,
  onAck,
  acking,
}: {
  change: SurfaceChange;
  onAck: (id: string) => void;
  acking: boolean;
}) {
  const openDrawer = useStore((s) => s.openDrawer);
  const color = changeTypeColor(change.change_type);
  return (
    <div className={`change-row${change.acknowledged ? " acked" : ""}`}>
      <span className="change-tag mono" style={{ color, borderColor: color }}>
        {changeTypeTag(change.change_type)}
      </span>
      <SeverityChip severity={change.severity} compact />
      <div className="change-body">
        <div className="change-summary">{change.summary}</div>
        {change.asset_value &&
          (change.asset_id ? (
            <button
              type="button"
              className="change-asset mono"
              title={change.asset_value}
              onClick={() => openDrawer({ kind: "asset", id: change.asset_id! })}
            >
              {change.asset_value}
            </button>
          ) : (
            <span className="change-asset mono static" title={change.asset_value}>
              {change.asset_value}
            </span>
          ))}
      </div>
      <span className="change-time mono" title={change.detected_at}>
        {change.live && <span className="live-dot" aria-hidden />}
        {relTime(change.detected_at)}
      </span>
      <div className="change-ack">
        {change.acknowledged ? (
          <span className="acked-tag mono">ack</span>
        ) : change.live ? (
          <span className="acked-tag mono" style={{ opacity: 0.5 }}>live</span>
        ) : (
          <Gate need="triage">
            <button className="ghost" disabled={acking} onClick={() => onAck(change.id)}>
              ack
            </button>
          </Gate>
        )}
      </div>
    </div>
  );
}

function ChangeFeed() {
  const qc = useQueryClient();
  const [types, setTypes] = useState<ChangeType[]>([]);
  const [sev, setSev] = useState<Severity[]>([]);
  const [ack, setAck] = useState<"" | "unack" | "ack">("");

  const filter = useMemo<ChangeFilter>(
    () => ({
      type: types.length === 1 ? types[0] : undefined,
      severity: sev.length === 1 ? sev[0] : undefined,
      acknowledged: ack === "" ? undefined : ack === "ack",
      limit: PAGE,
    }),
    [types, sev, ack],
  );

  const q = useQuery({
    queryKey: ["changes", filter],
    queryFn: () => listChanges(filter),
    staleTime: 10_000,
  });

  const ackMut = useMutation({
    mutationFn: (id: string) => ackChange(id),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["changes"] });
      // Optimistically flip acknowledged across every cached changes query.
      qc.setQueriesData<SurfaceChange[]>({ queryKey: ["changes"] }, (old) =>
        (old ?? []).map((c) => (c.id === id ? { ...c, acknowledged: true } : c)),
      );
    },
    onError: () => qc.invalidateQueries({ queryKey: ["changes"] }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["changes"] }),
  });

  // Live rows synthesized from the SSE ring, filtered + deduped against fetched.
  const liveEvents = useStore((s) => s.events);
  const rows = useMemo<SurfaceChange[]>(() => {
    const fetched = q.data ?? [];
    const seen = new Set(fetched.map((c) => `${c.change_type}:${c.asset_value ?? ""}`));
    const live = liveEvents
      .filter((e) => !e.seeded)
      .map(liveEventToChange)
      .filter((c): c is SurfaceChange => !!c)
      .filter((c) => {
        if (seen.has(`${c.change_type}:${c.asset_value ?? ""}`)) return false;
        if (types.length && !types.includes(c.change_type)) return false;
        if (sev.length && !sev.includes(c.severity)) return false;
        if (ack === "ack") return false; // live rows are never pre-acked
        return true;
      });
    // Client-side multiselect narrowing of the fetched set.
    const narrowed = fetched.filter((c) => {
      if (types.length > 1 && !types.includes(c.change_type)) return false;
      if (sev.length > 1 && !sev.includes(c.severity)) return false;
      return true;
    });
    return [...live, ...narrowed];
  }, [q.data, liveEvents, types, sev, ack]);

  const toggleType = (t: ChangeType) =>
    setTypes((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]));
  const toggleSev = (s: Severity) =>
    setSev((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  return (
    <div className="panel" style={{ padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div className="panel-h" style={{ padding: "12px 14px 8px", marginBottom: 0 }}>
        <h2>Change feed</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{rows.length} shown · newest first</span>
      </div>

      <div className="filterbar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label>Severity</label>
        {SEV_LIST.map((s) => (
          <label
            key={s}
            className={`checkchip ${sev.includes(s) ? "on" : ""}`}
            style={sev.includes(s) ? { borderColor: SEV_COLOR[s], color: SEV_COLOR[s] } : undefined}
          >
            <input type="checkbox" checked={sev.includes(s)} onChange={() => toggleSev(s)} />
            {s.toUpperCase()}
          </label>
        ))}
        <span className="sep" />
        <label>State</label>
        <select value={ack} onChange={(e) => setAck(e.target.value as "" | "unack" | "ack")}>
          <option value="">Any</option>
          <option value="unack">Unacknowledged</option>
          <option value="ack">Acknowledged</option>
        </select>
      </div>

      <div className="filterbar typebar" style={{ borderRadius: 0, border: 0, borderBottom: "1px solid var(--border)" }}>
        <label>Types</label>
        {CHANGE_TYPES.map((t) => {
          const on = types.includes(t);
          const c = changeTypeColor(t);
          return (
            <label key={t} className={`checkchip ${on ? "on" : ""}`} style={on ? { borderColor: c, color: c } : undefined}>
              <input type="checkbox" checked={on} onChange={() => toggleType(t)} />
              {t}
            </label>
          );
        })}
      </div>

      <div className="change-list">
        {q.isLoading && <div style={{ padding: 12, color: "var(--text-2)" }}>Loading changes…</div>}
        {q.isError && <div style={{ padding: 12, color: "var(--bad)" }}>Failed to load changes.</div>}
        {!q.isLoading && rows.length === 0 && (
          <EmptyState title="No changes match these filters." />
        )}
        {rows.map((c) => (
          <ChangeRow key={c.id} change={c} onAck={(id) => ackMut.mutate(id)} acking={ackMut.isPending} />
        ))}
      </div>
    </div>
  );
}

/* --------------------------- alert rules ------------------------------- */

function matchSummary(rule: { match: { change_types?: ChangeType[]; min_severity?: Severity; kinds?: AssetKind[] } }): string {
  const parts: string[] = [];
  if (rule.match.min_severity) parts.push(`${rule.match.min_severity}+`);
  if (rule.match.change_types?.length) parts.push(`${rule.match.change_types.length} types`);
  if (rule.match.kinds?.length) parts.push(`${rule.match.kinds.length} kinds`);
  return parts.length ? parts.join(" · ") : "any change";
}

function DeliveriesList({ ruleId }: { ruleId: string }) {
  const q = useQuery({
    queryKey: ["alert-deliveries", ruleId],
    queryFn: () => listAlertDeliveries(ruleId, 20),
    staleTime: 10_000,
  });
  if (q.isLoading) return <div className="rule-deliveries muted">Loading deliveries…</div>;
  if (!q.data || q.data.length === 0) return <div className="rule-deliveries muted">No deliveries yet.</div>;
  return (
    <ul className="rule-deliveries">
      {q.data.map((d) => (
        <li key={d.id}>
          <span className={`delivery-status status-${d.status}`}>{d.status}</span>
          <span className="mono" style={{ color: "var(--text-2)" }}>{relTime(d.delivered_at)}</span>
          {d.response && <span className="delivery-resp mono" title={d.response}>{d.response}</span>}
        </li>
      ))}
    </ul>
  );
}

function RuleRow({ ruleId, children }: { ruleId: string; children: (expanded: boolean, toggle: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      {children(open, () => setOpen((v) => !v))}
      {open && <DeliveriesList ruleId={ruleId} />}
    </>
  );
}

function AlertRules() {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const q = useQuery({ queryKey: ["alert-rules"], queryFn: listAlertRules, staleTime: 15_000 });

  const [name, setName] = useState("");
  const [channel, setChannel] = useState<AlertChannel>("log");
  const [target, setTarget] = useState("");
  const [minSev, setMinSev] = useState<Severity | "">("");
  const [ruleTypes, setRuleTypes] = useState<ChangeType[]>([]);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["alert-rules"] });

  const create = useMutation({
    mutationFn: () =>
      createAlertRule({
        name: name.trim(),
        channel,
        target: channel === "log" ? null : target.trim() || null,
        match: {
          change_types: ruleTypes.length ? ruleTypes : undefined,
          min_severity: minSev || undefined,
        },
        enabled: true,
      }),
    onSuccess: () => {
      pushToast({ text: "Alert rule created." });
      setName("");
      setTarget("");
      setMinSev("");
      setRuleTypes([]);
      setChannel("log");
      invalidate();
    },
    onError: () => pushToast({ text: "Could not create rule.", severity: "high" }),
  });

  const toggle = useMutation({
    mutationFn: (p: { id: string; enabled: boolean }) => patchAlertRule(p.id, { enabled: p.enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: string) => deleteAlertRule(id),
    onSuccess: invalidate,
  });

  const toggleRuleType = (t: ChangeType) =>
    setRuleTypes((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]));

  const canCreate = name.trim().length > 0 && (channel === "log" || target.trim().length > 0);

  return (
    <div className="panel alert-rules">
      <div className="panel-h">
        <h2>Alert rules</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>{q.data?.length ?? 0} rules</span>
      </div>

      <Gate need="admin">
      <div className="rule-list">
        {(q.data ?? []).length === 0 && !q.isLoading && (
          <div className="muted" style={{ fontSize: 12, padding: "4px 0" }}>No alert rules yet.</div>
        )}
        {(q.data ?? []).map((r) => (
          <RuleRow key={r.id} ruleId={r.id}>
            {(expanded, toggleExpand) => (
              <div className={`rule-row${r.enabled ? "" : " disabled"}`}>
                <label className="switch" title={r.enabled ? "enabled" : "disabled"}>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={(e) => toggle.mutate({ id: r.id, enabled: e.target.checked })}
                  />
                  <span className="track" />
                </label>
                <div className="rule-main">
                  <div className="rule-name">
                    {r.name}
                    <span className="rule-channel mono">{r.channel}</span>
                  </div>
                  <div className="rule-match mono">{matchSummary(r)}</div>
                </div>
                <button className="ghost rule-expand" onClick={toggleExpand} title="recent deliveries">
                  {expanded ? "▾" : "▸"} deliveries
                </button>
                <button className="ghost danger" onClick={() => remove.mutate(r.id)} title="delete rule">
                  ✕
                </button>
              </div>
            )}
          </RuleRow>
        ))}
      </div>

      <form
        className="rule-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (canCreate) create.mutate();
        }}
      >
        <div className="rule-form-head">New rule</div>
        <div className="field">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. crit secrets → slack" />
        </div>
        <div className="rule-form-grid">
          <div className="field">
            <label>Channel</label>
            <select value={channel} onChange={(e) => setChannel(e.target.value as AlertChannel)}>
              <option value="log">log</option>
              <option value="webhook">webhook</option>
              <option value="slack">slack</option>
            </select>
          </div>
          <div className="field">
            <label>Min severity</label>
            <select value={minSev} onChange={(e) => setMinSev(e.target.value as Severity | "")}>
              <option value="">any</option>
              {SEV_LIST.slice().reverse().map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
        {channel !== "log" && (
          <div className="field">
            <label>Target URL</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://hooks.example.com/…"
            />
            <span className="field-note">stored server-side</span>
          </div>
        )}
        <div className="field">
          <label>Change types (wildcard if none)</label>
          <div className="rule-type-chips">
            {CHANGE_TYPES.map((t) => {
              const on = ruleTypes.includes(t);
              const c = changeTypeColor(t);
              return (
                <label key={t} className={`checkchip ${on ? "on" : ""}`} style={on ? { borderColor: c, color: c } : undefined}>
                  <input type="checkbox" checked={on} onChange={() => toggleRuleType(t)} />
                  {t}
                </label>
              );
            })}
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

/* ------------------------------- page ---------------------------------- */

export default function ChangesPage() {
  const summary = useQuery({
    queryKey: ["changes-summary", 7],
    queryFn: () => getChangeSummary(7),
    staleTime: 30_000,
  });

  const stats = useMemo(() => {
    const s = summary.data;
    const total = s?.total ?? 0;
    const byType = s?.by_type ?? {};
    const secrets = byType.secret_found ?? 0;
    const exposure = byType.exposure_increased ?? 0;
    const today = s?.by_day?.length
      ? (() => {
          const d = s.by_day[s.by_day.length - 1];
          return d.info + d.low + d.medium + d.high + d.critical;
        })()
      : 0;
    return { total, secrets, exposure, today };
  }, [summary.data]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Changes</h1>
          <div className="subtitle">Change intelligence — what moved on the attack surface, and who to tell.</div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Changes (7d)" value={stats.total} accent="#9fc2d8" />
        <StatTile label="Today" value={stats.today} accent="#8fbf8a" />
        <StatTile label="Secrets found" value={stats.secrets} accent={SEV_COLOR.critical} />
        <StatTile label="Exposure increases" value={stats.exposure} accent={SEV_COLOR.high} />
      </div>

      <ChangeVelocity />

      <div className="changes-grid">
        <ChangeFeed />
        <AlertRules />
      </div>
    </div>
  );
}
