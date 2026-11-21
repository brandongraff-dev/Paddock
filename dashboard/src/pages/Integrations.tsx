/**
 * Integrations — connect → test → subscribe → watch deliveries.
 *
 *   header      health strip (connected / healthy / errors / sent 24h / queue)
 *   Connected   one row per configured integration: status dot, last result,
 *               enable switch, Configure
 *   Catalog     every registered connector, grouped by category
 *   Drawer      config form rendered from the connector's config_schema,
 *               password inputs for secret_fields (write-only), event
 *               subscriptions, min severity, filters, Test, delivery log + retry
 *
 * All mutate controls sit inside <Gate need="admin">; the API enforces the
 * same rule (admin capability) server-side.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  createIntegration,
  deleteIntegration,
  errorMessages,
  getCatalog,
  getIntegrationsHealth,
  listDeliveries,
  listIntegrations,
  retryDelivery,
  setIntegrationEnabled,
  testIntegration,
  updateIntegration,
  type Catalog,
  type ConnectorInfo,
  type DeliveryStatus,
  type Integration,
  type IntegrationInput,
  type IntegrationSeverity,
  type SchemaProp,
  type TestResult,
} from "../api/integrations";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import "../styles/integrations.css";

/* ------------------------------------------------------------------ *
 * Presentation helpers
 * ------------------------------------------------------------------ */

const CATEGORY_LABEL: Record<string, string> = {
  chat: "Chat",
  paging: "Paging & on-call",
  email: "Email",
  webhook: "Webhooks",
  ticketing: "Ticketing",
  siem: "SIEM & logging",
  identity: "Identity",
  cloud: "Cloud",
  edr: "Endpoint & MDM",
  network: "Network",
  other: "Other",
};
const CATEGORY_ORDER = Object.keys(CATEGORY_LABEL);

const BLURB: Record<string, string> = {
  webhook: "Signed JSON to any HTTPS endpoint. Wire Paddock into anything.",
  slack: "Post findings to a channel with severity, asset and a deep link.",
  teams: "Adaptive Cards in a Teams channel through a Workflows webhook.",
  pagerduty: "Page on-call for what matters; auto-resolve when it's fixed.",
  email: "Encrypted SMTP alerts to a team inbox or distribution list.",
};

const SEVERITIES: IntegrationSeverity[] = ["info", "low", "medium", "high", "critical"];
const DEFAULT_EVENTS = ["finding.opened", "attack_path.opened"];

const FILTER_LABEL: Record<string, { label: string; hint: string }> = {
  asset_kinds: { label: "Asset kinds", hint: "domain, subdomain" },
  rule_sources: { label: "Rule sources", hint: "nuclei, cve_match" },
  owners: { label: "Owners", hint: "payments-team" },
  tags: { label: "Asset tags", hint: "prod, pci" },
  assets: { label: "Assets (globs)", hint: "*.prod.example.com" },
};

const SECRET_LABEL: Record<string, string> = {
  webhook_url: "Webhook URL",
  signing_secret: "Signing secret",
  routing_key: "Routing key",
  username: "Username",
  password: "Password",
};

function humanize(key: string): string {
  return SECRET_LABEL[key] ?? key.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

function monogram(name: string): string {
  const words = name.replace(/[^A-Za-z0-9 ]/g, " ").split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const STATUS_LABEL: Record<Integration["status"], string> = {
  ok: "Healthy",
  error: "Failing",
  never: "No deliveries yet",
  disabled: "Disabled",
};

function StatusDot({ status }: { status: Integration["status"] }) {
  return <span className={`ig-dot ig-dot-${status}`} aria-label={STATUS_LABEL[status]} title={STATUS_LABEL[status]} />;
}

function DeliveryChip({ status }: { status: DeliveryStatus }) {
  return <span className={`ig-dchip ig-dchip-${status}`}>{status}</span>;
}

/* ------------------------------------------------------------------ *
 * Form model
 * ------------------------------------------------------------------ */

export interface FormState {
  name: string;
  config: Record<string, string | boolean>;
  secrets: Record<string, string>;
  events: string[];
  min_severity: IntegrationSeverity;
  filters: Record<string, string>;
  allow_private: boolean;
  enabled: boolean;
}

function propToText(prop: SchemaProp, v: unknown): string | boolean {
  if (prop.type === "boolean") return Boolean(v ?? prop.default ?? false);
  if (Array.isArray(v)) return v.join(", ");
  if (v === undefined || v === null) return prop.default !== undefined && prop.type !== "array" ? String(prop.default) : "";
  return String(v);
}

export function initialForm(conn: ConnectorInfo, existing?: Integration | null): FormState {
  const props = conn.config_schema.properties ?? {};
  const cfg = existing?.config ?? {};
  const config: FormState["config"] = {};
  for (const [k, p] of Object.entries(props)) config[k] = propToText(p, cfg[k]);
  const filters: Record<string, string> = {};
  for (const [k, v] of Object.entries(existing?.filters ?? {})) filters[k] = (v ?? []).join(", ");
  return {
    name: existing?.name ?? conn.display_name,
    config,
    secrets: Object.fromEntries(conn.secret_fields.map((f) => [f, ""])),
    events: existing?.events ?? DEFAULT_EVENTS,
    min_severity: existing?.min_severity ?? "medium",
    filters,
    allow_private: existing?.allow_private ?? false,
    enabled: existing?.enabled ?? true,
  };
}

const splitList = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

/** FormState -> API body. Blank secrets are omitted, i.e. "keep what's stored". */
export function toPayload(conn: ConnectorInfo, f: FormState, isNew: boolean): IntegrationInput {
  const props = conn.config_schema.properties ?? {};
  const config: Record<string, unknown> = {};
  for (const [k, p] of Object.entries(props)) {
    const raw = f.config[k];
    if (p.type === "boolean") config[k] = Boolean(raw);
    else if (p.type === "array") {
      const items = splitList(String(raw ?? ""));
      if (items.length) config[k] = items;
    } else if (p.type === "integer" || p.type === "number") {
      if (String(raw ?? "").trim() !== "") config[k] = Number(raw);
    } else if (String(raw ?? "") !== "") config[k] = String(raw);
  }
  const secrets: Record<string, string> = {};
  for (const [k, v] of Object.entries(f.secrets)) if (v) secrets[k] = v;
  const filters: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(f.filters)) {
    const items = splitList(v);
    if (items.length) filters[k] = items;
  }
  const body: IntegrationInput = {
    name: f.name.trim(),
    config,
    events: f.events,
    min_severity: f.min_severity,
    filters,
    allow_private: f.allow_private,
    enabled: f.enabled,
  };
  if (isNew) body.kind = conn.kind;
  if (isNew || Object.keys(secrets).length) body.secrets = secrets;
  return body;
}

/* ------------------------------------------------------------------ *
 * Config form rendered from config_schema
 * ------------------------------------------------------------------ */

function SchemaField({
  name,
  prop,
  required,
  value,
  onChange,
}: {
  name: string;
  prop: SchemaProp;
  required: boolean;
  value: string | boolean;
  onChange: (v: string | boolean) => void;
}) {
  const id = `ig-cfg-${name}`;
  const label = prop.title ?? humanize(name);
  if (prop.type === "boolean") {
    return (
      <label className="ig-check" htmlFor={id}>
        <input id={id} type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <span>{label}</span>
      </label>
    );
  }
  let control: ReactNode;
  if (prop.enum) {
    control = (
      <select id={id} value={String(value)} onChange={(e) => onChange(e.target.value)}>
        {!required && prop.default === undefined && <option value="">—</option>}
        {prop.enum.map((o) => (
          <option key={String(o)} value={String(o)}>{String(o)}</option>
        ))}
      </select>
    );
  } else if (prop.type === "array") {
    control = (
      <textarea
        id={id}
        rows={2}
        value={String(value)}
        placeholder={prop.items?.format === "email" ? "alice@example.com, bob@example.com" : "one, two"}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  } else {
    const type =
      prop.type === "integer" || prop.type === "number" ? "number"
        : prop.format === "email" ? "email"
        : prop.format === "uri" ? "url"
        : "text";
    control = (
      <input
        id={id}
        type={type}
        value={String(value)}
        min={prop.minimum}
        max={prop.maximum}
        maxLength={prop.maxLength}
        placeholder={prop.format === "uri" ? "https://" : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <div className="ig-field">
      <label htmlFor={id}>
        {label}
        {required && <span className="ig-req" aria-hidden> *</span>}
      </label>
      {control}
      {prop.description && <div className="ig-hint">{prop.description}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Delivery log
 * ------------------------------------------------------------------ */

function DeliveryLog({ integrationId }: { integrationId: string }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<DeliveryStatus | "">("");
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const q = useQuery({
    queryKey: ["integration-deliveries", integrationId, status, offset],
    queryFn: () => listDeliveries(integrationId, { status, limit, offset }),
    refetchInterval: 10_000,
  });
  const retry = useMutation({
    mutationFn: (did: number) => retryDelivery(integrationId, did),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integration-deliveries", integrationId] });
      qc.invalidateQueries({ queryKey: ["integrations"] });
    },
  });
  const total = q.data?.total ?? 0;
  return (
    <div className="ig-log">
      <div className="ig-log-bar">
        <select aria-label="Filter by status" value={status} onChange={(e) => { setStatus(e.target.value as DeliveryStatus | ""); setOffset(0); }}>
          <option value="">All statuses</option>
          {(["pending", "sent", "failed", "dead", "skipped"] as DeliveryStatus[]).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="ig-muted">{total} deliver{total === 1 ? "y" : "ies"}</span>
      </div>
      {q.isLoading ? (
        <div className="ig-muted ig-pad">Loading deliveries…</div>
      ) : !q.data?.items.length ? (
        <EmptyState title="No deliveries yet" hint="Send a test or wait for a matching event." />
      ) : (
        <table className="table ig-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
              <th>Status</th>
              <th className="ig-num">Tries</th>
              <th>Result</th>
              <th aria-label="actions" />
            </tr>
          </thead>
          <tbody>
            {q.data.items.map((d) => (
              <tr key={d.id}>
                <td className="mono ig-nowrap" title={d.created_at ?? ""}>{relTime(d.created_at)}</td>
                <td>
                  <div className="ig-ev-title">{d.title ?? d.event_type}</div>
                  <div className="ig-ev-type mono">
                    {d.event_type}
                    {d.severity ? ` · ${d.severity}` : ""}
                  </div>
                </td>
                <td>
                  <DeliveryChip status={d.status} />
                  {d.next_attempt_at && d.status === "failed" && (
                    <div className="ig-ev-type">retry at {new Date(d.next_attempt_at).toLocaleTimeString()}</div>
                  )}
                </td>
                <td className="mono ig-num">{d.attempts}</td>
                <td className="ig-detail" title={d.detail ?? ""}>
                  {d.status_code ? <span className="mono">{d.status_code} </span> : null}
                  {d.detail ?? "—"}
                </td>
                <td>
                  {d.status !== "pending" && (
                    <Gate need="admin">
                      <button className="ghost ig-small" onClick={() => retry.mutate(d.id)} disabled={retry.isPending}>
                        Retry
                      </button>
                    </Gate>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {total > limit && (
        <div className="ig-pager">
          <button className="ghost ig-small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
            ← Newer
          </button>
          <span className="ig-muted mono">
            {offset + 1}–{Math.min(offset + limit, total)} of {total}
          </span>
          <button className="ghost ig-small" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>
            Older →
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Configure drawer
 * ------------------------------------------------------------------ */

function TestOutcome({ result }: { result: TestResult }) {
  return (
    <div className={`ig-test ${result.ok ? "ok" : "bad"}`} role="status">
      <strong>{result.ok ? "Test delivered" : "Test failed"}</strong>
      <span className="mono">{result.status_code ?? ""}</span>
      <span className="ig-test-detail">{result.detail}</span>
      {!result.ok && result.retryable && <span className="ig-muted">(transient: the worker would retry this)</span>}
    </div>
  );
}

function ConfigureDrawer({
  conn,
  existing,
  catalog,
  onClose,
}: {
  conn: ConnectorInfo;
  existing: Integration | null;
  catalog: Catalog;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isNew = !existing;
  const [tab, setTab] = useState<"configure" | "deliveries">("configure");
  const [form, setForm] = useState<FormState>(() => initialForm(conn, existing));
  const [errors, setErrors] = useState<string[]>([]);
  const [saved, setSaved] = useState<Integration | null>(existing);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["integrations"] });
    qc.invalidateQueries({ queryKey: ["integrations-health"] });
  };

  const save = useMutation({
    mutationFn: () => {
      const body = toPayload(conn, form, !saved);
      return saved ? updateIntegration(saved.id, body) : createIntegration(body);
    },
    onSuccess: (it) => {
      setErrors([]);
      setSaved(it);
      setForm((f) => ({ ...f, secrets: Object.fromEntries(Object.keys(f.secrets).map((k) => [k, ""])) }));
      refresh();
    },
    onError: (e) => setErrors(errorMessages(e)),
  });

  const test = useMutation({
    mutationFn: () => testIntegration(saved!.id),
    onSuccess: (r) => {
      setTestResult(r);
      refresh();
      qc.invalidateQueries({ queryKey: ["integration-deliveries", saved!.id] });
    },
    onError: (e) => setTestResult({ mode: "deliver", ok: false, status_code: null, detail: errorMessages(e).join("; "), external_id: null, external_url: null, retryable: false, delivery_id: null }),
  });

  const remove = useMutation({
    mutationFn: () => deleteIntegration(saved!.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
    onError: (e) => setErrors(errorMessages(e)),
  });

  const props = conn.config_schema.properties ?? {};
  const required = new Set(conn.config_schema.required ?? []);
  const requiredSecrets = new Set(conn.required_secrets ?? []);
  const events = catalog.events.filter((e) => e.type !== "integration.test");

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    save.mutate();
  };
  const toggleEvent = (t: string) =>
    setForm((f) => ({ ...f, events: f.events.includes(t) ? f.events.filter((x) => x !== t) : [...f.events, t] }));

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer ig-drawer" role="dialog" aria-label={`Configure ${conn.display_name}`}>
        <header className="ig-drawer-head">
          <div className="ig-drawer-title">
            <span className={`ig-mono ig-cat-${conn.category}`} aria-hidden>{monogram(conn.display_name)}</span>
            <div>
              <h2>{saved ? saved.name : `Connect ${conn.display_name}`}</h2>
              <div className="ig-muted">
                {conn.display_name}
                {saved && <> · <StatusDot status={saved.status} /> {STATUS_LABEL[saved.status]}</>}
              </div>
            </div>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </header>

        {saved && (
          <div className="ig-tabs" role="tablist">
            <button role="tab" aria-selected={tab === "configure"} className={tab === "configure" ? "on" : ""} onClick={() => setTab("configure")}>
              Configure
            </button>
            <button role="tab" aria-selected={tab === "deliveries"} className={tab === "deliveries" ? "on" : ""} onClick={() => setTab("deliveries")}>
              Deliveries
              {saved.stats.dead + saved.stats.failed > 0 && <span className="ig-badge bad">{saved.stats.dead + saved.stats.failed}</span>}
            </button>
          </div>
        )}

        <div className="body ig-drawer-body">
          {tab === "deliveries" && saved ? (
            <DeliveryLog integrationId={saved.id} />
          ) : (
            <form onSubmit={submit} className="ig-form" aria-label="integration settings">
              <Gate need="admin">
                <section className="ig-section">
                  <div className="ig-field">
                    <label htmlFor="ig-name">Name</label>
                    <input id="ig-name" value={form.name} maxLength={100} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                  </div>
                  {Object.entries(props).map(([k, p]) => (
                    <SchemaField
                      key={k}
                      name={k}
                      prop={p}
                      required={required.has(k)}
                      value={form.config[k] ?? ""}
                      onChange={(v) => setForm({ ...form, config: { ...form.config, [k]: v } })}
                    />
                  ))}
                </section>

                {conn.secret_fields.length > 0 && (
                  <section className="ig-section">
                    <h3>Credentials</h3>
                    <p className="ig-hint">Encrypted at rest and never shown again. Leave blank to keep the stored value.</p>
                    {saved?.secrets_error && <div className="ig-alert">{saved.secrets_error}</div>}
                    {conn.secret_fields.map((f) => {
                      const stored = saved?.secrets?.[f] === "********";
                      return (
                        <div className="ig-field" key={f}>
                          <label htmlFor={`ig-sec-${f}`}>
                            {humanize(f)}
                            {requiredSecrets.has(f) && !stored && <span className="ig-req" aria-hidden> *</span>}
                          </label>
                          <input
                            id={`ig-sec-${f}`}
                            type="password"
                            autoComplete="new-password"
                            spellCheck={false}
                            value={form.secrets[f] ?? ""}
                            placeholder={stored ? "•••••••• stored" : ""}
                            onChange={(e) => setForm({ ...form, secrets: { ...form.secrets, [f]: e.target.value } })}
                          />
                        </div>
                      );
                    })}
                  </section>
                )}

                <section className="ig-section">
                  <h3>Events</h3>
                  <div className="ig-events">
                    {events.map((e) => (
                      <label key={e.type} className={`ig-event ${form.events.includes(e.type) ? "on" : ""}`}>
                        <input type="checkbox" checked={form.events.includes(e.type)} onChange={() => toggleEvent(e.type)} />
                        <span className="mono">{e.type}</span>
                        <span className="ig-event-desc">{e.description}</span>
                      </label>
                    ))}
                  </div>
                  <div className="ig-row">
                    <div className="ig-field">
                      <label htmlFor="ig-minsev">Minimum severity</label>
                      <select id="ig-minsev" value={form.min_severity} onChange={(e) => setForm({ ...form, min_severity: e.target.value as IntegrationSeverity })}>
                        {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>
                    <div className="ig-hint ig-grow">Applies to events that carry a severity (findings, attack paths).</div>
                  </div>
                </section>

                <details className="ig-section ig-advanced">
                  <summary>Filters &amp; network</summary>
                  <p className="ig-hint">Optional. Each filter narrows; comma-separated values.</p>
                  <div className="ig-grid2">
                    {catalog.filters.map((k) => (
                      <div className="ig-field" key={k}>
                        <label htmlFor={`ig-flt-${k}`}>{FILTER_LABEL[k]?.label ?? humanize(k)}</label>
                        <input
                          id={`ig-flt-${k}`}
                          value={form.filters[k] ?? ""}
                          placeholder={FILTER_LABEL[k]?.hint}
                          onChange={(e) => setForm({ ...form, filters: { ...form.filters, [k]: e.target.value } })}
                        />
                      </div>
                    ))}
                  </div>
                  <label className="ig-check">
                    <input type="checkbox" checked={form.allow_private} onChange={(e) => setForm({ ...form, allow_private: e.target.checked })} />
                    <span>Allow private network targets</span>
                  </label>
                  <div className="ig-hint">Only for self-hosted endpoints on your LAN. Cloud metadata addresses are always refused.</div>
                </details>

                {errors.length > 0 && (
                  <div className="ig-alert" role="alert">
                    {errors.map((e) => <div key={e}>{e}</div>)}
                  </div>
                )}
                {testResult && <TestOutcome result={testResult} />}

                <div className="ig-actions">
                  {saved && (
                    confirmDelete ? (
                      <span className="ig-confirm">
                        Delete this integration?
                        <button type="button" className="danger ig-small" onClick={() => remove.mutate()}>Delete</button>
                        <button type="button" className="ghost ig-small" onClick={() => setConfirmDelete(false)}>Cancel</button>
                      </span>
                    ) : (
                      <button type="button" className="ghost ig-danger-link" onClick={() => setConfirmDelete(true)}>Delete</button>
                    )
                  )}
                  <span className="ig-grow" />
                  {saved && (
                    <button type="button" onClick={() => test.mutate()} disabled={test.isPending}>
                      {test.isPending ? "Sending…" : "Send test"}
                    </button>
                  )}
                  <button type="submit" className="primary" disabled={save.isPending}>
                    {save.isPending ? "Saving…" : isNew && !saved ? "Connect" : "Save"}
                  </button>
                </div>
              </Gate>
            </form>
          )}
        </div>
      </aside>
    </>
  );
}

/* ------------------------------------------------------------------ *
 * Page
 * ------------------------------------------------------------------ */

type DrawerTarget = { conn: ConnectorInfo; existing: Integration | null } | null;

export default function IntegrationsPage() {
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["integrations-catalog"], queryFn: getCatalog, staleTime: 300_000 });
  const list = useQuery({ queryKey: ["integrations"], queryFn: listIntegrations, refetchInterval: 15_000 });
  const health = useQuery({ queryKey: ["integrations-health"], queryFn: getIntegrationsHealth, refetchInterval: 15_000 });
  const [drawer, setDrawer] = useState<DrawerTarget>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setIntegrationEnabled(id, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations"] });
      qc.invalidateQueries({ queryKey: ["integrations-health"] });
    },
  });

  const connectors = catalog.data?.connectors ?? [];
  const byKind = useMemo(() => new Map(connectors.map((c) => [c.kind, c])), [connectors]);
  const items = list.data?.items ?? [];
  const countByKind = useMemo(() => {
    const m = new Map<string, number>();
    for (const i of items) m.set(i.kind, (m.get(i.kind) ?? 0) + 1);
    return m;
  }, [items]);
  const groups = useMemo(() => {
    const g = new Map<string, ConnectorInfo[]>();
    for (const c of connectors) g.set(c.category, [...(g.get(c.category) ?? []), c]);
    const rank = (cat: string) => (CATEGORY_ORDER.includes(cat) ? CATEGORY_ORDER.indexOf(cat) : 99);
    return [...g.entries()].sort((a, b) => rank(a[0]) - rank(b[0]));
  }, [connectors]);

  const h = health.data;
  const queue = h ? h.deliveries.pending + h.deliveries.failed : 0;

  return (
    <div className="page ig-page">
      <div className="page-header">
        <div>
          <h1>Integrations</h1>
          <div className="subtitle">
            Push findings into the tools your team already watches. Every delivery is signed or encrypted,
            retried with backoff, and logged.
          </div>
        </div>
        {h && (
          <span className={`ig-health ig-health-${h.deliveries.stalled ? "stalled" : h.status}`}>
            <span className="ig-health-dot" />
            {h.deliveries.stalled ? "Queue stalled. Is the integrations worker running?" : h.status === "ok" ? "All systems delivering" : h.status === "empty" ? "Nothing connected yet" : "Attention needed"}
          </span>
        )}
      </div>

      {h && !h.secret_key_persistent && (
        <div className="ig-banner" role="note">
          <strong>PADDOCK_SECRET_KEY is not set.</strong> Credentials are encrypted with a temporary key and will
          not survive a restart. Set it in <span className="mono">.env</span> before connecting production tools.
        </div>
      )}

      <div className="stat-row ig-stats">
        <div className="stat-tile"><span className="label">Connected</span><span className="value">{h?.integrations.total ?? "—"}</span></div>
        <div className="stat-tile"><span className="label">Healthy</span><span className="value">{h?.integrations.ok ?? "—"}</span></div>
        <div className="stat-tile"><span className="label">Failing</span><span className={`value ${h?.integrations.error ? "ig-bad" : ""}`}>{h?.integrations.error ?? "—"}</span></div>
        <div className="stat-tile"><span className="label">Delivered, 24h</span><span className="value">{h?.deliveries.sent_24h ?? "—"}</span></div>
        <div className="stat-tile"><span className="label">In queue</span><span className="value">{h ? queue : "—"}</span></div>
        <div className="stat-tile"><span className="label">Dead-lettered</span><span className={`value ${h?.deliveries.dead ? "ig-bad" : ""}`}>{h?.deliveries.dead ?? "—"}</span></div>
      </div>

      <section className="panel">
        <div className="panel-h">
          <h2>Connected</h2>
          <span className="ig-muted">{items.length} integration{items.length === 1 ? "" : "s"}</span>
        </div>
        {list.isLoading ? (
          <div className="ig-muted ig-pad">Loading…</div>
        ) : list.isError ? (
          <EmptyState title="Couldn't load integrations" hint={errorMessages(list.error).join("; ")} />
        ) : items.length === 0 ? (
          <EmptyState title="No integrations yet" hint="Pick one from the catalog below. Slack or a signed webhook takes a minute." />
        ) : (
          <ul className="ig-list">
            {items.map((it) => {
              const conn = byKind.get(it.kind);
              return (
                <li key={it.id} className="ig-item">
                  <StatusDot status={it.status} />
                  <span className={`ig-mono ig-cat-${it.category}`} aria-hidden>{monogram(it.display_name)}</span>
                  <div className="ig-item-main">
                    <div className="ig-item-name">
                      {it.name}
                      <span className="ig-item-kind">{it.display_name}</span>
                    </div>
                    <div className="ig-item-meta">
                      {it.events.length} event{it.events.length === 1 ? "" : "s"} · ≥ {it.min_severity}
                      {it.status === "error" && it.last_error ? (
                        <span className="ig-item-err" title={it.last_error}> · {it.last_error}</span>
                      ) : (
                        <> · last delivery {relTime(it.last_ok_at)}</>
                      )}
                    </div>
                  </div>
                  <div className="ig-item-stats mono" aria-label="delivery stats">
                    <span title="sent in the last 24h">{it.stats.sent_24h} sent</span>
                    {it.stats.pending + it.stats.failed > 0 && <span title="queued or retrying">{it.stats.pending + it.stats.failed} queued</span>}
                    {it.stats.dead > 0 && <span className="ig-bad" title="dead-lettered">{it.stats.dead} dead</span>}
                  </div>
                  <Gate need="admin">
                    <label className="switch" title={it.enabled ? "Enabled" : "Disabled"}>
                      <input
                        type="checkbox"
                        aria-label={`${it.enabled ? "Disable" : "Enable"} ${it.name}`}
                        checked={it.enabled}
                        onChange={(e) => toggle.mutate({ id: it.id, enabled: e.target.checked })}
                      />
                      <span className="track" />
                    </label>
                  </Gate>
                  <button
                    className="ghost ig-small"
                    disabled={!conn}
                    title={conn ? undefined : "This connector is not installed"}
                    onClick={() => conn && setDrawer({ conn, existing: it })}
                  >
                    Configure
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="ig-catalog" aria-label="catalog">
        <div className="ig-catalog-head">
          <h2>Catalog</h2>
          <span className="ig-muted">{connectors.length} connectors</span>
        </div>
        {catalog.isLoading && <div className="ig-muted ig-pad">Loading catalog…</div>}
        {groups.map(([cat, conns]) => (
          <div key={cat} className="ig-group">
            <div className="ig-group-label">{CATEGORY_LABEL[cat] ?? cat}</div>
            <div className="ig-grid">
              {conns.map((c) => {
                const n = countByKind.get(c.kind) ?? 0;
                return (
                  <article key={c.kind} className="ig-card">
                    <div className="ig-card-top">
                      <span className={`ig-mono ig-cat-${c.category}`} aria-hidden>{monogram(c.display_name)}</span>
                      <div className="ig-card-name">{c.display_name}</div>
                      {n > 0 && <span className="ig-connected" title={`${n} connected`}>Connected{n > 1 ? ` ×${n}` : ""}</span>}
                    </div>
                    <p className="ig-card-blurb">{BLURB[c.kind] ?? `${c.capabilities.join(", ")} integration.`}</p>
                    <div className="ig-card-foot">
                      <span className="ig-caps">
                        {c.capabilities.map((cap) => <span key={cap} className="ig-cap">{cap}</span>)}
                      </span>
                      <Gate need="admin">
                        <button className="ig-small" onClick={() => setDrawer({ conn: c, existing: null })} aria-label={`Connect ${c.display_name}`}>
                          {n > 0 ? "Add another" : "Connect"}
                        </button>
                      </Gate>
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        ))}
      </section>

      {drawer && catalog.data && (
        <ConfigureDrawer
          key={drawer.existing?.id ?? `new-${drawer.conn.kind}`}
          conn={drawer.conn}
          existing={drawer.existing}
          catalog={catalog.data}
          onClose={() => setDrawer(null)}
        />
      )}
    </div>
  );
}
