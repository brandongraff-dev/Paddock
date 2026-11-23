/**
 * Settings → System (admin). What this install is made of: the Paddock
 * version, edition and profile, and one row per component with its health.
 * Services left out of a lite install show as "Not installed", which is
 * normal and not an error.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../api/client";
import {
  getAiStatus,
  getSystem,
  removeAiKey,
  saveAiKey,
  type AiStatus,
  type ComponentStatus,
  type SystemComponent,
  type SystemInfo,
} from "../api/system";
import StatTile from "../components/StatTile";
import "../styles/system.css";

const EDITION_LABEL: Record<string, string> = {
  community: "Community",
  team: "Team",
  enterprise: "Enterprise",
  edge: "Edge",
};

const STATUS_LABEL: Record<ComponentStatus, string> = {
  up: "Running",
  down: "Not responding",
  not_installed: "Not installed",
};

export function StatusDot({ status }: { status: ComponentStatus }) {
  return (
    <span className="sys-status" data-status={status}>
      <i className="sys-dot" aria-hidden="true" />
      {STATUS_LABEL[status]}
    </span>
  );
}

function Rows({ rows }: { rows: SystemComponent[] }) {
  return (
    <table className="table sys-table">
      <thead>
        <tr><th>Component</th><th>What it does</th><th>Status</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key} data-key={r.key}>
            <td>{r.label}</td>
            <td className="sys-desc">{r.description}</td>
            <td><StatusDot status={r.status} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function headline(s: SystemInfo): { tone: "ok" | "warn" | "bad"; title: string; body: string } | null {
  const down = [...s.core, ...s.services].filter((c) => c.status === "down");
  if (down.length === 0) return null;
  return {
    tone: s.core.some((c) => c.status === "down") ? "bad" : "warn",
    title: `${down.length} ${down.length === 1 ? "component is" : "components are"} not responding`,
    body: `${down.map((c) => c.label).join(", ")}. Check the container logs with: docker compose logs --tail=100`,
  };
}

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { detail?: unknown } | undefined;
    if (b && typeof b.detail === "string") return b.detail;
    return e.message;
  }
  return e instanceof Error ? e.message : "Request failed.";
}

/**
 * AI features: paste an Anthropic API key to turn on AI triage summaries and
 * natural-language Ask. Optional: Paddock works without it. The key is stored
 * encrypted on the server and is never shown again, only its last four
 * characters. The field is emptied after every save and never kept in the
 * query cache.
 */
export function AiPanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ai-status"], queryFn: getAiStatus });
  const [key, setKey] = useState("");
  const done = (s: AiStatus) => {
    setKey("");
    qc.setQueryData(["ai-status"], s);
  };
  const save = useMutation({ mutationFn: () => saveAiKey(key), onSuccess: done });
  const remove = useMutation({ mutationFn: removeAiKey, onSuccess: done });
  const s = q.data;
  const busy = save.isPending || remove.isPending;

  return (
    <section className="panel sys-ai" aria-labelledby="sys-ai-h">
      <div className="panel-h"><h2 id="sys-ai-h">AI features</h2></div>
      <div className="sys-ai-body">
        <p className="sys-ai-intro">
          Optional. With an Anthropic API key, Paddock writes plain-English summaries of finding clusters and
          answers questions in plain language on the Ask page. Without one, everything still works using
          built-in rules and a few ready-made questions.
        </p>
        <p className="sys-ai-privacy">
          When AI is on, finding titles, asset names and your questions are sent to Anthropic.
          The key is stored encrypted here and is never shown again.
        </p>

        {q.isError && <div className="sys-ai-state">AI settings are unavailable right now.</div>}
        {s && (
          <div className="sys-ai-state" data-configured={s.configured} aria-live="polite">
            {s.configured
              ? `Key saved (${s.hint})${s.updated_by ? ` by ${s.updated_by}` : ""}. AI is on.`
              : "No key saved. Using the built-in fallbacks."}
          </div>
        )}
        {s && s.brain !== "up" && (
          <div className="sys-ai-state" data-tone="warn">
            {s.brain === "not_installed"
              ? "The AI service (Brain) is not part of this install, so a key would have no effect."
              : "The AI service (Brain) is not responding yet. A saved key is picked up automatically once it is."}
          </div>
        )}
        {s && !s.editable && (
          <div className="sys-ai-state">AI settings are managed by the platform operator.</div>
        )}

        <form
          className="sys-ai-form"
          onSubmit={(e) => { e.preventDefault(); if (key.trim()) save.mutate(); }}
        >
          <div className="field">
            <label htmlFor="sys-ai-key">Anthropic API key</label>
            <input
              id="sys-ai-key"
              type="password"
              className="mono"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="sk-ant-…"
              autoComplete="new-password"
              spellCheck={false}
              disabled={!s?.editable || busy}
            />
          </div>
          <div className="sys-ai-actions">
            <button type="submit" className="primary" disabled={!s?.editable || busy || !key.trim()}>
              {s?.configured ? "Replace key" : "Save key"}
            </button>
            {s?.configured && (
              <button type="button" disabled={!s.editable || busy} onClick={() => remove.mutate()}>
                Remove key
              </button>
            )}
            {(save.isSuccess || remove.isSuccess) && !busy && <span className="sys-ai-saved">Saved</span>}
          </div>
          {save.isError && <div className="login-error" role="alert">{errText(save.error)}</div>}
          {remove.isError && <div className="login-error" role="alert">{errText(remove.error)}</div>}
        </form>
        <p className="sys-ai-help">
          Get a key at console.anthropic.com. You can also set <code>ANTHROPIC_API_KEY</code> in the server's
          <code> .env</code>; a key saved here takes priority.
        </p>
      </div>
    </section>
  );
}

export default function SystemPage() {
  const q = useQuery({ queryKey: ["system"], queryFn: getSystem, refetchInterval: 15000 });
  const s = q.data;
  const note = s ? headline(s) : null;

  return (
    <div className="page system-page">
      <div className="page-header">
        <div>
          <h1>System</h1>
          <div className="subtitle">What this install is made of and whether each part is running.</div>
        </div>
      </div>

      {q.isLoading && <div className="empty">Loading…</div>}
      {q.isError && <div className="empty">System details are unavailable right now.</div>}

      {note && (
        <div className={`sys-notice tone-${note.tone}`} role="status">
          <div className="sys-notice-title">{note.title}</div>
          <div className="sys-notice-body">{note.body}</div>
        </div>
      )}

      {s && (
        <>
          <div className="sys-tiles">
            <StatTile label="Version" value={s.version} />
            <StatTile label="Edition" value={EDITION_LABEL[s.edition] ?? s.edition} hint={s.license_status} />
            <StatTile
              label="Running"
              value={`${s.counts.up} / ${s.counts.up + s.counts.down + s.counts.not_installed}`}
              hint={s.counts.not_installed ? `${s.counts.not_installed} not installed` : undefined}
            />
            <StatTile
              label="Sign-in"
              value={s.auth_mode === "dev" ? "Open (dev)" : "Required"}
              hint={s.auth_mode === "dev" ? "Do not expose this install" : undefined}
            />
          </div>

          <AiPanel />

          <section className="panel">
            <div className="panel-h"><h2>Core</h2></div>
            <Rows rows={s.core} />
          </section>

          <section className="panel">
            <div className="panel-h"><h2>Services</h2></div>
            <Rows rows={s.services} />
            {s.counts.not_installed > 0 && (
              <p className="sys-foot">
                Services marked Not installed are not part of this install (the lite stack runs a smaller set).
                Everything that is installed keeps working without them.
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
