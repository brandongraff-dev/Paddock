/**
 * "Connect anything" panel for the Integrations page.
 *
 * Create an ingest source (a token that can only POST /v1/ingest), copy the
 * token once, then copy a ready-made snippet for curl / GitHub Actions /
 * GitLab / Python / TypeScript, or the MCP config for Claude Desktop / Cursor.
 * Uses the existing glass `panel` / `table` / `chip` classes; only layout lives
 * in connect.css. Mutations sit inside <Gate need="admin"> (the API enforces
 * admin too).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import {
  createIngestSource,
  listIngestLog,
  listIngestSources,
  revokeIngestSource,
  rotateIngestSource,
  type IngestSource,
} from "../api/ingest";
import { API_BASE } from "../api/client";
import { SNIPPET_HINT, SNIPPET_LABEL, SNIPPET_ORDER, snippetFor, type SnippetKind } from "../lib/connectSnippets";
import EmptyState from "./EmptyState";
import Gate from "./Gate";
import "../styles/connect.css";

function origin(): string {
  if (API_BASE) return API_BASE;
  return typeof window !== "undefined" ? window.location.origin : "";
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  return (
    <button
      type="button"
      className="ghost ig-small"
      onClick={async () => {
        setState((await copyText(text)) ? "ok" : "fail");
        setTimeout(() => setState("idle"), 1800);
      }}
    >
      {state === "ok" ? "Copied" : state === "fail" ? "Copy failed" : label}
    </button>
  );
}

function ago(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export default function ConnectAnything() {
  const qc = useQueryClient();
  const sources = useQuery({ queryKey: ["ingest-sources"], queryFn: listIngestSources, refetchInterval: 20_000 });
  const log = useQuery({ queryKey: ["ingest-log"], queryFn: () => listIngestLog(6), refetchInterval: 20_000 });
  const [name, setName] = useState("");
  const [project, setProject] = useState("");
  const [fresh, setFresh] = useState<IngestSource | null>(null);
  const [tab, setTab] = useState<SnippetKind>("curl");
  const [err, setErr] = useState<string | null>(null);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["ingest-sources"] });
    qc.invalidateQueries({ queryKey: ["ingest-log"] });
  };
  const fail = (e: unknown) => {
    const body = (e as { body?: { detail?: unknown } })?.body;
    setErr(typeof body?.detail === "string" ? body.detail : e instanceof Error ? e.message : "Request failed");
  };
  const create = useMutation({
    mutationFn: () => createIngestSource({ name: name.trim(), default_project: project.trim() || undefined }),
    onSuccess: (s) => { setFresh(s); setName(""); setProject(""); setErr(null); refresh(); },
    onError: fail,
  });
  const rotate = useMutation({
    mutationFn: (id: string) => rotateIngestSource(id),
    onSuccess: (s) => { setFresh(s); setErr(null); refresh(); },
    onError: fail,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => revokeIngestSource(id),
    onSuccess: (s) => { setFresh((f) => (f?.id === s.id ? null : f)); setErr(null); refresh(); },
    onError: fail,
  });

  const items = sources.data?.items ?? [];
  const ctx = { baseUrl: origin(), project: fresh?.default_project ?? undefined };
  const snippet = snippetFor(tab, ctx);
  const submit = (e: FormEvent) => { e.preventDefault(); if (name.trim()) create.mutate(); };

  return (
    <section className="panel cn-panel" aria-label="Connect anything">
      <div className="panel-h">
        <h2>Connect anything</h2>
        <span className="ig-muted">SARIF, CycloneDX, SPDX, OCSF, Trivy, Grype, Semgrep, Nuclei, ZAP, CSV</span>
      </div>
      <div className="cn-body">
        <p className="ig-muted cn-lead">
          Create a source for each tool or pipeline. Its token can only send results to Paddock: it is
          revocable, rate-limited, and every upload is audit-logged.
        </p>

        <Gate need="admin">
          <form className="cn-create" onSubmit={submit}>
            <div className="ig-field">
              <label htmlFor="cn-name">Source name</label>
              <input id="cn-name" value={name} maxLength={64} placeholder="ci-trivy"
                     onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="ig-field">
              <label htmlFor="cn-project">Default project (optional)</label>
              <input id="cn-project" value={project} maxLength={200} placeholder="acme/web"
                     onChange={(e) => setProject(e.target.value)} />
            </div>
            <button type="submit" disabled={!name.trim() || create.isPending}>
              {create.isPending ? "Creating…" : "New source"}
            </button>
          </form>
        </Gate>
        {err && <div className="ig-banner" role="alert">{err}</div>}

        {fresh?.token && (
          <div className="cn-reveal" role="status">
            <div className="cn-reveal-h">
              <strong>Token for {fresh.name}</strong>
              <span className="ig-muted">Shown once. Store it as a CI secret.</span>
            </div>
            <div className="cn-token">
              <code className="mono" data-testid="ingest-token">{fresh.token}</code>
              <CopyButton text={fresh.token} label="Copy token" />
            </div>
            <div className="cn-token">
              <code className="mono">{fresh.url}</code>
              <CopyButton text={fresh.url} label="Copy URL" />
            </div>
          </div>
        )}

        {sources.isLoading ? (
          <div className="ig-muted ig-pad">Loading…</div>
        ) : sources.isError ? (
          <EmptyState title="Couldn't load sources" hint="Listing sources needs the admin role." />
        ) : items.length === 0 ? (
          <EmptyState title="No sources yet" hint="Create one above, then paste a snippet into your pipeline." />
        ) : (
          <table className="table cn-table">
            <thead>
              <tr><th>Source</th><th>Token</th><th>Last used</th><th className="ig-num">Uploads</th><th /></tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>
                    {s.name}
                    {s.default_project && <span className="ig-muted"> · {s.default_project}</span>}
                    {!s.enabled && <span className="chip chip-status"> disabled</span>}
                  </td>
                  <td className="mono">pdi_…{s.token_prefix}</td>
                  <td>{ago(s.last_used_at)}</td>
                  <td className="ig-num mono">{s.ingest_count}</td>
                  <td className="ig-num ig-nowrap">
                    <Gate need="admin">
                      <button className="ghost ig-small" onClick={() => rotate.mutate(s.id)}
                              aria-label={`Rotate token for ${s.name}`}>Rotate</button>{" "}
                      <button className="ghost ig-small" onClick={() => revoke.mutate(s.id)}
                              aria-label={`Revoke ${s.name}`}>Revoke</button>
                    </Gate>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="cn-tabs" role="tablist" aria-label="Snippets">
          {SNIPPET_ORDER.map((k) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`cn-tab${tab === k ? " on" : ""}`}
                    onClick={() => setTab(k)}>
              {SNIPPET_LABEL[k]}
            </button>
          ))}
        </div>
        <div className="cn-snippet">
          <pre className="mono" aria-label={`${SNIPPET_LABEL[tab]} snippet`}>{snippet}</pre>
          <CopyButton text={snippet} label="Copy snippet" />
        </div>
        <div className="ig-muted">{SNIPPET_HINT[tab]}</div>

        {(log.data?.items?.length ?? 0) > 0 && (
          <>
            <div className="cn-sub">Recent uploads</div>
            <table className="table cn-table">
              <thead><tr><th>When</th><th>Source</th><th>Format</th><th>Result</th></tr></thead>
              <tbody>
                {log.data!.items.map((r) => (
                  <tr key={r.id}>
                    <td>{ago(r.created_at)}</td>
                    <td>{r.source_name}</td>
                    <td className="mono">{r.format ?? "?"}</td>
                    <td>
                      {r.status === "rejected"
                        ? <span className="ig-bad" title={r.errors[0]?.message}>rejected ({r.http_status})</span>
                        : <>{r.findings_new} new, {r.findings_updated} updated{r.components ? `, ${r.components} components` : ""}</>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  );
}
