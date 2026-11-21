import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import { ask, listClusters } from "../api/ask";
import type { AskResult, FindingCluster } from "../api/types";

/* ------------------------------ constants ------------------------------ */

const EXAMPLES = [
  "which internet-facing hosts run end-of-life software with a KEV CVE?",
  "show critical findings opened in the last 7 days",
  "which assets have the most open high-severity findings?",
  "list attack paths that end at a crown-jewel asset",
  "which subdomains have an expiring TLS certificate?",
];

const RECENT_KEY = "pa.ask.recent";
const RECENT_MAX = 8;

/* ------------------------------- helpers ------------------------------- */

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "string").slice(0, RECENT_MAX) : [];
  } catch {
    return [];
  }
}

function saveRecent(list: string[]): void {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, RECENT_MAX)));
  } catch {
    /* non-fatal: private mode / blocked storage */
  }
}

/** Normalize a result row (positional array or column-keyed object) to cells. */
function cellsOf(
  row: AskResult["rows"][number],
  columns: string[],
): (string | number | boolean | null)[] {
  if (Array.isArray(row)) return row;
  const obj = row as Record<string, unknown>;
  return columns.map((c) => {
    const v = obj[c];
    return v == null ? null : (typeof v === "object" ? JSON.stringify(v) : (v as string | number | boolean));
  });
}

function fmtCell(v: string | number | boolean | null): string {
  if (v == null) return "—";
  return String(v);
}

function engineClass(engine: string): string {
  if (engine === "llm") return "ok";
  if (engine === "fallback") return "neutral";
  return "warn"; // unavailable / anything else
}

/* ------------------------------ sub-views ------------------------------ */

function EngineBadge({ engine }: { engine: string }) {
  return <span className={`ask-engine ask-engine-${engineClass(engine)} mono`}>engine · {engine}</span>;
}

function ResultTable({ result }: { result: AskResult }) {
  const cols = result.columns ?? [];
  if (cols.length === 0 || result.rows.length === 0) {
    return <EmptyState title="Query ran, but returned no rows." />;
  }
  return (
    <div className="ask-table-wrap">
      <table className="ask-table">
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c} className="mono">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {result.rows.map((row, i) => {
            const cells = cellsOf(row, cols);
            return (
              <tr key={i}>
                {cols.map((_, j) => (
                  <td key={j} className="mono" title={fmtCell(cells[j])}>
                    {fmtCell(cells[j])}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SqlBlock({ sql, ok }: { sql: string; ok: boolean }) {
  const [open, setOpen] = useState(true);
  if (!sql) return null;
  return (
    <div className="ask-sql">
      <button type="button" className="ask-sql-toggle" onClick={() => setOpen((v) => !v)}>
        <span>{open ? "▾" : "▸"} generated SQL</span>
        <span className={`ask-sql-badge mono ${ok ? "ok" : "muted"}`}>
          {ok ? "read-only · validated" : "attempted · not executed"}
        </span>
      </button>
      {open && <pre className="ask-sql-code mono">{sql}</pre>}
    </div>
  );
}

function TriageClusters() {
  const q = useQuery({ queryKey: ["clusters"], queryFn: listClusters, staleTime: 30_000 });
  const clusters = q.data ?? [];
  if (q.isLoading || clusters.length === 0) return null;
  return (
    <div className="panel">
      <div className="panel-h">
        <h2>Triage clusters</h2>
        <span style={{ color: "var(--text-2)", fontSize: 11 }}>
          {clusters.length} cluster{clusters.length === 1 ? "" : "s"} · LLM / template
        </span>
      </div>
      <div className="cluster-list">
        {clusters.map((c: FindingCluster) => (
          <article key={c.id} className="cluster-card">
            <div className="cluster-h">
              {c.severity && <SeverityChip severity={c.severity} compact />}
              <span className="cluster-label">{c.label}</span>
              <span className={`cluster-engine mono ${c.engine === "llm" ? "llm" : ""}`}>{c.engine}</span>
              {(c.size ?? c.finding_ids?.length) != null && (
                <span className="cluster-size mono">{c.size ?? c.finding_ids?.length} findings</span>
              )}
            </div>
            {c.summary && <p className="cluster-summary">{c.summary}</p>}
            {c.remediation && <p className="cluster-rem">↳ {c.remediation}</p>}
          </article>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function AskPage() {
  const [question, setQuestion] = useState("");
  const [recent, setRecent] = useState<string[]>(() => loadRecent());
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const mut = useMutation({
    mutationFn: (q: string) => ask(q),
    onSuccess: (_data, q) => {
      setRecent((prev) => {
        const next = [q, ...prev.filter((x) => x !== q)].slice(0, RECENT_MAX);
        saveRecent(next);
        return next;
      });
    },
  });

  const result = mut.data;

  const submit = (q: string) => {
    const text = q.trim();
    if (!text || mut.isPending) return;
    setQuestion(text);
    mut.mutate(text);
  };

  const placeholder = useMemo(() => EXAMPLES[0], []);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Ask</h1>
          <div className="subtitle">
            Ask the attack surface a question in plain language. Every question is translated to a
            single read-only <span className="mono">SELECT</span>, validated server-side, and run
            against three allow-listed views — never a shell, never a write.
          </div>
        </div>
      </div>

      <div className="panel ask-box">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit(question);
          }}
        >
          <div className="ask-input-row">
            <textarea
              ref={inputRef}
              className="ask-input"
              rows={2}
              value={question}
              placeholder={placeholder}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  submit(question);
                }
              }}
            />
            <button type="submit" className="primary ask-submit" disabled={mut.isPending || !question.trim()}>
              {mut.isPending ? "Asking…" : "Ask"}
            </button>
          </div>
          <div className="ask-hint mono">
            <span className="kbd">enter</span> to ask · <span className="kbd">shift</span>+
            <span className="kbd">enter</span> for newline
          </div>
        </form>

        <div className="ask-examples">
          <span className="ask-examples-label">Try</span>
          {EXAMPLES.map((ex) => (
            <button key={ex} type="button" className="ask-chip" onClick={() => submit(ex)}>
              {ex}
            </button>
          ))}
        </div>
      </div>

      {mut.isError && (
        <div className="panel ask-error">
          Could not reach the query service. It may be degraded — try again shortly.
        </div>
      )}

      {result && (
        <div className="panel ask-result">
          <div className="ask-result-h">
            <div className="ask-result-status">
              {result.ok ? (
                <span className="ask-ok mono">✓ answered</span>
              ) : (
                <span className="ask-bad mono">✕ not answered</span>
              )}
              <EngineBadge engine={result.engine} />
            </div>
          </div>

          {result.ok ? (
            <ResultTable result={result} />
          ) : (
            <div className="ask-fail">
              <div className="ask-fail-reason">
                {result.error || result.note || "The question could not be turned into a safe, validated query."}
              </div>
            </div>
          )}

          <SqlBlock sql={result.generated_sql} ok={result.ok} />

          {result.note && result.ok && <div className="ask-note">{result.note}</div>}
        </div>
      )}

      {recent.length > 0 && (
        <div className="panel ask-recent">
          <div className="panel-h">
            <h2>Recent questions</h2>
            <span style={{ color: "var(--text-2)", fontSize: 11 }}>this browser only</span>
          </div>
          <div className="ask-recent-list">
            {recent.map((r) => (
              <button key={r} type="button" className="ask-recent-item" onClick={() => submit(r)}>
                <span className="ask-recent-glyph mono">⟲</span>
                <span className="ask-recent-text">{r}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <TriageClusters />
    </div>
  );
}
