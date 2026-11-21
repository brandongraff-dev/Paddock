import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import EmptyState from "../components/EmptyState";
import {
  getRemediation,
  listRemediations,
  proposeRemediation,
  type RemediationDetail,
  type RemediationKind,
  type RemediationRow,
  type RemediationStatus,
} from "../api/remediation";
import "../styles/remediation.css";

/* ------------------------------ constants ------------------------------ */

const KIND_LABEL: Record<RemediationKind, string> = {
  dependency_bump: "dependency bump",
  security_header: "security header",
  config_fix: "config fix",
  tls_fix: "TLS fix",
  dotfile_block: "dotfile block",
};

const STATUS_FILTERS: (RemediationStatus | "")[] = [
  "",
  "verified",
  "pr_open",
  "rejected",
  "proposed",
  "failed",
];

const PAGE = 100;

function relTime(iso: string | null): string {
  if (!iso) return "—";
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

function StatusChip({ status }: { status: RemediationStatus }) {
  return <span className={`rem-status rem-status-${status}`}>{status.replace("_", " ")}</span>;
}

/* ------------------------- diff (read-only, plain) --------------------- */

function DiffView({ diff }: { diff: string | null }) {
  if (!diff) return <div className="rem-muted">No diff (nothing was generated).</div>;
  return (
    <pre className="rem-diff" aria-label="proposed diff (read-only)">
      {diff.split("\n").map((line, i) => {
        let cls = "ctx";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "meta";
        else if (line.startsWith("@@")) cls = "hunk";
        else if (line.startsWith("+")) cls = "add";
        else if (line.startsWith("-")) cls = "del";
        return (
          <div key={i} className={`rem-diff-line ${cls}`}>
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}

/* --------------------------- injection panel --------------------------- */

function InjectionPanel({ row }: { row: RemediationRow }) {
  const inj = row.injection;
  if (inj.blocked) {
    return (
      <div className="rem-check rem-check-bad">
        <span className="rem-check-dot bad" />
        <div>
          <div className="rem-check-title">Prompt-injection flagged</div>
          <div className="rem-check-sub mono">{inj.summary}</div>
          {inj.categories.length > 0 && (
            <div className="rem-tags">
              {inj.categories.map((c) => (
                <span key={c} className="rem-tag bad">
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }
  return (
    <div className="rem-check rem-check-ok">
      <span className="rem-check-dot ok" />
      <div>
        <div className="rem-check-title">No injection detected</div>
        <div className="rem-check-sub">
          Finding fields and the generated PR body were scanned for
          instruction-override / exploit / exfiltration patterns and hidden unicode.
        </div>
      </div>
    </div>
  );
}

/* ---------------------------- verifier panel --------------------------- */

function VerifierPanel({ row }: { row: RemediationRow }) {
  const v = row.verifier;
  const addresses = v.verify_ok === true;
  return (
    <div className={`rem-check ${addresses ? "rem-check-ok" : "rem-check-bad"}`}>
      <span className={`rem-check-dot ${addresses ? "ok" : "bad"}`} />
      <div>
        <div className="rem-check-title">
          {addresses ? "Adversarial verifier: addresses the finding" : "Verifier rejected"}
        </div>
        <div className="rem-check-sub">
          {addresses
            ? "A deterministic gate + an independent second pass confirm the diff addresses this finding and nothing else — no out-of-scope changes."
            : v.summary || v.rejection_reason || "The diff did not pass verification."}
        </div>
        <div className="rem-check-meta mono">
          gate: {v.gate_ok === true ? "pass" : v.gate_ok === false ? "fail" : "—"} · verify:{" "}
          {v.verify_ok === true ? "pass" : v.verify_ok === false ? "fail" : "—"}
          {v.pr_opened != null && <> · pr: {v.pr_opened ? "opened" : "not pushed"}</>}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ a row ---------------------------------- */

function RemediationCard({ row }: { row: RemediationRow }) {
  const [open, setOpen] = useState(false);
  const detail = useQuery({
    queryKey: ["remediation", row.id],
    queryFn: () => getRemediation(row.id),
    enabled: open,
    staleTime: 30_000,
  });

  return (
    <div className={`rem-card rem-card-${row.status}`}>
      <button type="button" className="rem-card-head" onClick={() => setOpen((o) => !o)}>
        <span className={`rem-caret ${open ? "open" : ""}`} aria-hidden>
          ▸
        </span>
        <StatusChip status={row.status} />
        <span className="rem-kind mono">{KIND_LABEL[row.kind] ?? row.kind}</span>
        <span className="rem-summary">{row.summary}</span>
        <span className="rem-spacer" />
        {row.injection.blocked && <span className="rem-flag mono">injection</span>}
        {row.pr_url && (
          <a
            className="rem-prlink mono"
            href={row.pr_url}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => e.stopPropagation()}
          >
            PR #{row.pr_number ?? "?"}
          </a>
        )}
        <span className="rem-time mono">{relTime(row.verified_at ?? row.created_at)}</span>
      </button>

      {open && (
        <div className="rem-card-body">
          <div className="rem-meta-line mono">
            {row.repo && <span>repo: {row.repo}</span>}
            {row.finding_id && <span>finding: {row.finding_id.slice(0, 8)}</span>}
            {row.head_branch && <span>branch: {row.head_branch}</span>}
          </div>

          <div className="rem-checks">
            <VerifierPanel row={row} />
            <InjectionPanel row={row} />
          </div>

          <div className="rem-diff-head">
            <span>Proposed diff</span>
            <span className="rem-muted">read-only · a human applies/approves it</span>
          </div>
          {detail.isLoading && <div className="rem-muted">Loading diff…</div>}
          {detail.isError && <div className="rem-err">Failed to load the diff.</div>}
          {detail.data && <DiffView diff={(detail.data as RemediationDetail).diff} />}
        </div>
      )}
    </div>
  );
}

/* ------------------------------- page ---------------------------------- */

export default function RemediationPage() {
  const qc = useQueryClient();
  const [status, setStatus] = useState<RemediationStatus | "">("");
  const [proposeId, setProposeId] = useState("");

  const filter = useMemo(
    () => ({ status: status || undefined, limit: PAGE }),
    [status],
  );

  const q = useQuery({
    queryKey: ["remediations", filter],
    queryFn: () => listRemediations(filter),
    staleTime: 10_000,
  });

  const items = q.data?.items ?? [];
  const counts = useMemo(() => {
    const c = { verified: 0, pr_open: 0, rejected: 0, total: items.length };
    for (const r of items) {
      if (r.status === "verified") c.verified += 1;
      else if (r.status === "pr_open") c.pr_open += 1;
      else if (r.status === "rejected") c.rejected += 1;
    }
    return c;
  }, [items]);

  const propose = useMutation({
    mutationFn: (fid: string) => proposeRemediation(fid.trim()),
    onSuccess: () => {
      setProposeId("");
      qc.invalidateQueries({ queryKey: ["remediations"] });
    },
  });

  return (
    <div className="page rem-page">
      <div className="page-header">
        <div>
          <h1>Remediation</h1>
          <div className="subtitle">
            Constrained, prompt-injection-hardened auto-fixes — proposed for human review.
          </div>
        </div>
      </div>

      <div className="rem-banner" role="note">
        <span className="rem-banner-icon" aria-hidden>
          ⚑
        </span>
        <span>
          Proposed fixes are <strong>never auto-merged</strong>. Every change is constrained to an
          allowlisted class, the diff is generated deterministically (never written by an LLM) and
          double-checked for prompt injection — <strong>a human approves the PR.</strong>
        </span>
      </div>

      <div className="stat-row">
        <StatTile label="Proposed fixes" value={q.data?.total ?? 0} accent="#9fc2d8" />
        <StatTile label="Verified" value={counts.verified} accent="#8fbf8a" />
        <StatTile label="PRs open" value={counts.pr_open} accent="#c9b5e0" />
        <StatTile label="Rejected" value={counts.rejected} accent="#e67350" />
      </div>

      <div className="panel rem-panel">
        <div className="panel-h">
          <h2>Proposed fixes</h2>
          <div className="rem-controls">
            <form
              className="rem-propose"
              onSubmit={(e) => {
                e.preventDefault();
                if (proposeId.trim()) propose.mutate(proposeId);
              }}
            >
              <input
                placeholder="finding id to propose a fix for…"
                value={proposeId}
                onChange={(e) => setProposeId(e.target.value)}
              />
              <button type="submit" className="primary" disabled={!proposeId.trim() || propose.isPending}>
                {propose.isPending ? "Proposing…" : "Propose fix"}
              </button>
            </form>
            <select value={status} onChange={(e) => setStatus(e.target.value as RemediationStatus | "")}>
              {STATUS_FILTERS.map((s) => (
                <option key={s || "all"} value={s}>
                  {s || "all statuses"}
                </option>
              ))}
            </select>
          </div>
        </div>

        {propose.data && propose.data.ok === false && (
          <div className="rem-propose-note mono">
            {propose.data.reason ?? propose.data.note ?? "rejected"}
          </div>
        )}

        <div className="rem-list">
          {q.isLoading && <div className="rem-muted">Loading proposals…</div>}
          {q.isError && <div className="rem-err">Failed to load remediations.</div>}
          {!q.isLoading && items.length === 0 && (
            <EmptyState
              title="No proposed fixes yet."
              hint="Propose a fix for a finding above, or let the pipeline run. Fixes appear here for review — they are never merged automatically."
            />
          )}
          {items.map((r) => (
            <RemediationCard key={r.id} row={r} />
          ))}
        </div>
      </div>
    </div>
  );
}
