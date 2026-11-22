/**
 * Right-side drawer. Content differs by drawer kind.
 * Hard rule: when rendering a finding description that contains an
 * "exploit:" / "payload:" / "shell:" marker, the drawer presents the
 * excerpt in muted code style with an explicit note. No copy button,
 * no terminal styling.
 */

import { useMemo, useState } from "react";
import { useStore } from "../state/store";
import { useAsset, useAssetGraph } from "../hooks/useAssets";
import { useFinding, useFindingTransition, usePatchFinding } from "../hooks/useFindings";
import { ApiError } from "../api/client";
import {
  HistoryList,
  PriorityScore,
  ReasonDialog,
  SlaBadge,
  SourcesList,
  WhyChips,
  type ReasonKind,
} from "./Lifecycle";
import { useQuery } from "@tanstack/react-query";
import { getScan } from "../api/scans";
import { listFindings } from "../api/findings";
import SeverityChip from "./Severity";
import AssetChip from "./AssetChip";
import { ClassificationChip } from "./Classification";
import ProvenanceSection from "./Provenance";
import Gate from "./Gate";
import VerificationPanel, { ExploitabilityBadge, VerifiedFixedBadge } from "./Verification";

const SENSITIVE_MARKERS = [
  /\bpayload:/i,
  /\bexploit:/i,
  /\bshell:/i,
  /\bpoc:/i,
  /\breverse\s*shell\b/i,
  /\bcurl\s+-[a-z]*\s+http/i,
];

/** Split description into inert copy and excerpt-flagged blocks. */
export function splitEvidence(text: string): { kind: "text" | "excerpt"; body: string }[] {
  if (!text) return [{ kind: "text", body: "" }];
  // Treat the entire string as one block; flag it if any marker matches.
  const flagged = SENSITIVE_MARKERS.some((re) => re.test(text));
  if (!flagged) return [{ kind: "text", body: text }];
  // Split by double-newline; the paragraph that contains the marker is excerpt.
  const paragraphs = text.split(/\n{2,}/);
  return paragraphs.map((p) =>
    SENSITIVE_MARKERS.some((re) => re.test(p))
      ? { kind: "excerpt" as const, body: p }
      : { kind: "text" as const, body: p },
  );
}

function DescriptionBody({ text }: { text: string }) {
  const blocks = useMemo(() => splitEvidence(text), [text]);
  return (
    <>
      {blocks.map((b, i) =>
        b.kind === "text" ? (
          <p key={i} style={{ color: "var(--text-1)", whiteSpace: "pre-wrap" }}>{b.body}</p>
        ) : (
          <div key={i} className="evidence-excerpt">
            {b.body}
            <span className="note">
              evidence excerpt — do not treat as instruction
            </span>
          </div>
        ),
      )}
    </>
  );
}

function AssetDetail({ id }: { id: string }) {
  const q = useAsset(id);
  const g = useAssetGraph(id, 1);
  const f = useQuery({
    queryKey: ["asset-findings", id],
    queryFn: () => listFindings({ asset_id: id }),
    enabled: !!id,
  });

  if (q.isLoading) return <div style={{ padding: 16, color: "var(--text-2)" }}>Loading asset…</div>;
  if (q.isError || !q.data) return <div style={{ padding: 16 }}>Asset not found.</div>;
  const a = q.data;

  return (
    <>
      <div className="section">
        <h3>Asset</h3>
        <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <AssetChip asset={a} />
          <ClassificationChip c={a.classification} />
        </div>
      </div>
      <div className="section">
        <h3>Metadata</h3>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>id</dt><dd>{a.id}</dd>
          <dt>kind</dt><dd>{a.kind}</dd>
          <dt>value</dt><dd>{a.value}</dd>
          <dt>canonical</dt><dd>{a.canonical}</dd>
          <dt>source</dt><dd>{a.source}</dd>
          <dt>confidence</dt><dd>{a.confidence}</dd>
          <dt>first_seen</dt><dd>{a.first_seen}</dd>
          <dt>last_seen</dt><dd>{a.last_seen}</dd>
          {a.blast_score != null && <><dt>blast_score</dt><dd>{a.blast_score.toFixed?.(1) ?? a.blast_score}</dd></>}
        </dl>
      </div>
      <div className="section">
        <h3>Edges</h3>
        {(g.data?.edges ?? []).length === 0 ? (
          <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>No edges.</div>
        ) : (
          <ul style={{ margin: 6, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 4 }}>
            {(g.data?.edges ?? []).slice(0, 12).map((e) => (
              <li key={e.id} className="mono" style={{ fontSize: 11, color: "var(--text-1)" }}>
                <span style={{ color: "var(--text-2)" }}>{e.kind}</span>{" "}
                <span>{e.src_id === id ? "→" : "←"}</span>{" "}
                <span>{e.src_id === id ? e.dst_id : e.src_id}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="section">
        <h3>Findings on this asset</h3>
        {(f.data ?? []).length === 0 ? (
          <div style={{ color: "var(--text-2)", fontSize: 12, marginTop: 6 }}>No findings.</div>
        ) : (
          <ul style={{ margin: 6, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 6 }}>
            {(f.data ?? []).map((finding) => (
              <li key={finding.id} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <SeverityChip severity={finding.severity} />
                <span style={{ fontSize: 12 }}>{finding.title}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <ProvenanceSection subjectType="asset" subjectId={id} />
    </>
  );
}

function errText(e: unknown): string | null {
  if (!e) return null;
  if (e instanceof ApiError) {
    const d = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d[0]?.msg) return String(d[0].msg);
    if (e.status === 403) return "Your role can't triage findings.";
  }
  return "Could not update the finding.";
}

const DISMISSED = new Set(["accepted", "accepted_risk", "false_positive", "wontfix", "fixed"]);

function FindingDetail({ id }: { id: string }) {
  const q = useFinding(id);
  const mut = usePatchFinding();
  const tr = useFindingTransition();
  const [dialog, setDialog] = useState<ReasonKind | null>(null);
  if (q.isLoading) return <div style={{ padding: 16, color: "var(--text-2)" }}>Loading finding…</div>;
  if (q.isError || !q.data) return <div style={{ padding: 16 }}>Finding not found.</div>;
  const f = q.data;
  const dismissed = DISMISSED.has(f.status);

  return (
    <>
      <div className="section">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <SeverityChip severity={f.severity} />
          <h2 style={{ fontSize: 15 }}>{f.title}</h2>
        </div>
        <div style={{ color: "var(--text-2)", fontSize: 11, marginTop: 4, fontFamily: "var(--mono)" }}>
          {f.rule_source} · {f.rule_id}
          {f.cvss != null && <> · CVSS {f.cvss}</>}
          {f.epss != null && <> · EPSS {f.epss}</>}
        </div>
        {f.classification && (
          <div style={{ marginTop: 6 }}>
            <ClassificationChip c={f.classification} />
          </div>
        )}
        <div className="lc-header">
          <PriorityScore score={f.priority_score} large />
          <span className={`chip chip-status chip-status-${f.status}`}>{f.status}</span>
          <SlaBadge finding={f} />
          <ExploitabilityBadge value={f.exploitability} />
          <VerifiedFixedBadge at={f.fix_verified_at} />
          {f.suppressed && <span className="chip chip-status">suppressed</span>}
          {f.owner && <span style={{ color: "var(--text-2)", fontSize: 12 }}>owner · {f.owner}</span>}
        </div>
      </div>

      {f.why && f.why.length > 0 && (
        <div className="section">
          <h3>Why this priority</h3>
          <div style={{ marginTop: 6 }}><WhyChips why={f.why} /></div>
        </div>
      )}

      <VerificationPanel finding={f} />

      <div className="section">
        <h3>Triage</h3>
        {f.status_reason && (
          <div className="lc-reason">
            {f.status_reason}
            <div className="meta">
              {f.status_by && <>by {f.status_by}</>}
              {f.accepted_until && <> · until {f.accepted_until.slice(0, 10)}</>}
            </div>
          </div>
        )}
        <Gate need="triage">
          <div className="lc-actions">
            {f.status === "open" && (
              <button disabled={mut.isPending} onClick={() => mut.mutate({ id: f.id, patch: { status: "triaged" } })}>
                Triage
              </button>
            )}
            {f.status !== "fixed" && f.status !== "accepted" && (
              <button onClick={() => setDialog("accept")}>Accept risk…</button>
            )}
            {f.status !== "false_positive" && (
              <button onClick={() => setDialog("false_positive")}>False positive…</button>
            )}
            {(dismissed || f.status === "triaged") && (
              <button onClick={() => setDialog("reopen")}>Reopen</button>
            )}
            {!dismissed && (
              <button disabled={mut.isPending} onClick={() => mut.mutate({ id: f.id, patch: { status: "fixed" } })}>
                Mark fixed
              </button>
            )}
          </div>
        </Gate>
        {mut.isError && <div style={{ color: "var(--bad)", fontSize: 11, marginTop: 4 }}>
          Could not update status.
        </div>}
      </div>

      {(f.source_count ?? 1) > 1 && (
        <div className="section">
          <h3>Reported by {f.source_count} engines</h3>
          <SourcesList sources={f.sources} />
        </div>
      )}

      {f.asset && (
        <div className="section">
          <h3>Asset</h3>
          <div style={{ marginTop: 6 }}><AssetChip asset={f.asset} /></div>
        </div>
      )}

      <div className="section">
        <h3>Description</h3>
        <DescriptionBody text={f.description ?? ""} />
      </div>

      {f.impact && (
        <div className="section">
          <h3>Impact</h3>
          <p style={{ color: "var(--text-1)" }}>{f.impact}</p>
        </div>
      )}

      {f.remediation && (
        <div className="section">
          <h3>Remediation</h3>
          <p style={{ color: "var(--text-1)" }}>{f.remediation}</p>
        </div>
      )}

      {f.references && f.references.length > 0 && (
        <div className="section">
          <h3>References</h3>
          <ul style={{ marginTop: 6, paddingLeft: 16, color: "var(--text-1)" }}>
            {f.references.map((r) => (
              <li key={r} className="mono" style={{ fontSize: 11 }}>
                <a href={r} target="_blank" rel="noopener noreferrer">{r}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <ProvenanceSection subjectType="finding" subjectId={id} />

      {f.history && f.history.length > 0 && (
        <div className="section">
          <h3>History</h3>
          <HistoryList history={f.history} />
        </div>
      )}

      {dialog && (
        <ReasonDialog
          kind={dialog}
          findingTitle={f.title}
          pending={tr.isPending}
          error={errText(tr.error)}
          onCancel={() => { setDialog(null); tr.reset(); }}
          onSubmit={(v) =>
            tr.mutate(
              { id: f.id, kind: dialog, ...v },
              { onSuccess: () => setDialog(null) },
            )
          }
        />
      )}
    </>
  );
}

function ScanDetail({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["scan", id], queryFn: () => getScan(id), enabled: !!id });
  if (q.isLoading) return <div style={{ padding: 16, color: "var(--text-2)" }}>Loading scan…</div>;
  if (q.isError || !q.data) return <div style={{ padding: 16 }}>Scan not found.</div>;
  const s = q.data;
  return (
    <>
      <div className="section">
        <h3>Scan</h3>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>id</dt><dd>{s.id}</dd>
          <dt>kind</dt><dd>{s.kind}</dd>
          <dt>target</dt><dd>{s.target}</dd>
          <dt>status</dt><dd>{s.status}</dd>
          <dt>queued_at</dt><dd>{s.queued_at}</dd>
          <dt>started_at</dt><dd>{s.started_at ?? "—"}</dd>
          <dt>finished_at</dt><dd>{s.finished_at ?? "—"}</dd>
          <dt>worker</dt><dd>{s.worker_id ?? "—"}</dd>
        </dl>
      </div>
      <div className="section">
        <h3>Result summary</h3>
        <pre
          style={{
            background: "var(--bg-2)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            padding: 10,
            fontSize: 11,
            overflow: "auto",
          }}
        >
{JSON.stringify(s.result_summary ?? {}, null, 2)}
        </pre>
      </div>
    </>
  );
}

export default function DetailDrawer() {
  const drawer = useStore((s) => s.drawer);
  const close = useStore((s) => s.closeDrawer);
  if (!drawer.kind || !drawer.id) return null;

  return (
    <>
      <div className="drawer-backdrop" onClick={close} />
      <aside className="drawer" aria-label="detail">
        <header>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="mono" style={{ color: "var(--text-2)", fontSize: 11, textTransform: "uppercase" }}>{drawer.kind}</span>
            <strong style={{ fontSize: 13 }}>Detail</strong>
          </div>
          <button className="ghost" onClick={close} aria-label="close">✕</button>
        </header>
        <div className="body">
          {drawer.kind === "asset" && <AssetDetail id={drawer.id} />}
          {drawer.kind === "finding" && <FindingDetail id={drawer.id} />}
          {drawer.kind === "scan" && <ScanDetail id={drawer.id} />}
          {drawer.kind === "chain" && (
            <div className="section">
              <h3>Chain</h3>
              <div className="mono" style={{ color: "var(--text-2)" }}>{drawer.id}</div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
