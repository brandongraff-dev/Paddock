import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import FindingRow from "../components/FindingRow";
import FilterBar from "../components/FilterBar";
import EmptyState from "../components/EmptyState";
import "../styles/lifecycle.css";
import { useFindingCounts, useFindingsInfinite, usePatchFinding, type FindingFilter } from "../hooks/useFindings";
import type { Finding, FindingStatus, Severity } from "../api/types";
import { useStore } from "../state/store";

export default function FindingsPage() {
  const [sev, setSev] = useState<Severity[]>([]);
  const [status, setStatus] = useState<string>("");
  const [ruleSource, setRuleSource] = useState<string>("");
  const [text, setText] = useState<string>("");
  const [kevOnly, setKevOnly] = useState<boolean>(false);
  // Suppressed findings are stored but hidden by default; this flips the
  // list to show only them (server: ?suppressed=only).
  const [view, setView] = useState<"active" | "suppressed">("active");
  const [breachedOnly, setBreachedOnly] = useState<boolean>(false);
  // Safe-check verdict filter (schema 026): "" = any.
  const [exploit, setExploit] = useState<string>("");

  // Only pick one severity at a time on the URL-query side; multi-select is a
  // UI convenience filter we apply client-side. Server currently takes a
  // single value per CONTRACTS.md.
  const filter = useMemo(
    () => ({
      severity: sev.length === 1 ? sev[0] : undefined,
      status: (status || undefined) as FindingStatus | undefined,
      rule_source: ruleSource || undefined,
      kev: kevOnly || undefined,
      q: text || undefined,
      sla_breached: breachedOnly || undefined,
      exploitability: (exploit || undefined) as FindingFilter["exploitability"],
    }),
    [sev, status, ruleSource, kevOnly, text, breachedOnly, exploit],
  );
  const listFilter = useMemo(
    () => ({ ...filter, suppressed: view === "suppressed" ? ("only" as const) : undefined }),
    [filter, view],
  );

  const q = useFindingsInfinite(listFilter);
  const counts = useFindingCounts(filter);
  const items = useMemo<Finding[]>(() => {
    const rows = (q.data?.pages ?? []).flat();
    if (sev.length <= 1) return rows;
    return rows.filter((r) => sev.includes(r.severity));
  }, [q.data, sev]);

  const openDrawer = useStore((s) => s.openDrawer);
  // Deep links from notifications (Slack, Jira, email, webhooks) arrive as
  // /findings?focus=<finding id>: open that finding once, then drop the param.
  const [params, setParams] = useSearchParams();
  const focus = params.get("focus");
  useEffect(() => {
    if (!focus) return;
    openDrawer({ kind: "finding", id: focus });
    const next = new URLSearchParams(params);
    next.delete("focus");
    setParams(next, { replace: true });
  }, [focus, openDrawer, params, setParams]);
  const patch = usePatchFinding();
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLDivElement | null>(null);

  // j/k keyboard nav
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (/input|textarea|select/i.test((e.target as HTMLElement)?.tagName ?? "")) return;
      if (e.key === "j") setCursor((c) => Math.min(items.length - 1, c + 1));
      else if (e.key === "k") setCursor((c) => Math.max(0, c - 1));
      else if (e.key === "Enter") {
        const f = items[cursor];
        if (f) openDrawer({ kind: "finding", id: f.id });
      } else if (e.key === "s") {
        const f = items[cursor];
        if (f) patch.mutate({ id: f.id, patch: { status: "triaged" } });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [cursor, items, openDrawer, patch]);

  // Infinite scroll — observe sentinel
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting) && q.hasNextPage && !q.isFetchingNextPage) {
        q.fetchNextPage();
      }
    }, { rootMargin: "400px" });
    io.observe(el);
    return () => io.disconnect();
  }, [q]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Findings</h1>
          <div className="subtitle">
            <span className="kbd">j</span>/<span className="kbd">k</span> move ·{" "}
            <span className="kbd">enter</span> open drawer ·{" "}
            <span className="kbd">s</span> mark triaged
          </div>
        </div>
      </div>

      <div className="findings-toolbar">
        <div className="segmented" role="group" aria-label="finding visibility">
          <button aria-pressed={view === "active"} onClick={() => { setView("active"); setCursor(0); }}>
            Active
            {counts.data && <span className="n">{counts.data.total}</span>}
          </button>
          <button aria-pressed={view === "suppressed"} onClick={() => { setView("suppressed"); setCursor(0); }}>
            Suppressed
            <span className="n" data-testid="suppressed-count">{counts.data?.suppressed ?? 0}</span>
          </button>
        </div>
        <label className="checkchip" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={breachedOnly} onChange={(e) => setBreachedOnly(e.target.checked)} />
          SLA breached
        </label>
        <label className="checkchip" style={{ cursor: "pointer" }}>
          Exploitability
          <select
            aria-label="exploitability filter"
            value={exploit}
            onChange={(e) => { setExploit(e.target.value); setCursor(0); }}
          >
            <option value="">Any</option>
            <option value="confirmed">Verified exploitable</option>
            <option value="not_reproducible">Not reproducible</option>
            <option value="inconclusive">Inconclusive</option>
            <option value="unverified">Unverified</option>
          </select>
        </label>
        {(counts.data?.duplicates ?? 0) > 0 && (
          <span className="hint">
            {counts.data?.duplicates} duplicate report{counts.data?.duplicates === 1 ? "" : "s"} collapsed across engines
          </span>
        )}
        <span className="spacer" />
        <Link to="/suppressions" className="hint">Manage suppressions →</Link>
      </div>

      <FilterBar
        severity={sev}
        onSeverity={setSev}
        status={status}
        onStatus={setStatus}
        ruleSource={ruleSource}
        onRuleSource={setRuleSource}
        text={text}
        onText={setText}
        kevOnly={kevOnly}
        onKev={setKevOnly}
      />

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div className="finding-row" style={{ background: "var(--bg-1)", borderBottom: "1px solid var(--border)", color: "var(--text-2)", fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.08em", cursor: "default" }}>
          <div>Severity</div>
          <div>Title</div>
          <div>Asset</div>
          <div>Rule source</div>
          <div>Last seen</div>
          <div>Blast</div>
          <div>Status</div>
        </div>
        <div ref={listRef} style={{ maxHeight: "calc(100vh - 230px)", overflow: "auto" }}>
          {items.length === 0 && !q.isLoading && (
            <EmptyState
              title={view === "suppressed" ? "No suppressed findings." : "No findings match these filters."}
            />
          )}
          {items.map((f, i) => (
            <FindingRow
              key={f.id}
              finding={f}
              focused={i === cursor}
              onClick={(ff) => {
                setCursor(i);
                openDrawer({ kind: "finding", id: ff.id });
              }}
            />
          ))}
          <div ref={sentinelRef} style={{ height: 24 }} />
          {q.isFetchingNextPage && (
            <div style={{ padding: 10, color: "var(--text-2)", fontSize: 11, textAlign: "center" }}>
              Loading more…
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
