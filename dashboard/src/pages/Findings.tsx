import { useEffect, useMemo, useRef, useState } from "react";
import FindingRow from "../components/FindingRow";
import FilterBar from "../components/FilterBar";
import EmptyState from "../components/EmptyState";
import { useFindingsInfinite, usePatchFinding } from "../hooks/useFindings";
import type { Finding, FindingStatus, Severity } from "../api/types";
import { useStore } from "../state/store";

export default function FindingsPage() {
  const [sev, setSev] = useState<Severity[]>([]);
  const [status, setStatus] = useState<string>("");
  const [ruleSource, setRuleSource] = useState<string>("");
  const [text, setText] = useState<string>("");
  const [kevOnly, setKevOnly] = useState<boolean>(false);

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
    }),
    [sev, status, ruleSource, kevOnly, text],
  );

  const q = useFindingsInfinite(filter);
  const items = useMemo<Finding[]>(() => {
    const rows = (q.data?.pages ?? []).flat();
    if (sev.length <= 1) return rows;
    return rows.filter((r) => sev.includes(r.severity));
  }, [q.data, sev]);

  const openDrawer = useStore((s) => s.openDrawer);
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
            <EmptyState title="No findings match these filters." />
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
