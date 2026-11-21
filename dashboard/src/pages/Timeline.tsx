import Timeline from "../components/Timeline";
import { useTimeline } from "../hooks/useFindings";
import { useStore } from "../state/store";

export default function TimelinePage() {
  const q = useTimeline();
  const setFilter = useStore((s) => s.setFilter);
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Timeline</h1>
          <div className="subtitle">Daily ledger of new assets, findings, and scans.</div>
        </div>
      </div>
      {q.isLoading && <div style={{ color: "var(--text-2)" }}>Loading timeline…</div>}
      {q.isError && <div style={{ color: "var(--bad)" }}>Failed to load timeline.</div>}
      {q.data && (
        <Timeline
          days={q.data}
          onDaySelect={(date) => setFilter({ date })}
        />
      )}
    </div>
  );
}
