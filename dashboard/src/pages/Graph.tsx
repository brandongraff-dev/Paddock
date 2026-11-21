import GraphCanvas from "../components/GraphCanvas";
import { useFullGraph } from "../hooks/useAssets";
import { useFindingsInfinite } from "../hooks/useFindings";

export default function GraphPage() {
  const g = useFullGraph(400);
  const findings = useFindingsInfinite({ status: "open" });

  if (g.isLoading) {
    return (
      <div className="graph-wrap">
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--text-2)",
            fontFamily: "var(--mono)",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            fontSize: 11,
          }}
        >
          Resolving graph…
        </div>
      </div>
    );
  }
  if (g.isError) {
    return (
      <div className="graph-wrap">
        <div style={{ padding: 24, color: "var(--bad)" }}>
          Failed to load graph: {(g.error as Error).message}
        </div>
      </div>
    );
  }

  const nodes = g.data?.nodes ?? [];
  const edges = g.data?.edges ?? [];
  const allFindings = (findings.data?.pages ?? []).flat();

  return <GraphCanvas assets={nodes} edges={edges} findings={allFindings} />;
}
