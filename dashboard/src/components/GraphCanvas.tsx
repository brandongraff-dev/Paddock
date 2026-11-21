/**
 * GraphCanvas — the hero component.
 *
 * Renders the asset graph as a react-flow canvas with custom nodes.
 * Nodes are colored by kind, scaled by blast_score, and get a pulsing
 * ring if they carry an open high/critical finding.
 *
 * We don't let react-flow decide layout — layoutGraph() in lib/graph.ts
 * assigns deterministic left-to-right positions, so the graph *reads*
 * (domain → subdomain → ip → port → endpoint) instead of looking like
 * a bowl of spaghetti.
 *
 * Interaction extras live here (not in layoutGraph, which stays pure):
 *   - a cursor-following hover tooltip (non-interactive, never blocks clicks)
 *   - a "KEV only" chip that dims nodes that aren't KEV-affected or adjacent
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
  ReactFlowProvider,
  useReactFlow,
} from "reactflow";
import type { Asset, AssetEdge, AssetKind, Finding, Severity } from "../api/types";
import { distinctKinds, layoutGraph } from "../lib/graph";
import { kindColor } from "../lib/color";
import { useStore } from "../state/store";
import NodeTooltip, { type NodeTooltipData } from "./graph/NodeTooltip";
import "../styles/graph-extras.css";

/**
 * Local view of the extra fields the graph endpoint carries that aren't yet
 * in the shared api/types Asset. Cast at the edge, don't mutate the contract.
 */
type GraphAsset = Asset & {
  blast_score?: number | null;
  open_high_crit_count?: number;
};

interface Props {
  assets: Asset[];
  edges: AssetEdge[];
  findings?: Finding[];
}

function AssetNode({ data }: NodeProps) {
  const a = data.asset as GraphAsset;
  const hot = !!data.hot;
  const dimmed = !!data.dimmed;
  const color = data.color as string;
  return (
    <div
      className={`gn ${hot ? "hot" : ""} ${dimmed ? "gx-dim" : ""}`}
      style={{
        ["--kind-color" as any]: color,
        transform: `scale(${data.scale ?? 1})`,
        transformOrigin: "left center",
      }}
    >
      {hot && <span className="gn-pulse" />}
      <Handle type="target" position={Position.Left} />
      <div className="gn-kind">{a.kind}</div>
      <div className="gn-value" title={a.value}>{a.value}</div>
      <div className="gn-footer">
        <span>blast {Math.round(a.blast_score ?? 0)}</span>
        {typeof a.open_high === "number" && a.open_high > 0 && (
          <span style={{ color: "var(--sev-crit)" }}>{a.open_high}!</span>
        )}
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes: NodeTypes = { assetNode: AssetNode };

interface Hover {
  data: NodeTooltipData;
  x: number;
  y: number;
}

function InnerGraph({ assets, edges, findings }: Props) {
  const openDrawer = useStore((s) => s.openDrawer);
  const { fitView } = useReactFlow();

  const hotSet = useMemo(() => {
    const set = new Set<string>();
    for (const f of findings ?? []) {
      if ((f.severity === "high" || f.severity === "critical") && f.status === "open") {
        set.add(f.asset_id);
      }
    }
    return set;
  }, [findings]);

  // Open-finding counts per asset, by severity — drives the tooltip breakdown.
  const sevByAsset = useMemo(() => {
    const m = new Map<string, Partial<Record<Severity, number>>>();
    for (const f of findings ?? []) {
      if (f.status && f.status !== "open") continue;
      const cur = m.get(f.asset_id) ?? {};
      cur[f.severity] = (cur[f.severity] ?? 0) + 1;
      m.set(f.asset_id, cur);
    }
    return m;
  }, [findings]);

  // KEV set. Prefer explicit signals (asset metadata `kev`, or a finding
  // flagged kev); only if none exist anywhere fall back to the red-glow proxy
  // (open high/crit host == open_high_crit_count > 0).
  const kevSet = useMemo(() => {
    const explicit = new Set<string>();
    for (const a of assets as GraphAsset[]) {
      if (a.metadata && (a.metadata as Record<string, unknown>).kev) explicit.add(a.id);
    }
    for (const f of findings ?? []) {
      if (f.kev && (!f.status || f.status === "open")) explicit.add(f.asset_id);
    }
    return explicit.size > 0 ? explicit : hotSet;
  }, [assets, findings, hotSet]);

  const allKinds = useMemo(() => distinctKinds(assets), [assets]);
  const [enabledKinds, setEnabledKinds] = useState<Set<AssetKind>>(() => new Set(allKinds));
  const [kevOnly, setKevOnly] = useState(false);

  // Re-sync filter set when the underlying data changes.
  useEffect(() => {
    setEnabledKinds(new Set(allKinds));
  }, [allKinds]);

  const { nodes: baseNodes, edges: baseEdges } = useMemo(() => {
    const filteredAssets = assets.filter((a) => enabledKinds.has(a.kind));
    const allowed = new Set(filteredAssets.map((a) => a.id));
    const filteredEdges = edges.filter(
      (e) => allowed.has(e.src_id) && allowed.has(e.dst_id),
    );
    return layoutGraph({
      assets: filteredAssets,
      edges: filteredEdges,
      hot: hotSet,
    });
  }, [assets, edges, enabledKinds, hotSet]);

  // Nodes to keep lit when KEV-only is on: KEV nodes + their direct neighbours.
  const kevKeep = useMemo(() => {
    if (!kevOnly) return null;
    const keep = new Set<string>(kevSet);
    for (const e of edges) {
      if (kevSet.has(e.src_id)) keep.add(e.dst_id);
      if (kevSet.has(e.dst_id)) keep.add(e.src_id);
    }
    return keep;
  }, [kevOnly, kevSet, edges]);

  // Apply dimming without recomputing layout (cheap map over existing nodes).
  const displayNodes = useMemo<Node[]>(() => {
    if (!kevKeep) return baseNodes;
    return baseNodes.map((n) =>
      kevKeep.has(n.id)
        ? n
        : { ...n, data: { ...n.data, dimmed: true } },
    );
  }, [baseNodes, kevKeep]);

  const displayEdges = useMemo<Edge[]>(() => {
    if (!kevKeep) return baseEdges;
    return baseEdges.map((e) => {
      const lit = kevKeep.has(e.source) && kevKeep.has(e.target);
      return lit
        ? e
        : { ...e, style: { ...e.style, opacity: 0.05 }, label: undefined };
    });
  }, [baseEdges, kevKeep]);

  const onNodeClick = useCallback(
    (_: unknown, node: { id: string; data?: { dimmed?: boolean } }) => {
      if (node.data?.dimmed) return; // dimmed nodes are visually out of scope
      openDrawer({ kind: "asset", id: node.id });
    },
    [openDrawer],
  );

  // ---- Hover tooltip (cursor-following, coalesced to one update per frame) ----
  const [hover, setHover] = useState<Hover | null>(null);
  const raf = useRef<number | null>(null);
  const pending = useRef<Hover | null>(null);

  const flush = useCallback(() => {
    raf.current = null;
    if (pending.current) setHover(pending.current);
  }, []);

  const buildHover = useCallback(
    (ev: { clientX: number; clientY: number }, node: Node): Hover => {
      const a = node.data.asset as GraphAsset;
      return {
        x: ev.clientX,
        y: ev.clientY,
        data: {
          asset: a,
          blastScore: a.blast_score ?? null,
          sevCounts: sevByAsset.get(a.id) ?? {},
          kev: kevSet.has(a.id),
        },
      };
    },
    [sevByAsset, kevSet],
  );

  const onNodeMouseEnter = useCallback(
    (ev: React.MouseEvent, node: Node) => {
      setHover(buildHover(ev, node));
    },
    [buildHover],
  );

  const onNodeMouseMove = useCallback(
    (ev: React.MouseEvent, node: Node) => {
      pending.current = buildHover(ev, node);
      if (raf.current == null) raf.current = requestAnimationFrame(flush);
    },
    [buildHover, flush],
  );

  const onNodeMouseLeave = useCallback(() => {
    pending.current = null;
    if (raf.current != null) {
      cancelAnimationFrame(raf.current);
      raf.current = null;
    }
    setHover(null);
  }, []);

  useEffect(() => () => {
    if (raf.current != null) cancelAnimationFrame(raf.current);
  }, []);

  useEffect(() => {
    // Fit on first render, and when kinds toggled meaningfully.
    const t = setTimeout(() => fitView({ padding: 0.2, duration: 300 }), 60);
    return () => clearTimeout(t);
  }, [fitView, baseNodes.length]);

  return (
    <div className="graph-wrap">
      <div className="graph-overlay filters">
        {allKinds.map((k) => {
          const on = enabledKinds.has(k);
          return (
            <label
              key={k}
              className={`checkchip ${on ? "on" : ""}`}
              style={{
                borderColor: on ? kindColor(k) : undefined,
                color: on ? kindColor(k) : undefined,
                background: on ? "rgba(255,255,255,0.03)" : undefined,
              }}
            >
              <input
                type="checkbox"
                checked={on}
                onChange={() => {
                  setEnabledKinds((prev) => {
                    const next = new Set(prev);
                    if (next.has(k)) next.delete(k);
                    else next.add(k);
                    return next;
                  });
                }}
              />
              <span
                className="dot"
                style={{
                  display: "inline-block",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: kindColor(k),
                }}
              />
              {k}
            </label>
          );
        })}

        <label
          className={`checkchip ${kevOnly ? "on" : ""}`}
          style={{
            borderColor: kevOnly ? "var(--sev-crit)" : undefined,
            color: kevOnly ? "var(--sev-crit)" : undefined,
            background: kevOnly ? "rgba(213, 73, 60,0.1)" : undefined,
          }}
          title="Show only known-exploited (KEV) assets and their direct neighbours"
        >
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={() => setKevOnly((v) => !v)}
          />
          <span
            className="dot"
            style={{
              display: "inline-block",
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "var(--sev-crit)",
            }}
          />
          KEV only
        </label>
      </div>

      <ReactFlow
        nodes={displayNodes}
        edges={displayEdges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onNodeMouseEnter={onNodeMouseEnter}
        onNodeMouseMove={onNodeMouseMove}
        onNodeMouseLeave={onNodeMouseLeave}
        proOptions={{ hideAttribution: true }}
        minZoom={0.1}
        maxZoom={2.5}
        fitView
        nodesDraggable
        panOnDrag
        selectionOnDrag={false}
        zoomOnScroll
        elementsSelectable
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1}
          color="rgba(236,226,208,0.07)"
        />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => (n.data?.color as string) ?? "#9fc2d8"}
          maskColor="rgba(10,13,18,0.75)"
          nodeStrokeColor="rgba(236,226,208,0.13)"
          nodeStrokeWidth={1}
          pannable
          zoomable
          style={{ height: 120, width: 180 }}
        />
      </ReactFlow>

      <div className="graph-overlay legend">
        {allKinds.map((k) => (
          <span key={k} className="sw">
            <span className="dot" style={{ background: kindColor(k) }} />
            {k}
          </span>
        ))}
      </div>

      {hover && <NodeTooltip data={hover.data} x={hover.x} y={hover.y} />}
    </div>
  );
}

export default function GraphCanvas(props: Props) {
  return (
    <ReactFlowProvider>
      <InnerGraph {...props} />
    </ReactFlowProvider>
  );
}
