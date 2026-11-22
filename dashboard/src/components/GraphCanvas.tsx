/**
 * GraphCanvas — the hero component.
 *
 * Renders the asset graph as a react-flow canvas with custom nodes.
 * Nodes are uniform workflow-style cards coloured by kind; blast radius is
 * on the card and in the tooltip, and open high/critical findings get a red
 * rim and a count badge.
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
import { canvasKindColor } from "../lib/color";
import { useStore } from "../state/store";
import NodeTooltip, { type NodeTooltipData } from "./graph/NodeTooltip";
import KindIcon from "./graph/kindIcon";
import "../styles/graph-extras.css";
import "../styles/graph-nodes.css";

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

const KIND_LABEL: Partial<Record<AssetKind, string>> = {
  ipv4: "IPv4", ipv6: "IPv6", org: "Org", secret_candidate: "Secret", cloud_account: "Cloud account",
  cloud_resource: "Cloud resource",
};
/** Toolbar label for a kind: "Subdomain", "IPv4", ... */
function kindLabel(k: AssetKind): string {
  return KIND_LABEL[k] ?? k.charAt(0).toUpperCase() + k.slice(1).replace(/_/g, " ");
}

/** A workflow-canvas card: icon tile, value, "kind · blast" subtitle. */
function AssetNode({ data }: NodeProps) {
  const a = data.asset as GraphAsset;
  const hot = !!data.hot;
  const color = data.color as string;
  const blast = Math.round(a.blast_score ?? 0);
  const openHigh = typeof a.open_high === "number" ? a.open_high : (a.open_high_crit_count ?? 0);
  const cls = ["gnode", hot ? "hot" : "", data.dimmed ? "gx-dim" : "", data.faded ? "gx-fade" : ""]
    .filter(Boolean).join(" ");
  return (
    <div className={cls} style={{ ["--kind-color" as any]: color }}>
      <Handle type="target" position={Position.Left} />
      <div className="gnode-icon"><KindIcon kind={a.kind} /></div>
      <div className="gnode-text">
        <div className="gnode-title" title={a.value}>{a.value}</div>
        <div className="gnode-sub">
          {a.kind.replace(/_/g, " ")}
          {blast > 0 && <> · <span className="blast">blast {blast}</span></>}
        </div>
      </div>
      {openHigh > 0 && <span className="gnode-badge" title={`${openHigh} open high/critical`}>{openHigh}</span>}
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
  const kindCounts = useMemo(() => {
    const m = new Map<AssetKind, number>();
    for (const a of assets) m.set(a.kind, (m.get(a.kind) ?? 0) + 1);
    return m;
  }, [assets]);
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

  // Hovering a node lights its own links and fades everything it isn't
  // connected to (n8n-style focus), without recomputing the layout.
  const [focusId, setFocusId] = useState<string | null>(null);
  const focusKeep = useMemo(() => {
    if (!focusId) return null;
    const keep = new Set<string>([focusId]);
    for (const e of baseEdges) {
      if (e.source === focusId) keep.add(e.target);
      if (e.target === focusId) keep.add(e.source);
    }
    return keep;
  }, [focusId, baseEdges]);

  // Apply dimming without recomputing layout (cheap map over existing nodes).
  const displayNodes = useMemo<Node[]>(() => {
    if (!kevKeep && !focusKeep) return baseNodes;
    return baseNodes.map((n) => {
      const dimmed = !!kevKeep && !kevKeep.has(n.id);
      const faded = !dimmed && !!focusKeep && !focusKeep.has(n.id);
      return dimmed || faded ? { ...n, data: { ...n.data, dimmed, faded } } : n;
    });
  }, [baseNodes, kevKeep, focusKeep]);

  const displayEdges = useMemo<Edge[]>(() => {
    if (!kevKeep && !focusId) return baseEdges;
    return baseEdges.map((e) => {
      if (kevKeep && !(kevKeep.has(e.source) && kevKeep.has(e.target))) {
        return { ...e, style: { ...e.style, opacity: 0.05 } };
      }
      if (focusId) {
        const lit = e.source === focusId || e.target === focusId;
        return lit
          ? { ...e, className: "gx-edge-lit", zIndex: 1 }
          : { ...e, style: { ...e.style, opacity: 0.25 } };
      }
      return e;
    });
  }, [baseEdges, kevKeep, focusId]);

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
      setFocusId(node.id);
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
    setFocusId(null);
  }, []);

  useEffect(() => () => {
    if (raf.current != null) cancelAnimationFrame(raf.current);
  }, []);

  useEffect(() => {
    // Fit on first render, and when kinds toggled meaningfully.
    const t = setTimeout(() => fitView({ padding: 0.12, maxZoom: 1, duration: 300 }), 60);
    return () => clearTimeout(t);
  }, [fitView, baseNodes.length]);

  return (
    <div className="graph-wrap">
      <div className="graph-overlay filters">
        <div className="gfilter" role="group" aria-label="Show asset kinds">
          {allKinds.map((k) => {
            const on = enabledKinds.has(k);
            return (
              <button
                key={k}
                type="button"
                className={`gchip ${on ? "on" : ""}`}
                aria-pressed={on}
                onClick={() => {
                  setEnabledKinds((prev) => {
                    const next = new Set(prev);
                    if (next.has(k)) next.delete(k);
                    else next.add(k);
                    return next;
                  });
                }}
              >
                <span className="sq" style={{ background: canvasKindColor(k) }} />
                {kindLabel(k)}
                <span className="n">{kindCounts.get(k) ?? 0}</span>
              </button>
            );
          })}
          <span className="gsep" aria-hidden="true" />
          <button
            type="button"
            className={`gchip kev ${kevOnly ? "on" : ""}`}
            aria-pressed={kevOnly}
            onClick={() => setKevOnly((v) => !v)}
            title="Show only known-exploited (KEV) assets and their direct neighbours"
          >
            <span className="sq" />
            KEV only
          </button>
        </div>
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
        fitViewOptions={{ padding: 0.12, maxZoom: 1 }}
        nodesDraggable
        panOnDrag
        selectionOnDrag={false}
        zoomOnScroll
        elementsSelectable
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1.2}
          color="rgba(236,226,208,0.09)"
        />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => (n.data?.color as string) ?? "#9fc2d8"}
          nodeBorderRadius={6}
          maskColor="rgba(14,12,10,0.72)"
          nodeStrokeColor="rgba(236,226,208,0.13)"
          nodeStrokeWidth={1}
          pannable
          zoomable
          style={{ height: 120, width: 180 }}
        />
      </ReactFlow>

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
