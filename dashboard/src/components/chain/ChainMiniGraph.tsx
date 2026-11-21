/**
 * ChainMiniGraph — inline react-flow strip for a single chain card.
 *
 * Reads left→right: the anchor asset on the left, then each contributing
 * finding in sequence, coloured by severity. Positions are hand-placed
 * (no physics sim — it's a 3–6 node path), react-flow is used purely as a
 * renderer: controls / minimap off, panning + zoom disabled, fitView on.
 *
 * Clicking a finding node opens it in the shared DetailDrawer; clicking the
 * anchor opens the asset. Severity is taken from whatever the chain already
 * carries (hydrated `findings`, or a `finding_severities` map/array); if a
 * finding's severity isn't present we render it neutral rather than fetch
 * per-id here (keeps a page of cards cheap).
 */

import { useMemo } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "reactflow";
import type { Asset, FindingChain, Severity } from "../../api/types";
import { severityColor } from "../../lib/color";
import { kindColor } from "../../lib/color";
import { useStore } from "../../state/store";
import "../../styles/chains.css";

/** Local view of chain fields not (yet) in the shared contract. */
type ChainX = FindingChain & {
  finding_severities?: Record<string, Severity> | Severity[];
  anchor_asset?: Asset;
  blast_radius_score?: number | null;
};

interface Props {
  chain: ChainX;
}

const STEP_X = 164;
const ROW_Y = 54;

function AnchorNode({ data }: NodeProps) {
  const label = data.label as string;
  const kind = data.kind as string;
  const blast = data.blast as number | null;
  return (
    <div
      className="cmini-node cmini-anchor"
      style={{ ["--kind-color" as any]: data.color as string }}
    >
      <Handle type="source" position={Position.Right} />
      <div className="cmini-kind">
        <span>{kind ?? "anchor"}</span>
        {blast != null && <span className="cmini-blast">blast {Math.round(blast)}</span>}
      </div>
      <div className="cmini-title" title={label}>{label}</div>
    </div>
  );
}

function FindingNode({ data }: NodeProps) {
  const sev = data.severity as Severity;
  const color = severityColor(sev);
  return (
    <div
      className="cmini-node cmini-finding"
      style={{ ["--kind-color" as any]: color }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="cmini-kind">
        <span className="cmini-sev" style={{ color }}>{sev}</span>
        <span>#{data.seq as number}</span>
      </div>
      <div className="cmini-title" title={data.label as string}>{data.label as string}</div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes: NodeTypes = { cAnchor: AnchorNode, cFinding: FindingNode };

/** Resolve a severity for each finding id from whatever the chain carries. */
function severityLookup(chain: ChainX): (id: string, idx: number) => Severity {
  const byId = new Map<string, Severity>();
  for (const f of chain.findings ?? []) byId.set(f.id, f.severity);
  const fs = chain.finding_severities;
  const arr = Array.isArray(fs) ? fs : undefined;
  const rec = fs && !Array.isArray(fs) ? fs : undefined;
  return (id, idx) =>
    byId.get(id) ?? rec?.[id] ?? arr?.[idx] ?? ("info" as Severity);
}

function titleLookup(chain: ChainX): (id: string) => string | undefined {
  const byId = new Map<string, string>();
  for (const f of chain.findings ?? []) byId.set(f.id, f.title);
  return (id) => byId.get(id);
}

function shortId(id: string): string {
  return id.length > 10 ? `…${id.slice(-8)}` : id;
}

export default function ChainMiniGraph({ chain }: Props) {
  const openDrawer = useStore((s) => s.openDrawer);

  const { nodes, edges } = useMemo<{ nodes: Node[]; edges: Edge[] }>(() => {
    const sevOf = severityLookup(chain);
    const titleOf = titleLookup(chain);
    const ns: Node[] = [];
    const es: Edge[] = [];

    const anchor = chain.anchor_asset;
    const anchorNodeId = "anchor";
    ns.push({
      id: anchorNodeId,
      type: "cAnchor",
      position: { x: 0, y: ROW_Y },
      data: {
        label: anchor?.value ?? (chain.anchor_asset_id ? shortId(chain.anchor_asset_id) : "anchor"),
        kind: anchor?.kind ?? "asset",
        color: kindColor(anchor?.kind),
        blast: chain.blast_radius_score ?? null,
        assetId: anchor?.id ?? chain.anchor_asset_id ?? null,
      },
      draggable: false,
      selectable: true,
    });

    let prev = anchorNodeId;
    chain.finding_ids.forEach((fid, i) => {
      const id = `f:${fid}`;
      ns.push({
        id,
        type: "cFinding",
        position: { x: (i + 1) * STEP_X, y: ROW_Y },
        data: {
          findingId: fid,
          severity: sevOf(fid, i),
          seq: i + 1,
          label: titleOf(fid) ?? shortId(fid),
        },
        draggable: false,
        selectable: true,
      });
      es.push({
        id: `e:${i}`,
        source: prev,
        target: id,
        type: "default",
        style: { stroke: "var(--border-strong)", strokeWidth: 1, opacity: 0.85 },
      });
      prev = id;
    });

    return { nodes: ns, edges: es };
  }, [chain]);

  const onNodeClick = useCallbackClick(openDrawer);

  if (chain.finding_ids.length === 0 && !chain.anchor_asset && !chain.anchor_asset_id) {
    return (
      <div className="cmini">
        <div className="cmini-empty">no finding sequence</div>
      </div>
    );
  }

  return (
    <div className="cmini">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        proOptions={{ hideAttribution: true }}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.2}
        maxZoom={1.5}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        panOnDrag={false}
        panOnScroll={false}
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="rgba(236,226,208,0.07)" />
      </ReactFlow>
    </div>
  );
}

/** Click handler: finding node → finding drawer, anchor node → asset drawer. */
function useCallbackClick(
  openDrawer: (t: { kind: "asset" | "finding"; id: string }) => void,
) {
  return useMemo(
    () =>
      (_: unknown, node: Node) => {
        const d = node.data as { findingId?: string; assetId?: string | null };
        if (d.findingId) openDrawer({ kind: "finding", id: d.findingId });
        else if (d.assetId) openDrawer({ kind: "asset", id: d.assetId });
      },
    [openDrawer],
  );
}
