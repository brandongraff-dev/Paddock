/**
 * AttackPathStrip — inline react-flow strip for a single attack-path card.
 *
 * Modeled on ChainMiniGraph: a hand-placed left→right sequence, react-flow
 * used purely as a renderer (controls / minimap off, pan + zoom disabled,
 * fitView on). Reads: SOURCE asset ("internet-facing") → each hop, coloured
 * by its max severity → TARGET asset ("crown jewel", gold accent).
 *
 * Only hops carry an asset_id, so only hops are clickable → they open the
 * shared DetailDrawer (asset). The endpoints are summaries (value + kind);
 * if the engine already lists an endpoint as the first/last hop we drop the
 * duplicate synthetic node rather than render it twice.
 */

import { useMemo } from "react";
import ReactFlow, {
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "reactflow";
import type { AttackPath, Severity } from "../../api/types";
import { kindColor, severityColor } from "../../lib/color";
import { useStore } from "../../state/store";
import "../../styles/path.css";

interface Props {
  path: AttackPath;
}

const STEP_X = 172;
const ROW_Y = 48;

function EndpointNode({ data }: NodeProps) {
  const role = data.role as string;
  const klass = data.variant === "target" ? "pmini-target" : "pmini-source";
  return (
    <div className={`pmini-node is-static ${klass}`}>
      <Handle type="target" position={Position.Left} />
      <div className="pmini-kind">
        <span>{data.kind as string}</span>
      </div>
      <div className="pmini-title" title={data.label as string}>{data.label as string}</div>
      <span className="pmini-role">{role}</span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function HopNode({ data }: NodeProps) {
  const sev = data.severity as Severity;
  const color = severityColor(sev);
  return (
    <div className="pmini-node" style={{ ["--node-color" as any]: color }}>
      <Handle type="target" position={Position.Left} />
      <div className="pmini-kind">
        <span className="pmini-sev">{sev}</span>
        <span>{data.kind as string} · #{data.seq as number}</span>
      </div>
      <div className="pmini-title" title={data.label as string}>{data.label as string}</div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes: NodeTypes = { pEndpoint: EndpointNode, pHop: HopNode };

export default function AttackPathStrip({ path }: Props) {
  const openDrawer = useStore((s) => s.openDrawer);

  const { nodes, edges } = useMemo<{ nodes: Node[]; edges: Edge[] }>(() => {
    const ns: Node[] = [];
    const es: Edge[] = [];

    const srcVal = path.source_asset?.value;
    const tgtVal = path.target_asset?.value;
    // Drop a hop that merely restates an endpoint so the route isn't doubled.
    const midHops = (path.hops ?? []).filter(
      (h) => h.value !== srcVal && h.value !== tgtVal,
    );

    let col = 0;
    const push = (node: Node) => {
      ns.push({ ...node, position: { x: col * STEP_X, y: ROW_Y }, draggable: false, selectable: !!node.selectable });
      col += 1;
    };

    push({
      id: "src",
      type: "pEndpoint",
      data: {
        variant: "source",
        label: path.source_asset?.value ?? "source",
        kind: path.source_asset?.kind ?? "asset",
        color: kindColor(path.source_asset?.kind),
        role: "internet-facing",
      },
      position: { x: 0, y: ROW_Y },
      selectable: false,
    });

    let prev = "src";
    midHops.forEach((h, i) => {
      const id = `h:${h.asset_id}:${i}`;
      push({
        id,
        type: "pHop",
        data: {
          assetId: h.asset_id,
          severity: h.max_severity ?? ("info" as Severity),
          kind: h.kind,
          seq: i + 1,
          label: h.value,
        },
        position: { x: 0, y: ROW_Y },
        selectable: true,
      });
      es.push({
        id: `e:${prev}:${id}`,
        source: prev,
        target: id,
        type: "default",
        style: { stroke: "var(--border-strong)", strokeWidth: 1, opacity: 0.85 },
      });
      prev = id;
    });

    push({
      id: "tgt",
      type: "pEndpoint",
      data: {
        variant: "target",
        label: path.target_asset?.value ?? "target",
        kind: path.target_asset?.kind ?? "asset",
        color: kindColor(path.target_asset?.kind),
        role: "crown jewel",
      },
      position: { x: 0, y: ROW_Y },
      selectable: false,
    });
    es.push({
      id: `e:${prev}:tgt`,
      source: prev,
      target: "tgt",
      type: "default",
      style: { stroke: "var(--border-strong)", strokeWidth: 1, opacity: 0.85 },
    });

    return { nodes: ns, edges: es };
  }, [path]);

  if (!path.source_asset && !path.target_asset && (path.hops ?? []).length === 0) {
    return (
      <div className="pmini">
        <div className="pmini-empty">no route</div>
      </div>
    );
  }

  return (
    <div className="pmini">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => {
          const d = node.data as { assetId?: string };
          if (d.assetId) openDrawer({ kind: "asset", id: d.assetId });
        }}
        proOptions={{ hideAttribution: true }}
        fitView
        fitViewOptions={{ padding: 0.16 }}
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
      />
    </div>
  );
}
