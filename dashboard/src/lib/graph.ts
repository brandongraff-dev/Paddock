/**
 * Graph layout helpers.
 *
 * Why a hand-rolled layout? react-flow ships no layout engine of its own,
 * and we didn't want to pull dagre as a direct dep just for the hero page.
 * We approximate dagre's left-to-right layered layout by:
 *   1) running a BFS from the "seed" nodes (lowest in-degree) to assign ranks
 *   2) bucketing nodes per rank
 *   3) stacking vertically inside each rank with gentle centering
 *
 * It's deterministic, keeps the "flow" feel (domains on the left, IPs
 * next, endpoints on the right), and plays nicely with react-flow's
 * fitView() on mount.
 */

import type { Edge, Node, XYPosition } from "reactflow";
import type { Asset, AssetEdge, AssetKind } from "../api/types";
import { kindColor } from "./color";

const RANK_HINT: Record<AssetKind, number> = {
  org: 0,
  domain: 1,
  subdomain: 2,
  ipv4: 3,
  ipv6: 3,
  port: 4,
  service: 5,
  technology: 6,
  certificate: 6,
  endpoint: 7,
  repository: 7,
  secret_candidate: 8,
  cloud_account: 1,
  cloud_resource: 2,
};

export interface GraphLayoutInput {
  assets: Asset[];
  edges: AssetEdge[];
  /** Asset id -> has at least one high/critical open finding. */
  hot?: Set<string>;
}

export interface GraphLayoutResult {
  nodes: Node[];
  edges: Edge[];
}

/** Spacing constants (in px, reactflow world units). */
const COL_W = 240;
const ROW_H = 72;

export function layoutGraph(input: GraphLayoutInput): GraphLayoutResult {
  const { assets, edges, hot } = input;

  // Group by rank (prefer kind hint; fall back to topological distance).
  const indeg = new Map<string, number>();
  for (const a of assets) indeg.set(a.id, 0);
  for (const e of edges) {
    if (indeg.has(e.dst_id)) indeg.set(e.dst_id, (indeg.get(e.dst_id) ?? 0) + 1);
  }

  const rankOf = (a: Asset): number => {
    const hint = RANK_HINT[a.kind] ?? 3;
    // nudge nodes with no incoming edges slightly left
    if ((indeg.get(a.id) ?? 0) === 0) return hint - 0.25;
    return hint;
  };

  const sorted = [...assets].sort((a, b) => {
    const ra = rankOf(a);
    const rb = rankOf(b);
    if (ra !== rb) return ra - rb;
    return (a.canonical || a.value).localeCompare(b.canonical || b.value);
  });

  // Bucket by rounded rank.
  const byRank = new Map<number, Asset[]>();
  for (const a of sorted) {
    const r = Math.round(rankOf(a));
    const list = byRank.get(r) ?? [];
    list.push(a);
    byRank.set(r, list);
  }

  const positions = new Map<string, XYPosition>();
  const ranks = [...byRank.keys()].sort((a, b) => a - b);
  const maxCount = Math.max(...[...byRank.values()].map((l) => l.length), 1);
  const totalH = maxCount * ROW_H;

  for (const r of ranks) {
    const list = byRank.get(r)!;
    const colH = list.length * ROW_H;
    const yOffset = (totalH - colH) / 2;
    list.forEach((a, i) => {
      positions.set(a.id, {
        x: r * COL_W,
        y: yOffset + i * ROW_H,
      });
    });
  }

  const sizeFor = (a: Asset): number => {
    const bs = a.blast_score ?? 0;
    // Node "weight" shows up in the custom node — we pass it via data.
    // Clamp hard so a single huge-blast host can't blow out the layout.
    return 0.85 + Math.min(0.5, Math.max(0, bs) / 100);
  };

  // Undirected degree per node, used as a legibility cue for edge weight:
  // "spine" edges (a host resolving to many ports/services) read heavier.
  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.src_id, (degree.get(e.src_id) ?? 0) + 1);
    degree.set(e.dst_id, (degree.get(e.dst_id) ?? 0) + 1);
  }
  const WEIGHTED_KINDS = new Set(["resolves_to", "hosts", "runs"]);
  const edgeWidth = (e: AssetEdge): number => {
    if (!WEIGHTED_KINDS.has(e.kind)) return 1;
    const combined = (degree.get(e.src_id) ?? 0) + (degree.get(e.dst_id) ?? 0);
    // Subtle: 1px baseline, up to ~2.2px for the busiest hubs.
    return Math.min(2.2, 1 + Math.max(0, combined - 2) * 0.12);
  };

  const nodes: Node[] = assets.map((a) => ({
    id: a.id,
    type: "assetNode",
    position: positions.get(a.id) ?? { x: 0, y: 0 },
    data: {
      asset: a,
      hot: hot?.has(a.id) ?? false,
      scale: sizeFor(a),
      color: kindColor(a.kind),
    },
    draggable: true,
    selectable: true,
  }));

  const rfEdges: Edge[] = edges.map((e) => ({
    id: e.id,
    source: e.src_id,
    target: e.dst_id,
    type: "default",
    animated: false,
    label: e.kind,
    labelStyle: {
      fill: "var(--text-2)",
      fontSize: 9,
      fontFamily: "var(--mono)",
      letterSpacing: "0.06em",
      textTransform: "uppercase",
    },
    labelBgStyle: { fill: "rgba(16,21,29,0.8)" },
    labelBgPadding: [3, 2] as [number, number],
    style: {
      stroke: "var(--border-strong)",
      strokeWidth: edgeWidth(e),
      opacity: 0.8,
    },
  }));

  return { nodes, edges: rfEdges };
}

/** Utility: list of unique kinds present, in sorted RANK_HINT order. */
export function distinctKinds(assets: Asset[]): AssetKind[] {
  const set = new Set<AssetKind>();
  for (const a of assets) set.add(a.kind);
  return [...set].sort((a, b) => (RANK_HINT[a] ?? 0) - (RANK_HINT[b] ?? 0));
}
