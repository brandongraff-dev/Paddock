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
import { canvasKindColor } from "./color";

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

/**
 * Spacing (react-flow world units). Every node is the same size, like a
 * workflow canvas: the eye reads columns and links, not box sizes. Blast
 * radius lives on the card (subtitle + tooltip), not in its scale.
 */
export const NODE_W = 208;
export const NODE_H = 56;
const COL_GAP = 72;
const ROW_GAP = 20;
const COL_W = NODE_W + COL_GAP;
const ROW_H = NODE_H + ROW_GAP;

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

  // Bucket by rounded rank, then compact: empty ranks don't leave holes.
  const byRankRaw = new Map<number, Asset[]>();
  for (const a of sorted) {
    const r = Math.round(rankOf(a));
    const list = byRankRaw.get(r) ?? [];
    list.push(a);
    byRankRaw.set(r, list);
  }
  const columns = [...byRankRaw.keys()].sort((a, b) => a - b).map((r) => byRankRaw.get(r)!);

  // Order each column by the average row of its neighbours in the previous
  // column (barycenter heuristic): children sit next to their parents, which
  // removes most crossings. Two sweeps, left->right then right->left.
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    (neighbours.get(e.src_id) ?? neighbours.set(e.src_id, []).get(e.src_id)!).push(e.dst_id);
    (neighbours.get(e.dst_id) ?? neighbours.set(e.dst_id, []).get(e.dst_id)!).push(e.src_id);
  }
  const rowOf = new Map<string, number>();
  const indexColumn = (col: Asset[]) => col.forEach((a, i) => rowOf.set(a.id, i));
  columns.forEach(indexColumn);
  const reorder = (col: Asset[], ref: Set<string>) => {
    const key = (a: Asset): number => {
      const rows = (neighbours.get(a.id) ?? []).filter((n) => ref.has(n)).map((n) => rowOf.get(n)!);
      return rows.length ? rows.reduce((x, y) => x + y, 0) / rows.length : rowOf.get(a.id)!;
    };
    col.sort((a, b) => key(a) - key(b));
    indexColumn(col);
  };
  for (let c = 1; c < columns.length; c++) reorder(columns[c], new Set(columns[c - 1].map((a) => a.id)));
  for (let c = columns.length - 2; c >= 0; c--) reorder(columns[c], new Set(columns[c + 1].map((a) => a.id)));

  // Centre each column vertically against the tallest one.
  const positions = new Map<string, XYPosition>();
  const maxCount = Math.max(...columns.map((l) => l.length), 1);
  const totalH = maxCount * ROW_H;
  columns.forEach((list, c) => {
    const yOffset = (totalH - list.length * ROW_H) / 2;
    list.forEach((a, i) => positions.set(a.id, { x: c * COL_W, y: yOffset + i * ROW_H }));
  });

  // Undirected degree per node, used as a legibility cue for edge weight:
  // "spine" edges (a host resolving to many ports/services) read heavier.
  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.src_id, (degree.get(e.src_id) ?? 0) + 1);
    degree.set(e.dst_id, (degree.get(e.dst_id) ?? 0) + 1);
  }
  const WEIGHTED_KINDS = new Set(["resolves_to", "hosts", "runs"]);
  const edgeWidth = (e: AssetEdge): number => {
    if (!WEIGHTED_KINDS.has(e.kind)) return 1.25;
    const combined = (degree.get(e.src_id) ?? 0) + (degree.get(e.dst_id) ?? 0);
    return Math.min(2.2, 1.25 + Math.max(0, combined - 2) * 0.1);
  };

  const nodes: Node[] = assets.map((a) => ({
    id: a.id,
    type: "assetNode",
    position: positions.get(a.id) ?? { x: 0, y: 0 },
    data: {
      asset: a,
      hot: hot?.has(a.id) ?? false,
      color: canvasKindColor(a.kind),
    },
    draggable: true,
    selectable: true,
  }));

  // No text labels on edges: the column order already says what each link
  // is (domain -> subdomain -> ip -> port ...). The kind stays in `data` for
  // tooltips and filters.
  const rfEdges: Edge[] = edges.map((e) => ({
    id: e.id,
    source: e.src_id,
    target: e.dst_id,
    type: "default",
    animated: false,
    data: { kind: e.kind },
    style: {
      stroke: "rgba(236,226,208,0.22)",
      strokeWidth: edgeWidth(e),
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
