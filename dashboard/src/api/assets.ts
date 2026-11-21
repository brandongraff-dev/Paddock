import { apiFetch } from "./client";
import type { Asset, AssetGraphResponse, AssetKind } from "./types";

export function listAssets(q?: {
  kind?: AssetKind;
  value?: string;
  limit?: number;
}): Promise<Asset[]> {
  return apiFetch<Asset[]>("/v1/assets", { query: q });
}

export function getAsset(id: string): Promise<Asset & { edges: AssetGraphResponse["edges"] }> {
  return apiFetch(`/v1/assets/${encodeURIComponent(id)}`);
}

export function getAssetGraph(id: string, depth = 2): Promise<AssetGraphResponse> {
  return apiFetch<AssetGraphResponse>(
    `/v1/assets/${encodeURIComponent(id)}/graph`,
    { query: { depth } },
  );
}

/**
 * NOTE: not in CONTRACTS.md — documented in DASHBOARD_NOTES.md.
 * Returns the whole graph (bounded) for the hero canvas.
 */
export function getFullGraph(limit = 400): Promise<AssetGraphResponse> {
  return apiFetch<AssetGraphResponse>("/v1/assets/graph", { query: { limit } });
}
