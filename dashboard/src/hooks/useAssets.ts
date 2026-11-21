import { useQuery } from "@tanstack/react-query";
import { getAsset, getAssetGraph, getFullGraph, listAssets } from "../api/assets";
import type { AssetKind } from "../api/types";

export function useAssets(query?: { kind?: AssetKind; value?: string; limit?: number }) {
  return useQuery({
    queryKey: ["assets", query ?? {}],
    queryFn: () => listAssets(query),
    staleTime: 10_000,
  });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => getAsset(id!),
    enabled: !!id,
    staleTime: 10_000,
  });
}

export function useAssetGraph(id: string | undefined, depth = 2) {
  return useQuery({
    queryKey: ["asset-graph", id, depth],
    queryFn: () => getAssetGraph(id!, depth),
    enabled: !!id,
    staleTime: 10_000,
  });
}

export function useFullGraph(limit = 400) {
  return useQuery({
    queryKey: ["asset-graph-full", limit],
    queryFn: () => getFullGraph(limit),
    staleTime: 15_000,
    // Keep the hero graph warm; it's the most expensive call.
    refetchOnWindowFocus: false,
  });
}
