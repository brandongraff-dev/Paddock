import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getFinding, listChains, listFindings, listTimeline, patchFinding } from "../api/findings";
import type { Finding, FindingStatus, Severity } from "../api/types";

export interface FindingFilter {
  severity?: Severity;
  status?: FindingStatus;
  asset_id?: string;
  rule_source?: string;
  kev?: boolean;
  q?: string;
}

const PAGE = 50;

export function useFindingsInfinite(filter: FindingFilter) {
  return useInfiniteQuery({
    queryKey: ["findings", filter],
    initialPageParam: 0,
    queryFn: async ({ pageParam = 0 }) =>
      listFindings({ ...filter, limit: PAGE, offset: pageParam as number }),
    getNextPageParam: (lastPage, pages) =>
      lastPage.length < PAGE ? undefined : pages.length * PAGE,
    staleTime: 10_000,
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id!),
    enabled: !!id,
    staleTime: 10_000,
  });
}

export function usePatchFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: { id: string; patch: Partial<Pick<Finding, "status" | "assigned_to">> & { notes?: string } }) =>
      patchFinding(p.id, p.patch),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.setQueryData(["finding", data.id], data);
    },
  });
}

export function useChains() {
  return useQuery({
    queryKey: ["chains"],
    queryFn: listChains,
    staleTime: 15_000,
  });
}

export function useTimeline(range?: { from?: string; to?: string }) {
  return useQuery({
    queryKey: ["timeline", range ?? {}],
    queryFn: () => listTimeline(range),
    staleTime: 30_000,
  });
}
