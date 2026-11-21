import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  acceptFinding,
  createSuppression,
  deleteSuppression,
  getFinding,
  listChains,
  listFindings,
  listFindingsPage,
  listSuppressions,
  listTimeline,
  markFalsePositive,
  patchFinding,
  patchSuppression,
  reopenFinding,
  type DismissBody,
} from "../api/findings";
import type {
  Finding,
  FindingStatus,
  Severity,
  SuppressedFilter,
  Suppression,
  SuppressionInput,
} from "../api/types";

export interface FindingFilter {
  severity?: Severity;
  status?: FindingStatus;
  asset_id?: string;
  rule_source?: string;
  kev?: boolean;
  q?: string;
  suppressed?: SuppressedFilter;
  sla_breached?: boolean;
  exploitability?: "unverified" | "confirmed" | "not_reproducible" | "inconclusive";
  fix_verified?: boolean;
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

/** Counts only (limit=1): total + hidden-by-default suppressed/duplicate rows. */
export function useFindingCounts(filter: FindingFilter) {
  return useQuery({
    queryKey: ["findings", "counts", filter],
    queryFn: () => listFindingsPage({ ...filter, limit: 1, offset: 0 }),
    select: (p) => ({
      total: p.total,
      suppressed: p.suppressed_total ?? 0,
      duplicates: p.duplicates_total ?? 0,
    }),
    staleTime: 10_000,
  });
}

export type TransitionKind = "accept" | "false_positive" | "reopen";

/** accept / false-positive / reopen — all audited server-side. */
export function useFindingTransition() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: { id: string; kind: TransitionKind } & Partial<DismissBody>) => {
      if (p.kind === "reopen") return reopenFinding(p.id, p.reason);
      const body: DismissBody = {
        reason: p.reason ?? "",
        accepted_until: p.accepted_until ?? undefined,
        suppress: p.suppress || undefined,
      };
      return p.kind === "accept" ? acceptFinding(p.id, body) : markFalsePositive(p.id, body);
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["finding", res.finding.id] });
      if (res.suppression_id) qc.invalidateQueries({ queryKey: ["suppressions"] });
    },
  });
}

export function useSuppressions() {
  return useQuery({ queryKey: ["suppressions"], queryFn: () => listSuppressions(), staleTime: 10_000 });
}

export function useSuppressionMutations() {
  const qc = useQueryClient();
  const done = () => {
    qc.invalidateQueries({ queryKey: ["suppressions"] });
    qc.invalidateQueries({ queryKey: ["findings"] });
  };
  return {
    create: useMutation({ mutationFn: (b: SuppressionInput) => createSuppression(b), onSuccess: done }),
    toggle: useMutation({
      mutationFn: (s: Pick<Suppression, "id" | "enabled">) => patchSuppression(s.id, { enabled: !s.enabled }),
      onSuccess: done,
    }),
    remove: useMutation({ mutationFn: (id: string) => deleteSuppression(id), onSuccess: done }),
  };
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
