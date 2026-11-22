import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listVerifications, verifyFinding, type VerificationHistory } from "../api/verification";

const IN_FLIGHT = new Set(["scheduled", "queued"]);

/** The ledger for one finding; polls every 4s while a check is in flight. */
export function useVerifications(id: string | undefined) {
  return useQuery<VerificationHistory>({
    queryKey: ["verifications", id],
    queryFn: () => listVerifications(id!),
    enabled: !!id,
    staleTime: 5_000,
    refetchInterval: (q) =>
      q.state.data?.items?.some((v) => IN_FLIGHT.has(v.status)) ? 4_000 : false,
  });
}

export function useVerifyFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => verifyFinding(id),
    onSettled: (_d, _e, id) => {
      qc.invalidateQueries({ queryKey: ["verifications", id] });
      qc.invalidateQueries({ queryKey: ["finding", id] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}
