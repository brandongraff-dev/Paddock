/** React Query hooks for the MSP console (api/msp.ts). */

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createCustomer,
  getMspMe,
  getMspSummary,
  listCustomers,
  setCustomerStatus,
  switchCustomer,
  type CustomerQuery,
} from "../api/msp";
import { useAuth } from "../state/auth";
import { useMsp } from "../state/msp";

/** Who am I as far as the MSP console is concerned. Cheap; drives the nav entry. */
export function useMspMe() {
  const token = useAuth((s) => s.token);
  const actingId = useMsp((s) => s.acting?.customer.id ?? null);
  return useQuery({
    queryKey: ["msp", "me", actingId],
    queryFn: getMspMe,
    enabled: !!token,
    staleTime: 60_000,
    retry: false,
  });
}

export function useCustomers(q: CustomerQuery) {
  return useQuery({
    queryKey: ["msp", "customers", q],
    queryFn: () => listCustomers(q),
    placeholderData: keepPreviousData,
  });
}

export function useMspSummary() {
  return useQuery({ queryKey: ["msp", "summary"], queryFn: getMspSummary });
}

export function useMspMutations() {
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: ["msp"] });
  return {
    create: useMutation({ mutationFn: createCustomer, onSuccess: refresh }),
    status: useMutation({
      mutationFn: (v: { id: string; action: "suspend" | "reactivate" }) => setCustomerStatus(v.id, v.action),
      onSuccess: refresh,
    }),
    // No cache invalidation here: entering a customer clears the whole cache
    // (see openCustomer in pages/MspConsole.tsx) so nothing of the previous
    // tenant can be shown.
    switchTo: useMutation({ mutationFn: (id: string) => switchCustomer(id) }),
  };
}
