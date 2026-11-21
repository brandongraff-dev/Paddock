import { apiFetch } from "./client";
import type {
  Owner,
  OwnerMatch,
  Severity,
  SlaPolicy,
  Ticket,
  TicketPage,
  TicketSummary,
} from "./types";

export type TicketFilter = {
  status?: string;
  team?: string;
  severity?: Severity;
  breached?: boolean;
  limit?: number;
  offset?: number;
};

/**
 * GET /v1/tickets — {items,total,limit,offset}, includes joined finding+asset
 * summaries. Unwrap to the array the queue renders (same convention as the
 * other list endpoints). Tolerates a raw array too.
 */
export function listTickets(q?: TicketFilter): Promise<Ticket[]> {
  return apiFetch<TicketPage | Ticket[]>("/v1/tickets", { query: q }).then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

/** GET /v1/tickets/summary — open/breached/resolved + by-team/by-severity. */
export function getTicketSummary(): Promise<TicketSummary> {
  return apiFetch<TicketSummary>("/v1/tickets/summary");
}

export interface TicketPatch {
  status?: string;
  owner_team?: string | null;
  contact?: string | null;
}

/** PATCH /v1/tickets/{id} — status (sets closed_at when terminal), owner, contact. */
export function patchTicket(id: string, patch: TicketPatch): Promise<Ticket> {
  return apiFetch<Ticket>(`/v1/tickets/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
  });
}

/* ------------------------------- owners -------------------------------- */

export function listOwners(): Promise<Owner[]> {
  return apiFetch<{ items: Owner[] } | Owner[]>("/v1/owners").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export interface OwnerInput {
  name: string;
  team: string;
  contact?: string | null;
  match: OwnerMatch;
  priority: number;
  enabled?: boolean;
}

export function createOwner(body: OwnerInput): Promise<Owner> {
  return apiFetch<Owner>("/v1/owners", { method: "POST", body });
}

export function patchOwner(id: string, patch: Partial<OwnerInput>): Promise<Owner> {
  return apiFetch<Owner>(`/v1/owners/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
  });
}

export function deleteOwner(id: string): Promise<void> {
  return apiFetch<void>(`/v1/owners/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/* ----------------------------- sla policies ---------------------------- */

export function listSlaPolicies(): Promise<SlaPolicy[]> {
  return apiFetch<{ items: SlaPolicy[] } | SlaPolicy[]>("/v1/sla-policies").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

/** PATCH /v1/sla-policies/{severity} — {hours}. */
export function patchSlaPolicy(severity: Severity, hours: number): Promise<SlaPolicy> {
  return apiFetch<SlaPolicy>(`/v1/sla-policies/${encodeURIComponent(severity)}`, {
    method: "PATCH",
    body: { hours },
  });
}
