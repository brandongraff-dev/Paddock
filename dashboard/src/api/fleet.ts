import { apiFetch } from "./client";

/**
 * Fleet + gated enforcement endpoints (orchestrator /v1/fleet). Follows the
 * same self-contained convention as api/ti.ts: local TS types live here rather
 * than editing the shared types.ts.
 *
 * SAFETY FRAMING (mirrored in the UI): every enforcement action is host-local
 * only, proposed before it can be applied, dry-run by default, reversible, and
 * audited. Nothing here can target a remote host.
 */

export type AgentStatus = "enrolled" | "online" | "stale" | "offline" | "revoked";
export type Platform = "linux" | "windows" | "macos";

export type ActionType =
  | "block_ip"
  | "block_domain"
  | "quarantine_file"
  | "firewall_rule"
  | "revert";

export type ActionStatus =
  | "proposed"
  | "approved"
  | "applied"
  | "failed"
  | "reverted"
  | "denied";

export interface Agent {
  id: string;
  hostname: string;
  platform: Platform | null;
  agent_version: string | null;
  labels: string[];
  capabilities: string[];
  status: AgentStatus;
  last_seen: string | null;
  enrolled_at: string;
  stale: boolean;
}

export interface InventorySnapshot {
  id: string;
  collected_at: string;
  os_info: Record<string, unknown>;
  packages: Record<string, unknown>[];
  listeners: Record<string, unknown>[];
  posture: Record<string, unknown>;
}

export interface AgentDetail extends Agent {
  inventory: InventorySnapshot | null;
  action_counts: Record<string, number>;
}

export interface Action {
  id: string;
  agent_id: string;
  action_type: ActionType;
  target: string;
  reason: string | null;
  indicator_id: string | null;
  finding_id: string | null;
  dry_run: boolean;
  status: ActionStatus;
  requested_by: string | null;
  approved_by: string | null;
  result: Record<string, unknown>;
  created_at: string;
  decided_at: string | null;
  applied_at: string | null;
  revert_of: string | null;
}

export interface ActionPage {
  items: Action[];
  total: number;
}

export interface ProposeInput {
  agent_id: string;
  action_type: Exclude<ActionType, "revert">;
  target: string;
  reason?: string;
}

/* -------------------------------- agents ------------------------------- */

export function listAgents(): Promise<Agent[]> {
  return apiFetch<Agent[]>("/v1/fleet/agents");
}

export function getAgent(id: string): Promise<AgentDetail> {
  return apiFetch<AgentDetail>(`/v1/fleet/agents/${encodeURIComponent(id)}`);
}

/* -------------------------------- actions ------------------------------ */

export function listActions(q?: { agent?: string; status?: ActionStatus }): Promise<ActionPage> {
  return apiFetch<ActionPage>("/v1/fleet/actions", { query: q });
}

export function proposeAction(body: ProposeInput): Promise<Action> {
  return apiFetch<Action>("/v1/fleet/actions", { method: "POST", body });
}

/** Admin only. `apply_for_real` flips dry_run off — the conscious real-apply grant. */
export function approveAction(id: string, apply_for_real = false, note?: string): Promise<Action> {
  return apiFetch<Action>(`/v1/fleet/actions/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: { apply_for_real, note },
  });
}

export function denyAction(id: string, note?: string): Promise<Action> {
  return apiFetch<Action>(`/v1/fleet/actions/${encodeURIComponent(id)}/deny`, {
    method: "POST",
    body: { note },
  });
}

/** Mint a first-class revert action for an applied block. */
export function revertAction(id: string, note?: string): Promise<Action> {
  return apiFetch<Action>(`/v1/fleet/actions/${encodeURIComponent(id)}/revert`, {
    method: "POST",
    body: { note },
  });
}
