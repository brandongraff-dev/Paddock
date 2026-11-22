import { apiFetch } from "./client";
import type { ActionStatus } from "./fleet";

/**
 * Network quarantine actions proposed through UniFi / Meraki
 * (orchestrator /v1/fleet/network-actions). They ride the SAME approve gate as
 * host actions:
 *
 *   propose -> approve (admin, four-eyes; `apply_for_real` makes it live)
 *           -> execute (admin; runs the ACTION connector) -> applied | failed
 *
 * An approval WITHOUT `apply_for_real` only ever produces a dry-run preview
 * (read calls only). Release is the first-class revert.
 */

export type NetworkActionType = "quarantine_device" | "release_device" | "revert";

export interface NetworkAction {
  id: string;
  integration_id: string | null;
  action_type: NetworkActionType;
  target: string; // device MAC
  reason: string | null;
  finding_id: string | null;
  dry_run: boolean;
  status: ActionStatus;
  requested_by: string | null;
  approved_by: string | null;
  result: {
    integration_kind?: string;
    integration_name?: string;
    device?: string;
    source_rule?: string;
    output?: ExecOutput;
    dry_run_preview?: ExecOutput;
    revert?: Record<string, unknown>;
    [k: string]: unknown;
  };
  created_at: string;
  decided_at: string | null;
  applied_at: string | null;
  revert_of: string | null;
}

export interface ExecOutput {
  ok: boolean;
  detail: string;
  planned: string[];
  dry_run: boolean;
  at: string;
  executed_by: string;
}

export interface NetworkActionPage {
  items: NetworkAction[];
  total: number;
}

export interface ActionEvidence {
  action_id: string;
  finding: {
    id: string;
    rule_id: string;
    severity: string;
    status: string;
    title: string;
    description: string;
    evidence: Record<string, unknown>;
    first_seen: string | null;
    last_seen: string | null;
  } | null;
  device: Record<string, unknown>;
}

export interface ExecuteResult {
  action: NetworkAction;
  ok: boolean;
  dry_run: boolean;
  detail: string;
  planned: string[];
}

const BASE = "/v1/fleet/network-actions";

export const listNetworkActions = (status?: ActionStatus) =>
  apiFetch<NetworkActionPage>(BASE, { query: { status, limit: 200 } });

export const getActionEvidence = (id: string) =>
  apiFetch<ActionEvidence>(`${BASE}/${encodeURIComponent(id)}/evidence`);

/** Admin only. `applyForReal` is the conscious grant that makes the action live. */
export const approveNetworkAction = (id: string, note: string, applyForReal: boolean) =>
  apiFetch<NetworkAction>(`/v1/fleet/actions/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: { apply_for_real: applyForReal, note },
  });

export const rejectNetworkAction = (id: string, note: string) =>
  apiFetch<NetworkAction>(`/v1/fleet/actions/${encodeURIComponent(id)}/deny`, {
    method: "POST",
    body: { note },
  });

export const executeNetworkAction = (id: string, note?: string) =>
  apiFetch<ExecuteResult>(`${BASE}/${encodeURIComponent(id)}/execute`, {
    method: "POST",
    body: { note },
  });

/** Mint the release (first-class revert) of an applied quarantine. */
export const releaseNetworkAction = (id: string, note?: string) =>
  apiFetch<NetworkAction>(`/v1/fleet/actions/${encodeURIComponent(id)}/revert`, {
    method: "POST",
    body: { note },
  });
