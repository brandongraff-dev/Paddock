/**
 * First-run wizard + scope proof-of-control endpoints (orchestrator schema 021).
 *
 *   GET  /v1/onboarding              wizard state + live counts
 *   PUT  /v1/onboarding              record progress (admin)
 *   POST /v1/scope/{id}/challenge    issue/return the ownership challenge
 *   POST /v1/scope/{id}/verify       check now (domains) / attest (IP ranges)
 *   GET  /v1/system/services         optional services: ok / down / not_enabled
 */

import { apiFetch } from "./client";
/** The orchestrator's scope kinds (schema/001_scope.sql). */
export type ScopeKind = "domain" | "subdomain_wildcard" | "ipv4_cidr" | "ipv6_cidr" | "asn";

export type ProofStatus = "pending" | "verified" | "attested" | "expired";
export type ProofMethod = "dns_txt" | "http_file" | "attestation";

export interface ScopeProof {
  status: ProofStatus;
  method: ProofMethod | null;
  methods: string[];
  token_issued: boolean;
  verified_at: string | null;
  last_checked_at: string | null;
  last_error: string | null;
  failing_since: string | null;
  grace_until: string | null;
  required: boolean;
  effective: boolean;
  approver?: string | null;
  attested_by?: string | null;
}

export interface ScopeEntryWithProof {
  id: number;
  kind: ScopeKind;
  value: string;
  active: boolean;
  added_by: string;
  added_at: string;
  auth_doc_ref?: string | null;
  proof: ScopeProof;
}

export type WizardStep = "workspace" | "domain" | "verify" | "scan" | "results" | "team" | "done";

export interface ScanBrief {
  id: string;
  kind: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  queued_at: string | null;
  finished_at: string | null;
  error: string | null;
}

export interface Onboarding {
  available: boolean;
  workspace_name: string | null;
  current_step: WizardStep;
  steps_done: WizardStep[];
  dismissed: boolean;
  completed_at: string | null;
  scope_entry: ScopeEntryWithProof | null;
  first_scan: ScanBrief | null;
  counts: { assets: number; findings: number; domain_assets: number; domain_findings: number };
  has_verified_scope: boolean;
  needs_setup: boolean;
  require_scope_proof: boolean;
  deployment_mode: "full" | "lite" | string;
}

export interface OnboardingPatch {
  workspace_name?: string;
  current_step?: WizardStep;
  step_done?: WizardStep;
  scope_entry_id?: number | null;
  first_scan_id?: string | null;
  dismissed?: boolean;
  completed?: boolean;
}

export interface Challenge {
  scope_entry_id: number;
  kind: ScopeKind;
  domain: string;
  token: string;
  methods: string[];
  dns_txt: { name: string; type: "TXT"; value: string };
  http_file: { url: string; body: string } | null;
  proof: ScopeProof;
}

export interface VerifyResult {
  scope_entry_id: number;
  check: { ok: boolean; method: string; detail: string };
  proof: ScopeProof;
}

export interface ServiceStatus {
  name: string;
  feature: string;
  enabled: boolean;
  status: "ok" | "down" | "not_enabled";
}

export const getOnboarding = () => apiFetch<Onboarding>("/v1/onboarding");

export const putOnboarding = (patch: OnboardingPatch) =>
  apiFetch<Onboarding>("/v1/onboarding", { method: "PUT", body: patch });

export const issueChallenge = (entryId: number) =>
  apiFetch<Challenge>(`/v1/scope/${entryId}/challenge`, { method: "POST" });

export const verifyScope = (
  entryId: number,
  body: { method?: ProofMethod; loa_ref?: string; approver?: string } = {},
) => apiFetch<VerifyResult>(`/v1/scope/${entryId}/verify`, { method: "POST", body });

export const addScope = (body: {
  kind: ScopeKind;
  value: string;
  added_by: string;
  auth_doc_ref?: string;
}) => apiFetch<ScopeEntryWithProof>("/v1/scope", { body });

export const startScan = (kind: string, target: string) =>
  apiFetch<ScanBrief>("/v1/scans", { body: { kind, target } });

export const createInviteKey = (name: string) =>
  apiFetch<{ api_key: string; prefix: string; scopes: string[] }>("/v1/auth/apikeys", {
    body: { name, scopes: ["read"] },
  });

export const getServices = () =>
  apiFetch<{ mode: string; services: ServiceStatus[] }>("/v1/system/services");
