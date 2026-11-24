/**
 * System inventory (admin): what this install is made of and what is healthy.
 * Mirrors orchestrator/app/system.py.
 */
import { apiFetch } from "./client";

/** `not_installed` = the service's host does not resolve (e.g. left out of the lite stack). */
export type ComponentStatus = "up" | "down" | "not_installed";

export interface SystemComponent {
  key: string;
  label: string;
  description: string;
  status: ComponentStatus;
}

export interface SystemInfo {
  version: string;
  edition: string;
  license_status: string;
  auth_mode: "dev" | "enforce";
  scheduler_enabled: boolean;
  core: SystemComponent[];
  services: SystemComponent[];
  counts: Record<ComponentStatus, number>;
}

export const getSystem = () => apiFetch<SystemInfo>("/v1/system");

/** AI features (Settings → System): the optional Anthropic key. Mirrors orchestrator/app/ai_settings.py. */
export interface AiStatus {
  configured: boolean;
  /** "…abcd": the last four characters. The key itself is never returned. */
  hint: string | null;
  updated_at: string | null;
  updated_by: string | null;
  /** Only the platform operator may change it. */
  editable: boolean;
  /** Whether the Brain service (which uses the key) is running. */
  brain: ComponentStatus;
}

export const getAiStatus = () => apiFetch<AiStatus>("/v1/system/ai");
export const saveAiKey = (api_key: string) =>
  apiFetch<AiStatus>("/v1/system/ai", { method: "PUT", body: { api_key } });
export const removeAiKey = () => apiFetch<AiStatus>("/v1/system/ai", { method: "DELETE" });
