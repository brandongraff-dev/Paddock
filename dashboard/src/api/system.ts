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
