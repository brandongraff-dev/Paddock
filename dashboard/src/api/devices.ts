import { apiFetch } from "./client";

/**
 * IoT/OT device inventory API (orchestrator /v1/devices). Types are declared
 * here rather than in the shared types.ts so this feature stays self-contained.
 * Mirrors the envelope-unwrap tolerance of the other list endpoints.
 */

export type DeviceRole = "iot" | "ot";

export interface Device {
  id: string;
  kind: string;
  role: DeviceRole;
  value: string;
  canonical: string;
  vendor?: string | null;
  model?: string | null;
  type?: string | null;
  mac?: string | null;
  ips: string[];
  protocols: string[];
  os?: string | null;
  confidence: number;
  segment?: string | null;
  first_seen: string;
  last_seen: string;
  open_finding_count: number;
  exposed: boolean;
  metadata: Record<string, unknown>;
}

export interface DevicePage {
  items: Device[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceFindingBrief {
  id: string;
  rule_id: string;
  rule_source: string;
  severity: string;
  status: string;
  title: string;
  description?: string | null;
  cvss?: number | null;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
}

export interface DeviceSegment {
  id: string;
  value: string;
  canonical: string;
  classification?: string | null;
  internet_facing: boolean;
  device_count?: number | null;
  metadata: Record<string, unknown>;
}

export interface DeviceDetail {
  device: Device;
  findings: DeviceFindingBrief[];
  segment?: DeviceSegment | null;
}

export interface DeviceSummary {
  total: number;
  ot_total: number;
  iot_total: number;
  by_role: Record<string, number>;
  by_type: Record<string, number>;
  by_vendor: Record<string, number>;
  exposed_ot: number;
  it_ot_violations: number;
  internet_facing_ot: number;
  segments: number;
}

export type DeviceFilter = {
  type?: string;
  role?: DeviceRole;
  vendor?: string;
  limit?: number;
  offset?: number;
};

/** GET /v1/devices — paged. Tolerates both the envelope and a bare array. */
export function listDevices(q?: DeviceFilter): Promise<DevicePage> {
  return apiFetch<DevicePage | Device[]>("/v1/devices", { query: q }).then((r) =>
    Array.isArray(r)
      ? { items: r, total: r.length, limit: q?.limit ?? r.length, offset: q?.offset ?? 0 }
      : r,
  );
}

/** GET /v1/devices/{id} — device + findings + segment. */
export function getDevice(id: string): Promise<DeviceDetail> {
  return apiFetch<DeviceDetail>(`/v1/devices/${encodeURIComponent(id)}`);
}

/** GET /v1/devices/summary — header-tile counts. */
export function getDeviceSummary(): Promise<DeviceSummary> {
  return apiFetch<DeviceSummary>("/v1/devices/summary");
}
