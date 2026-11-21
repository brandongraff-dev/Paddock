import { apiFetch } from "./client";
import type { Scan, ScanStatus } from "./types";

export function listScans(q?: { target?: string; status?: ScanStatus; limit?: number }): Promise<Scan[]> {
  return apiFetch<Scan[]>("/v1/scans", { query: q });
}

export function getScan(id: string): Promise<Scan> {
  return apiFetch<Scan>(`/v1/scans/${encodeURIComponent(id)}`);
}

export function createScan(body: {
  kind: string;
  target: string;
  config?: Record<string, unknown>;
}): Promise<{ scan_id: string }> {
  return apiFetch<{ scan_id: string }>("/v1/scans", { body });
}
