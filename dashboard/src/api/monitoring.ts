import { apiFetch } from "./client";
import type { Schedule } from "./types";

export function listSchedules(): Promise<Schedule[]> {
  return apiFetch<{ items: Schedule[] } | Schedule[]>("/v1/schedules").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}

export interface ScheduleInput {
  name: string;
  scan_kind: string;
  target_scope: string;
  /** Either a cron string or a config carrying every_n_minutes (not both). */
  cron?: string | null;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export function createSchedule(body: ScheduleInput): Promise<Schedule> {
  return apiFetch<Schedule>("/v1/schedules", { method: "POST", body });
}

export function patchSchedule(id: string, patch: Partial<ScheduleInput>): Promise<Schedule> {
  return apiFetch<Schedule>(`/v1/schedules/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
  });
}

export function deleteSchedule(id: string): Promise<void> {
  return apiFetch<void>(`/v1/schedules/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** POST /v1/schedules/{id}/run-now — enqueues the scan immediately. */
export function runScheduleNow(id: string): Promise<{ queued?: boolean; scan_id?: string }> {
  return apiFetch<{ queued?: boolean; scan_id?: string }>(
    `/v1/schedules/${encodeURIComponent(id)}/run-now`,
    { method: "POST", body: {} },
  );
}
