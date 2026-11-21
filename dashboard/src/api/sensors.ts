import { apiFetch } from "./client";

/**
 * Sentry sensors (orchestrator /v1/sensors, schema 034): enrollment tokens,
 * enrolled sensors with health, revocation. Self-contained types, same
 * convention as api/fleet.ts.
 */

export type SensorState = "online" | "degraded" | "offline" | "revoked";
export type TokenState = "pending" | "used" | "expired" | "revoked";

export interface SensorHealth {
  clock_skew_s?: number;
  packets_seen?: number;
  packets_dropped?: number;
  flows_dropped?: number;
  buffer_fill_pct?: number;
  buffer_bytes?: number;
  buffer_batches?: number;
  batches_dropped?: number;
  last_upload_ts?: number;
  last_upload_ok?: boolean;
  uptime_s?: number;
  iface?: string;
  reported_at?: string;
}

export interface SensorInterface {
  name: string;
  up?: boolean;
  speed_mbps?: number;
  mac?: string;
}

export interface Sensor {
  id: string;
  name: string;
  site: string;
  state: SensorState;
  status: "active" | "revoked";
  version: string | null;
  hostname: string | null;
  interfaces: SensorInterface[];
  enrolled_at: string;
  last_seen_at: string | null;
  last_heartbeat_at: string | null;
  last_upload_at: string | null;
  offline_since: string | null;
  silent_after_s: number;
  health: SensorHealth;
  warnings: string[];
  batches_total: number;
  flows_total: number;
  duplicates_total: number;
}

export interface EnrollToken {
  id: string;
  token_prefix: string;
  site: string;
  label: string | null;
  created_by: string | null;
  created_at: string;
  expires_at: string;
  state: TokenState;
  used_by_sensor: string | null;
}

export interface TokenCreated extends EnrollToken {
  /** The enrollment token. Returned once; never retrievable again. */
  token: string;
}

export interface TokenInput {
  site: string;
  label?: string;
  ttl_minutes: number;
}

export function listSensors(): Promise<Sensor[]> {
  return apiFetch<Sensor[]>("/v1/sensors");
}

export function listTokens(): Promise<EnrollToken[]> {
  return apiFetch<EnrollToken[]>("/v1/sensors/tokens");
}

export function createToken(body: TokenInput): Promise<TokenCreated> {
  return apiFetch<TokenCreated>("/v1/sensors/tokens", { method: "POST", body });
}

export function revokeToken(id: string): Promise<void> {
  return apiFetch<void>(`/v1/sensors/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function revokeSensor(id: string): Promise<Sensor> {
  return apiFetch<Sensor>(`/v1/sensors/${encodeURIComponent(id)}/revoke`, { method: "POST" });
}

export function patchSensor(
  id: string,
  body: { name?: string; site?: string; silent_after_s?: number },
): Promise<Sensor> {
  return apiFetch<Sensor>(`/v1/sensors/${encodeURIComponent(id)}`, { method: "PATCH", body });
}

/** The exact commands the wizard shows for a fresh token. */
export function enrollCommand(server: string, token: string): string {
  return `sudo paddock-sentry enroll ${server} ${token}`;
}

/** The boot-partition file (`paddock-sentry.env`) the first-boot installer reads. */
export function bootFile(server: string, token: string, site: string): string {
  return [
    "# Paddock Sentry: first-boot enrollment. Copy to the boot partition of the SD card",
    "# (the drive named bootfs / boot) as paddock-sentry.env, then power the Pi on.",
    `PADDOCK_SERVER=${server}`,
    `PADDOCK_ENROLL_TOKEN=${token}`,
    `# site: ${site} (set by the token)`,
    "# PADDOCK_SENTRY_IFACE=eth1     # optional: force the mirror-port NIC",
    "# PADDOCK_SENTRY_NAME=lobby-1   # optional: name shown in the dashboard",
    "",
  ].join("\n");
}
