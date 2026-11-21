/**
 * Auth endpoints (governance §A). The token itself lives in state/auth.ts;
 * this module only talks to the orchestrator. apiFetch attaches the bearer
 * automatically once the store holds a token, so `me()` works right after
 * `setAuth()`.
 */

import { apiFetch } from "./client";
import type { AuthUser, LoginResponse } from "./types";

/** POST /v1/auth/login — username/password → JWT + role/clearance. */
export function login(username: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/v1/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

/** GET /v1/auth/me — resolve the principal behind the current bearer. */
export function me(): Promise<AuthUser> {
  return apiFetch<AuthUser>("/v1/auth/me");
}
