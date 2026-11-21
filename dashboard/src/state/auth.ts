/**
 * Auth store (zustand) — governance §B.
 *
 * Holds the bearer token + the authenticated principal. Persisted to
 * localStorage so a reload keeps you signed in; every read/write is wrapped in
 * try/catch because storage can throw (private mode, blocked site data) or
 * come back empty. This is the ONLY place the token lives; api/client.ts reads
 * it via useAuth.getState() to attach the Authorization header, and clears it
 * here on a 401.
 *
 * The permission model (RBAC) is pure and lives here too so both React
 * components (useCan) and non-React code can reason about it:
 *   viewer   — read non-restricted. No mutate.
 *   auditor  — read + audit log + integrity verify. No mutate.
 *   analyst  — read + triage (patch findings/tickets/anomalies, scan, retrain).
 *   admin    — everything, incl. scope / owners / alerts / schedules / keys.
 */

import { create } from "zustand";
import type { AuthUser, Classification, Role } from "../api/types";

/** A user's clearance is a point on the same ladder as data classification. */
export type Clearance = Classification;

const LS_KEY = "paddock.auth.v1";

interface Persisted {
  token: string | null;
  user: AuthUser | null;
}

function load(): Persisted {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const p = JSON.parse(raw) as Partial<Persisted>;
      return { token: p.token ?? null, user: p.user ?? null };
    }
  } catch {
    /* storage unavailable — start signed out */
  }
  return { token: null, user: null };
}

function persist(next: Persisted): void {
  try {
    if (next.token) localStorage.setItem(LS_KEY, JSON.stringify(next));
    else localStorage.removeItem(LS_KEY);
  } catch {
    /* ignore — in-memory state is still authoritative for this tab */
  }
}

export interface AuthState {
  token: string | null;
  user: AuthUser | null;
  /** Set after a successful login / API-key submit. */
  setAuth: (token: string, user: AuthUser | null) => void;
  /** Fill / refresh the principal once GET /v1/auth/me returns. */
  setUser: (user: AuthUser) => void;
  /** Drop the session (logout button, or a 401 from the API). */
  logout: () => void;
}

const initial = load();

export const useAuth = create<AuthState>((set, get) => ({
  token: initial.token,
  user: initial.user,
  setAuth: (token, user) => {
    persist({ token, user });
    set({ token, user });
  },
  setUser: (user) => {
    persist({ token: get().token, user });
    set({ user });
  },
  logout: () => {
    persist({ token: null, user: null });
    set({ token: null, user: null });
  },
}));

/* ----------------------------- permissions ----------------------------- */

/** A gated capability. "triage" = analyst-level mutate; "admin" = admin-only. */
export type Capability = "triage" | "admin";

/** Pure RBAC check — safe to call from React or plain code. */
export function roleCan(role: Role | null | undefined, cap: Capability): boolean {
  if (!role) return false;
  if (role === "admin") return true;
  if (role === "analyst") return cap === "triage";
  return false; // viewer, auditor: read-only
}

/** Who may open the Audit log (read + integrity verify). */
export function canViewAudit(role: Role | null | undefined): boolean {
  return role === "auditor" || role === "admin";
}

/* ------------------------------- hooks --------------------------------- */

/** React selector for a capability check against the current principal. */
export function useCan(cap: Capability): boolean {
  return useAuth((s) => roleCan(s.user?.role, cap));
}

export const selectToken = (s: AuthState) => s.token;
export const selectUser = (s: AuthState) => s.user;
