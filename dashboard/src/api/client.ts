/**
 * Thin fetch wrapper for the orchestrator API, plus an EventSource helper
 * for /v1/events. All API calls go through apiFetch() so error handling,
 * base URL, and auth placeholder live in exactly one place.
 */

import type { LiveEvent } from "./types";
import { useAuth } from "../state/auth";
import { actingToken, useMsp } from "../state/msp";

/** VITE_API_URL is set in the Vite env; in prod nginx proxies /v1/* so "" works. */
const RAW_BASE = (import.meta as any).env?.VITE_API_URL ?? "";
/** Strip a trailing slash so joinUrl() doesn't double-up. */
export const API_BASE: string = String(RAW_BASE).replace(/\/+$/, "");

/**
 * Attach `Authorization: Bearer <token>` whenever we hold a session token.
 * The live token comes from the auth store (set by login / API-key submit);
 * VITE_API_TOKEN remains a build-time fallback for local dev. The store is
 * read via getState() so this stays usable outside React.
 */
export function authHeaders(): Record<string, string> {
  // Inside an MSP customer the short-lived customer-scoped token replaces the
  // MSP session token (state/msp.ts); "Back to MSP" drops it again.
  const token =
    actingToken() ??
    useAuth.getState().token ??
    ((import.meta as any).env?.VITE_API_TOKEN as string | undefined);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function joinUrl(base: string, path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  if (!base) return path.startsWith("/") ? path : `/${path}`;
  return `${base}${path.startsWith("/") ? "" : "/"}${path}`;
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export interface FetchOpts extends Omit<RequestInit, "body"> {
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
}

export function buildUrl(path: string, query?: FetchOpts["query"]): string {
  const url = joinUrl(API_BASE, path);
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    params.append(k, String(v));
  }
  const q = params.toString();
  if (!q) return url;
  return `${url}${url.includes("?") ? "&" : "?"}${q}`;
}

export async function apiFetch<T = unknown>(path: string, opts: FetchOpts = {}): Promise<T> {
  const { body, query, headers, method, ...rest } = opts;
  const url = buildUrl(path, query);
  const init: RequestInit = {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...authHeaders(),
      ...(headers as Record<string, string> | undefined),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    ...rest,
  };

  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (e) {
    throw new ApiError(`network error calling ${url}`, 0, String(e));
  }

  const text = await res.text();
  let parsed: unknown = text;
  if (text && /^[\[{]/.test(text.trimStart())) {
    try {
      parsed = JSON.parse(text);
    } catch {
      /* leave as text */
    }
  }

  if (!res.ok) {
    // Expired / rejected token → drop the session. Clearing it makes the
    // top-level gate in App.tsx re-render to the Login screen. We only clear
    // when a token was actually in play, so a 401 from the login call itself
    // (bad credentials, handled by the Login screen) doesn't loop.
    if (res.status === 401 && useMsp.getState().acting) {
      // The customer token expired / the grant was revoked / the customer was
      // suspended: leave the customer, keep the MSP session.
      useMsp.getState().exit();
    } else if (res.status === 401 && useAuth.getState().token) {
      useAuth.getState().logout();
    }
    throw new ApiError(
      `${res.status} ${res.statusText} on ${init.method} ${path}`,
      res.status,
      parsed,
    );
  }
  return parsed as T;
}

/* -------------------------------------------------------------------- *
 *  Server-sent events: /v1/events                                       *
 * -------------------------------------------------------------------- */

export interface EventStreamHandle {
  close: () => void;
}

/**
 * openEventStream — subscribe to orchestrator SSE.
 *
 * The orchestrator exposes `GET /v1/events` which emits NDJSON-shaped
 * payloads per `data:` line (see CONTRACTS.md "Event stream"). We parse each
 * and forward through onEvent. Auto-reconnect happens via EventSource itself.
 *
 * If EventSource is unavailable (SSR / test env), returns a no-op handle so
 * callers can still mount without crashing.
 */
export function openEventStream(
  onEvent: (e: LiveEvent) => void,
  onError?: (err: unknown) => void,
): EventStreamHandle {
  if (typeof EventSource === "undefined") {
    return { close: () => undefined };
  }
  const url = buildUrl("/v1/events");
  const es = new EventSource(url, { withCredentials: false });

  es.onmessage = (ev) => {
    if (!ev.data) return;
    try {
      const parsed = JSON.parse(ev.data) as LiveEvent;
      onEvent(parsed);
    } catch (err) {
      onError?.(err);
    }
  };
  es.onerror = (err) => {
    onError?.(err);
  };

  return { close: () => es.close() };
}
