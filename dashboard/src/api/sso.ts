/**
 * Enterprise identity API: SSO (OIDC / SAML) login flow + admin config for
 * identity providers, the SSO-required policy, and SCIM tokens.
 *
 * Login flow (no token ever travels in a URL):
 *   1. beginSso(): make a random verifier, keep it in sessionStorage, and
 *      navigate to /v1/auth/sso/<slug>/start?spa_challenge=<S256(verifier)>.
 *   2. The IdP round-trips through the orchestrator, which redirects back to
 *      /sso/callback?code=<one-time code>.
 *   3. completeSso(): POST {code, verifier} to /v1/auth/sso/exchange → JWT.
 *      The code is useless without the verifier, which never left this tab.
 */

import { apiFetch, buildUrl } from "./client";
import type { Classification, Role } from "./types";

/* ------------------------------- types --------------------------------- */

export type ProviderKind = "oidc" | "saml";
export type Preset = "generic" | "okta" | "entra" | "google" | "auth0" | "keycloak";

export interface PublicProvider {
  slug: string;
  kind: ProviderKind;
  preset: Preset;
  display_name: string;
  start_url: string;
}

export interface PublicProviders {
  providers: PublicProvider[];
  sso_required: boolean;
}

export interface ExchangeResponse {
  access_token: string;
  role: Role;
  clearance: Classification;
  expires_in: number;
  username: string;
}

export interface RoleMapping {
  group: string;
  role: Role;
  clearance?: Classification | null;
}

export interface OIDCSettings {
  issuer: string;
  client_id: string;
  scopes?: string[];
  token_auth_method?: "client_secret_basic" | "client_secret_post" | "none";
  use_userinfo?: boolean;
  trust_unverified_email?: boolean;
  allow_private?: boolean;
}

export interface SAMLSettings {
  idp_entity_id: string;
  idp_sso_url: string;
  idp_x509_cert: string;
  name_id_format?: string;
  email_attribute?: string | null;
  groups_attribute?: string | null;
  name_attribute?: string | null;
  want_messages_signed?: boolean;
}

export interface Provider {
  id: string;
  slug: string;
  kind: ProviderKind;
  preset: Preset;
  display_name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  has_client_secret: boolean;
  allowed_domains: string[];
  jit_provisioning: boolean;
  sync_roles: boolean;
  require_mapping: boolean;
  default_role: Role;
  default_clearance: Classification;
  groups_claim: string;
  role_mappings: RoleMapping[];
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  redirect_uri?: string | null;
  saml_acs_url?: string | null;
  saml_entity_id?: string | null;
  saml_metadata_url?: string | null;
}

export interface ProviderInput {
  slug?: string;
  kind?: ProviderKind;
  preset?: Preset;
  display_name?: string;
  enabled?: boolean;
  oidc?: OIDCSettings;
  saml?: SAMLSettings;
  saml_metadata_xml?: string;
  client_secret?: string;
  allowed_domains?: string[];
  jit_provisioning?: boolean;
  sync_roles?: boolean;
  require_mapping?: boolean;
  default_role?: Role;
  default_clearance?: Classification;
  groups_claim?: string;
  role_mappings?: RoleMapping[];
}

export interface IdentitySettings {
  sso_required: boolean;
  break_glass_users: string[];
  scim_role_mappings: RoleMapping[];
  scim_default_role: Role;
  scim_default_clearance: Classification;
  updated_by?: string | null;
  updated_at: string;
  scim_base_url: string;
}

export interface ScimToken {
  id: string;
  name: string;
  prefix: string;
  created_by?: string | null;
  created_at: string;
  last_used?: string | null;
  expires_at?: string | null;
  revoked: boolean;
}

export interface ScimTokenCreated extends ScimToken {
  token: string;
}

export interface ProviderTestResult {
  ok: boolean;
  error?: string;
  detail?: string;
  [k: string]: unknown;
}

/* ----------------------------- public flow ----------------------------- */

const VERIFIER_KEY = "paddock.sso.verifier";

/** Indirection so tests can observe navigation (jsdom can't navigate). */
export const nav = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

export function listSsoProviders(): Promise<PublicProviders> {
  return apiFetch<PublicProviders>("/v1/auth/sso/providers");
}

/** Coerce whatever the endpoint returned into a safe shape. */
export function normalizeProviders(raw: unknown): PublicProviders {
  const r = (raw ?? {}) as Partial<PublicProviders>;
  const providers = Array.isArray(r.providers)
    ? r.providers.filter((p): p is PublicProvider => !!p && typeof p.slug === "string")
    : [];
  return { providers, sso_required: r.sso_required === true };
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

/** base64url(sha256(verifier)) — WebCrypto when available, else a JS fallback
 *  (crypto.subtle is missing on plain-http LAN deployments). */
export async function s256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (subtle) {
    try {
      return b64url(new Uint8Array(await subtle.digest("SHA-256", data)));
    } catch {
      /* fall through to the JS implementation */
    }
  }
  return b64url(sha256(data));
}

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** Kick off SP-initiated SSO for one provider. */
export async function beginSso(p: PublicProvider, returnTo = "/"): Promise<void> {
  const verifier = randomVerifier();
  storage()?.setItem(VERIFIER_KEY, verifier);
  const challenge = await s256(verifier);
  nav.assign(buildUrl(p.start_url, { spa_challenge: challenge, return_to: returnTo }));
}

/** Read (and forget) the verifier stored by beginSso. */
export function takeVerifier(): string | null {
  const s = storage();
  if (!s) return null;
  const v = s.getItem(VERIFIER_KEY);
  s.removeItem(VERIFIER_KEY);
  return v;
}

export function exchangeSsoCode(code: string, verifier: string | null): Promise<ExchangeResponse> {
  return apiFetch<ExchangeResponse>("/v1/auth/sso/exchange", {
    method: "POST",
    body: verifier ? { code, verifier } : { code },
  });
}

/** Human copy for the callback's ?error= codes (server never sends detail). */
export const SSO_ERRORS: Record<string, string> = {
  state_mismatch: "This sign-in link expired or was opened in a different browser. Start again.",
  invalid_token: "The identity provider's response could not be verified.",
  invalid_assertion: "The identity provider's SAML response could not be verified.",
  replay: "That sign-in response was already used. Start again.",
  idp_error: "The identity provider declined the sign-in.",
  provider_unavailable: "The identity provider could not be reached.",
  provider_misconfigured: "Single sign-on is misconfigured. Contact your administrator.",
  unknown_provider: "That identity provider is not enabled.",
  domain_not_allowed: "Your email domain is not allowed to sign in here.",
  no_mapping: "Your account is not in a group that grants access to Paddock.",
  provisioning_disabled: "You don't have a Paddock account yet. Ask an administrator to provision you.",
  account_conflict: "An account with your email already exists and couldn't be linked safely. Contact your administrator.",
  user_disabled: "Your Paddock account is deactivated.",
  saml_unavailable: "SAML is not installed on this server.",
};

export function ssoErrorMessage(code: string | null | undefined): string {
  if (!code) return "Single sign-on failed.";
  return SSO_ERRORS[code] ?? "Single sign-on failed.";
}

/** Only same-origin absolute paths. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  return next;
}

/* ------------------------------- admin --------------------------------- */

const ADMIN = "/v1/auth/sso/admin";

export const listProviders = () => apiFetch<Provider[]>(`${ADMIN}/providers`);
export const createProvider = (body: ProviderInput) =>
  apiFetch<Provider>(`${ADMIN}/providers`, { method: "POST", body });
export const updateProvider = (id: string, body: ProviderInput) =>
  apiFetch<Provider>(`${ADMIN}/providers/${id}`, { method: "PATCH", body });
export const deleteProvider = (id: string) =>
  apiFetch<unknown>(`${ADMIN}/providers/${id}`, { method: "DELETE" });
export const testProvider = (id: string) =>
  apiFetch<ProviderTestResult>(`${ADMIN}/providers/${id}/test`, { method: "POST", body: {} });

export const getIdentitySettings = () => apiFetch<IdentitySettings>(`${ADMIN}/settings`);
export const putIdentitySettings = (body: Partial<IdentitySettings>) =>
  apiFetch<IdentitySettings>(`${ADMIN}/settings`, { method: "PUT", body });

export const listScimTokens = () => apiFetch<ScimToken[]>(`${ADMIN}/scim-tokens`);
export const createScimToken = (name: string) =>
  apiFetch<ScimTokenCreated>(`${ADMIN}/scim-tokens`, { method: "POST", body: { name } });
export const revokeScimToken = (id: string) =>
  apiFetch<ScimToken>(`${ADMIN}/scim-tokens/${id}`, { method: "DELETE" });

/* ------------------------- SHA-256 (fallback) --------------------------- */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Minimal SHA-256 (FIPS 180-4) for environments without WebCrypto. */
export function sha256(msg: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const len = msg.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  const bits = len * 8;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
  dv.setUint32(padded.length - 4, bits >>> 0);
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
  return out;
}
