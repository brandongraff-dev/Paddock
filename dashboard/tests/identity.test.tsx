/**
 * Enterprise identity (SSO + SCIM) dashboard tests:
 *   - Login renders "Continue with <IdP>" from the public providers endpoint
 *     and starts SP-initiated SSO with an S256 challenge (no token in URLs).
 *   - SSO-required folds the password form behind break-glass access.
 *   - /sso/callback exchanges code + verifier for a session, or explains errors.
 *   - Settings → Identity lists providers and reveals a new SCIM token once.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Login from "../src/pages/Login";
import SsoCallback from "../src/pages/SsoCallback";
import IdentitySettingsPage from "../src/pages/IdentitySettings";
import * as sso from "../src/api/sso";
import { useAuth } from "../src/state/auth";

type Route = [RegExp, unknown, number?, string?];

function mockFetch(routes: Route[]) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    for (const [re, body, status, m] of routes) {
      if (re.test(url) && (!m || m === method)) {
        return new Response(JSON.stringify(body), {
          status: status ?? 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  });
}

function withClient(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, node));
}

const PROVIDERS = {
  providers: [
    { slug: "okta", kind: "oidc", preset: "okta", display_name: "Okta", start_url: "/v1/auth/sso/okta/start" },
    { slug: "corp", kind: "saml", preset: "generic", display_name: "Corp SAML", start_url: "/v1/auth/sso/corp/start" },
  ],
  sso_required: false,
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuth.setState({ token: null, user: null });
  try { sessionStorage.clear(); } catch { /* ignore */ }
  window.history.replaceState(null, "", "/");
});

describe("sha256 fallback", () => {
  it("matches the RFC 7636 appendix B PKCE vector", async () => {
    const v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const viaJs = btoa(String.fromCharCode(...sso.sha256(new TextEncoder().encode(v))))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(viaJs).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    expect(await sso.s256(v)).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});

describe("Login SSO", () => {
  it("shows a Continue-with button per provider and keeps the password form", async () => {
    mockFetch([[/\/v1\/auth\/sso\/providers/, PROVIDERS]]);
    render(React.createElement(Login));
    expect(await screen.findByRole("button", { name: /continue with okta/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /continue with corp saml/i })).toBeInTheDocument();
    // existing surface intact
    expect(screen.getByText("Paddock")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
  });

  it("starts SSO with an S256 challenge and stores the verifier in this tab", async () => {
    mockFetch([[/\/v1\/auth\/sso\/providers/, PROVIDERS]]);
    const assign = vi.spyOn(sso.nav, "assign").mockImplementation(() => undefined);
    window.history.replaceState(null, "", "/findings?sev=high");
    render(React.createElement(Login));
    fireEvent.click(await screen.findByRole("button", { name: /continue with okta/i }));
    await vi.waitFor(() => expect(assign).toHaveBeenCalledTimes(1));
    const url = new URL(assign.mock.calls[0][0], "http://x");
    expect(url.pathname).toBe("/v1/auth/sso/okta/start");
    expect(url.searchParams.get("return_to")).toBe("/findings?sev=high");
    const verifier = sessionStorage.getItem("paddock.sso.verifier")!;
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(url.searchParams.get("spa_challenge")).toBe(await sso.s256(verifier));
    expect(url.toString()).not.toContain(verifier);
  });

  it("renders no SSO buttons when the endpoint returns nothing useful", async () => {
    const f = mockFetch([]);
    render(React.createElement(Login));
    await vi.waitFor(() => expect(f).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /continue with/i })).toBeNull();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("folds local sign-in behind break-glass access when SSO is required", async () => {
    mockFetch([[/\/v1\/auth\/sso\/providers/, { ...PROVIDERS, sso_required: true }]]);
    render(React.createElement(Login));
    const bg = await screen.findByRole("button", { name: /break-glass access/i });
    expect(screen.queryByLabelText(/password/i)).toBeNull();
    fireEvent.click(bg);
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});

describe("SSO callback", () => {
  it("exchanges the one-time code + verifier, stores the session and lands on next", async () => {
    sessionStorage.setItem("paddock.sso.verifier", "v".repeat(43));
    window.history.replaceState(null, "", "/sso/callback?code=one-time-code-123456&next=/findings");
    const f = mockFetch([
      [/\/v1\/auth\/sso\/exchange/, {
        access_token: "jwt-sso", role: "analyst", clearance: "internal", expires_in: 3600, username: "alice@example.com",
      }, 200, "POST"],
      [/\/v1\/auth\/me/, { username: "alice@example.com", role: "analyst", clearance: "internal" }],
    ]);
    render(React.createElement(SsoCallback));
    await vi.waitFor(() => expect(useAuth.getState().token).toBe("jwt-sso"));
    const call = f.mock.calls.find(([u]) => /exchange/.test(String(u)))!;
    expect(JSON.parse(String(call[1]!.body))).toEqual({ code: "one-time-code-123456", verifier: "v".repeat(43) });
    expect(window.location.pathname).toBe("/findings");
    expect(window.location.search).not.toContain("code");
    expect(sessionStorage.getItem("paddock.sso.verifier")).toBeNull(); // single use
    await vi.waitFor(() => expect(useAuth.getState().user?.username).toBe("alice@example.com"));
  });

  it("explains an error code without echoing server detail", async () => {
    window.history.replaceState(null, "", "/sso/callback?error=domain_not_allowed");
    render(React.createElement(SsoCallback));
    expect(await screen.findByRole("alert")).toHaveTextContent(/email domain is not allowed/i);
    expect(screen.getByRole("link", { name: /back to sign-in/i })).toBeInTheDocument();
    expect(useAuth.getState().token).toBeNull();
  });

  it("rejects an open redirect in next", () => {
    expect(sso.safeNext("//evil.example")).toBe("/");
    expect(sso.safeNext("https://evil.example")).toBe("/");
    expect(sso.safeNext("/graph")).toBe("/graph");
  });
});

describe("Settings → Identity", () => {
  const provider = {
    id: "p1", slug: "okta", kind: "oidc", preset: "okta", display_name: "Okta", enabled: true,
    config: { issuer: "https://acme.okta.com/oauth2/default", client_id: "cid" }, has_client_secret: true,
    allowed_domains: ["acme.example"], jit_provisioning: true, sync_roles: true, require_mapping: false,
    default_role: "viewer", default_clearance: "internal", groups_claim: "groups",
    role_mappings: [{ group: "paddock-admins", role: "admin", clearance: "restricted" }],
    created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00Z",
    redirect_uri: "https://paddock.acme.example/v1/auth/sso/okta/callback",
  };
  const settings = {
    sso_required: false, break_glass_users: ["admin"], scim_role_mappings: [],
    scim_default_role: "viewer", scim_default_clearance: "internal", updated_at: "2026-11-01T00:00:00Z",
    scim_base_url: "https://paddock.acme.example/scim/v2",
  };

  it("lists providers and shows a new SCIM token exactly once", async () => {
    useAuth.setState({ token: "t", user: { username: "root", role: "admin", clearance: "restricted" } });
    const f = mockFetch([
      [/\/admin\/providers$/, [provider]],
      [/\/admin\/settings$/, settings],
      [/\/admin\/scim-tokens$/, {
        id: "t1", name: "okta-prov", prefix: "abcd1234", created_at: "2026-11-21T00:00:00Z", revoked: false,
        token: "pscim_abcd1234_SECRET",
      }, 201, "POST"],
      [/\/admin\/scim-tokens$/, []],
    ]);
    withClient(React.createElement(IdentitySettingsPage));
    expect(await screen.findByText("Okta")).toBeInTheDocument();
    expect(screen.getByText(/okta · OIDC · 1 mapping · acme.example/)).toBeInTheDocument();
    expect(await screen.findByText("https://paddock.acme.example/scim/v2")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/new token name/i), { target: { value: "okta-prov" } });
    fireEvent.click(screen.getByRole("button", { name: /create token/i }));
    const box = await screen.findByRole("status");
    expect(within(box).getByText("pscim_abcd1234_SECRET")).toBeInTheDocument();
    expect(within(box).getByText(/won't be shown again/i)).toBeInTheDocument();
    const post = f.mock.calls.find(([u, i]) => /scim-tokens/.test(String(u)) && i?.method === "POST")!;
    expect(JSON.parse(String(post[1]!.body))).toEqual({ name: "okta-prov" });
    fireEvent.click(within(box).getByRole("button", { name: /dismiss token/i }));
    expect(screen.queryByText("pscim_abcd1234_SECRET")).toBeNull();
  });

  it("disables admin controls for a non-admin", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });
    mockFetch([[/\/admin\/providers$/, []], [/\/admin\/settings$/, settings], [/\/admin\/scim-tokens$/, []]]);
    withClient(React.createElement(IdentitySettingsPage));
    expect(await screen.findByRole("button", { name: /add provider/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /save policy/i })).toBeDisabled();
  });

  it("builds an OIDC provider payload from the editor", async () => {
    useAuth.setState({ token: "t", user: { username: "root", role: "admin", clearance: "restricted" } });
    const f = mockFetch([
      [/\/admin\/providers$/, { ...provider, id: "p2" }, 201, "POST"],
      [/\/admin\/providers$/, []],
      [/\/admin\/settings$/, settings],
      [/\/admin\/scim-tokens$/, []],
    ]);
    withClient(React.createElement(IdentitySettingsPage));
    fireEvent.click(await screen.findByRole("button", { name: /add provider/i }));
    const dialog = screen.getByRole("form", { name: /identity provider/i });
    fireEvent.change(within(dialog).getByLabelText(/^provider$/i), { target: { value: "entra" } });
    fireEvent.change(within(dialog).getByLabelText(/issuer url/i), {
      target: { value: "https://login.microsoftonline.com/tid/v2.0" },
    });
    fireEvent.change(within(dialog).getByLabelText(/client id/i), { target: { value: "app-id" } });
    fireEvent.change(within(dialog).getByLabelText(/client secret/i), { target: { value: "shh" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /add mapping/i }));
    fireEvent.change(within(dialog).getByLabelText(/mapping 1 group/i), { target: { value: "Paddock.Admin" } });
    fireEvent.change(within(dialog).getByLabelText(/mapping 1 role/i), { target: { value: "admin" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /^add provider$/i }));
    await vi.waitFor(() =>
      expect(f.mock.calls.some(([u, i]) => /admin\/providers$/.test(String(u)) && i?.method === "POST")).toBe(true),
    );
    const post = f.mock.calls.find(([u, i]) => /admin\/providers$/.test(String(u)) && i?.method === "POST")!;
    const body = JSON.parse(String(post[1]!.body));
    expect(body).toMatchObject({
      slug: "entra", kind: "oidc", preset: "entra", display_name: "Microsoft Entra ID",
      client_secret: "shh", groups_claim: "roles",
      oidc: { issuer: "https://login.microsoftonline.com/tid/v2.0", client_id: "app-id" },
      role_mappings: [{ group: "Paddock.Admin", role: "admin", clearance: null }],
    });
  });
});
