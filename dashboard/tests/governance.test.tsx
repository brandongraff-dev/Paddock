/**
 * Governance smoke tests (contract §B):
 *   1  Login renders and stores the token on a successful sign-in.
 *   2  A viewer sees mutate controls disabled (role gating).
 *   3  The Audit page renders the chain-integrity verify result.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Login from "../src/pages/Login";
import AuditPage from "../src/pages/Audit";
import ScansPage from "../src/pages/Scans";
import Gate from "../src/components/Gate";
import { useAuth } from "../src/state/auth";
import { useStore } from "../src/state/store";

function withClient(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(React.createElement(QueryClientProvider, { client: qc }, node));
}

/** Route a mocked fetch by URL → response body. */
function mockFetch(routes: Array<[RegExp, unknown, number?]>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    for (const [re, body, status] of routes) {
      if (re.test(url)) {
        return new Response(JSON.stringify(body), {
          status: status ?? 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuth.setState({ token: null, user: null });
  useStore.setState({ seenClassification: null });
});

describe("Login", () => {
  it("renders and stores the token + principal on successful login", async () => {
    mockFetch([
      [/\/v1\/auth\/login/, { access_token: "jwt-abc", role: "analyst", clearance: "confidential", expires_in: 3600 }],
      [/\/v1\/auth\/me/, { username: "nel", role: "analyst", clearance: "confidential" }],
    ]);

    render(React.createElement(Login));
    // It renders a recognizable sign-in surface.
    expect(screen.getByText("palantir-asm")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "nel" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    // Token lands in the auth store; the principal is resolved via /v1/auth/me.
    await vi.waitFor(() => expect(useAuth.getState().token).toBe("jwt-abc"));
    expect(useAuth.getState().user).toMatchObject({ username: "nel", role: "analyst" });
  });
});

describe("role gating", () => {
  it("disables a gated control for a viewer and enables it for an analyst", () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });
    const { rerender } = render(
      <Gate need="triage"><button>act</button></Gate>,
    );
    expect(screen.getByRole("button", { name: "act" })).toBeDisabled();

    // Same control, analyst role → usable.
    useAuth.setState({ token: "t", user: { username: "a", role: "analyst", clearance: "internal" } });
    rerender(
      <Gate need="triage"><button>act</button></Gate>,
    );
    expect(screen.getByRole("button", { name: "act" })).toBeEnabled();
  });

  it("disables the Scans page mutate control for a viewer", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });
    mockFetch([[/\/v1\/scans/, { items: [], total: 0, limit: 200, offset: 0 }]]);
    withClient(React.createElement(ScansPage));
    expect(screen.getByRole("button", { name: /new scan/i })).toBeDisabled();
  });
});

describe("Audit page", () => {
  it("renders the verify button and shows the chain-intact result", async () => {
    useAuth.setState({ token: "t", user: { username: "aud", role: "auditor", clearance: "restricted" } });
    mockFetch([
      [/\/v1\/audit\/verify/, { ok: true, checked: 42 }],
      [/\/v1\/audit/, { items: [], total: 0, limit: 100, offset: 0 }],
    ]);

    withClient(React.createElement(AuditPage));
    const btn = screen.getByRole("button", { name: /verify chain integrity/i });
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);

    expect(await screen.findByText(/chain intact · 42 entries verified/i)).toBeInTheDocument();
  });
});
