/**
 * MSP console dashboard tests:
 *   - the customer list renders health, searches and sorts via the API;
 *   - "Open" exchanges the session for a customer token, which then replaces the
 *     MSP token on API calls, and the topbar shows which customer + a way back;
 *   - "Back to MSP" drops the customer token and restores the MSP principal;
 *   - the nav entry exists only for MSP users and the indicator is absent otherwise.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import MspConsolePage from "../src/pages/MspConsole";
import MspIndicator from "../src/components/MspIndicator";
import Shell from "../src/components/Shell";
import { apiFetch, authHeaders } from "../src/api/client";
import { useAuth } from "../src/state/auth";
import { useMsp } from "../src/state/msp";

type Route = [RegExp, unknown, number?, string?];

const calls: { url: string; method: string; auth: string | null }[] = [];

function mockFetch(routes: Route[]) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const h = new Headers(init?.headers as HeadersInit | undefined);
    calls.push({ url, method, auth: h.get("authorization") });
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

const health = (over: Record<string, unknown> = {}) => ({
  grade: "B", exposure_index: 20, open_findings: 4, open_criticals: 0, sla_breaches: 1,
  verified_fixes: 3, last_scan_at: new Date(Date.now() - 3 * 3600_000).toISOString(),
  monitored_assets: 12, seats_used: 4, seats_limit: 10, assets_limit: 50, computed_at: new Date().toISOString(),
  ...over,
});

const PAGE = {
  items: [
    { id: "11111111-1111-1111-1111-111111111111", slug: "acme", name: "Acme Dental", status: "active",
      role: "analyst", created_at: "2026-01-01T00:00:00Z", health: health({ grade: "D", open_criticals: 3, exposure_index: 140 }) },
    { id: "22222222-2222-2222-2222-222222222222", slug: "globex", name: "Globex", status: "suspended",
      role: "admin", created_at: "2026-01-02T00:00:00Z", health: health() },
  ],
  total: 2, limit: 25, offset: 0, sort: "name", order: "asc",
};
const SUMMARY = { customers: 2, with_health: 2, open_criticals: 3, sla_breaches: 2, verified_fixes: 6, at_risk: 1 };

function app(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(
      QueryClientProvider,
      { client: qc },
      React.createElement(MemoryRouter, null, node),
    ),
  );
}

const HOME = { username: "root", role: "admin" as const, clearance: "restricted" as const };

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  calls.length = 0;
  useMsp.setState({ acting: null });
  useAuth.setState({ token: null, user: null });
  try { sessionStorage.clear(); } catch { /* ignore */ }
});

describe("MSP console", () => {
  it("lists customers with health and queries the API for search and sort", async () => {
    useAuth.setState({ token: "msp-token", user: HOME });
    mockFetch([
      [/\/v1\/msp\/summary/, SUMMARY],
      [/\/v1\/msp\/customers/, PAGE, 200, "GET"],
    ]);
    app(React.createElement(MspConsolePage));

    expect(await screen.findByText("Acme Dental")).toBeInTheDocument();
    expect(screen.getByText("Globex")).toBeInTheDocument();
    const grades = screen.getAllByText(/^[A-F]$/).map((e) => e.textContent);
    expect(grades).toContain("D");
    expect(screen.getByText(/suspended/)).toBeInTheDocument();
    // a suspended customer cannot be opened
    expect(screen.getByRole("button", { name: "Open Globex" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Open Acme Dental" })).toBeEnabled();

    fireEvent.change(screen.getByLabelText("search customers"), { target: { value: "acm" } });
    await waitFor(() => expect(calls.some((c) => /q=acm/.test(c.url))).toBe(true));
    fireEvent.change(screen.getByLabelText("sort customers"), { target: { value: "2" } }); // criticals
    await waitFor(() =>
      expect(calls.some((c) => /sort=criticals/.test(c.url) && /order=desc/.test(c.url))).toBe(true),
    );
    // every list call carried the MSP session token
    expect(calls.filter((c) => /\/v1\/msp\/customers/.test(c.url)).every((c) => c.auth === "Bearer msp-token")).toBe(true);
  });

  it("opens a customer: its token replaces the MSP token, the indicator shows, Back restores", async () => {
    useAuth.setState({ token: "msp-token", user: HOME });
    mockFetch([
      [/\/v1\/msp\/summary/, SUMMARY],
      [/\/v1\/msp\/customers\/11111111-1111-1111-1111-111111111111\/switch/, {
        access_token: "cust-token", token_type: "bearer", expires_in: 900, role: "analyst", clearance: "internal",
        customer: { id: "11111111-1111-1111-1111-111111111111", slug: "acme", name: "Acme Dental" },
        msp: { slug: "msp-one", name: "MSP One" },
      }, 200, "POST"],
      [/\/v1\/msp\/customers/, PAGE, 200, "GET"],
    ]);
    app(
      React.createElement(React.Fragment, null,
        React.createElement(MspIndicator),
        React.createElement(MspConsolePage)),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Open Acme Dental" }));

    await waitFor(() => expect(useMsp.getState().acting?.customer.slug).toBe("acme"));
    // the principal's role now reflects the GRANT, not the MSP role
    expect(useAuth.getState().user?.role).toBe("analyst");
    // the customer token is what API calls carry; the MSP token is untouched
    expect(authHeaders()).toEqual({ Authorization: "Bearer cust-token" });
    expect(useAuth.getState().token).toBe("msp-token");

    // clear persistent indicator + one-click way back
    const pill = await screen.findByRole("status", { name: /Acting in customer Acme Dental/ });
    expect(pill).toHaveTextContent("Acme Dental");
    expect(pill).toHaveTextContent("analyst");
    fireEvent.click(screen.getByRole("button", { name: "Back to MSP console" }));
    expect(useMsp.getState().acting).toBeNull();
    expect(authHeaders()).toEqual({ Authorization: "Bearer msp-token" });
    expect(useAuth.getState().user).toMatchObject({ role: "admin", username: "root" });
    expect(screen.queryByRole("status", { name: /Acting in customer/ })).toBeNull();
  });

  it("a 401 while acting leaves the customer but keeps the MSP session", async () => {
    useAuth.setState({ token: "msp-token", user: HOME });
    useMsp.getState().enter({
      access_token: "cust-token", token_type: "bearer", expires_in: 900, role: "viewer", clearance: "internal",
      customer: { id: "c1", slug: "acme", name: "Acme" }, msp: { slug: "m", name: "M" },
    });
    mockFetch([[/\/v1\/findings/, { detail: "no access grant for this customer" }, 401]]);
    await expect(apiFetch("/v1/findings")).rejects.toThrow();
    expect(useMsp.getState().acting).toBeNull();
    expect(useAuth.getState().token).toBe("msp-token");
    expect(useAuth.getState().user?.role).toBe("admin");
  });

  it("an expired customer token is never sent", () => {
    useAuth.setState({ token: "msp-token", user: HOME });
    useMsp.getState().enter({
      access_token: "cust-token", token_type: "bearer", expires_in: -5, role: "viewer", clearance: "internal",
      customer: { id: "c1", slug: "acme", name: "Acme" }, msp: { slug: "m", name: "M" },
    });
    expect(authHeaders()).toEqual({ Authorization: "Bearer msp-token" });
    expect(useMsp.getState().acting).toBeNull();
  });

  it("signing out of the MSP session also leaves the customer", () => {
    useAuth.setState({ token: "msp-token", user: HOME });
    useMsp.getState().enter({
      access_token: "cust-token", token_type: "bearer", expires_in: 900, role: "viewer", clearance: "internal",
      customer: { id: "c1", slug: "acme", name: "Acme" }, msp: { slug: "m", name: "M" },
    });
    useAuth.getState().logout();
    expect(useMsp.getState().acting).toBeNull();
  });
});

describe("Shell integration", () => {
  const nav = () => screen.queryByRole("link", { name: "Customers" });

  it("shows the Customers nav entry only for MSP users", async () => {
    useAuth.setState({ token: "t", user: HOME });
    mockFetch([[/\/v1\/msp\/me/, { mode: "msp", is_msp: true, org: { name: "MSP One", max_customers: null } }]]);
    app(React.createElement(Shell, null, React.createElement("div", null, "body")));
    await waitFor(() => expect(nav()).not.toBeNull());
    expect(screen.queryByRole("status", { name: /Acting in customer/ })).toBeNull();
    // the classification pill is still there
    expect(screen.getByRole("status", { name: /Classification/ })).toBeInTheDocument();
  });

  it("hides the entry for an ordinary tenant", async () => {
    useAuth.setState({ token: "t", user: HOME });
    const f = mockFetch([[/\/v1\/msp\/me/, { mode: "none", is_msp: false }]]);
    app(React.createElement(Shell, null, React.createElement("div", null, "body")));
    await waitFor(() => expect(f.mock.calls.some((c) => /\/v1\/msp\/me/.test(String(c[0])))).toBe(true));
    expect(nav()).toBeNull();
  });

  it("shows the acting indicator next to the classification pill and hides the entry inside a customer", async () => {
    useAuth.setState({ token: "t", user: HOME });
    useMsp.getState().enter({
      access_token: "cust-token", token_type: "bearer", expires_in: 900, role: "analyst", clearance: "internal",
      customer: { id: "c1", slug: "acme", name: "Acme" }, msp: { slug: "m", name: "M" },
    });
    mockFetch([[/\/v1\/msp\/me/, { mode: "delegated", is_msp: false, customer: { id: "c1", slug: "acme", name: "Acme" } }]]);
    app(React.createElement(Shell, null, React.createElement("div", null, "body")));
    const pill = await screen.findByRole("status", { name: /Acting in customer Acme/ });
    const cls = screen.getByRole("status", { name: /Classification/ });
    expect(cls.parentElement).toBe(pill.parentElement); // same topbar row, side by side
    expect(nav()).toBeNull();
  });
});
