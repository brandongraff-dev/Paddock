/**
 * First-run wizard (/setup) + the admin auto-redirect.
 *
 * fetch is stubbed with a tiny router keyed on "METHOD path"; every request
 * is recorded so tests can assert what the wizard sent.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Setup, { FirstRunRedirect } from "../src/pages/Setup";
import { useAuth } from "../src/state/auth";
import type { Onboarding } from "../src/api/onboarding";

type Handler = (body: any) => unknown;

function baseOnboarding(over: Partial<Onboarding> = {}): Onboarding {
  return {
    available: true,
    workspace_name: null,
    current_step: "workspace",
    steps_done: [],
    dismissed: false,
    completed_at: null,
    scope_entry: null,
    first_scan: null,
    counts: { assets: 0, findings: 0, domain_assets: 0, domain_findings: 0 },
    has_verified_scope: false,
    needs_setup: true,
    require_scope_proof: true,
    deployment_mode: "lite",
    ...over,
  };
}

const entry = (status: "pending" | "verified" = "pending") => ({
  id: 7,
  kind: "subdomain_wildcard" as const,
  value: "example.com",
  active: true,
  added_by: "admin",
  added_at: "2026-11-21T00:00:00Z",
  proof: {
    status, method: null, methods: ["dns_txt"], token_issued: true, verified_at: null,
    last_checked_at: null, last_error: null, failing_since: null, grace_until: null,
    required: true, effective: status === "verified",
  },
});

let calls: { method: string; path: string; body: any }[] = [];

function mockApi(routes: Record<string, Handler>) {
  calls = [];
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: any, init?: any) => {
    const url = new URL(String(input), "http://x");
    const method = (init?.method ?? "GET").toUpperCase();
    const body = init?.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: url.pathname, body });
    const h = routes[`${method} ${url.pathname}`];
    if (!h) return new Response(JSON.stringify({ detail: "not mocked" }), { status: 404 });
    const out = h(body);
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  });
}

function renderAt(path: string, node: React.ReactElement = React.createElement(Setup)) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(
      QueryClientProvider,
      { client: qc },
      React.createElement(
        MemoryRouter,
        { initialEntries: [path] },
        React.createElement(
          Routes,
          null,
          React.createElement(Route, { path: "/setup", element: node }),
          React.createElement(Route, {
            path: "/",
            element: React.createElement(React.Fragment, null,
              React.createElement(FirstRunRedirect),
              React.createElement("div", null, "overview page")),
          }),
        ),
      ),
    ),
  );
}

beforeEach(() => {
  useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
  try { sessionStorage.clear(); } catch { /* */ }
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("Setup wizard", () => {
  it("starts at the workspace step and persists the name server-side", async () => {
    let state = baseOnboarding();
    mockApi({
      "GET /v1/onboarding": () => state,
      "PUT /v1/onboarding": (b) => (state = { ...state, ...b, workspace_name: b.workspace_name ?? state.workspace_name, steps_done: ["workspace"] }),
    });
    renderAt("/setup");
    expect(await screen.findByRole("heading", { name: "Name your workspace" })).toBeInTheDocument();
    expect(screen.getByText("lite")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Workspace name"), { target: { value: "Acme Security" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: "Add your domain" })).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ workspace_name: "Acme Security", step_done: "workspace", current_step: "domain" });
  });

  it("adds the domain as a wildcard scope entry and links it", async () => {
    let state = baseOnboarding({ current_step: "domain", steps_done: ["workspace"] });
    mockApi({
      "GET /v1/onboarding": () => state,
      "POST /v1/scope": (b) => ({ ...entry(), kind: b.kind, value: b.value }),
      "PUT /v1/onboarding": (b) => (state = { ...state, current_step: b.current_step ?? state.current_step, scope_entry: entry() }),
      "POST /v1/scope/7/challenge": () => ({
        scope_entry_id: 7, kind: "subdomain_wildcard", domain: "example.com", token: "tok123",
        methods: ["dns_txt"], dns_txt: { name: "_paddock-challenge.example.com", type: "TXT", value: "tok123" },
        http_file: null, proof: entry().proof,
      }),
    });
    renderAt("/setup");
    fireEvent.change(await screen.findByLabelText("Domain"), { target: { value: "https://Example.com/" } });
    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));
    expect(await screen.findByRole("heading", { name: "Prove you control it" })).toBeInTheDocument();
    const add = calls.find((c) => c.method === "POST" && c.path === "/v1/scope");
    expect(add?.body.kind).toBe("subdomain_wildcard");
    expect(add?.body.value).toBe("Example.com");
    expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ scope_entry_id: 7, current_step: "verify" });
  });

  it("shows the exact TXT values with copy buttons and checks live", async () => {
    let verified = false;
    const state = baseOnboarding({ current_step: "verify", steps_done: ["workspace", "domain"], scope_entry: entry() });
    mockApi({
      "GET /v1/onboarding": () => state,
      "POST /v1/scope/7/challenge": () => ({
        scope_entry_id: 7, kind: "subdomain_wildcard", domain: "example.com", token: "tok123",
        methods: ["dns_txt"], dns_txt: { name: "_paddock-challenge.example.com", type: "TXT", value: "tok123" },
        http_file: null, proof: entry().proof,
      }),
      "POST /v1/scope/7/verify": () => {
        const ok = verified;
        verified = true;
        return {
          scope_entry_id: 7,
          check: ok
            ? { ok: true, method: "dns_txt", detail: "TXT _paddock-challenge.example.com matches" }
            : { ok: false, method: "dns_txt", detail: "no TXT record at _paddock-challenge.example.com" },
          proof: entry(ok ? "verified" : "pending").proof,
        };
      },
    });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    renderAt("/setup");
    expect(await screen.findByText("_paddock-challenge.example.com")).toBeInTheDocument();
    expect(screen.getByText("tok123")).toBeInTheDocument();
    expect(screen.getByTestId("proof-status")).toHaveTextContent("Waiting for proof");

    fireEvent.click(screen.getByRole("button", { name: "Copy Value" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("tok123"));
    expect(await screen.findByText("Copied")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText(/no TXT record/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText(/matches/)).toBeInTheDocument();
    expect(screen.getByTestId("proof-status")).toHaveTextContent("Verified");
    expect(screen.getByRole("button", { name: "Continue" })).toBeInTheDocument();
  });

  it("starts a passive discovery scan and shows live counts", async () => {
    let state = baseOnboarding({
      current_step: "scan", steps_done: ["workspace", "domain", "verify"], scope_entry: entry("verified"),
    });
    mockApi({
      "GET /v1/onboarding": () => state,
      "POST /v1/scans": (b) => ({ id: "s-1", kind: b.kind, target: b.target, status: "queued" }),
      "PUT /v1/onboarding": (b) =>
        (state = {
          ...state,
          current_step: b.current_step,
          first_scan: { id: "s-1", kind: "passive_full", target: "example.com", status: "running", queued_at: null, finished_at: null, error: null },
          counts: { assets: 12, findings: 2, domain_assets: 9, domain_findings: 1 },
        }),
    });
    renderAt("/setup");
    fireEvent.click(await screen.findByRole("button", { name: "Start passive discovery" }));
    expect(await screen.findByRole("heading", { name: "Your first results" })).toBeInTheDocument();
    const scan = calls.find((c) => c.path === "/v1/scans");
    expect(scan?.body).toEqual({ kind: "passive_full", target: "example.com" });
    expect(screen.getByTestId("count-assets")).toHaveTextContent("9");
    expect(screen.getByTestId("count-findings")).toHaveTextContent("1");
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("surfaces a scope denial instead of failing silently", async () => {
    const state = baseOnboarding({ current_step: "scan", scope_entry: entry() });
    mockApi({
      "GET /v1/onboarding": () => state,
      "POST /v1/scans": () =>
        new Response(JSON.stringify({ detail: { allow: false, reason: "scope entry 7 matches but its proof-of-control is pending" } }), { status: 403 }),
    });
    renderAt("/setup");
    fireEvent.click(await screen.findByRole("button", { name: "Start passive discovery" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("proof-of-control is pending");
  });

  it("links Slack to /integrations and says lite services are not enabled", async () => {
    let state = baseOnboarding({ current_step: "team", workspace_name: "Acme" });
    mockApi({
      "GET /v1/onboarding": () => state,
      "PUT /v1/onboarding": (b) => (state = { ...state, current_step: b.current_step ?? state.current_step }),
      "GET /v1/system/services": () => ({
        mode: "lite",
        services: [{ name: "brain", feature: "Ask (LLM triage)", enabled: false, status: "not_enabled" }],
      }),
    });
    renderAt("/setup");
    expect(await screen.findByRole("link", { name: /Set up integrations/ })).toHaveAttribute("href", "/integrations");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: "Acme is ready" })).toBeInTheDocument();
    expect(await screen.findByText("Ask (LLM triage)")).toBeInTheDocument();
    expect(screen.getByText("not enabled")).toBeInTheDocument();
  });

  it("can be skipped (recorded as dismissed)", async () => {
    mockApi({
      "GET /v1/onboarding": () => baseOnboarding(),
      "PUT /v1/onboarding": () => baseOnboarding({ dismissed: true, needs_setup: false }),
    });
    renderAt("/setup");
    fireEvent.click(await screen.findByRole("button", { name: "Skip setup" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body?.dismissed === true)).toBe(true));
  });
});

describe("FirstRunRedirect", () => {
  it("sends an admin to /setup when the workspace has no verified scope", async () => {
    mockApi({ "GET /v1/onboarding": () => baseOnboarding() });
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Name your workspace" })).toBeInTheDocument();
  });

  it("does nothing once setup is done", async () => {
    mockApi({ "GET /v1/onboarding": () => baseOnboarding({ needs_setup: false }) });
    renderAt("/");
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(screen.getByText("overview page")).toBeInTheDocument();
  });

  it("never redirects (or even asks) for a non-admin", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "internal" } });
    mockApi({ "GET /v1/onboarding": () => baseOnboarding() });
    renderAt("/");
    await new Promise((r) => setTimeout(r, 30));
    expect(screen.getByText("overview page")).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });
});
