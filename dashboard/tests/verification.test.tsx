/**
 * Verified findings (schema 026): exploitability badge, "Verified fixed" badge,
 * evidence excerpt, "Verify now" button (queues a check, shows a refusal reason),
 * verification history, the exploitability filter and negative why-weights.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import VerificationPanel, {
  ExploitabilityBadge,
  VerifiedFixedBadge,
  evidenceLines,
} from "../src/components/Verification";
import { WhyChips } from "../src/components/Lifecycle";
import FindingsPage from "../src/pages/Findings";
import { useStore } from "../src/state/store";
import { useAuth } from "../src/state/auth";
import type { Finding } from "../src/api/types";
import type { VerificationHistory } from "../src/api/verification";

const NOW = Date.now();
const iso = (deltaH: number) => new Date(NOW + deltaH * 3_600_000).toISOString();

const FINDING: Finding = {
  id: "f-1",
  asset_id: "a-1",
  rule_id: "exposed-env",
  rule_source: "exposed_file",
  severity: "high",
  title: ".env file exposed",
  description: "d",
  evidence: {},
  status: "open",
  first_seen: iso(-30),
  last_seen: iso(-1),
  metadata: {},
  exploitability: "confirmed",
  last_verified_at: iso(-2),
};

const HISTORY: VerificationHistory = {
  finding_id: "f-1",
  exploitability: "confirmed",
  last_verified_at: iso(-2),
  fix_verified_at: null,
  items: [
    {
      id: "v-2", finding_id: "f-1", purpose: "exploitability", trigger: "manual", requested_by: "dev-admin",
      status: "done", verdict: "confirmed", check_id: "exposed_file",
      reason: "/.env is still served (HTTP 200, expected content present)",
      evidence: { url: "https://app.example.com/.env", status: 200, excerpt: "APP_ENV=<redacted>" },
      requested_at: iso(-2), checked_at: iso(-2), completed_at: iso(-2),
    },
    {
      id: "v-1", finding_id: "f-1", purpose: "exploitability", trigger: "bulk", requested_by: "dev-admin",
      status: "refused", check_id: null, evidence: {}, reason: "scope: no_active_scope_entries",
      requested_at: iso(-30),
    },
  ],
};

type Route = [RegExp, unknown | ((init?: RequestInit) => Response | unknown), string?];

function mockFetch(routes: Route[]) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    for (const [re, body, m] of routes) {
      if (re.test(url) && (!m || m === method)) {
        const out = typeof body === "function" ? (body as (i?: RequestInit) => unknown)(init) : body;
        if (out instanceof Response) return out;
        return new Response(JSON.stringify(out ?? {}), { status: 200, headers: { "content-type": "application/json" } });
      }
    }
    return new Response(JSON.stringify({ items: [], total: 0 }), { status: 200, headers: { "content-type": "application/json" } });
  });
}

function renderApp(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(QueryClientProvider, { client: qc },
      React.createElement(MemoryRouter, null, node)),
  );
}

const analyst = () =>
  useAuth.setState({ token: "t", user: { username: "a", role: "analyst", clearance: "internal" } });

beforeEach(analyst);

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
  useAuth.setState({ token: null, user: null });
});

describe("badges", () => {
  it("labels every verdict and defaults to Unverified", () => {
    const { rerender } = render(<ExploitabilityBadge value="confirmed" />);
    expect(screen.getByText("Verified exploitable")).toHaveAttribute("data-state", "confirmed");
    rerender(<ExploitabilityBadge value="not_reproducible" />);
    expect(screen.getByText("Not reproducible")).toHaveAttribute("data-state", "not_reproducible");
    rerender(<ExploitabilityBadge value="inconclusive" />);
    expect(screen.getByText("Inconclusive")).toBeInTheDocument();
    rerender(<ExploitabilityBadge />);
    expect(screen.getByText("Unverified")).toHaveAttribute("data-state", "unverified");
  });

  it("shows Verified fixed only when the fix was proven", () => {
    const { container, rerender } = render(<VerifiedFixedBadge at={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<VerifiedFixedBadge at={iso(-1)} />);
    expect(screen.getByText("Verified fixed")).toHaveAttribute("data-state", "verified_fixed");
  });

  it("negative why weights show a minus sign", () => {
    render(<WhyChips why={[
      { key: "severity", label: "severity: high", weight: 25 },
      { key: "not_reproducible", label: "Not reproducible on 2026-11-21", weight: -12 },
    ]} />);
    expect(screen.getByText("+25")).toBeInTheDocument();
    expect(screen.getByText("−12")).toBeInTheDocument();
  });

  it("flattens evidence into a few short lines", () => {
    const lines = evidenceLines({ url: "https://x/.env", status: 200, excerpt: "APP_ENV=<redacted>", z: "x".repeat(900) });
    expect(lines.map(([k]) => k)).toEqual(["url", "status", "excerpt", "z"]);
    expect(lines[3][1].length).toBeLessThanOrEqual(240);
  });
});

describe("VerificationPanel", () => {
  it("shows the verdict, the evidence excerpt and the history", async () => {
    mockFetch([[/\/v1\/findings\/f-1\/verifications/, HISTORY]]);
    renderApp(<VerificationPanel finding={FINDING} />);
    await screen.findByLabelText("evidence excerpt");
    expect(screen.getAllByText("Verified exploitable").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("evidence excerpt")).toHaveTextContent("APP_ENV=<redacted>");
    const hist = screen.getByLabelText("verification history");
    expect(hist.querySelectorAll("li")).toHaveLength(2);
    expect(hist).toHaveTextContent("scope: no_active_scope_entries");
  });

  it("Verify now posts to the verify endpoint and refreshes the ledger", async () => {
    const spy = mockFetch([
      [/\/v1\/findings\/f-1\/verify$/, { ...HISTORY.items[0], id: "v-3", status: "queued", verdict: null }, "POST"],
      [/\/v1\/findings\/f-1\/verifications/, HISTORY],
    ]);
    renderApp(<VerificationPanel finding={FINDING} />);
    const btn = await screen.findByRole("button", { name: "Verify now" });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    await waitFor(() => {
      const posts = spy.mock.calls.filter(([u, i]) => /\/f-1\/verify$/.test(String(u)) && i?.method === "POST");
      expect(posts).toHaveLength(1);
    });
    await waitFor(() => {
      const gets = spy.mock.calls.filter(([u]) => /\/f-1\/verifications/.test(String(u)));
      expect(gets.length).toBeGreaterThanOrEqual(2);   // refetched after the POST
    });
  });

  it("a refusal (scope / proof-of-control) is shown with its reason", async () => {
    mockFetch([
      [/\/v1\/findings\/f-1\/verify$/, () => new Response(JSON.stringify({ detail: {
        error: "verification_refused",
        reason: "scope entry 3 (domain example.com) has no verified proof-of-control (status: pending)",
        verification_id: "v-9" } }), { status: 403, headers: { "content-type": "application/json" } }), "POST"],
      [/\/v1\/findings\/f-1\/verifications/, { ...HISTORY, items: [] }],
    ]);
    renderApp(<VerificationPanel finding={{ ...FINDING, exploitability: "unverified" }} />);
    fireEvent.click(await screen.findByRole("button", { name: "Verify now" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("no verified proof-of-control");
  });

  it("a viewer cannot run a check", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "internal" } });
    mockFetch([[/\/v1\/findings\/f-1\/verifications/, HISTORY]]);
    renderApp(<VerificationPanel finding={FINDING} />);
    expect(await screen.findByRole("button", { name: "Verify now" })).toBeDisabled();
  });

  it("disables the button while a check is in flight", async () => {
    mockFetch([[/\/v1\/findings\/f-1\/verifications/, {
      ...HISTORY, items: [{ ...HISTORY.items[0], id: "v-4", status: "queued", verdict: null }],
    }]]);
    renderApp(<VerificationPanel finding={FINDING} />);
    const btn = await screen.findByRole("button", { name: "Checking…" });
    expect(btn).toBeDisabled();
  });

  it("a fixed finding offers Verify fix now and a proven fix shows Verified fixed", async () => {
    mockFetch([[/\/v1\/findings\/f-1\/verifications/, {
      ...HISTORY, exploitability: "not_reproducible", fix_verified_at: iso(-1), items: [],
    }]]);
    renderApp(<VerificationPanel finding={{ ...FINDING, status: "fixed", exploitability: "not_reproducible" }} />);
    expect(await screen.findByRole("button", { name: "Verify fix now" })).toBeInTheDocument();
    await screen.findByText("Verified fixed");
  });
});

describe("Findings page exploitability filter", () => {
  it("sends ?exploitability= to the server", async () => {
    const spy = mockFetch([[/\/v1\/findings/, { items: [], total: 0 }]]);
    renderApp(<FindingsPage />);
    const sel = await screen.findByLabelText("exploitability filter");
    fireEvent.change(sel, { target: { value: "confirmed" } });
    await waitFor(() => {
      expect(spy.mock.calls.some(([u]) => /exploitability=confirmed/.test(String(u)))).toBe(true);
    });
  });
});
