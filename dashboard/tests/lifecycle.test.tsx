/**
 * Finding lifecycle UI (schema 019).
 *   - priority score, why chips, SLA badge (pure pieces)
 *   - reason dialog: reason required, optional expiry, suppress feedback
 *   - Findings page: Active/Suppressed toggle with the hidden count
 *   - DetailDrawer: why/SLA/sources/history + accept flow posts a reason
 *   - Suppressions page: list + create
 *   - getFinding flattens the {finding, asset, chains, history} envelope
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  PriorityScore,
  ReasonDialog,
  SlaBadge,
  WhyChips,
  priorityBand,
  slaState,
} from "../src/components/Lifecycle";
import FindingsPage from "../src/pages/Findings";
import SuppressionsPage, { suppressionInput } from "../src/pages/Suppressions";
import DetailDrawer from "../src/components/DetailDrawer";
import { getFinding } from "../src/api/findings";
import { useStore } from "../src/state/store";
import { useAuth } from "../src/state/auth";
import type { Finding, Suppression } from "../src/api/types";

const NOW = Date.now();
const iso = (deltaH: number) => new Date(NOW + deltaH * 3_600_000).toISOString();

const FINDING: Finding = {
  id: "f-1",
  asset_id: "a-1",
  rule_id: "CVE-2021-44228",
  rule_source: "cve_match",
  severity: "critical",
  title: "Log4Shell on pay.example.com",
  description: "JNDI lookup",
  evidence: {},
  status: "open",
  first_seen: iso(-30),
  last_seen: iso(-1),
  metadata: {},
  asset_value: "pay.example.com",
  asset_kind: "subdomain",
  priority_score: 92,
  why: [
    { key: "severity", label: "severity: critical", weight: 35 },
    { key: "kev", label: "KEV-listed", weight: 25 },
    { key: "epss", label: "EPSS 0.97", weight: 19 },
    { key: "attack_path", label: "2 hops from crown jewel payments-db", weight: 9 },
    { key: "owner", label: "owner: payments", weight: 0 },
  ],
  due_at: iso(-6),
  sla_breached: true,
  source_count: 3,
  sources: [
    { finding_id: "f-1", rule_source: "cve_match", rule_id: "CVE-2021-44228", status: "open", last_seen: iso(-1), primary: true },
    { finding_id: "f-2", rule_source: "nuclei", rule_id: "CVE-2021-44228", status: "open", last_seen: iso(-2), primary: false },
    { finding_id: "f-3", rule_source: "sca", rule_id: "sca:Maven:log4j-core", status: "open", last_seen: iso(-3), primary: false },
  ],
  owner: "payments",
};

type Route = [RegExp, unknown, ((init?: RequestInit) => unknown)?];

function mockFetch(routes: Route[]) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    for (const [re, body, fn] of routes) {
      if (re.test(url)) {
        const out = fn ? fn(init) : body;
        return new Response(JSON.stringify(out ?? {}), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
    return new Response(JSON.stringify({ items: [], total: 0 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

function renderApp(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(
      QueryClientProvider,
      { client: qc },
      React.createElement(MemoryRouter, null, node),
    ),
  );
}

function callsTo(spy: ReturnType<typeof mockFetch>, re: RegExp) {
  return spy.mock.calls.filter(([u]) => re.test(String(u)));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useStore.setState({ events: [], toasts: [], drawer: { kind: null } });
  useAuth.setState({ token: null, user: null });
});

/* ------------------------------------------------------------------ */

describe("priority + why + SLA pieces", () => {
  it("bands the score and lights the meter", () => {
    expect(priorityBand(92)).toBe("urgent");
    expect(priorityBand(61)).toBe("high");
    expect(priorityBand(40)).toBe("medium");
    expect(priorityBand(5)).toBe("low");
    render(<PriorityScore score={92} />);
    const el = screen.getByLabelText("priority 92 of 100");
    expect(el).toHaveAttribute("data-band", "urgent");
    expect(el.querySelectorAll(".bars i.on")).toHaveLength(4);
  });

  it("renders nothing without a score", () => {
    const { container } = render(<PriorityScore score={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows each factor with its weight, context factors muted, overflow collapsed", () => {
    render(<WhyChips why={FINDING.why} />);
    expect(screen.getByText("KEV-listed")).toBeInTheDocument();
    expect(screen.getByText("+25")).toBeInTheDocument();
    expect(screen.getByText("owner: payments")).toHaveAttribute("data-zero", "true");
    cleanup();
    render(<WhyChips why={FINDING.why} max={2} />);
    expect(screen.getByText("+3 more")).toBeInTheDocument();
  });

  it("computes the SLA state and hides it for dismissed findings", () => {
    expect(slaState({ due_at: iso(-2), sla_breached: true, status: "open" }, NOW)?.state).toBe("breached");
    expect(slaState({ due_at: iso(5), sla_breached: false, status: "triaged" }, NOW)?.state).toBe("soon");
    expect(slaState({ due_at: iso(72), sla_breached: false, status: "open" }, NOW)).toEqual({
      state: "ok",
      label: "due in 3d",
    });
    expect(slaState({ due_at: iso(-2), sla_breached: true, status: "accepted" }, NOW)).toBeNull();
    expect(slaState({ due_at: null, status: "open" }, NOW)).toBeNull();
    render(<SlaBadge finding={{ due_at: iso(-50), sla_breached: true, status: "open" }} />);
    expect(screen.getByText(/SLA breached · 2d over/)).toHaveAttribute("data-state", "breached");
  });
});

/* ------------------------------------------------------------------ */

describe("reason dialog", () => {
  it("requires a reason to accept and sends the expiry as end of day UTC", () => {
    const onSubmit = vi.fn();
    render(<ReasonDialog kind="accept" onCancel={() => undefined} onSubmit={onSubmit} />);
    const cta = screen.getByRole("button", { name: "Accept risk" });
    expect(cta).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "  ok " } });
    expect(cta).toBeDisabled(); // < 3 non-blank chars
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Compensating WAF rule" } });
    fireEvent.change(screen.getByLabelText("Expires (optional)"), { target: { value: "2030-01-31" } });
    expect(cta).toBeEnabled();
    fireEvent.click(cta);
    expect(onSubmit).toHaveBeenCalledWith({
      reason: "Compensating WAF rule",
      accepted_until: "2030-01-31T23:59:59Z",
      suppress: undefined,
    });
  });

  it("offers suppression feedback for false positives", () => {
    const onSubmit = vi.fn();
    render(<ReasonDialog kind="false_positive" onCancel={() => undefined} onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "md5 for cache keys" } });
    fireEvent.click(screen.getByLabelText(/Also suppress this rule/));
    fireEvent.click(screen.getByRole("button", { name: "Mark false positive" }));
    expect(onSubmit).toHaveBeenCalledWith({ reason: "md5 for cache keys", accepted_until: undefined, suppress: true });
  });

  it("lets reopen go without a reason and cancels on Escape", () => {
    const onSubmit = vi.fn();
    const onCancel = vi.fn();
    render(<ReasonDialog kind="reopen" onCancel={onCancel} onSubmit={onSubmit} />);
    expect(screen.queryByLabelText("Expires (optional)")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Reopen" }));
    expect(onSubmit).toHaveBeenCalledWith({ reason: "", accepted_until: undefined, suppress: undefined });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onCancel).toHaveBeenCalled();
  });
});

/* ------------------------------------------------------------------ */

describe("Findings page", () => {
  it("shows priority/SLA/duplicates on rows and toggles to the suppressed view", async () => {
    const spy = mockFetch([
      [/\/v1\/findings\?.*limit=1(&|$)/, { items: [], total: 1, limit: 1, offset: 0, suppressed_total: 4, duplicates_total: 2 }],
      [/suppressed=only/, { items: [{ ...FINDING, id: "s-1", title: "Weak hash in lab", suppressed: true }], total: 1, limit: 50, offset: 0 }],
      [/\/v1\/findings\?/, { items: [FINDING], total: 1, limit: 50, offset: 0 }],
    ]);
    renderApp(<FindingsPage />);
    expect(await screen.findByText("Log4Shell on pay.example.com")).toBeInTheDocument();
    expect(screen.getByLabelText("priority 92 of 100")).toBeInTheDocument();
    expect(screen.getByText("×3")).toBeInTheDocument();
    expect(screen.getByText("overdue 6h")).toHaveAttribute("data-state", "breached");
    await waitFor(() => expect(screen.getByTestId("suppressed-count")).toHaveTextContent("4"));
    expect(screen.getByText(/2 duplicate reports collapsed/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Suppressed/ }));
    expect(await screen.findByText("Weak hash in lab")).toBeInTheDocument();
    expect(callsTo(spy, /suppressed=only/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Suppressed/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("filters to SLA-breached findings server-side", async () => {
    const spy = mockFetch([[/\/v1\/findings\?/, { items: [], total: 0, limit: 50, offset: 0 }]]);
    renderApp(<FindingsPage />);
    fireEvent.click(screen.getByLabelText("SLA breached"));
    await waitFor(() => expect(callsTo(spy, /sla_breached=true/).length).toBeGreaterThan(0));
  });
});

/* ------------------------------------------------------------------ */

describe("DetailDrawer lifecycle", () => {
  const detail = {
    finding: FINDING,
    asset: null,
    chains: [],
    history: [
      { id: "h1", from_status: "accepted", to_status: "open", reason: "auto-reopened: acceptance expired",
        accepted_until: null, actor: "system:lifecycle", at: iso(-3) },
    ],
  };

  it("explains the priority, shows sources/SLA/history, and posts an accept with a reason", async () => {
    useAuth.setState({ token: "t", user: { username: "a", role: "analyst", clearance: "internal" } });
    let posted: unknown = null;
    const spy = mockFetch([
      [/\/v1\/findings\/f-1\/accept$/, null, (init) => {
        posted = JSON.parse(String(init?.body));
        return { finding: { ...FINDING, status: "accepted" }, from_status: "open", to_status: "accepted",
                 propagated_to: 2, suppression_id: null };
      }],
      [/\/v1\/findings\/f-1$/, detail],
    ]);
    useStore.setState({ drawer: { kind: "finding", id: "f-1" } });
    renderApp(<DetailDrawer />);

    expect(await screen.findByText("Why this priority")).toBeInTheDocument();
    expect(screen.getByText("2 hops from crown jewel payments-db")).toBeInTheDocument();
    expect(screen.getByLabelText("priority 92 of 100")).toBeInTheDocument();
    expect(screen.getByText(/SLA breached ·/)).toBeInTheDocument();
    const sources = screen.getByLabelText("duplicate sources");
    expect(within(sources).getByText("nuclei")).toBeInTheDocument();
    expect(within(sources).getByText("primary")).toBeInTheDocument();
    expect(screen.getByText("auto-reopened: acceptance expired")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Accept risk…" }));
    const dialog = screen.getByRole("dialog", { name: "Accept risk" });
    fireEvent.change(within(dialog).getByLabelText("Reason"), { target: { value: "Isolated segment, patch in Q3" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Accept risk" }));
    await waitFor(() => expect(posted).toEqual({ reason: "Isolated segment, patch in Q3" }));
    expect(callsTo(spy, /\/accept$/)[0][1]?.method).toBe("POST");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("disables lifecycle actions for viewers", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "internal" } });
    mockFetch([[/\/v1\/findings\/f-1$/, detail]]);
    useStore.setState({ drawer: { kind: "finding", id: "f-1" } });
    renderApp(<DetailDrawer />);
    expect(await screen.findByRole("button", { name: "Accept risk…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "False positive…" })).toBeDisabled();
  });

  it("surfaces the server's validation message", async () => {
    useAuth.setState({ token: "t", user: { username: "a", role: "analyst", clearance: "internal" } });
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (/\/false-positive$/.test(String(input))) {
        return new Response(JSON.stringify({ detail: "accepted_until must be in the future" }), {
          status: 422, headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify(detail), { status: 200, headers: { "content-type": "application/json" } });
    });
    useStore.setState({ drawer: { kind: "finding", id: "f-1" } });
    renderApp(<DetailDrawer />);
    fireEvent.click(await screen.findByRole("button", { name: "False positive…" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Reason"), { target: { value: "scanner bug" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Mark false positive" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("accepted_until must be in the future");
  });
});

/* ------------------------------------------------------------------ */

describe("Suppressions page", () => {
  const SUP: Suppression = {
    id: "s-1", name: null, rule_id: "sast:weak-*", rule_source: null, asset_pattern: "*.staging.example.com",
    tag: null, reason: "staging uses test crypto", author: "nel", expires_at: null, enabled: true,
    active: true, match_count: 7, suppressed_now: 5, last_matched_at: null, created_at: iso(-48), updated_at: iso(-48),
  };

  it("validates the form helper", () => {
    const base = { rule_id: "", asset_pattern: "", tag: "", reason: "", expires: "" };
    expect(suppressionInput({ ...base, reason: "noise" })).toBeNull(); // no matcher
    expect(suppressionInput({ ...base, tag: "lab", reason: "no" })).toBeNull(); // short reason
    expect(suppressionInput({ ...base, tag: " lab ", reason: "lab gear", expires: "2030-02-01" })).toEqual({
      rule_id: null, asset_pattern: null, tag: "lab", reason: "lab gear", expires_at: "2030-02-01T23:59:59Z",
    });
  });

  it("lists rules and creates one", async () => {
    useAuth.setState({ token: "t", user: { username: "a", role: "analyst", clearance: "internal" } });
    let created: unknown = null;
    mockFetch([
      [/\/v1\/suppressions$/, [SUP], (init) => {
        if (init?.method === "POST") {
          created = JSON.parse(String(init.body));
          return { ...SUP, id: "s-2" };
        }
        return [SUP];
      }],
    ]);
    renderApp(<SuppressionsPage />);
    expect(await screen.findByText("staging uses test crypto")).toBeInTheDocument();
    expect(screen.getByText("rule sast:weak-*")).toBeInTheDocument();
    const add = screen.getByRole("button", { name: "Add suppression" });
    expect(add).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "lab" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "lab gear, no data" } });
    expect(add).toBeEnabled();
    fireEvent.click(add);
    await waitFor(() =>
      expect(created).toEqual({ rule_id: null, asset_pattern: null, tag: "lab", reason: "lab gear, no data", expires_at: null }),
    );
  });
});

/* ------------------------------------------------------------------ */

describe("api: getFinding", () => {
  it("flattens the detail envelope and passes bare findings through", async () => {
    mockFetch([
      [/\/v1\/findings\/env$/, { finding: { ...FINDING, id: "env" }, asset: { id: "a-1", kind: "subdomain", value: "pay.example.com" }, chains: [], history: [] }],
      [/\/v1\/findings\/bare$/, { ...FINDING, id: "bare" }],
    ]);
    const a = await getFinding("env");
    expect(a.id).toBe("env");
    expect(a.asset?.value).toBe("pay.example.com");
    expect(a.history).toEqual([]);
    const b = await getFinding("bare");
    expect(b.id).toBe("bare");
  });
});
