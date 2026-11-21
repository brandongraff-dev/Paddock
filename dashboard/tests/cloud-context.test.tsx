/**
 * Context sync + Network actions screens: source status and Sync now, scope
 * suggestions (accept goes through scope add, dismiss), the approvals queue
 * with required reasons, dry-run vs live indication, admin gating, history.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ContextSyncPage, { importedCount, relTime, syncHealth } from "../src/pages/ContextSync";
import NetworkActionsPage, { outcomeOf } from "../src/pages/NetworkActions";
import type { SyncStatus } from "../src/api/context";
import type { NetworkAction } from "../src/api/networkActions";
import { useAuth } from "../src/state/auth";

const NOW = "2026-11-21T10:00:00Z";
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
const ahead = (min: number) => new Date(Date.now() + min * 60_000).toISOString();

const run = (over: Partial<NonNullable<SyncStatus["last_run"]>> = {}): NonNullable<SyncStatus["last_run"]> => ({
  id: 1, integration_id: "i-gcp", trigger: "schedule", status: "ok", started_at: ago(30),
  finished_at: ago(29), counts: { assets_inserted: 40, assets_updated: 2, findings_inserted: 3, edges_inserted: 10 },
  detail: null, ...over,
});

const GCP: SyncStatus = {
  integration_id: "i-gcp", kind: "gcp", name: "gcp-prod", enabled: true, last_run: run(),
  interval_minutes: 60, next_run_at: ahead(30), pending_suggestions: 2,
};
const AZURE: SyncStatus = {
  integration_id: "i-az", kind: "azure", name: "azure-core", enabled: true,
  last_run: run({ id: 2, integration_id: "i-az", status: "ok", counts: { assets_inserted: 5, warnings: 2 },
                  detail: "partial: nsgs: HTTP 403 (check the credential and its permissions)" }),
  interval_minutes: 360, next_run_at: ahead(200), pending_suggestions: 0,
};
const CS: SyncStatus = {
  integration_id: "i-cs", kind: "crowdstrike", name: "falcon", enabled: true,
  last_run: run({ id: 3, integration_id: "i-cs", status: "error", counts: {}, detail: "Falcon token request: HTTP 401 (check the credential and its permissions)" }),
  interval_minutes: 360, next_run_at: ahead(10), pending_suggestions: 0,
};

const SUGGESTIONS = [
  { id: 11, integration_id: "i-gcp", integration_name: "gcp-prod", source: "integration:gcp", kind: "ipv4_cidr",
    value: "34.120.10.5/32", evidence: { cloud: "gcp", project: "acme-prod", type: "compute.instance", resource: "//compute.googleapis.com/projects/acme-prod/zones/z/instances/web-1" },
    status: "pending", first_seen: ago(120), last_seen: ago(30), decided_by: null, decided_at: null, scope_entry_id: null },
  { id: 12, integration_id: "i-gcp", integration_name: "gcp-prod", source: "integration:gcp", kind: "domain",
    value: "acme-test.com", evidence: { cloud: "gcp", dns_zone: "pub" },
    status: "pending", first_seen: ago(120), last_seen: ago(30), decided_by: null, decided_at: null, scope_entry_id: null },
];

const ACTION = (over: Partial<NetworkAction> = {}): NetworkAction => ({
  id: "a1", integration_id: "i-unifi", action_type: "quarantine_device", target: "00:1a:2b:3c:4d:5e",
  reason: "Sentry device_lateral_scan: Camera is scanning", finding_id: "f1", dry_run: true, status: "proposed",
  requested_by: "sentry", approved_by: null,
  result: { network: true, integration_kind: "unifi", integration_name: "unifi-hq", device: "10.5.0.20" },
  created_at: ago(15), decided_at: null, applied_at: null, revert_of: null, ...over,
});

const EVIDENCE = {
  action_id: "a1",
  finding: { id: "f1", rule_id: "device_lateral_scan", severity: "high", status: "open",
             title: "Hikvision camera is scanning", description: "Touched 40 hosts in 60s",
             evidence: { distinct_hosts: 40 }, first_seen: ago(20), last_seen: ago(1) },
  device: { mac: "00:1a:2b:3c:4d:5e", vendor: "Hikvision", type: "camera" },
};

type Call = { url: string; method: string; body: any };
type Route = [string, RegExp, unknown, number?];

function mockApi(routes: Route[]) {
  const calls: Call[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    for (const [m, re, body, status] of routes) {
      if (m === method && re.test(url)) {
        return new Response(JSON.stringify(body), { status: status ?? 200, headers: { "content-type": "application/json" } });
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

function renderPage(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const asAdmin = () => useAuth.setState({ token: "t", user: { username: "alice", role: "admin", clearance: "restricted" } });
const asViewer = () => useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuth.setState({ token: null, user: null });
});

/* ------------------------------ pure helpers ----------------------------- */

describe("helpers", () => {
  it("classifies sync health, treating ok-with-warnings as degraded", () => {
    expect(syncHealth(GCP)).toBe("ok");
    expect(syncHealth(AZURE)).toBe("degraded");
    expect(syncHealth(CS)).toBe("error");
    expect(syncHealth({ ...GCP, last_run: null })).toBe("never");
    expect(syncHealth({ ...GCP, last_run: null, enabled: false })).toBe("paused");
    expect(syncHealth({ ...GCP, last_run: run({ status: "running" }) })).toBe("running");
  });

  it("counts imported items and formats past/future times", () => {
    expect(importedCount(GCP.last_run!.counts)).toBe(55);
    expect(importedCount(undefined)).toBe(0);
    const now = Date.parse(NOW);
    expect(relTime("2026-11-21T09:30:00Z", now)).toBe("30m ago");
    expect(relTime("2026-11-21T12:00:00Z", now)).toBe("in 2h");
    expect(relTime(null, now)).toBe("never");
  });

  it("summarises the outcome of an action from what the connector reported", () => {
    expect(outcomeOf(ACTION({ status: "denied" }))).toMatch(/nothing was changed/);
    expect(outcomeOf(ACTION({ status: "applied", dry_run: false,
      result: { output: { ok: true, detail: "blocked 00:1a", planned: [], dry_run: false, at: "", executed_by: "a" } } }))).toBe("blocked 00:1a");
    expect(outcomeOf(ACTION({ status: "approved",
      result: { dry_run_preview: { ok: true, detail: "client found", planned: ["POST /x"], dry_run: true, at: "", executed_by: "a" } } }))).toMatch(/Dry-run preview: client found/);
  });
});

/* ------------------------------- context sync ----------------------------- */

const contextRoutes = (extra: Route[] = []): Route[] => [
  ...extra,
  ["GET", /\/v1\/integration-sync\/suggestions/, SUGGESTIONS],
  ["GET", /\/v1\/integration-sync$/, [GCP, AZURE, CS]],
];

describe("Context sync page", () => {
  it("shows each source's status, last sync, items, errors and next run", async () => {
    asAdmin();
    mockApi(contextRoutes());
    renderPage(<ContextSyncPage />);
    const table = (await screen.findByText("azure-core")).closest("table")!;
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    const gcp = within(rows[0]);
    expect(gcp.getByLabelText("Healthy")).toBeInTheDocument();
    expect(gcp.getByText("29m ago")).toBeInTheDocument();       // last sync = finished_at
    expect(gcp.getByText("55")).toBeInTheDocument();            // items imported
    expect(gcp.getByText("in 30m")).toBeInTheDocument();        // next run
  });

  it("flags a degraded source and a failing source with their error text", async () => {
    asAdmin();
    mockApi(contextRoutes());
    renderPage(<ContextSyncPage />);
    await screen.findByText("azure-core");
    expect(screen.getByLabelText("Degraded")).toBeInTheDocument();
    expect(screen.getByText(/partial: nsgs: HTTP 403/)).toBeInTheDocument();
    expect(screen.getByLabelText("Failing")).toBeInTheDocument();
    expect(screen.getByText(/Falcon token request: HTTP 401/)).toBeInTheDocument();
    expect(screen.getByText("every 60m")).toBeInTheDocument();
    // tiles
    expect(screen.getByText("Needs attention").closest(".stat-tile")).toHaveTextContent("2");
    expect(screen.getByText("Pending suggestions").closest(".stat-tile")).toHaveTextContent("2");
  });

  it("Sync now posts to the integration and refreshes", async () => {
    asAdmin();
    const calls = mockApi(contextRoutes([
      ["POST", /\/v1\/integration-sync\/i-gcp$/, { status: "ok", detail: null, counts: { assets_inserted: 1 }, run_id: 9 }],
    ]));
    renderPage(<ContextSyncPage />);
    await screen.findByText("azure-core");
    const before = calls.filter((c) => c.method === "GET" && /\/v1\/integration-sync$/.test(c.url)).length;
    const row = screen.getAllByText("gcp-prod")[0].closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Sync now" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && /integration-sync\/i-gcp$/.test(c.url))).toBe(true));
    await waitFor(() =>
      expect(calls.filter((c) => c.method === "GET" && /\/v1\/integration-sync$/.test(c.url)).length).toBeGreaterThan(before));
  });

  it("accepting a suggestion goes through the scope add and points at proof of control", async () => {
    asAdmin();
    const calls = mockApi(contextRoutes([
      ["POST", /suggestions\/12\/accept$/, {
        suggestion: { ...SUGGESTIONS[1], status: "accepted", scope_entry_id: 5 },
        scope_entry: { id: 5, kind: "domain", value: "acme-test.com", proof: { status: "unverified" } } }],
    ]));
    renderPage(<ContextSyncPage />);
    await screen.findByText("acme-test.com");
    fireEvent.click(screen.getByRole("button", { name: "Accept acme-test.com" }));
    fireEvent.change(screen.getByLabelText("Authorization reference for acme-test.com"), { target: { value: "LOA-9" } });
    fireEvent.click(screen.getByRole("button", { name: "Add to scope" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && /suggestions\/12\/accept$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /suggestions\/12\/accept$/.test(c.url))!.body).toEqual({ auth_doc_ref: "LOA-9" });
    const note = await screen.findByRole("status");
    expect(note).toHaveTextContent("Added acme-test.com to scope");
    expect(within(note).getByRole("link", { name: /Verify ownership in Scope/ })).toHaveAttribute("href", "/scope");
  });

  it("dismisses a suggestion", async () => {
    asAdmin();
    const calls = mockApi(contextRoutes([
      ["POST", /suggestions\/11\/dismiss$/, { ...SUGGESTIONS[0], status: "dismissed" }],
    ]));
    renderPage(<ContextSyncPage />);
    await screen.findByText("34.120.10.5/32");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss 34.120.10.5/32" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && /suggestions\/11\/dismiss$/.test(c.url))).toBe(true));
  });

  it("a refused scope add keeps the suggestion and shows the reason", async () => {
    asAdmin();
    mockApi(contextRoutes([
      ["POST", /suggestions\/11\/accept$/, { detail: "ipv4_cidr broader than /16 refused" }, 422],
    ]));
    renderPage(<ContextSyncPage />);
    await screen.findByText("34.120.10.5/32");
    fireEvent.click(screen.getByRole("button", { name: "Accept 34.120.10.5/32" }));
    fireEvent.click(screen.getByRole("button", { name: "Add to scope" }));
    await screen.findByRole("button", { name: "Add to scope" });
    expect(screen.queryByText(/to scope\.$/)).toBeNull();
    expect(screen.getByText("34.120.10.5/32")).toBeInTheDocument();
  });

  it("is read-only for non-admins: sync and decisions are disabled", async () => {
    asViewer();
    mockApi(contextRoutes());
    renderPage(<ContextSyncPage />);
    await screen.findByText("azure-core");
    expect(screen.getAllByRole("button", { name: "Sync now" })[0]).toBeDisabled();
    expect(screen.getByRole("button", { name: "Accept acme-test.com" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Dismiss acme-test.com" })).toBeDisabled();
  });

  it("explains an empty state", async () => {
    asAdmin();
    mockApi([["GET", /suggestions/, []], ["GET", /\/v1\/integration-sync$/, []]]);
    renderPage(<ContextSyncPage />);
    expect(await screen.findByText("No source integrations.")).toBeInTheDocument();
    expect(await screen.findByText("No pending suggestions.")).toBeInTheDocument();
  });
});

/* ----------------------------- network actions ---------------------------- */

const LIVE_APPLIED = ACTION({
  id: "a3", status: "applied", dry_run: false, approved_by: "alice", applied_at: ago(5), decided_at: ago(6),
  result: { integration_name: "unifi-hq", output: { ok: true, detail: "blocked client", planned: [], dry_run: false, at: "", executed_by: "alice" }, revert: { mode: "block" } },
});
const DENIED = ACTION({ id: "a4", status: "denied", approved_by: "alice", decided_at: ago(40), target: "aa:bb:cc:00:00:09" });
const APPROVED_DRY = ACTION({
  id: "a2", status: "approved", dry_run: true, approved_by: "alice", decided_at: ago(2),
  result: { integration_name: "unifi-hq" },
});

const netRoutes = (items: NetworkAction[], extra: Route[] = []): Route[] => [
  ...extra,
  ["GET", /\/v1\/fleet\/network-actions\/a1\/evidence/, EVIDENCE],
  ["GET", /\/v1\/fleet\/network-actions(\?|$)/, { items, total: items.length }],
];

describe("Network actions page", () => {
  it("lists pending proposals with device, reason, proposer and a dry-run indication", async () => {
    asAdmin();
    mockApi(netRoutes([ACTION()]));
    renderPage(<NetworkActionsPage />);
    const card = await screen.findByRole("article", { name: /Quarantine 00:1a:2b:3c:4d:5e/ });
    expect(within(card).getByText("DRY RUN")).toBeInTheDocument();
    expect(within(card).getByText(/Camera is scanning/)).toBeInTheDocument();
    expect(within(card).getByText("sentry")).toBeInTheDocument();
    expect(within(card).getByText(/unifi-hq/)).toBeInTheDocument();
    expect(within(card).getByText("10.5.0.20")).toBeInTheDocument();
  });

  it("loads the evidence on demand", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([ACTION()]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    expect(calls.some((c) => /evidence/.test(c.url))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Show evidence" }));
    const ev = await screen.findByLabelText("Evidence");
    expect(within(ev).getByText("Hikvision camera is scanning")).toBeInTheDocument();
    expect(within(ev).getByText("distinct_hosts")).toBeInTheDocument();
    expect(within(ev).getByText("40")).toBeInTheDocument();
  });

  it("requires a reason before approve or reject is enabled", async () => {
    asAdmin();
    mockApi(netRoutes([ACTION()]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    const approve = screen.getByRole("button", { name: "Approve dry run" });
    const reject = screen.getByRole("button", { name: "Reject" });
    expect(approve).toBeDisabled();
    expect(reject).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "  " } });
    expect(approve).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "Camera is on the guest VLAN" } });
    expect(approve).toBeEnabled();
    expect(reject).toBeEnabled();
  });

  it("approves as a dry run by default, sending the reason and apply_for_real=false", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([ACTION()], [["POST", /\/v1\/fleet\/actions\/a1\/approve$/, ACTION({ status: "approved" })]]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    expect(screen.getByRole("status")).toHaveTextContent(/DRY RUN: approving only allows a read-only preview/);
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "Looks like a scanner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve dry run" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && /actions\/a1\/approve$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /actions\/a1\/approve$/.test(c.url))!.body).toEqual({ apply_for_real: false, note: "Looks like a scanner" });
  });

  it("makes the live choice unmistakable and sends apply_for_real=true", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([ACTION()], [["POST", /\/v1\/fleet\/actions\/a1\/approve$/, ACTION({ status: "approved", dry_run: false })]]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    fireEvent.click(screen.getByLabelText("Apply for real (live quarantine)"));
    expect(screen.getByRole("status")).toHaveTextContent(/LIVE: after execution the device loses network access/);
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "Confirmed with the site owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve live quarantine" }));
    await waitFor(() => expect(calls.some((c) => /actions\/a1\/approve$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /actions\/a1\/approve$/.test(c.url))!.body).toEqual({ apply_for_real: true, note: "Confirmed with the site owner" });
  });

  it("rejects with the reason", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([ACTION()], [["POST", /\/v1\/fleet\/actions\/a1\/deny$/, ACTION({ status: "denied" })]]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "It is the NVR, expected" } });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(calls.some((c) => /actions\/a1\/deny$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /actions\/a1\/deny$/.test(c.url))!.body).toEqual({ note: "It is the NVR, expected" });
  });

  it("surfaces a four-eyes refusal from the API", async () => {
    asAdmin();
    mockApi(netRoutes([ACTION({ requested_by: "alice" })], [
      ["POST", /\/v1\/fleet\/actions\/a1\/approve$/, { detail: "four-eyes: approver must differ from requester" }, 409]]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "self approve" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve dry run" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Approve dry run" })).toBeEnabled());
    const { useStore } = await import("../src/state/store");
    expect(useStore.getState().toasts.some((t) => /four-eyes/.test(t.text))).toBe(true);
  });

  it("is admin-only: viewers see the queue but cannot decide", async () => {
    asViewer();
    mockApi(netRoutes([ACTION()]));
    renderPage(<NetworkActionsPage />);
    await screen.findByRole("article");
    expect(screen.getByLabelText("Reason (required)")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve dry run" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reject" })).toBeDisabled();
  });

  it("an approved dry run offers a preview run, not a live execute", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([APPROVED_DRY], [
      ["POST", /network-actions\/a2\/execute$/, { action: APPROVED_DRY, ok: true, dry_run: true, detail: "client found", planned: ["POST /stamgr"] }]]));
    renderPage(<NetworkActionsPage />);
    const btn = await screen.findByRole("button", { name: "Run dry-run preview" });
    expect(screen.queryByRole("button", { name: /Execute live quarantine/ })).toBeNull();
    fireEvent.click(btn);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && /network-actions\/a2\/execute$/.test(c.url))).toBe(true));
  });

  it("an approved LIVE action is clearly marked and executes on request", async () => {
    asAdmin();
    const live = ACTION({ id: "a5", status: "approved", dry_run: false, approved_by: "alice" });
    const calls = mockApi(netRoutes([live], [
      ["POST", /network-actions\/a5\/execute$/, { action: { ...live, status: "applied" }, ok: true, dry_run: false, detail: "ok", planned: [] }]]));
    renderPage(<NetworkActionsPage />);
    const card = await screen.findByRole("article");
    expect(within(card).getByText("LIVE")).toBeInTheDocument();
    fireEvent.click(within(card).getByRole("button", { name: "Execute live quarantine" }));
    await waitFor(() => expect(calls.some((c) => /network-actions\/a5\/execute$/.test(c.url))).toBe(true));
  });

  it("history shows outcomes and mode, and can release an applied quarantine", async () => {
    asAdmin();
    const calls = mockApi(netRoutes([LIVE_APPLIED, DENIED], [
      ["POST", /\/v1\/fleet\/actions\/a3\/revert$/, ACTION({ id: "rev1", action_type: "revert", status: "approved", revert_of: "a3" })],
      ["POST", /network-actions\/rev1\/execute$/, { action: ACTION({ id: "rev1" }), ok: true, dry_run: false, detail: "unblocked", planned: [] }],
    ]));
    renderPage(<NetworkActionsPage />);
    const table = (await screen.findByText("blocked client")).closest("table")!;
    const rows = within(table).getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("LIVE")).toBeInTheDocument();
    expect(within(rows[0]).getByText("applied")).toBeInTheDocument();
    expect(within(rows[1]).getByText(/Rejected — nothing was changed/)).toBeInTheDocument();
    expect(within(rows[1]).queryByRole("button", { name: "Release" })).toBeNull();
    fireEvent.click(within(rows[0]).getByRole("button", { name: "Release" }));
    await waitFor(() => expect(calls.some((c) => /network-actions\/rev1\/execute$/.test(c.url))).toBe(true));
    expect(calls.some((c) => /actions\/a3\/revert$/.test(c.url))).toBe(true);
  });

  it("shows empty states", async () => {
    asAdmin();
    mockApi(netRoutes([]));
    renderPage(<NetworkActionsPage />);
    expect(await screen.findByText("Nothing waiting for approval.")).toBeInTheDocument();
    expect(screen.getByText("No history yet.")).toBeInTheDocument();
  });
});
