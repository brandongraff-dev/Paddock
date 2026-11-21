/**
 * Integrations page: catalog + connected list, the schema-driven configure
 * drawer (secrets write-only), Test, delivery log + retry, role gating, and
 * the pure form helpers.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import IntegrationsPage, { initialForm, relTime, toPayload } from "../src/pages/Integrations";
import type { Catalog, ConnectorInfo, Integration } from "../src/api/integrations";
import { useAuth } from "../src/state/auth";

const SLACK: ConnectorInfo = {
  kind: "slack",
  display_name: "Slack",
  category: "chat",
  capabilities: ["notify"],
  config_schema: {
    type: "object",
    properties: { mention: { type: "string", title: "Mention on high/critical", maxLength: 64 } },
  },
  secret_fields: ["webhook_url"],
  required_secrets: ["webhook_url"],
  docs_url: null,
};

const EMAIL: ConnectorInfo = {
  kind: "email",
  display_name: "Email (SMTP)",
  category: "email",
  capabilities: ["notify"],
  config_schema: {
    type: "object",
    required: ["host", "from_addr", "to"],
    properties: {
      host: { type: "string", format: "hostname", title: "SMTP host" },
      port: { type: "integer", default: 587, title: "Port" },
      security: { type: "string", enum: ["starttls", "tls"], default: "starttls", title: "Encryption" },
      from_addr: { type: "string", format: "email", title: "From address" },
      to: { type: "array", items: { type: "string", format: "email" }, title: "Recipients" },
    },
  },
  secret_fields: ["username", "password"],
  docs_url: null,
};

const PD: ConnectorInfo = { ...SLACK, kind: "pagerduty", display_name: "PagerDuty", category: "paging", secret_fields: ["routing_key"], config_schema: { type: "object", properties: {} } };

const CATALOG: Catalog = {
  connectors: [EMAIL, PD, SLACK],
  events: [
    { type: "finding.opened", description: "A new finding was opened" },
    { type: "attack_path.opened", description: "A new attack path to a crown jewel appeared" },
    { type: "scan.failed", description: "A scan failed" },
    { type: "integration.test", description: "A test event" },
  ],
  severities: ["info", "low", "medium", "high", "critical"],
  filters: ["asset_kinds", "tags"],
};

const EXISTING: Integration = {
  id: "11111111-1111-1111-1111-111111111111",
  kind: "slack",
  name: "sec-alerts",
  display_name: "Slack",
  category: "chat",
  capabilities: ["notify"],
  enabled: true,
  config: {},
  secrets: { webhook_url: "********" },
  secret_fields: ["webhook_url"],
  secrets_error: null,
  events: ["finding.opened"],
  min_severity: "high",
  filters: {},
  allow_private: false,
  created_by: "admin",
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
  last_ok_at: null,
  last_error: "HTTP 404: no_service",
  last_error_at: "2026-11-21T09:00:00Z",
  status: "error",
  available: true,
  stats: { pending: 0, failed: 1, dead: 2, sent_24h: 7 },
};

const HEALTH = {
  status: "degraded",
  integrations: { total: 1, enabled: 1, ok: 0, error: 1, never: 0, disabled: 0 },
  deliveries: { pending: 1, failed: 1, dead: 2, sent_24h: 7, oldest_due_at: null, stalled: false },
  secret_key_persistent: false,
  items: [],
};

const DELIVERIES = {
  items: [
    { id: 42, event_id: "e1", event_type: "finding.opened", status: "dead", attempts: 8, next_attempt_at: null, status_code: 404, detail: "HTTP 404: no_service", created_at: "2026-11-21T09:00:00Z", updated_at: null, title: "Exposed admin panel", severity: "high", url: null },
    { id: 41, event_id: "e0", event_type: "integration.test", status: "sent", attempts: 1, next_attempt_at: null, status_code: 200, detail: "HTTP 200: ok", created_at: "2026-11-21T08:00:00Z", updated_at: null, title: "Paddock test event", severity: "info", url: null },
  ],
  total: 2,
  limit: 25,
  offset: 0,
};

type Call = { url: string; method: string; body: unknown };

function mockApi(overrides: Array<[string, RegExp, unknown, number?]> = []) {
  const calls: Call[] = [];
  const routes: Array<[string, RegExp, unknown, number?]> = [
    ...overrides,
    ["GET", /\/v1\/integrations\/catalog/, CATALOG],
    ["GET", /\/v1\/integrations\/health/, HEALTH],
    ["GET", /\/v1\/integrations\/[^/]+\/deliveries/, DELIVERIES],
    ["POST", /\/v1\/integrations\/[^/]+\/deliveries\/\d+\/retry/, { ...DELIVERIES.items[0], status: "pending" }],
    ["POST", /\/v1\/integrations\/[^/]+\/test/, { mode: "deliver", ok: true, status_code: 200, detail: "HTTP 200: ok", external_id: null, external_url: null, retryable: true, delivery_id: 43 }],
    ["POST", /\/v1\/integrations\/[^/]+\/(enable|disable)/, EXISTING],
    ["POST", /\/v1\/integrations(\?|$)/, { ...EXISTING, id: "new-id", name: "Slack" }, 201],
    ["PATCH", /\/v1\/integrations\/[^/]+$/, EXISTING],
    ["GET", /\/v1\/integrations(\?|$)/, { items: [EXISTING], total: 1 }],
  ];
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

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <IntegrationsPage />
    </QueryClientProvider>,
  );
}

const asAdmin = () => useAuth.setState({ token: "t", user: { username: "a", role: "admin", clearance: "restricted" } });
const asViewer = () => useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } });

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuth.setState({ token: null, user: null });
});

describe("Integrations page", () => {
  it("renders health, the connected list and the catalog grouped by category", async () => {
    asAdmin();
    mockApi();
    renderPage();
    expect(await screen.findByText("sec-alerts")).toBeInTheDocument();
    expect(screen.getByText("Attention needed")).toBeInTheDocument();
    expect(screen.getByText(/PADDOCK_SECRET_KEY is not set/)).toBeInTheDocument();
    expect(screen.getByText(/HTTP 404: no_service/)).toBeInTheDocument();
    expect(screen.getByLabelText("Failing")).toBeInTheDocument();
    // catalog groups in a stable order: Chat before Paging before Email
    const labels = Array.from(document.querySelectorAll(".ig-group-label")).map((n) => n.textContent);
    expect(labels).toEqual(["Chat", "Paging & on-call", "Email"]);
    expect(screen.getByRole("heading", { name: "Connected" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connect Slack" })).toHaveTextContent("Add another");
  });

  it("connects a new integration from a schema-rendered form with write-only secrets", async () => {
    asAdmin();
    const calls = mockApi();
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Connect PagerDuty" }));
    const drawer = await screen.findByRole("dialog", { name: "Configure PagerDuty" });
    const key = within(drawer).getByLabelText(/Routing key/);
    expect(key).toHaveAttribute("type", "password");
    fireEvent.change(key, { target: { value: "R0UTINGKEY" } });
    // integration.test is not offered as a subscription
    expect(within(drawer).queryByText("integration.test")).toBeNull();
    fireEvent.click(within(drawer).getByLabelText(/scan\.failed/));
    fireEvent.change(within(drawer).getByLabelText("Minimum severity"), { target: { value: "critical" } });
    fireEvent.click(within(drawer).getByRole("button", { name: "Connect" }));
    await vi.waitFor(() => expect(calls.some((c) => c.method === "POST" && /\/v1\/integrations$/.test(c.url))).toBe(true));
    const post = calls.find((c) => c.method === "POST" && /\/v1\/integrations$/.test(c.url))!;
    expect(post.body).toMatchObject({
      kind: "pagerduty",
      name: "PagerDuty",
      secrets: { routing_key: "R0UTINGKEY" },
      events: ["finding.opened", "attack_path.opened", "scan.failed"],
      min_severity: "critical",
    });
    // after saving, the secret input is cleared (never echoed back)
    await vi.waitFor(() => expect(within(drawer).getByLabelText(/Routing key/)).toHaveValue(""));
    expect(within(drawer).getByRole("button", { name: "Send test" })).toBeInTheDocument();
  });

  it("shows 422 validation messages from the API", async () => {
    asAdmin();
    mockApi([["POST", /\/v1\/integrations$/, { detail: { message: "missing credentials", errors: ["secrets.routing_key: is required"] } }, 422]]);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Connect PagerDuty" }));
    const drawer = await screen.findByRole("dialog");
    fireEvent.click(within(drawer).getByRole("button", { name: "Connect" }));
    expect(await within(drawer).findByText("secrets.routing_key: is required")).toBeInTheDocument();
  });

  it("edits an existing integration: stored secret shown as placeholder, test result, deliveries + retry", async () => {
    asAdmin();
    const calls = mockApi();
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Configure" }));
    const drawer = await screen.findByRole("dialog", { name: "Configure Slack" });
    const url = within(drawer).getByLabelText(/Webhook URL/);
    expect(url).toHaveValue("");
    expect(url).toHaveAttribute("placeholder", "•••••••• stored");

    fireEvent.click(within(drawer).getByRole("button", { name: "Send test" }));
    expect(await within(drawer).findByText("Test delivered")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.url.endsWith(`/${EXISTING.id}/test`))).toBe(true);

    // saving without touching the secret must not send it (keep stored value)
    fireEvent.click(within(drawer).getByRole("button", { name: "Save" }));
    await vi.waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect((calls.find((c) => c.method === "PATCH")!.body as Record<string, unknown>).secrets).toBeUndefined();

    fireEvent.click(within(drawer).getByRole("tab", { name: /Deliveries/ }));
    expect(await within(drawer).findByText("Exposed admin panel")).toBeInTheDocument();
    expect(drawer.querySelector(".ig-dchip-dead")).toHaveTextContent("dead");
    fireEvent.click(within(drawer).getAllByRole("button", { name: "Retry" })[0]);
    await vi.waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && /\/deliveries\/42\/retry$/.test(c.url))).toBe(true),
    );
  });

  it("toggles enable from the list", async () => {
    asAdmin();
    const calls = mockApi();
    renderPage();
    fireEvent.click(await screen.findByLabelText("Disable sec-alerts"));
    await vi.waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/disable"))).toBe(true));
  });

  it("is read-only for a viewer", async () => {
    asViewer();
    mockApi();
    renderPage();
    expect(await screen.findByRole("button", { name: "Connect Slack" })).toBeDisabled();
    expect(screen.getByLabelText("Disable sec-alerts")).toBeDisabled();
  });
});

describe("form helpers", () => {
  it("fills schema defaults and converts types; blank secrets mean keep", () => {
    const f = initialForm(EMAIL, null);
    expect(f.config.port).toBe("587");
    expect(f.config.security).toBe("starttls");
    f.config.host = "smtp.example.com";
    f.config.from_addr = "p@example.com";
    f.config.to = "a@example.com,\n b@example.com";
    f.secrets.username = "u";
    f.filters = { tags: "prod, pci", asset_kinds: "" };
    const body = toPayload(EMAIL, f, true);
    expect(body).toMatchObject({
      kind: "email",
      config: { host: "smtp.example.com", port: 587, security: "starttls", from_addr: "p@example.com", to: ["a@example.com", "b@example.com"] },
      secrets: { username: "u" },
      filters: { tags: ["prod", "pci"] },
    });
    const edit = toPayload(SLACK, initialForm(SLACK, EXISTING), false);
    expect(edit.secrets).toBeUndefined();
    expect(edit.kind).toBeUndefined();
    expect(edit.events).toEqual(["finding.opened"]);
  });

  it("formats relative times", () => {
    const now = Date.parse("2026-11-21T12:00:00Z");
    expect(relTime(null, now)).toBe("never");
    expect(relTime("2026-11-21T11:59:30Z", now)).toBe("just now");
    expect(relTime("2026-11-21T11:00:00Z", now)).toBe("1h ago");
    expect(relTime("2026-11-19T12:00:00Z", now)).toBe("2d ago");
  });
});
