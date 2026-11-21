/**
 * Billing dashboard tests:
 *   - the 402 body parser (flat and FastAPI `detail`-wrapped) and the reusable
 *     UpgradePrompt empty state;
 *   - Settings → Billing: trial countdown, usage meters vs quota, dunning and
 *     downgrade notices, Checkout / Portal hand-offs, admin-only buttons, and
 *     the self-hosted (billing off) variant.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import BillingPage, { UsageMeter } from "../src/pages/Billing";
import UpgradePrompt from "../src/components/UpgradePrompt";
import { ApiError } from "../src/api/client";
import { paymentRequired, upgradeHref } from "../src/api/billing";
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

const PLANS = [
  { key: "team", name: "Team", edition: "team", seats: 10, sites: 3, assets: 5000, purchasable: true },
  { key: "enterprise", name: "Enterprise", edition: "enterprise", seats: null, sites: null, assets: null, purchasable: true },
];

function billing(over: Record<string, unknown> = {}) {
  return {
    enabled: true, enforcement: true, edition: "team", status: "trialing", source: "trial", plan: "team",
    features: ["sso_saml", "digest_branding", "hosted_sites"],
    limits: { seats: 10, sites: 3, assets: 5000 },
    usage: {
      seats: { used: 2, limit: 10, over: false },
      sites: { used: 1, limit: 3, over: false },
      assets: { used: 1200, limit: 5000, over: false },
    },
    trial_ends_at: "2026-12-05T00:00:00Z", trial_days_left: 9, grace_ends_at: null, current_period_end: null,
    cancel_at_period_end: false, downgraded: false, dunning: false, read_only: false, can_manage: false,
    plans: PLANS, upgrade_url: "https://app.example.test/settings/billing",
    ...over,
  };
}

function renderPage(path = "/settings/billing") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    React.createElement(
      QueryClientProvider,
      { client: qc },
      React.createElement(MemoryRouter, { initialEntries: [path] }, React.createElement(BillingPage)),
    ),
  );
}

const assign = vi.fn();
const realLocation = window.location;

beforeEach(() => {
  assign.mockReset();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...realLocation, origin: "http://localhost", assign },
  });
  useAuth.setState({
    token: "t",
    user: { username: "root", role: "admin", clearance: "restricted" } as never,
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Object.defineProperty(window, "location", { configurable: true, value: realLocation });
  useAuth.setState({ token: null, user: null });
});

/* ------------------------------ 402 parser ------------------------------ */

describe("paymentRequired()", () => {
  const body402 = {
    error: "payment_required", feature: "scim", required_edition: "enterprise",
    upgrade_url: "https://app.example.test/settings/billing?feature=scim&plan=enterprise",
  };

  it("reads the flat body", () => {
    const info = paymentRequired(new ApiError("402", 402, body402));
    expect(info).toMatchObject({ feature: "scim", required_edition: "enterprise", kind: "payment_required" });
  });

  it("reads the FastAPI detail wrapper (and the legacy license gate)", () => {
    const info = paymentRequired(new ApiError("402", 402, { detail: { ...body402, error: "feature_not_licensed" } }));
    expect(info?.kind).toBe("feature_not_licensed");
    expect(info?.feature).toBe("scim");
  });

  it("returns null for anything that is not a 402", () => {
    expect(paymentRequired(new ApiError("403", 403, body402))).toBeNull();
    expect(paymentRequired(new Error("boom"))).toBeNull();
    expect(paymentRequired(null)).toBeNull();
  });

  it("tolerates a sparse 402 and keeps upgrade links in-app", () => {
    const info = paymentRequired(new ApiError("402", 402, {}));
    expect(info?.upgrade_url).toBe("/settings/billing");
    expect(upgradeHref(paymentRequired(new ApiError("402", 402, body402))!)).toBe(
      "https://app.example.test/settings/billing?feature=scim&plan=enterprise",
    );
    expect(upgradeHref({ ...info!, upgrade_url: "http://localhost/settings/billing?x=1" })).toBe("/settings/billing?x=1");
  });
});

/* ----------------------------- UpgradePrompt ---------------------------- */

describe("UpgradePrompt", () => {
  it("shows the feature, the needed edition and an upgrade link on a 402", () => {
    const err = new ApiError("402", 402, {
      feature: "compliance_packs", required_edition: "enterprise",
      upgrade_url: "/settings/billing?feature=compliance_packs&plan=enterprise",
    });
    render(React.createElement(UpgradePrompt, { error: err, fallback: React.createElement("div", null, "fallback") }));
    expect(screen.getByText(/compliance evidence packs is part of enterprise/i)).toBeInTheDocument();
    const cta = screen.getByRole("link", { name: /upgrade to enterprise/i });
    expect(cta.getAttribute("href")).toBe("/settings/billing?feature=compliance_packs&plan=enterprise");
    expect(screen.queryByText("fallback")).toBeNull();
  });

  it("explains a quota 402 and says data stays readable", () => {
    const err = new ApiError("402", 402, {
      error: "quota_exceeded", feature: "assets", required_edition: "team", upgrade_url: "/settings/billing",
      used: 4, limit: 3,
    });
    render(React.createElement(UpgradePrompt, { error: err }));
    expect(screen.getByText(/monitored assets allowance reached/i)).toBeInTheDocument();
    expect(screen.getByText(/existing data stays readable/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /review plans/i })).toBeInTheDocument();
  });

  it("falls back for non-402 errors", () => {
    render(React.createElement(UpgradePrompt, {
      error: new ApiError("500", 500, {}),
      fallback: React.createElement("div", null, "Could not load."),
    }));
    expect(screen.getByText("Could not load.")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });
});

/* ------------------------------- usage meter ----------------------------- */

describe("UsageMeter", () => {
  it("flags near and over quota and shows unlimited", () => {
    const { rerender } = render(React.createElement(UsageMeter, { label: "Sites", hint: "h", used: 1, limit: 3, over: false }));
    expect(screen.getByRole("meter", { name: /sites usage/i }).parentElement?.getAttribute("data-tone")).toBe("ok");
    rerender(React.createElement(UsageMeter, { label: "Sites", hint: "h", used: 3, limit: 3, over: false }));
    expect(screen.getByRole("meter").parentElement?.getAttribute("data-tone")).toBe("near");
    rerender(React.createElement(UsageMeter, { label: "Sites", hint: "h", used: 4, limit: 3, over: true }));
    expect(screen.getByRole("meter").parentElement?.getAttribute("data-tone")).toBe("over");
    expect(screen.getByText(/new growth is paused/i)).toBeInTheDocument();
    rerender(React.createElement(UsageMeter, { label: "Seats", hint: "h", used: 40, limit: null, over: false }));
    expect(screen.getByText(/Unlimited/)).toBeInTheDocument();
  });
});

/* -------------------------------- the page ------------------------------- */

describe("Billing page", () => {
  it("shows the trial countdown, usage vs quota and plan buttons", async () => {
    mockFetch([[/\/v1\/billing$/, billing()]]);
    renderPage();
    expect(await screen.findByText(/9 days left in your Team trial/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Billing" })).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: /monitored assets usage/i })).toBeInTheDocument();
    expect(screen.getByText("1,200")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /choose team/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /choose enterprise/i })).toBeEnabled();
    // no Stripe customer yet -> nothing to manage
    expect(screen.queryByRole("button", { name: /manage billing/i })).toBeNull();
  });

  it("upgrade starts Checkout and redirects to Stripe", async () => {
    const f = mockFetch([
      [/\/v1\/billing$/, billing()],
      [/\/v1\/billing\/checkout$/, { url: "https://checkout.stripe.test/c/cs_1" }, 200, "POST"],
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /choose enterprise/i }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://checkout.stripe.test/c/cs_1"));
    const call = f.mock.calls.find(([u]) => String(u).endsWith("/v1/billing/checkout"))!;
    expect(JSON.parse(String(call[1]?.body))).toEqual({ plan: "enterprise" });
  });

  it("Manage billing opens the Customer Portal for a subscriber", async () => {
    mockFetch([
      [/\/v1\/billing$/, billing({
        status: "active", source: "subscription", plan: "team", trial_ends_at: null, trial_days_left: null,
        can_manage: true, current_period_end: "2027-01-10T00:00:00Z",
      })],
      [/\/v1\/billing\/portal$/, { url: "https://billing.stripe.test/p/1" }, 200, "POST"],
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /manage billing/i }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://billing.stripe.test/p/1"));
    expect(screen.getByRole("button", { name: /your plan/i })).toBeDisabled();
  });

  it("warns during dunning with the grace deadline", async () => {
    mockFetch([[/\/v1\/billing$/, billing({
      status: "past_due", source: "subscription", dunning: true, grace_ends_at: "2026-12-30T00:00:00Z",
      trial_days_left: null, can_manage: true,
    })]]);
    renderPage();
    expect(await screen.findByText(/last payment failed/i)).toBeInTheDocument();
    expect(screen.getByText(/drops to Community limits/i)).toBeInTheDocument();
  });

  it("explains a downgrade that is over quota (read-only, nothing deleted)", async () => {
    mockFetch([[/\/v1\/billing$/, billing({
      edition: "community", status: "trial_expired", source: "subscription", plan: null, downgraded: true,
      read_only: true, trial_days_left: null, features: [], limits: { seats: 3, sites: 0, assets: 250 },
      usage: {
        seats: { used: 2, limit: 3, over: false }, sites: { used: 0, limit: 0, over: false },
        assets: { used: 400, limit: 250, over: true },
      },
    })]]);
    renderPage();
    expect(await screen.findByText(/you are on community limits/i)).toBeInTheDocument();
    expect(screen.getByText(/new scans are paused/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing has been deleted/i)).toBeInTheDocument();
    const meter = screen.getByRole("meter", { name: /monitored assets usage/i });
    expect(meter.parentElement?.getAttribute("data-tone")).toBe("over");
  });

  it("highlights the plan a 402 sent the user for", async () => {
    mockFetch([[/\/v1\/billing$/, billing()]]);
    renderPage("/settings/billing?feature=scim&plan=enterprise");
    const card = (await screen.findByRole("button", { name: /choose enterprise/i })).closest(".bill-plan");
    expect(card?.className).toContain("is-highlighted");
    expect(screen.getByText(/needs Enterprise/i)).toBeInTheDocument();
  });

  it("is read-only for non-admins", async () => {
    useAuth.setState({ token: "t", user: { username: "v", role: "viewer", clearance: "public" } as never });
    mockFetch([[/\/v1\/billing$/, billing()]]);
    renderPage();
    expect(await screen.findByRole("button", { name: /choose team/i })).toBeDisabled();
  });

  it("surfaces a Checkout error from the API", async () => {
    mockFetch([
      [/\/v1\/billing$/, billing()],
      [/\/v1\/billing\/checkout$/, { detail: { error: "already_subscribed" } }, 409, "POST"],
    ]);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /choose team/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/already have a subscription/i);
    expect(assign).not.toHaveBeenCalled();
  });

  it("self-hosted: billing off shows the license note and no purchase buttons", async () => {
    mockFetch([[/\/v1\/billing$/, billing({
      enabled: false, enforcement: false, edition: "community", status: "community", source: "default",
      plan: null, plans: [], trial_days_left: null, trial_ends_at: null,
    })]]);
    renderPage();
    const panel = (await screen.findByText(/online billing is not enabled/i)).closest("section")!;
    expect(within(panel).getByText(/no usage caps/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /choose/i })).toBeNull();
  });
});
