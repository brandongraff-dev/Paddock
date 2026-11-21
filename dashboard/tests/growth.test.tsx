/**
 * Growth pages: /check (public), /trust/:token (public), Reports -> trust
 * link manager, Suppliers. fetch is stubbed with a router keyed on
 * "METHOD path"; every request (headers included) is recorded.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Check, { describeError, normalizeDomain } from "../src/pages/Check";
import Trust from "../src/pages/Trust";
import TrustLinksPage from "../src/pages/TrustLinks";
import SuppliersPage, { rankFindings } from "../src/pages/Suppliers";
import Shell from "../src/components/Shell";
import { ApiError } from "../src/api/client";
import { useAuth } from "../src/state/auth";
import type { ExposureReport, Supplier, SupplierDetail, TrustLink, TrustView } from "../src/api/growth";

type Handler = (body: any, req: { headers: Record<string, string>; query: URLSearchParams }) => unknown;
let calls: { method: string; path: string; body: any; headers: Record<string, string> }[] = [];

function mockApi(routes: Record<string, Handler>) {
  calls = [];
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: any, init?: any) => {
    const url = new URL(String(input), "http://x");
    const method = (init?.method ?? "GET").toUpperCase();
    const body = init?.body ? JSON.parse(init.body) : undefined;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ method, path: url.pathname, body, headers });
    const h = routes[`${method} ${url.pathname}`];
    if (!h) return new Response(JSON.stringify({ detail: "not mocked" }), { status: 404 });
    const out = h(body, { headers, query: url.searchParams });
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  });
}
const fail = (status: number, detail: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ detail }), { status, headers: { "content-type": "application/json", ...headers } });

function renderAt(path: string, routes: { path: string; el: React.ReactElement }[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          {routes.map((r) => <Route key={r.path} path={r.path} element={r.el} />)}
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  useAuth.setState({ token: null, user: null });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/* ------------------------------------------------------------------ */
/* /check                                                              */
/* ------------------------------------------------------------------ */

const REPORT: ExposureReport = {
  id: "11111111-1111-4111-8111-111111111111",
  domain: "acme-corp.org",
  status: "done",
  created_at: "2026-11-21T10:00:00Z",
  finished_at: "2026-11-21T10:00:20Z",
  error: null,
  summary: {
    grade: "C",
    score: 72,
    reasons: ["No DMARC policy (high)", "Possible subdomain takeover via Heroku (high)"],
    findings_total: 6,
    by_severity: { info: 0, low: 2, medium: 2, high: 2, critical: 0 },
    by_category: { email: 3, dangling_dns: 1 },
    checks: [
      { key: "email", label: "Email authentication (SPF, DKIM, DMARC, MTA-STS)", status: "fail" },
      { key: "dangling_dns", label: "Dangling DNS records", status: "fail" },
      { key: "certificates", label: "Certificate hygiene", status: "pass" },
    ],
    stats: { subdomains: 14, live_hosts: 9, certificates_valid: 5, wildcard_certificates: 1, issuers: 2, nameservers: 2, dnssec: false, ct_available: true },
    email: { spf: "softfail", dmarc: "missing", dkim_found: false, mta_sts: false },
    assessed_at: "2026-11-21T10:00:20Z",
  },
  teaser: {
    shown: [
      { severity: "high", category: "dangling_dns", title: "Possible subdomain takeover via Heroku", confidence: "possible", host: "o***.acme-corp.org" },
      { severity: "high", category: "email", title: "No DMARC policy", confidence: "confirmed", host: null },
      { severity: "medium", category: "email", title: "SPF ends in ?all and enforces nothing", confidence: "confirmed", host: null },
    ],
    hidden: 3,
  },
  cta: { text: "3 more findings and the fix steps are in the full report. Verify ownership.", url: "/welcome" },
  passive_notice: "Built only from public DNS and certificate-transparency data. No traffic was sent to this domain.",
};

describe("normalizeDomain / describeError", () => {
  it("forgives pasted URLs", () => {
    expect(normalizeDomain("  https://User:pw@WWW.Acme-Corp.org:8443/path?q=1#x ")).toBe("acme-corp.org");
    expect(normalizeDomain("acme-corp.org.")).toBe("acme-corp.org");
    expect(normalizeDomain("http://www.example.co.uk/")).toBe("example.co.uk");
    expect(normalizeDomain("")).toBe("");
  });
  it("maps API errors to plain language", () => {
    const e = (status: number, detail: unknown) => new ApiError("x", status, { detail });
    expect(describeError(e(422, { code: "ip_literal", message: "x" }))).toMatch(/IP address/);
    expect(describeError(e(422, { code: "internal_name" }))).toMatch(/internal/);
    expect(describeError(e(503, "busy"))).toMatch(/busy/);
    expect(describeError(new Error("boom"))).toMatch(/Something went wrong/);
    const rl = Object.assign(e(429, "slow down"), { retryAfter: 1800 });
    expect(describeError(rl)).toMatch(/30 minutes/);
  });
});

describe("Check page", () => {
  it("submits a normalised domain, polls, then shows grade, teaser and CTA", async () => {
    let polls = 0;
    mockApi({
      "POST /v1/public/exposure-report": () =>
        new Response(JSON.stringify({ id: REPORT.id, domain: "acme-corp.org", status: "queued", cached: false, email_stored: false }), { status: 202 }),
      [`GET /v1/public/exposure-report/${REPORT.id}`]: () => {
        polls += 1;
        return polls < 2 ? { ...REPORT, status: "running", summary: null, teaser: null, cta: null } : REPORT;
      },
    });
    renderAt("/check", [{ path: "/check", el: <Check /> }]);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "https://www.Acme-Corp.org/" } });
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));

    expect(await screen.findByRole("status")).toHaveTextContent(/certificate-transparency/i);
    const result = await screen.findByTestId("check-result", {}, { timeout: 6000 });
    expect(within(result).getByLabelText("Grade C")).toBeInTheDocument();
    expect(within(result).getByText("72")).toBeInTheDocument();
    expect(within(result).getByText("No DMARC policy (high)")).toBeInTheDocument();
    expect(within(result).getByText("o***.acme-corp.org")).toBeInTheDocument();
    expect(within(result).getByText("possible")).toBeInTheDocument();
    expect(within(result).getByText(/\+ 3 more in the full report/)).toBeInTheDocument();
    expect(within(result).getByRole("link", { name: /Get the full report/ })).toHaveAttribute("href", "/welcome");
    expect(within(result).getByText(/No traffic was sent/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toEqual({ domain: "acme-corp.org" });
  });

  it("never sends the session token to the anonymous endpoints", async () => {
    useAuth.setState({ token: "secret-session-token", user: { username: "a", role: "admin", clearance: "restricted" } });
    mockApi({
      "POST /v1/public/exposure-report": () => ({ id: REPORT.id, domain: "acme-corp.org", status: "queued", cached: false, email_stored: false }),
      [`GET /v1/public/exposure-report/${REPORT.id}`]: () => REPORT,
    });
    renderAt("/check", [{ path: "/check", el: <Check /> }]);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "acme-corp.org" } });
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));
    await screen.findByTestId("check-result", {}, { timeout: 6000 });
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const c of calls) expect(JSON.stringify(c.headers)).not.toMatch(/authorization|secret-session-token/i);
  });

  it("sends email and the consent flag only when an email is entered", async () => {
    mockApi({
      "POST /v1/public/exposure-report": () => ({ id: REPORT.id, domain: "acme-corp.org", status: "queued", cached: false, email_stored: true }),
      [`GET /v1/public/exposure-report/${REPORT.id}`]: () => REPORT,
    });
    renderAt("/check", [{ path: "/check", el: <Check /> }]);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "acme-corp.org" } });
    fireEvent.click(screen.getByText(/Email me when anything changes/));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "jane@acme-corp.org" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));
    await screen.findByTestId("check-result", {}, { timeout: 6000 });
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ domain: "acme-corp.org", email: "jane@acme-corp.org", consent: true });
  });

  it("shows readable errors for invalid domains and rate limits", async () => {
    mockApi({
      "POST /v1/public/exposure-report": (b) =>
        b.domain === "10.0.0.1"
          ? fail(422, { code: "ip_literal", message: "IP addresses are not accepted" })
          : fail(429, "too many requests (per address); try again later", { "retry-after": "600" }),
    });
    renderAt("/check", [{ path: "/check", el: <Check /> }]);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "10.0.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/IP address/);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "acme-corp.org" } });
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/10 minutes/));
  });

  it("blocks an empty submit without calling the API", async () => {
    mockApi({});
    renderAt("/check", [{ path: "/check", el: <Check /> }]);
    fireEvent.click(screen.getByRole("button", { name: "Check my domain" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Enter a domain/);
    expect(calls).toHaveLength(0);
  });

  it("reopens a shared report from ?id= and explains a domain that does not exist", async () => {
    mockApi({
      [`GET /v1/public/exposure-report/${REPORT.id}`]: () => ({
        ...REPORT, status: "failed", error: "domain_not_found", summary: null, teaser: null, cta: null,
      }),
    });
    renderAt(`/check?id=${REPORT.id}`, [{ path: "/check", el: <Check /> }]);
    expect(await screen.findByText(/could not find acme-corp.org in public DNS/)).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* /trust/:token                                                       */
/* ------------------------------------------------------------------ */

const TRUST: TrustView = {
  organization: "Acme Corp",
  generated_at: "2026-11-21T12:00:00Z",
  period_days: 30,
  expires_at: "2026-12-21T12:00:00Z",
  sections: ["grade", "verified_fixes", "sla", "compliance", "coverage"],
  data: {
    grade: { grade: "B", score: 84, trend: "improving", open_by_severity: { critical: 0, high: 2, medium: 9, low: 14 }, open_critical_high: 2 },
    verified_fixes: { fixed: 41, verified: 36, regressed: 1, pending_verification: 4, fixed_by_severity: { high: 12 }, median_hours_to_fix: 30 },
    sla: {
      compliance_pct: 92.4, met: 50, late: 3, breached_open: 1,
      by_severity: [{ severity: "critical", policy_hours: 24, met: 5, late: 0, breached_open: 0, compliance_pct: 100 }],
    },
    compliance: [{ id: "iso27001", name: "ISO 27001", version: "2022", total: 20, automated: 12, counts: { satisfied: 10, partial: 4, gap: 2, requires_attestation: 4 } }],
    coverage: {
      assets_total: 120, by_kind: [{ kind: "subdomain", total: 80, seen_7d: 78, stale: 2 }], scans_by_status: { completed: 12 },
      last_completed_scan: "2026-11-20T00:00:00Z", sbom_projects: 6, tls_graded: 30, tls_below_b: 3, fleet_agents: 11, fleet_agents_recent: 10,
    },
  },
};

describe("Trust page", () => {
  const route = [{ path: "/trust/:token", el: <Trust /> }];

  it("renders exactly the sections the API returned", async () => {
    mockApi({ "GET /v1/public/trust/tok": () => TRUST });
    renderAt("/trust/tok", route);
    expect(await screen.findByRole("heading", { name: "Acme Corp" })).toBeInTheDocument();
    expect(screen.getByLabelText("Grade B")).toBeInTheDocument();
    expect(screen.getByText(/Exposure is improving/)).toBeInTheDocument();
    expect(screen.getByText("92%")).toBeInTheDocument();
    expect(screen.getByText("ISO 27001")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
    expect(screen.getByText(/Aggregate figures only/)).toBeInTheDocument();
    expect(document.head.querySelector('meta[name="robots"]')?.getAttribute("content")).toMatch(/noindex/);
  });

  it("omits sections that were not shared", async () => {
    mockApi({
      "GET /v1/public/trust/tok": () => ({ ...TRUST, sections: ["grade"], data: { grade: TRUST.data.grade } }),
    });
    renderAt("/trust/tok", route);
    await screen.findByLabelText("Grade B");
    expect(screen.queryByLabelText("SLA compliance")).toBeNull();
    expect(screen.queryByLabelText("Coverage")).toBeNull();
    expect(screen.queryByLabelText("Compliance packs")).toBeNull();
  });

  it("asks for the password, rejects a wrong one, accepts the right one", async () => {
    mockApi({
      "GET /v1/public/trust/tok": () => fail(401, { code: "password_required" }),
      "POST /v1/public/trust/tok": (b) =>
        b.password === "correct horse" ? TRUST : fail(401, { code: "password_incorrect" }),
    });
    renderAt("/trust/tok", route);
    const input = await screen.findByLabelText("Password");
    fireEvent.change(input, { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "View" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/not correct/);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct horse" } });
    fireEvent.click(screen.getByRole("button", { name: "View" }));
    expect(await screen.findByRole("heading", { name: "Acme Corp" })).toBeInTheDocument();
    for (const c of calls) expect(JSON.stringify(c.headers)).not.toMatch(/authorization/i);
  });

  it("says the link is unavailable for expired, revoked or forged tokens alike", async () => {
    mockApi({ "GET /v1/public/trust/bad": () => fail(404, "this link is not available") });
    renderAt("/trust/bad", route);
    expect(await screen.findByRole("alert")).toHaveTextContent(/no longer available/);
  });
});

/* ------------------------------------------------------------------ */
/* Reports -> trust link manager                                       */
/* ------------------------------------------------------------------ */

const LINK: TrustLink = {
  id: "l1", label: "Insurer 2027", sections: ["grade", "sla"], period_days: 30, created_at: "2026-11-01T00:00:00Z",
  created_by: "admin", expires_at: "2026-12-01T00:00:00Z", revoked_at: null, password_protected: true,
  view_count: 3, last_viewed_at: "2026-11-20T00:00:00Z", token_hint: "ab12", status: "active",
};

describe("Trust link manager", () => {
  beforeEach(() => {
    useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
  });

  it("creates a link, shows the URL once, and lists links with view counts", async () => {
    let links: TrustLink[] = [LINK];
    mockApi({
      "GET /v1/trust-links": () => links,
      "POST /v1/trust-links": (b) => {
        links = [{ ...LINK, id: "l2", label: b.label, sections: b.sections }, ...links];
        return { ...links[0], token: "pt1.SECRETBODY.sig", path: "/trust/pt1.SECRETBODY.sig" };
      },
    });
    renderAt("/reports/trust", [{ path: "/reports/trust", el: <TrustLinksPage /> }]);
    expect(await screen.findByText("Insurer 2027")).toBeInTheDocument();
    expect(screen.getByText("locked")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Label/), { target: { value: "Customer X" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /Coverage/ }));
    fireEvent.click(screen.getByRole("button", { name: "Create link" }));

    const url = await screen.findByTestId("trust-url");
    expect(url.textContent).toMatch(/\/trust\/pt1\.SECRETBODY\.sig$/);
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toMatchObject({ label: "Customer X", expires_in_days: 30 });
    expect(post.body.sections).toEqual(["grade", "verified_fixes", "sla", "coverage"]);
    expect(post.body.password).toBeUndefined();
    expect(await screen.findByText("Customer X")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByTestId("trust-url")).toBeNull();
    // the token is not part of the list data
    expect(document.body.textContent).not.toContain("SECRETBODY");
  });

  it("will not submit without a label, sections, or with a short password", async () => {
    mockApi({ "GET /v1/trust-links": () => [] });
    renderAt("/reports/trust", [{ path: "/reports/trust", el: <TrustLinksPage /> }]);
    const btn = await screen.findByRole("button", { name: "Create link" });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Label/), { target: { value: "x" } });
    expect(btn).not.toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "short" } });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "long enough pw" } });
    expect(btn).not.toBeDisabled();
  });

  it("revokes after confirmation", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    let links: TrustLink[] = [LINK];
    mockApi({
      "GET /v1/trust-links": () => links,
      "DELETE /v1/trust-links/l1": () => {
        links = [{ ...LINK, status: "revoked", revoked_at: "2026-11-21T00:00:00Z" }];
        return links[0];
      },
    });
    renderAt("/reports/trust", [{ path: "/reports/trust", el: <TrustLinksPage /> }]);
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull());
    expect(await screen.findByText("revoked")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* Suppliers                                                           */
/* ------------------------------------------------------------------ */

const SUP: Supplier = {
  id: "s1", domain: "vendor-co.com", name: "Vendor Co", criticality: "high", notes: null, enabled: true,
  interval_hours: 168, next_run_at: "2026-11-28T00:00:00Z", last_assessed_at: "2026-11-21T00:00:00Z",
  last_grade: "D", last_score: 58, last_error: null, created_at: "2026-11-01T00:00:00Z",
};
const DETAIL: SupplierDetail = {
  ...SUP,
  history: [
    { id: "a2", created_at: "2026-11-21T00:00:00Z", grade: "D", score: 58, changes: { first: false, grade_from: "B", grade_to: "D", grade_direction: "drop", score_from: 84, score_to: 58, score_delta: -26, new: [{ id: "f1", rule: "dmarc_missing", severity: "high", title: "No DMARC policy", host: null }], resolved: [], new_dangling: [], new_cert_expiring: [] } },
    { id: "a1", created_at: "2026-11-14T00:00:00Z", grade: "B", score: 84, changes: { first: true, grade_from: null, grade_to: "B", grade_direction: "none", score_from: null, score_to: 84, score_delta: null, new: [], resolved: [], new_dangling: [], new_cert_expiring: [] } },
  ],
  findings: [
    { id: "f2", rule: "no_caa", category: "certificates", severity: "low", title: "No CAA record", detail: "d", fix: "f", host: null, confidence: "confirmed" },
    { id: "f1", rule: "dangling_cname_takeover", category: "dangling_dns", severity: "high", title: "Possible subdomain takeover via Heroku", detail: "d", fix: "f", host: "old.vendor-co.com", confidence: "possible" },
  ],
  summary: null,
};

describe("Suppliers page", () => {
  beforeEach(() => {
    useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
  });

  it("ranks findings by severity", () => {
    expect(rankFindings(DETAIL.findings).map((f) => f.id)).toEqual(["f1", "f2"]);
  });

  it("lists suppliers with grades and opens history + findings", async () => {
    mockApi({
      "GET /v1/suppliers": () => [SUP, { ...SUP, id: "s2", name: "New Vendor", domain: "new-vendor.io", last_grade: null, last_score: null, last_assessed_at: null }],
      "GET /v1/suppliers/s1": () => DETAIL,
    });
    renderAt("/suppliers", [{ path: "/suppliers", el: <SuppliersPage /> }]);
    expect(await screen.findByText("Vendor Co")).toBeInTheDocument();
    expect(screen.getByLabelText("Grade D")).toBeInTheDocument();
    expect(screen.getByTitle("Not assessed yet")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Vendor Co" }));
    const detail = await screen.findByLabelText("Vendor Co detail");
    expect(within(detail).getByText(/Dropped from B/)).toBeInTheDocument();
    expect(within(detail).getByText("old.vendor-co.com")).toBeInTheDocument();
    expect(within(detail).getByText("possible")).toBeInTheDocument();
    const items = within(detail).getAllByRole("listitem").map((li) => li.textContent ?? "");
    const hi = items.findIndex((t) => t.includes("takeover"));
    const lo = items.findIndex((t) => t.includes("No CAA"));
    expect(hi).toBeGreaterThanOrEqual(0);
    expect(hi).toBeLessThan(lo);
  });

  it("adds a supplier and surfaces server validation", async () => {
    mockApi({
      "GET /v1/suppliers": () => [],
      "POST /v1/suppliers": (b) =>
        b.domain === "localhost"
          ? fail(422, { code: "internal_name", message: "internal or reserved names are not public domains" })
          : { ...SUP, domain: b.domain, name: b.name ?? b.domain },
    });
    renderAt("/suppliers", [{ path: "/suppliers", el: <SuppliersPage /> }]);
    const add = await screen.findByRole("button", { name: "Add supplier" });
    expect(add).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "localhost" } });
    fireEvent.click(add);
    expect(await screen.findByRole("alert")).toHaveTextContent(/internal or reserved/);
    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "vendor-co.com" } });
    fireEvent.change(screen.getByLabelText("Criticality"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Check"), { target: { value: "24" } });
    fireEvent.click(screen.getByRole("button", { name: "Add supplier" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "POST")[1].body).toEqual({
      domain: "vendor-co.com", criticality: "critical", interval_hours: 24,
    });
  });

  it("queues an immediate check", async () => {
    mockApi({
      "GET /v1/suppliers": () => [SUP],
      "POST /v1/suppliers/s1/assess": () => SUP,
    });
    renderAt("/suppliers", [{ path: "/suppliers", el: <SuppliersPage /> }]);
    fireEvent.click(await screen.findByRole("button", { name: "Check now" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/v1/suppliers/s1/assess")).toBe(true));
  });
});

/* ------------------------------------------------------------------ */
/* Navigation                                                          */
/* ------------------------------------------------------------------ */

describe("Shell navigation", () => {
  it("lists Suppliers under Risk", () => {
    useAuth.setState({ token: "t", user: { username: "admin", role: "admin", clearance: "restricted" } });
    mockApi({});
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={["/suppliers"]}>
          <Shell><div>page</div></Shell>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const link = screen.getByRole("link", { name: "Suppliers" });
    expect(link).toHaveAttribute("href", "/suppliers");
    expect(link.closest(".rail-group")?.querySelector(".rail-group-label")?.textContent).toBe("Risk");
  });
});
