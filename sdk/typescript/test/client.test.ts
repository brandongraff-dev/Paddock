import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  FeatureNotLicensed,
  NotFound,
  OPERATIONS,
  PaddockClient,
  PermissionDenied,
  ServerError,
  TransportError,
  UnprocessableEntity,
  retryDelayMs,
  DEFAULT_RETRY,
  type FindingOut,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));

type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function fakeServer(routes: Record<string, Handler | Response[] | unknown>) {
  const calls: { method: string; url: URL; init: RequestInit }[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    calls.push({ method, url, init });
    const r = routes[`${method} ${url.pathname}`];
    if (r === undefined) return json(404, { detail: "Not Found" });
    if (typeof r === "function") return (r as Handler)(url, init);
    if (Array.isArray(r) && r.every((x) => x instanceof Response)) {
      return (r.length > 1 ? r.shift() : r[0])!.clone();
    }
    return json(200, r);
  });
  return { fetchImpl, calls };
}

function client(routes: Record<string, Handler | Response[] | unknown>, extra: Record<string, unknown> = {}) {
  const srv = fakeServer(routes);
  const sleeps: number[] = [];
  const c = new PaddockClient({
    baseUrl: "http://paddock.test/",
    apiKey: "pak_abc_secret",
    fetch: srv.fetchImpl as unknown as typeof fetch,
    retry: { maxRetries: 2 },
    sleep: async (ms) => void sleeps.push(ms),
    ...extra,
  });
  return { c, ...srv, sleeps };
}

describe("PaddockClient", () => {
  it("sends the API key as a bearer token", async () => {
    const { c, calls } = client({ "GET /v1/auth/me": { actor: "alice", role: "admin" } });
    const me = await c.me();
    expect(me.actor).toBe("alice");
    const h = calls[0].init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer pak_abc_secret");
    expect(h["User-Agent"]).toMatch(/^paddock-sdk-ts\//);
  });

  it("encodes path params and drops null query values", async () => {
    const { c, calls } = client({
      "GET /v1/findings": { items: [], total: 0, limit: 5, offset: 0 },
      "GET /v1/scans/a%2Fb": { id: "x" },
    });
    await c.listFindingsPaged({ severity: "high", kev: true, q: null, limit: 5 });
    expect(calls[0].url.searchParams.get("severity")).toBe("high");
    expect(calls[0].url.searchParams.get("kev")).toBe("true");
    expect(calls[0].url.searchParams.has("q")).toBe(false);
    await c.getScan("a/b");
    expect(calls[1].url.pathname).toBe("/v1/scans/a%2Fb");
  });

  it("posts JSON bodies and handles 204", async () => {
    const { c, calls } = client({
      "POST /v1/scope": () => json(201, { id: 7 }),
      "DELETE /v1/owners/o1": () => new Response(null, { status: 204 }),
    });
    const out = await c.addScope({ kind: "domain", value: "example.com", added_by: "me" });
    expect(out.id).toBe(7);
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ kind: "domain", value: "example.com", added_by: "me" });
    expect(await c.deleteOwner("o1")).toBeUndefined();
  });

  it("retries idempotent requests on 503 and gives up", async () => {
    const { c, calls, sleeps } = client({ "GET /v1/scope": [json(503, {}), json(503, {}), json(200, [])] });
    expect(await c.listScope()).toEqual([]);
    expect(calls.length).toBe(3);
    expect(sleeps.length).toBe(2);

    const bad = client({ "GET /v1/scope": [json(502, { detail: "bad gateway" })] });
    await expect(bad.c.listScope()).rejects.toBeInstanceOf(ServerError);
    expect(bad.calls.length).toBe(3);
  });

  it("does not retry POST on 5xx but honours 429 Retry-After", async () => {
    const a = client({ "POST /v1/scans": [json(503, {})] });
    await expect(a.c.createScan({ kind: "passive", target: "example.com" })).rejects.toBeInstanceOf(ServerError);
    expect(a.calls.length).toBe(1);
    const b = client({ "POST /v1/scans": [json(429, {}, { "retry-after": "2" }), json(201, { id: "s1" })] });
    const s = await b.c.createScan({ kind: "passive", target: "example.com" });
    expect(s.id).toBe("s1");
    expect(b.sleeps).toEqual([2000]);
  });

  it("wraps network failures", async () => {
    const c = new PaddockClient({
      fetch: (async () => {
        throw new TypeError("fetch failed");
      }) as unknown as typeof fetch,
      retry: { maxRetries: 1 },
      sleep: async () => {},
    });
    await expect(c.listScope()).rejects.toBeInstanceOf(TransportError);
  });

  it.each([
    [402, FeatureNotLicensed],
    [403, PermissionDenied],
    [404, NotFound],
    [422, UnprocessableEntity],
  ])("maps HTTP %i to a typed error", async (status, Err) => {
    const { c } = client({ "GET /v1/license": [json(status, { detail: { error: "x" } }, { "x-request-id": "rid" })] });
    const err = await c.getLicense().catch((e) => e);
    expect(err).toBeInstanceOf(Err);
    expect(err.status).toBe(status);
    expect(err.requestId).toBe("rid");
  });

  it("paginates page objects and bare arrays", async () => {
    const all = Array.from({ length: 5 }, (_, i) => ({ id: String(i) }));
    const { c, calls } = client({
      "GET /v1/findings": (url: URL) => {
        const off = Number(url.searchParams.get("offset"));
        const lim = Number(url.searchParams.get("limit"));
        return json(200, { items: all.slice(off, off + lim), total: all.length, limit: lim, offset: off });
      },
      "GET /v1/scope": (url: URL) => {
        const off = Number(url.searchParams.get("offset"));
        const lim = Number(url.searchParams.get("limit"));
        return json(200, all.slice(off, off + lim));
      },
    });
    const got: FindingOut[] = [];
    for await (const f of c.paginate((q) => c.listFindingsPaged({ ...q, severity: "critical" }), { pageSize: 2 })) {
      got.push(f);
    }
    expect(got.map((f) => f.id)).toEqual(["0", "1", "2", "3", "4"]);
    expect(calls.length).toBe(3);
    const scope = [];
    for await (const s of c.paginate((q) => c.listScope(q), { pageSize: 2, maxItems: 3 })) scope.push(s);
    expect(scope.length).toBe(3);
  });

  it("reports deprecated operations once", async () => {
    const onDeprecation = vi.fn();
    const { c } = client(
      { "GET /v1/findings/list": [json(200, [], { deprecation: "true", sunset: "Wed, 30 Jun 2027 00:00:00 GMT" })] },
      { onDeprecation },
    );
    await c.listFindingsLegacy();
    await c.listFindingsLegacy();
    expect(onDeprecation).toHaveBeenCalledTimes(1);
    expect(onDeprecation.mock.calls[0][0].sunset).toContain("2027");
  });

  it("explains endpoints missing on older servers", async () => {
    const { c } = client({});
    await expect(c.exportFormat("sarif")).rejects.toThrow(/does not provide sarif export/);
    await expect(c.integrationsList()).rejects.toThrow(/does not provide integrations/);
  });

  it("logs in with a password and switches to the JWT", async () => {
    const { c, calls } = client({
      "POST /v1/auth/login": { access_token: "eyJ.new", expires_in: 3600, role: "admin", clearance: "restricted" },
      "GET /v1/auth/me": { actor: "admin" },
    });
    await c.loginWithPassword("admin", "pw");
    await c.me();
    expect((calls[1].init.headers as Record<string, string>).Authorization).toBe("Bearer eyJ.new");
  });

  it("bounds the backoff", () => {
    for (let i = 0; i < 8; i++) expect(retryDelayMs(DEFAULT_RETRY, i, null)).toBeLessThanOrEqual(DEFAULT_RETRY.maxBackoffMs);
    expect(retryDelayMs(DEFAULT_RETRY, 0, "1")).toBe(1000);
  });

  it("exposes one method per operation", () => {
    for (const [name, [method, path]] of Object.entries(OPERATIONS)) {
      expect(typeof (PaddockClient.prototype as unknown as Record<string, unknown>)[name], `${method} ${path}`).toBe(
        "function",
      );
    }
  });

  it("generated code is current", () => {
    execFileSync(process.execPath, [resolve(HERE, "..", "scripts", "codegen.mjs"), "--check"], { stdio: "pipe" });
  });
});
