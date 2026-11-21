// Hand-written transport core for @paddock/sdk: auth, retries, errors,
// pagination. Generated operations (./generated.ts) only call _request().
import { GeneratedOperations, OPERATIONS, type OperationRequest, type RequestOptions } from "./generated.js";

export const SDK_VERSION = "0.1.0";

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

export class PaddockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The server could not be reached (DNS, connect, timeout, abort). */
export class TransportError extends PaddockError {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
  }
}

/** The server answered with a non-2xx status. */
export class APIError extends PaddockError {
  constructor(
    readonly status: number,
    readonly detail: unknown,
    readonly method: string,
    readonly url: string,
    readonly requestId: string | null = null,
  ) {
    const msg =
      typeof detail === "string"
        ? detail
        : detail && typeof detail === "object" && "error" in detail
          ? String((detail as { error: unknown }).error)
          : JSON.stringify(detail);
    super(`${method} ${url} -> HTTP ${status}: ${msg}`);
  }
}
export class AuthenticationError extends APIError {}
export class FeatureNotLicensed extends APIError {}
export class PermissionDenied extends APIError {}
export class NotFound extends APIError {}
export class Conflict extends APIError {}
/** 422: request failed validation (named to avoid clashing with the generated `ValidationError` model). */
export class UnprocessableEntity extends APIError {}
export class RateLimited extends APIError {}
export class ServerError extends APIError {}

const STATUS_ERRORS: Record<number, typeof APIError> = {
  401: AuthenticationError,
  402: FeatureNotLicensed,
  403: PermissionDenied,
  404: NotFound,
  409: Conflict,
  422: UnprocessableEntity,
  429: RateLimited,
};

export function errorFor(status: number): typeof APIError {
  return STATUS_ERRORS[status] ?? (status >= 500 ? ServerError : APIError);
}

// --------------------------------------------------------------------------
// Retries
// --------------------------------------------------------------------------

export interface RetryPolicy {
  maxRetries: number;
  backoffMs: number;
  maxBackoffMs: number;
  retryStatuses: number[];
  idempotentMethods: string[];
}

export const DEFAULT_RETRY: RetryPolicy = {
  maxRetries: 3,
  backoffMs: 500,
  maxBackoffMs: 10_000,
  retryStatuses: [429, 502, 503, 504],
  idempotentMethods: ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"],
};

export function shouldRetry(p: RetryPolicy, method: string, attempt: number, status: number | null): boolean {
  if (attempt >= p.maxRetries) return false;
  if (status === null) return p.idempotentMethods.includes(method);
  if (status === 429) return true;
  return p.retryStatuses.includes(status) && p.idempotentMethods.includes(method);
}

export function retryDelayMs(p: RetryPolicy, attempt: number, retryAfter: string | null): number {
  if (retryAfter) {
    const secs = Number(retryAfter);
    if (Number.isFinite(secs)) return Math.min(p.maxBackoffMs, Math.max(0, secs * 1000));
    const when = Date.parse(retryAfter);
    if (!Number.isNaN(when)) return Math.min(p.maxBackoffMs, Math.max(0, when - Date.now()));
  }
  return Math.random() * Math.min(p.maxBackoffMs, p.backoffMs * 2 ** attempt);
}

// --------------------------------------------------------------------------
// Client
// --------------------------------------------------------------------------

export interface ClientOptions {
  /** e.g. https://paddock.internal (default http://localhost:8080) */
  baseUrl?: string;
  /** `pak_...` API key (sent as `Authorization: Bearer`). */
  apiKey?: string;
  /** JWT from /v1/auth/login. */
  token?: string;
  fetch?: typeof fetch;
  retry?: Partial<RetryPolicy>;
  timeoutMs?: number;
  headers?: Record<string, string>;
  /** Called once per deprecated operation the client touches. */
  onDeprecation?: (info: { method: string; path: string; sunset: string | null; link: string | null }) => void;
  /** Injected for tests. */
  sleep?: (ms: number) => Promise<void>;
}

type Page<T> = { items: T[]; total?: number };
type PageLike<T> = T[] | Page<T>;
type ItemOf<R> = R extends Array<infer U> ? U : R extends { items: Array<infer U> } ? U : never;

export class PaddockClient extends GeneratedOperations {
  readonly baseUrl: string;
  apiKey?: string;
  token?: string;
  readonly retry: RetryPolicy;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly extraHeaders: Record<string, string>;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly onDeprecation: NonNullable<ClientOptions["onDeprecation"]>;
  private readonly warned = new Set<string>();

  static readonly OPERATIONS = OPERATIONS;

  constructor(opts: ClientOptions = {}) {
    super();
    this.baseUrl = (opts.baseUrl ?? "http://localhost:8080").replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.token = opts.token;
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    const f = opts.fetch ?? globalThis.fetch;
    if (!f) throw new PaddockError("no fetch implementation available; pass options.fetch");
    this.fetchImpl = f.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.extraHeaders = opts.headers ?? {};
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.onDeprecation =
      opts.onDeprecation ??
      ((i) => console.warn(`[paddock] ${i.method} ${i.path} is deprecated${i.sunset ? `; sunset ${i.sunset}` : ""}`));
  }

  /** Exchange username/password for a JWT and use it for later calls. */
  async loginWithPassword(username: string, password: string) {
    const out = await this.login({ username, password });
    this.token = out.access_token;
    this.apiKey = undefined;
    return out;
  }

  protected _request<T>(method: string, path: string, req: OperationRequest): Promise<T> {
    let url = path;
    for (const [k, v] of Object.entries(req.pathParams ?? {})) {
      url = url.replace(`{${k}}`, encodeURIComponent(String(v)));
    }
    return this.request<T>(method, url, { query: req.query, body: req.body, ...req.options });
  }

  /** Low-level request with auth + retries. Returns parsed JSON, text, or undefined for 204. */
  async request<T = unknown>(
    method: string,
    path: string,
    opts: RequestOptions & { query?: Record<string, unknown>; body?: unknown } = {},
  ): Promise<T> {
    method = method.toUpperCase();
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) v.forEach((x) => qs.append(k, String(x)));
      else qs.append(k, String(v));
    }
    const qstr = qs.toString();
    const url = `${this.baseUrl}${path}${qstr ? `?${qstr}` : ""}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": `paddock-sdk-ts/${SDK_VERSION}`,
      ...this.extraHeaders,
      ...(opts.headers ?? {}),
    };
    const cred = this.apiKey ?? this.token;
    if (cred) headers.Authorization = `Bearer ${cred}`;
    let payload: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }

    let attempt = 0;
    let resp: Response;
    for (;;) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      const onAbort = () => ctrl.abort();
      opts.signal?.addEventListener("abort", onAbort);
      try {
        resp = await this.fetchImpl(url, { method, headers, body: payload, signal: ctrl.signal });
      } catch (err) {
        if (!opts.signal?.aborted && shouldRetry(this.retry, method, attempt, null)) {
          await this.sleep(retryDelayMs(this.retry, attempt, null));
          attempt++;
          continue;
        }
        throw new TransportError(`${method} ${url}: ${String(err)}`, err);
      } finally {
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
      }
      if (resp.status >= 400 && shouldRetry(this.retry, method, attempt, resp.status)) {
        await this.sleep(retryDelayMs(this.retry, attempt, resp.headers.get("retry-after")));
        attempt++;
        continue;
      }
      break;
    }

    this.noteDeprecation(method, path, resp);
    const text = await resp.text();
    const isJson = (resp.headers.get("content-type") ?? "").includes("json");
    if (resp.status >= 400) {
      let detail: unknown = text;
      if (isJson && text) {
        try {
          const parsed = JSON.parse(text);
          detail = parsed && typeof parsed === "object" && "detail" in parsed ? parsed.detail : parsed;
        } catch {
          /* keep raw text */
        }
      }
      const Err = errorFor(resp.status);
      throw new Err(resp.status, detail, method, path, resp.headers.get("x-request-id"));
    }
    if (resp.status === 204 || !text) return undefined as T;
    return (isJson ? JSON.parse(text) : text) as T;
  }

  private noteDeprecation(method: string, path: string, resp: Response) {
    if (!resp.headers.get("deprecation")) return;
    const key = `${method} ${path}`;
    if (this.warned.has(key)) return;
    this.warned.add(key);
    this.onDeprecation({ method, path, sunset: resp.headers.get("sunset"), link: resp.headers.get("link") });
  }

  /**
   * Iterate every item of a limit/offset operation, for both response shapes
   * the API uses (a page object `{items,total}` or a bare array).
   *
   *   for await (const f of client.paginate((q) => client.listFindingsPaged({ ...q, severity: "critical" }))) {}
   */
  async *paginate<R extends PageLike<unknown>>(
    fetchPage: (q: { limit: number; offset: number }) => Promise<R>,
    opts: { pageSize?: number; maxItems?: number; offset?: number } = {},
  ): AsyncGenerator<ItemOf<R>> {
    const pageSize = opts.pageSize ?? 100;
    let offset = opts.offset ?? 0;
    let seen = 0;
    for (;;) {
      const page = await fetchPage({ limit: pageSize, offset });
      const items = (Array.isArray(page) ? page : (page as Page<unknown>).items ?? []) as ItemOf<R>[];
      const total = Array.isArray(page) ? undefined : (page as Page<unknown>).total;
      for (const it of items) {
        yield it;
        if (opts.maxItems !== undefined && ++seen >= opts.maxItems) return;
      }
      offset += items.length;
      if (!items.length || items.length < pageSize || (total !== undefined && offset >= total)) return;
    }
  }

  // ---- endpoints newer than some servers ---------------------------------

  private async optional<T>(method: string, path: string, feature: string, query?: Record<string, unknown>) {
    try {
      return await this.request<T>(method, path, { query });
    } catch (e) {
      if (e instanceof NotFound && (e.detail === "Not Found" || !e.detail)) {
        throw new NotFound(404, `this Paddock server does not provide ${feature} (${method} ${path}); upgrade the server`, method, path);
      }
      throw e;
    }
  }

  /** GET /v1/export/{format} — SARIF / SBOM / OCSF. */
  exportFormat(format: "sarif" | "sbom" | "ocsf" | string, query?: Record<string, unknown>) {
    return this.optional<unknown>("GET", `/v1/export/${encodeURIComponent(format)}`, `${format} export`, query);
  }

  /** GET /v1/integrations. */
  integrationsList(query?: Record<string, unknown>) {
    return this.optional<unknown>("GET", "/v1/integrations", "integrations", query);
  }
}
