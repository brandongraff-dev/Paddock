import { apiFetch } from "./client";
import type { AskResult, FindingCluster } from "./types";

/**
 * NL-query + triage-cluster read endpoints (contract §E / §C). The orchestrator
 * proxies POST /v1/ask to the brain service, whose engine validates the SQL
 * (single read-only SELECT over three allow-listed views) before executing it.
 * When the brain is down the orchestrator degrades to {ok:false, note}.
 */

/** POST /v1/ask — translate a question to a validated read-only SELECT. */
export function ask(question: string): Promise<AskResult> {
  return apiFetch<AskResult>("/v1/ask", { method: "POST", body: { question } }).then((r) => ({
    ok: !!r?.ok,
    columns: r?.columns ?? [],
    rows: r?.rows ?? [],
    generated_sql: r?.generated_sql ?? "",
    engine: r?.engine ?? "unavailable",
    note: r?.note ?? null,
    error: r?.error ?? null,
  }));
}

/** GET /v1/clusters — LLM/template triage clusters over open findings. */
export function listClusters(): Promise<FindingCluster[]> {
  return apiFetch<{ items: FindingCluster[] } | FindingCluster[]>("/v1/clusters").then((r) =>
    Array.isArray(r) ? r : r.items ?? [],
  );
}
