/**
 * Ready-made "connect anything" snippets. Pure functions (unit-tested).
 *
 * Snippets reference the token through an environment variable / CI secret and
 * never inline it, so a copied snippet is safe to paste into a repository. The
 * one-time reveal in the UI shows the real token separately.
 */

export type SnippetKind =
  | "curl" | "github" | "gitlab" | "python" | "typescript" | "mcp-claude" | "mcp-cursor";

export const SNIPPET_LABEL: Record<SnippetKind, string> = {
  curl: "curl",
  github: "GitHub Actions",
  gitlab: "GitLab CI",
  python: "Python",
  typescript: "TypeScript",
  "mcp-claude": "MCP: Claude Desktop",
  "mcp-cursor": "MCP: Cursor",
};

export const SNIPPET_ORDER: SnippetKind[] = [
  "curl", "github", "gitlab", "python", "typescript", "mcp-claude", "mcp-cursor",
];

export interface SnippetCtx {
  /** Origin that serves /v1 (the dashboard proxy or the orchestrator). */
  baseUrl: string;
  /** Source name, for the label only. */
  source?: string;
  /** Optional project / repository the results belong to. */
  project?: string;
}

/** Trim and strip a trailing slash; keeps an http(s) URL or falls back to a placeholder. */
export function cleanBase(url: string): string {
  const u = (url || "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^\s'"`$\\]+$/.test(u) ? u : "https://paddock.example.com";
}

/** Shell-safe single-quoted literal. */
function sq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function ingestUrl(ctx: SnippetCtx): string {
  const base = `${cleanBase(ctx.baseUrl)}/v1/ingest`;
  return ctx.project ? `${base}?project=${encodeURIComponent(ctx.project)}` : base;
}

export function snippetFor(kind: SnippetKind, ctx: SnippetCtx): string {
  const base = cleanBase(ctx.baseUrl);
  const url = ingestUrl(ctx);
  switch (kind) {
    case "curl":
      return [
        `# any scanner output: SARIF, CycloneDX, SPDX, OCSF, Trivy, Grype, Semgrep, Nuclei, ZAP, CSV`,
        `export PADDOCK_INGEST_TOKEN=<token from this page>`,
        `curl -fsS -X POST ${sq(url)} \\`,
        `  -H "X-Paddock-Ingest-Token: $PADDOCK_INGEST_TOKEN" \\`,
        `  -H "Content-Type: application/octet-stream" \\`,
        `  --data-binary @report.json`,
      ].join("\n");
    case "github":
      return [
        `# Settings > Secrets and variables > Actions: add PADDOCK_INGEST_TOKEN`,
        `- name: Scan`,
        `  run: trivy fs --quiet --format json --output trivy.json .`,
        `- name: Send to Paddock`,
        `  env:`,
        `    PADDOCK_INGEST_TOKEN: \${{ secrets.PADDOCK_INGEST_TOKEN }}`,
        `  run: |`,
        `    curl -fsS -X POST ${sq(ctx.project ? url : `${url}?project=\${GITHUB_REPOSITORY}`).replace(/^'|'$/g, '"')} \\`,
        `      -H "X-Paddock-Ingest-Token: $PADDOCK_INGEST_TOKEN" \\`,
        `      --data-binary @trivy.json`,
      ].join("\n");
    case "gitlab":
      return [
        `# CI/CD variables: PADDOCK_INGEST_TOKEN (masked)`,
        `paddock:`,
        `  image: { name: aquasec/trivy:0.58.1, entrypoint: [""] }`,
        `  script:`,
        `    - apk add --no-cache -q curl`,
        `    - trivy fs --quiet --format json --output trivy.json .`,
        `    - >-`,
        `      curl -fsS -X POST "${ctx.project ? url : `${url}?project=\${CI_PROJECT_PATH}`}"`,
        `      -H "X-Paddock-Ingest-Token: $PADDOCK_INGEST_TOKEN"`,
        `      --data-binary @trivy.json`,
      ].join("\n");
    case "python":
      return [
        `import os, httpx`,
        ``,
        `r = httpx.post(`,
        `    "${url}",`,
        `    headers={"X-Paddock-Ingest-Token": os.environ["PADDOCK_INGEST_TOKEN"]},`,
        `    content=open("report.json", "rb").read(),`,
        `    timeout=120,`,
        `)`,
        `r.raise_for_status()`,
        `print(r.json())  # {"format": "...", "findings_new": N, "findings_updated": M, ...}`,
      ].join("\n");
    case "typescript":
      return [
        `import { readFile } from "node:fs/promises";`,
        ``,
        `const res = await fetch("${url}", {`,
        `  method: "POST",`,
        `  headers: { "X-Paddock-Ingest-Token": process.env.PADDOCK_INGEST_TOKEN! },`,
        `  body: await readFile("report.json"),`,
        `});`,
        `if (!res.ok) throw new Error(\`ingest failed: \${res.status} \${await res.text()}\`);`,
        `console.log(await res.json());`,
      ].join("\n");
    case "mcp-claude":
      return JSON.stringify(mcpConfig(base), null, 2);
    case "mcp-cursor":
      return JSON.stringify(mcpConfig(base), null, 2);
  }
}

export function mcpConfig(baseUrl: string): { mcpServers: Record<string, unknown> } {
  return {
    mcpServers: {
      paddock: {
        command: "paddock-mcp",
        env: {
          PADDOCK_URL: cleanBase(baseUrl),
          PADDOCK_API_KEY: "<a read-only Paddock API key>",
        },
      },
    },
  };
}

/** Where each snippet goes, one line of guidance shown under it. */
export const SNIPPET_HINT: Record<SnippetKind, string> = {
  curl: "Works from any shell or cron job. Gzip the body and add Content-Encoding: gzip for large reports.",
  github: "Add the token as a repository secret; the snippet never contains it.",
  gitlab: "Add PADDOCK_INGEST_TOKEN as a masked CI/CD variable.",
  python: "Needs httpx (pip install httpx).",
  typescript: "Node 18+ (global fetch).",
  "mcp-claude": "pip install paddock-mcp, then paste into claude_desktop_config.json. Read-only unless you add --allow-write.",
  "mcp-cursor": "pip install paddock-mcp, then paste into .cursor/mcp.json (or ~/.cursor/mcp.json).",
};
