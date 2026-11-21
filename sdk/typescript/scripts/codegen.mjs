#!/usr/bin/env node
// Generate src/generated.ts from docs/api/openapi.json.
//
//   node scripts/codegen.mjs           # regenerate
//   node scripts/codegen.mjs --check   # exit 1 when src/generated.ts is stale
//
// Small and dependency-free on purpose: every components.schema becomes an
// interface, every operation a typed method on GeneratedOperations that calls
// the hand-written core (src/client.ts). Output is deterministic.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..", "..");
const SPEC = resolve(ROOT, "docs", "api", "openapi.json");
const OUT = resolve(HERE, "..", "src", "generated.ts");
const METHODS = ["get", "post", "put", "patch", "delete"];
const RESERVED = new Set(["delete", "export", "import", "default", "function", "class", "new", "in", "for", "if"]);

const ident = (s) => {
  let out = s.replace(/\W+/g, "_").replace(/^_+|_+$/g, "") || "x";
  if (/^\d/.test(out)) out = "_" + out;
  return out;
};
const camel = (s) => {
  const parts = ident(s).split("_").filter(Boolean);
  let out = parts.map((p, i) => (i === 0 ? p.toLowerCase() : p[0].toUpperCase() + p.slice(1))).join("");
  if (RESERVED.has(out)) out += "_";
  return out;
};
const typeName = (ref) => ident(ref.split("/").pop());
const propKey = (k) => (/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k));
const lit = (v) => JSON.stringify(v);

function tsType(s) {
  if (!s || Object.keys(s).length === 0) return "unknown";
  if (s.$ref) return typeName(s.$ref);
  if ("const" in s) return lit(s.const);
  if (s.enum) return s.enum.map(lit).join(" | ");
  for (const k of ["anyOf", "oneOf"]) {
    if (s[k]) {
      const parts = [];
      for (const sub of s[k]) {
        const t = tsType(sub);
        if (!parts.includes(t)) parts.push(t);
      }
      return parts.map((p) => (p.includes("|") && !p.startsWith("(") ? `(${p})` : p)).join(" | ");
    }
  }
  if (s.allOf && s.allOf.length === 1) return tsType(s.allOf[0]);
  switch (s.type) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "null":
      return "null";
    case "array": {
      const inner = tsType(s.items || {});
      return /[|&]/.test(inner) ? `Array<${inner}>` : `${inner}[]`;
    }
  }
  if (s.type === "object" || s.properties || s.additionalProperties) {
    const ap = s.additionalProperties;
    if (ap && typeof ap === "object" && Object.keys(ap).length) return `Record<string, ${tsType(ap)}>`;
    return "Record<string, unknown>";
  }
  return "unknown";
}

function stripSuffix(opId, path, method) {
  const suffix = path.replace(/\W/g, "_") + "_" + method;
  if (opId.endsWith(suffix) && opId.length > suffix.length) return opId.slice(0, -suffix.length).replace(/_+$/, "");
  return opId;
}

const jsonSchema = (c) => (c && c.content && c.content["application/json"] ? c.content["application/json"].schema || {} : null);
const comment = (lines, indent = "") =>
  [`${indent}/**`, ...lines.map((l) => `${indent} * ${l.replace(/\*\//g, "*\\/")}`.trimEnd()), `${indent} */`];

function collect(spec) {
  const ops = [];
  const used = new Set();
  for (const path of Object.keys(spec.paths || {}).sort()) {
    const item = spec.paths[path];
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const base = camel(stripSuffix(op.operationId || `${method}_${path}`, path, method));
      let name = base;
      if (used.has(name)) {
        name = base + camel("_" + ((op.tags || ["x"])[0] || "x")).replace(/^./, (c) => c.toUpperCase());
        let i = 2;
        while (used.has(name)) name = `${base}${i++}`;
      }
      used.add(name);
      const params = [...(item.parameters || []), ...(op.parameters || [])];
      const ok = Object.keys(op.responses || {}).filter((c) => c.startsWith("2")).sort();
      const noContent = ok[0] === "204";
      const body = op.requestBody;
      ops.push({
        name,
        method: method.toUpperCase(),
        path,
        summary: op.summary || "",
        description: (op.description || "").trim(),
        deprecated: !!op.deprecated,
        pathParams: params.filter((p) => p.in === "path"),
        queryParams: params.filter((p) => p.in === "query"),
        body: body ? jsonSchema(body) : null,
        bodyRequired: !!(body && body.required),
        returns: ok.length && !noContent ? jsonSchema(op.responses[ok[0]]) : null,
        noContent,
        paginated: ["limit", "offset"].every((n) => params.some((p) => p.in === "query" && p.name === n)),
      });
    }
  }
  return ops;
}

function genModels(spec) {
  const out = [];
  const schemas = (spec.components && spec.components.schemas) || {};
  for (const name of Object.keys(schemas).sort()) {
    const s = schemas[name];
    const req = new Set(s.required || []);
    if (s.description) out.push(...comment(s.description.trim().split("\n").slice(0, 8)));
    if (s.type === "object" || s.properties) {
      out.push(`export interface ${ident(name)} {`);
      for (const [k, v] of Object.entries(s.properties || {})) {
        if (v.description) out.push(...comment([v.description.trim().split("\n")[0]], "  "));
        out.push(`  ${propKey(k)}${req.has(k) ? "" : "?"}: ${tsType(v)};`);
      }
      if (!s.properties && s.additionalProperties) out.push(`  [key: string]: unknown;`);
      out.push("}", "");
    } else {
      out.push(`export type ${ident(name)} = ${tsType(s)};`, "");
    }
  }
  return out;
}

function genOperations(ops) {
  const out = [
    "/** One typed method per API operation (generated). */",
    "export abstract class GeneratedOperations {",
    "  protected abstract _request<T>(method: string, path: string, opts: OperationRequest): Promise<T>;",
    "",
  ];
  for (const op of ops) {
    const args = [];
    for (const p of op.pathParams) args.push(`${camel(p.name)}: ${tsType(p.schema || {})}`);
    if (op.body) {
      const bt = tsType(op.body);
      args.push(op.bodyRequired ? `body: ${bt}` : `body?: ${bt}`);
    }
    if (op.queryParams.length) {
      const fields = op.queryParams.map((p) => `${propKey(p.name)}${p.required ? "" : "?"}: ${tsType(p.schema || {})}`);
      const anyRequired = op.queryParams.some((p) => p.required);
      args.push(`query${anyRequired ? "" : "?"}: { ${fields.join("; ")} }`);
    }
    args.push("options?: RequestOptions");
    const ret = op.noContent ? "void" : op.returns ? tsType(op.returns) : "unknown";
    const doc = [`${op.method} ${op.path}${op.summary ? " — " + op.summary : ""}`];
    if (op.deprecated) doc.push("", "@deprecated See the Sunset/Link response headers for the successor.");
    if (op.description) doc.push("", ...op.description.split("\n").slice(0, 12));
    out.push(...comment(doc, "  "));
    out.push(`  ${op.name}(${args.join(", ")}): Promise<${ret}> {`);
    const parts = [];
    if (op.pathParams.length) parts.push(`pathParams: { ${op.pathParams.map((p) => `${propKey(p.name)}: ${camel(p.name)}`).join(", ")} }`);
    if (op.queryParams.length) parts.push("query");
    if (op.body) parts.push("body");
    parts.push("options");
    out.push(`    return this._request<${ret}>(${lit(op.method)}, ${lit(op.path)}, { ${parts.join(", ")} });`);
    out.push("  }", "");
  }
  out.push("}", "");
  return out;
}

function genIndex(ops) {
  const out = ["/** name -> [method, path, paginated] */", "export const OPERATIONS = {"];
  for (const op of ops) out.push(`  ${op.name}: [${lit(op.method)}, ${lit(op.path)}, ${op.paginated}],`);
  out.push("} as const;", "", "export type OperationName = keyof typeof OPERATIONS;", "");
  return out;
}

export function generate(spec) {
  const ops = collect(spec);
  const info = spec.info || {};
  const head = [
    "/* eslint-disable */",
    "// GENERATED by sdk/typescript/scripts/codegen.mjs from docs/api/openapi.json -- DO NOT EDIT.",
    "",
    "export const API_TITLE = " + lit(info.title || "") + ";",
    "export const API_VERSION = " + lit(info.version || "") + ";",
    "",
    "/** Per-call options accepted by every operation. */",
    "export interface RequestOptions {",
    "  signal?: AbortSignal;",
    "  headers?: Record<string, string>;",
    "}",
    "",
    "export interface OperationRequest {",
    "  pathParams?: Record<string, string | number>;",
    "  query?: Record<string, unknown>;",
    "  body?: unknown;",
    "  options?: RequestOptions;",
    "}",
    "",
  ];
  return [...head, ...genModels(spec), ...genIndex(ops), ...genOperations(ops)].join("\n").trimEnd() + "\n";
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const check = process.argv.includes("--check");
  const spec = JSON.parse(readFileSync(SPEC, "utf8"));
  const text = generate(spec);
  if (check) {
    if (existsSync(OUT) && readFileSync(OUT, "utf8") === text) {
      console.log("OK: typescript SDK is up to date");
    } else {
      console.error("ERROR: sdk/typescript/src/generated.ts is stale; run `make api-regen`");
      process.exit(1);
    }
  } else {
    writeFileSync(OUT, text);
    console.log(`wrote ${OUT} (${collect(spec).length} operations)`);
  }
}
