/**
 * Wargame sample estate: the "60-minute aha" scene from docs/WARGAME.md §5
 * (guest Wi-Fi → a smart fridge → the POS controller → the payment database),
 * shaped exactly like the orchestrator's /v1/wargame/* responses.
 *
 * Only used when the viewer explicitly opens sample mode (?sample=1); the page
 * labels every screen of it as sample data. It is never a fallback for a
 * failed or empty API call: showing invented routes as if they were the
 * customer's would break the one promise Wargame makes.
 */

import type {
  WargameAssessment,
  WargameBoundary,
  WargameCertificate,
  WargameChangeImpact,
  WargameFixSet,
  WargameRoute,
  WargameTwinSummary,
} from "../api/types";

const HOUR = 3_600_000;

export interface WargameSample {
  twin: WargameTwinSummary;
  assessments: WargameAssessment[];
  routes: WargameRoute[];
  boundaries: WargameBoundary[];
  certificates: WargameCertificate[];
  fixSet: WargameFixSet;
}

export function buildWargameSample(now = Date.now()): WargameSample {
  const iso = (ms: number) => new Date(ms).toISOString();
  const assessment: WargameAssessment = {
    id: "00000000-0000-4000-8000-0000000000a1",
    label: "Sample estate: 3 firewalls + 1 AWS account",
    crownjewel_total: 8,
    crownjewel_open: 3,
    crownjewel_closed: 4,
    crownjewel_conditional: 1,
    closure_pct: 50,
    coverage_pct: 62,
    false_closed_rate: null,
    board_line:
      "50% of routes to crown jewels are proved closed, over a model explaining 62% of observed traffic; 3 routes remain open.",
    blind_spots: [
      "No sensor on the PHI segment: closure there is absence of evidence only",
      "Kubernetes NetworkPolicy on cluster prod-east is not modelled",
    ],
    computed_at: iso(now - 40 * 60_000),
    metadata: { source: "twin" },
  };
  const older: WargameAssessment = {
    ...assessment,
    id: "00000000-0000-4000-8000-0000000000a0",
    label: "Sample estate: first import",
    crownjewel_open: 5,
    crownjewel_closed: 2,
    crownjewel_conditional: 1,
    closure_pct: 25,
    coverage_pct: null,
    board_line:
      "25% of routes to crown jewels are proved closed, over a model whose coverage is not yet measured; 5 routes remain open.",
    computed_at: iso(now - 26 * HOUR),
  };

  const routes: WargameRoute[] = [
    {
      id: "r-guest-pay",
      entry: "guest_wifi",
      jewel: "payments_db",
      length: 3,
      weakest_label: "proved_config",
      fingerprint: "5f1c0a9e7d24b3c8a1e6f0d2b9c47a3e8d1f6b2c0a9e7d24b3c8a1e6f0d2b9c4",
      hops: [
        { src: "guest_wifi", dst: "fridge", labels: ["observed"], port: null, rule_ref: null, fix_candidate_ids: ["seg:guest->corp"] },
        { src: "fridge", dst: "pos", labels: ["proved_config", "observed"], port: "tcp/8080", rule_ref: "fw_pos/allow_fridge_pos", fix_candidate_ids: ["fw_pos:allow_fridge_pos"] },
        { src: "pos", dst: "payments_db", labels: ["proved_config", "tested_probe"], port: "tcp/5432", rule_ref: "sg-db/allow_pos", fix_candidate_ids: ["sg-db:allow_pos"] },
      ],
    },
    {
      id: "r-vendor-pay",
      entry: "vendor_vpn",
      jewel: "payments_db",
      length: 2,
      weakest_label: "inferred",
      fingerprint: "a73e19c40b5d82f6e1a0c3b7d94e2f58a73e19c40b5d82f6e1a0c3b7d94e2f58",
      hops: [
        { src: "vendor_vpn", dst: "pos", labels: ["inferred"], port: "tcp/3389", rule_ref: "identity/shared_admin_credential", fix_candidate_ids: ["identity:vendor_vpn->pos"] },
        { src: "pos", dst: "payments_db", labels: ["proved_config", "tested_probe"], port: "tcp/5432", rule_ref: "sg-db/allow_pos", fix_candidate_ids: ["sg-db:allow_pos"] },
      ],
    },
    {
      id: "r-net-pay",
      entry: "internet",
      jewel: "payments_db",
      length: 3,
      weakest_label: "conditional",
      fingerprint: "c2d9b4f70e1a6385d2c9b4f70e1a6385d2c9b4f70e1a6385d2c9b4f70e1a6385",
      hops: [
        { src: "internet", dst: "web_lb", labels: ["tested_probe", "proved_config"], port: "tcp/443", rule_ref: "sg-edge/allow_https", fix_candidate_ids: [] },
        { src: "web_lb", dst: "app_api", labels: ["observed"], port: "tcp/8443", rule_ref: "sg-app/allow_lb", fix_candidate_ids: [] },
        { src: "app_api", dst: "payments_db", labels: ["conditional"], port: "tcp/5432", rule_ref: "fw_db/appid_postgres", fix_candidate_ids: ["fw_db:appid_postgres"] },
      ],
    },
    {
      id: "r-guest-phi",
      entry: "guest_wifi",
      jewel: "phi_store",
      length: 3,
      weakest_label: "unknown",
      fingerprint: "e84f2a6c19b07d35e84f2a6c19b07d35e84f2a6c19b07d35e84f2a6c19b07d35",
      hops: [
        { src: "guest_wifi", dst: "fridge", labels: ["observed"], port: null, rule_ref: null, fix_candidate_ids: [] },
        { src: "fridge", dst: "lab_printer", labels: ["inferred"], port: "tcp/9100", rule_ref: null, fix_candidate_ids: [] },
        { src: "lab_printer", dst: "phi_store", labels: ["unknown"], port: "tcp/445", rule_ref: null, fix_candidate_ids: [] },
      ],
    },
  ];

  const boundaries: WargameBoundary[] = [
    {
      id: "b1",
      boundary_src: "guest_wifi",
      boundary_dst: "payments_db",
      port: "tcp/5432",
      verdict: "fail_open",
      disagreements: ["config says open via fridge → pos", "probe crossed pos → payments_db"],
      note: "Config and probe agree the boundary is open; observed traffic reaches the fridge.",
    },
    {
      id: "b2",
      boundary_src: "internet",
      boundary_dst: "payments_db",
      port: "tcp/5432",
      verdict: "conditional",
      disagreements: [],
      note: "Closure rests on App-ID rule fw_db/appid_postgres, which config can't prove.",
    },
    {
      id: "b3",
      boundary_src: "clinic_wifi",
      boundary_dst: "payments_db",
      port: "any",
      verdict: "pass",
      disagreements: [],
      note: "Config denies, probe was blocked, no crossing seen in 30 days.",
    },
    {
      id: "b4",
      boundary_src: "clinic_wifi",
      boundary_dst: "phi_store",
      port: "tcp/443",
      verdict: "proved_config",
      disagreements: [],
      note: "Config denies; no probe agent on the clinic segment yet.",
    },
    {
      id: "b5",
      boundary_src: "vendor_vpn",
      boundary_dst: "phi_store",
      port: "any",
      verdict: "insufficient",
      disagreements: ["no probe run", "no flow logs from the vendor concentrator"],
      note: "Config is silent on the vendor concentrator's NAT pool.",
    },
  ];

  const certificates: WargameCertificate[] = [
    {
      id: "c1",
      boundary_src: "clinic_wifi",
      boundary_dst: "payments_db",
      port: "any",
      claim: "no route from clinic_wifi to payments_db on any",
      assumptions: [
        { key: "no_unmodelled_links", text: "No links outside the modelled topology." },
        { key: "config_current", text: "Firewall fw_clinic runs the config snapshot hashed below." },
      ],
      config_hashes: ["sha256:3b7f0c2e9a41d6b85e0f7c2a9d3b61e4f8a0c5d7e2b9f1a36c4d8e0b7a5f2c91"],
      status: "valid",
      issued_at: iso(now - 4 * HOUR),
      expires_at: iso(now + 20 * HOUR),
      fingerprint: "9d4e1b7a0c3f6e2d8b5a1c7f4e0d9b3a6c2f8e5d1b7a4c0f3e6d2b9a5c1f8e4d",
    },
    {
      id: "c2",
      boundary_src: "internet",
      boundary_dst: "phi_store",
      port: "any",
      claim: "no route from internet to phi_store on any",
      assumptions: [
        { key: "no_unmodelled_links", text: "No links outside the modelled topology." },
        {
          key: "observation_side",
          text: "No sensor on the protected side: no crossing seen is absence of evidence, not proof the boundary is shut.",
        },
      ],
      config_hashes: [
        "sha256:a1c9e4f27b0d385e6c1a9f4b2e7d03c8a5f1b6e9d2c7a04f8b3e6d1c9a5f2b70",
        "sha256:0e6b3d9f2a5c81e47b0d6a3f9c2e5b18d4a7f0c3e6b9d2a5f8c1e4b7d0a3f6c9",
      ],
      status: "valid",
      issued_at: iso(now - 50 * HOUR),
      expires_at: iso(now - 2 * HOUR),
      fingerprint: "1f7c3a9e5b2d8f4a0c6e2b9d5f1a7c3e8b4d0f6a2c9e5b1d7f3a8c4e0b6d2f9a",
    },
  ];

  const fixSet: WargameFixSet = {
    id: "f1",
    total_cost: 2,
    optimality: "exact",
    cuts_all: false,
    selected: [
      {
        id: "sg-db:allow_pos",
        kind: "rule",
        cost_class: "cloud_policy",
        description: "Scope the payments DB security group off the POS CIDR",
        cost: 1,
      },
      {
        id: "fw_db:appid_postgres",
        kind: "rule",
        cost_class: "network_rule",
        description: "Replace the App-ID rule app_api → payments_db with an explicit tcp/5432 allow from the app subnet only",
        cost: 1,
      },
    ],
    metadata: {},
  };

  return {
    twin: { ruleset_count: 14, rule_count: 612, segment_count: 11, edge_count: 23, snapshot_count: 4, has_twin: true },
    assessments: [assessment, older],
    routes,
    boundaries,
    certificates,
    fixSet,
  };
}

/* ------------------------------------------------------------------ */
/* Change gate samples                                                 */
/* ------------------------------------------------------------------ */

export interface SamplePlan {
  id: string;
  title: string;
  plan: string;
  flows: string;
  result: WargameChangeImpact;
}

const planJson = (changes: unknown[]) =>
  JSON.stringify({ format_version: "1.2", terraform_version: "1.9.5", resource_changes: changes }, null, 2);

const FLOWS = [
  '{"ts":"2026-11-21T02:00:04Z","src":"10.9.0.50","dst":"10.5.0.12","proto":"tcp","dport":8080,"action":"allow","state":"established","service":"menu-sync"}',
  '{"ts":"2026-11-21T14:31:10Z","src":"10.9.0.50","dst":"10.5.0.14","proto":"tcp","dport":8080,"action":"allow","state":"established","service":"stock-levels"}',
  '{"ts":"2026-11-21T09:12:44Z","src":"10.5.0.12","dst":"10.1.0.9","proto":"tcp","dport":5432,"action":"allow","state":"established"}',
].join("\n");

export const SAMPLE_PLANS: SamplePlan[] = [
  {
    id: "close-fridge",
    title: "Remove the fridge → POS allow",
    plan: planJson([
      {
        address: "aws_security_group_rule.pos_from_fridge",
        type: "aws_security_group_rule",
        change: {
          actions: ["delete"],
          before: { type: "ingress", protocol: "tcp", from_port: 8080, to_port: 8080, cidr_blocks: ["10.9.0.0/24"], security_group_id: "sg-pos" },
          after: null,
        },
      },
    ]),
    flows: FLOWS,
    result: {
      verdict: "breaks_live_flows",
      routes_opened: [],
      routes_closed: [{ entry: "guest_wifi", jewel: "payments_db" }],
      newly_denied_flows: [
        { src_ip: "10.9.0.50", dst_ip: "10.5.0.12", proto: "tcp", dst_port: 8080 },
        { src_ip: "10.9.0.50", dst_ip: "10.5.0.14", proto: "tcp", dst_port: 8080 },
      ],
      newly_allowed_flows: [],
      summary:
        "Closes guest_wifi → payments_db. Would block 2 of 3 flows supplied, including the fridge → POS menu sync at 02:00 nightly.",
      warnings: [],
    },
  },
  {
    id: "open-vendor",
    title: "Let the vendor VPN reach the records subnet",
    plan: planJson([
      {
        address: "aws_security_group_rule.records_from_vendor",
        type: "aws_security_group_rule",
        change: {
          actions: ["create"],
          before: null,
          after: { type: "ingress", protocol: "tcp", from_port: 445, to_port: 445, cidr_blocks: ["172.20.0.0/16"], security_group_id: "sg-records" },
        },
      },
    ]),
    flows: "",
    result: {
      verdict: "opens_route_to_crown_jewel",
      routes_opened: [{ entry: "vendor_vpn", jewel: "phi_store" }],
      routes_closed: [],
      newly_denied_flows: [],
      newly_allowed_flows: [],
      summary: "Opens vendor_vpn → phi_store on tcp/445 through sg-records.",
      warnings: ["No flow log supplied: live flows this change would break were not checked."],
    },
  },
];

/** Sample mode only answers for its own plans; anything else is refused. */
export function sampleImpactFor(planText: string): WargameChangeImpact | null {
  const norm = (s: string) => s.replace(/\s+/g, "");
  const hit = SAMPLE_PLANS.find((p) => norm(p.plan) === norm(planText));
  return hit ? hit.result : null;
}
