import type { AssetKind } from "../../api/types";

/** Small line icons (16px, currentColor) for each asset kind on the canvas. */
const PATHS: Partial<Record<AssetKind, string>> = {
  org: "M4 20V8l8-4 8 4v12M9 20v-5h6v5M8 10h.01M12 10h.01M16 10h.01",
  domain: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z",
  subdomain: "M6 4v8a4 4 0 0 0 4 4h8M6 4H4M18 16l-3-3M18 16l-3 3",
  ipv4: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  ipv6: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  port: "M9 3v4M15 3v4M6 7h12v4a6 6 0 0 1-12 0zM12 17v4",
  service: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1",
  technology: "M12 3 4 7.5v9L12 21l8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9",
  certificate: "M6 11V8a6 6 0 0 1 12 0v3M5 11h14v10H5zM12 15v2",
  endpoint: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  repository: "M6 3v12M18 9a3 3 0 1 0 0-.01M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 12c0 3-3 4-6 4H9",
  secret_candidate: "M15 7a4 4 0 1 1-3.5 6L4 20.5V17h3v-3h3l1.5-1.5",
  cloud_account: "M7 18a5 5 0 0 1-.8-9.9A6 6 0 0 1 17.7 9 4.5 4.5 0 0 1 17 18z",
  cloud_resource: "M7 18a5 5 0 0 1-.8-9.9A6 6 0 0 1 17.7 9 4.5 4.5 0 0 1 17 18zM12 11v4M10 13h4",
};

export default function KindIcon({ kind }: { kind: AssetKind }) {
  const d = PATHS[kind] ?? "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16z";
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}
