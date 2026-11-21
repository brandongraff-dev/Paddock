import PixelField from "../../brand/PixelField";
import Wordmark from "../../brand/Wordmark";
import HorseMark from "../../brand/HorseMark";
import { CountUp, Trend, SEV } from "./Showcase";

/**
 * Phone-native versions of the two product windows: real, readable type at
 * 390px instead of a scaled-down desktop frame. Same mock data.
 */

function Frame({ url, run, children }: { url: string; run: boolean; children: React.ReactNode }) {
  return (
    <div className={`ph-win${run ? " in" : ""}`}>
      <div className="ph-chrome"><i /><i /><i /><span>{url}</span></div>
      <div className="ph-body">
        <PixelField className="ph-px" cell={5} animate={false} originX={0.1} />
        <div className="ph-content">{children}</div>
      </div>
    </div>
  );
}

export function PhoneOverview({ run }: { run: boolean }) {
  return (
    <Frame url="paddock.acme.io / overview" run={run}>
      <div className="ph-brand"><HorseMark size={20} /><Wordmark height={15} /></div>
      <h4 className="ph-title">Overview</h4>
      <div className="ph-stats">
        <div className="stat-tile"><span className="label">Exposure index</span><span className="value"><CountUp to={52} run={run} /></span><span className="delta down">▼ 22 in 14d</span></div>
        <div className="stat-tile"><span className="label">Assets</span><span className="value"><CountUp to={1284} run={run} /></span><span className="delta">38 kinds</span></div>
        <div className="stat-tile"><span className="label">Critical open</span><span className="value"><CountUp to={3} run={run} /></span><span className="delta">2 on KEV</span></div>
        <div className="stat-tile"><span className="label">Attack paths</span><span className="value"><CountUp to={7} run={run} /></span><span className="delta down">▼ 4 closed</span></div>
      </div>
      <div className="panel">
        <div className="panel-h"><h2>Exposure over time</h2><span className="panel-meta">14 days</span></div>
        <Trend run={run} />
      </div>
      <div className="panel">
        <div className="panel-h"><h2>Open by severity</h2><span className="panel-meta">82 open</span></div>
        <div className="sc-bars">
          {SEV.map(([n, c, col], i) => (
            <div className="sc-bar" key={n}>
              <span>{n}</span>
              <div><i style={{ ["--w" as string]: `${(c / 41) * 100}%`, background: col, transitionDelay: `${400 + i * 120}ms` } as React.CSSProperties} /></div>
              <b>{c}</b>
            </div>
          ))}
        </div>
      </div>
    </Frame>
  );
}

const HOPS: { t: string; s: string; c: string; chip?: string }[] = [
  { t: "Internet", s: "0.0.0.0/0", c: "var(--kind-org)" },
  { t: "shop.acme.io", s: "subdomain", c: "var(--kind-subdomain)" },
  { t: "nginx 1.18.0", s: "CVE-2021-23017", c: "var(--kind-service)", chip: "KEV" },
  { t: "api-gateway", s: "service · 8443", c: "var(--kind-technology)" },
  { t: "customers-db", s: "crown jewel", c: "var(--sev-crit)", chip: "PII" },
];

export function PhonePath({ run }: { run: boolean }) {
  return (
    <Frame url="attack-paths / PATH-0147" run={run}>
      <div className="ph-head">
        <h4 className="ph-title">Internet to customer data in 4 hops</h4>
        <span className="sc-pill crit">Critical</span>
      </div>
      <p className="ph-sub">PATH-0147 · blast radius 92 · first seen 2 days ago</p>
      <ol className="ph-hops">
        {HOPS.map((h, i) => (
          <li key={h.t} style={{ transitionDelay: `${300 + i * 380}ms` }}>
            <i className="ph-dot" style={{ background: h.c }} />
            <div className="ph-hop"><b>{h.t}</b><span>{h.s}</span></div>
            {h.chip && <em className={h.chip === "PII" ? "pii" : ""}>{h.chip}</em>}
          </li>
        ))}
      </ol>
      <div className="panel ph-why">
        <div className="panel-h"><h2>Why it ranks first</h2></div>
        {[["Exploited in the wild", "CISA KEV", "var(--sev-crit)"], ["Internet-facing", "no WAF in front", "var(--sev-high)"], ["Reaches PII", "4 hops · no segmentation", "var(--sev-med)"], ["Owner", "payments-platform", "var(--accent)"]].map(([a, b, c]) => (
          <div className="sc-why-row" key={a}><i style={{ background: c }} /><div><b>{a}</b><span>{b}</span></div></div>
        ))}
        <div className="sc-cta">Open fix in Jira <span>→</span></div>
      </div>
    </Frame>
  );
}
