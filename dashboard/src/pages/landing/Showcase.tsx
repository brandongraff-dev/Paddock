import { useEffect, useState, type ReactNode } from "react";
import HorseMark from "../../brand/HorseMark";
import PixelField from "../../brand/PixelField";
import Wordmark from "../../brand/Wordmark";
import { useFit, useInView } from "./hooks";
import "../../styles/showcase.css";

/**
 * "See it work": two product windows built from mock data (never real
 * customer data), using the console's own glass classes so they stay in step
 * with the app. Everything animates in once the section scrolls into view.
 */

const W = 1120;
const H = 700;

function CountUp({ to, run, dur = 1400, fmt }: { to: number; run: boolean; dur?: number; fmt?: (n: number) => string }) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!run) return;
    let raf = 0;
    const t0 = performance.now();
    const tick = (t: number) => {
      const k = Math.min(1, (t - t0) / dur);
      setV(Math.round(to * (1 - Math.pow(1 - k, 3))));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [run, to, dur]);
  return <>{fmt ? fmt(v) : v.toLocaleString("en-US")}</>;
}

/** A window with chrome, a mini sidebar and an aurora canvas. */
function AppWindow({ url, active, children, className, run, h = H, rail = true }: { url: string; active: string; children: ReactNode; className?: string; run: boolean; h?: number; rail?: boolean }) {
  const [box, scale] = useFit<HTMLDivElement>(W);
  const nav = ["Overview", "Graph", "Findings", "Attack Paths", "Threat Intel", "Reports"];
  return (
    <div className={`sc-win ${className ?? ""}${run ? " in" : ""}`} ref={box} style={{ height: h * scale }}>
      <div className="sc-frame" style={{ width: W, height: h, transform: `scale(${scale})` }}>
        <div className="sc-chrome">
          <i /><i /><i />
          <span className="sc-url">{url}</span>
        </div>
        <div className="sc-body">
          {rail && <aside className="sc-rail">
            <div className="sc-brand"><HorseMark size={24} /><Wordmark height={19} /></div>
            {nav.map((n) => (
              <div key={n} className={`sc-nav${n === active ? " on" : ""}`}><b />{n}</div>
            ))}
          </aside>}
          <div className="sc-canvas">
            <PixelField className="sc-pixels" cell={5} animate={false} originX={0.2} />
            <div className="sc-content">{children}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ----------------------------- Overview ----------------------------- */
const TREND = [74, 71, 73, 69, 70, 66, 67, 63, 64, 60, 61, 58, 55, 52];

function Trend({ run }: { run: boolean }) {
  const w = 560, h = 190;
  const pts = TREND.map((v, i) => [(i / (TREND.length - 1)) * w, h - ((v - 40) / 40) * h] as const);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  return (
    <svg className={`sc-trend${run ? " in" : ""}`} viewBox={`0 -8 ${w} ${h + 16}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id="sc-line" x1="0" x2="1">
          <stop offset="0" stopColor="#9fc2d8" />
          <stop offset="0.55" stopColor="#ecdec4" />
          <stop offset="1" stopColor="#e67350" />
        </linearGradient>
        <linearGradient id="sc-fill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#9fc2d8" stopOpacity="0.28" />
          <stop offset="1" stopColor="#9fc2d8" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1="0" x2={w} y1={h * g} y2={h * g} stroke="rgba(236,226,208,0.07)" />
      ))}
      <path className="sc-area" d={`${line} L${w} ${h} L0 ${h} Z`} fill="url(#sc-fill)" />
      <path className="sc-stroke" d={line} fill="none" stroke="url(#sc-line)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" pathLength={1} />
      <circle className="sc-end" cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="5" fill="#e67350" />
    </svg>
  );
}

const SEV: [string, number, string][] = [
  ["Critical", 3, "var(--sev-crit)"],
  ["High", 11, "var(--sev-high)"],
  ["Medium", 27, "var(--sev-med)"],
  ["Low", 41, "var(--sev-low)"],
];

export function OverviewWindow({ run }: { run: boolean }) {
  return (
    <AppWindow url="paddock.acme.io / overview" active="Overview" run={run} h={640}>
      <h4 className="sc-title">Overview</h4>
      <p className="sc-sub">Your attack surface, what is open on it, and what changed.</p>
      <div className="stat-row sc-stats">
        <div className="stat-tile"><span className="label">Exposure index</span><span className="value"><CountUp to={52} run={run} /></span><span className="delta down">▼ 22 in 14d</span></div>
        <div className="stat-tile"><span className="label">Assets</span><span className="value"><CountUp to={1284} run={run} /></span><span className="delta">38 kinds</span></div>
        <div className="stat-tile"><span className="label"><i className="stat-dot" style={{ background: "var(--sev-crit)" }} /> Critical open</span><span className="value"><CountUp to={3} run={run} /></span><span className="delta">2 on KEV</span></div>
        <div className="stat-tile"><span className="label">Attack paths</span><span className="value"><CountUp to={7} run={run} /></span><span className="delta down">▼ 4 closed</span></div>
      </div>
      <div className="sc-grid">
        <div className="panel">
          <div className="panel-h"><h2>Exposure over time</h2><span className="panel-meta">last 14 days</span></div>
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
      </div>
    </AppWindow>
  );
}

/* ---------------------------- Attack path ---------------------------- */
interface N { id: string; x: number; y: number; t: string; s: string; c: string; chip?: string; dim?: boolean }
const NODES: N[] = [
  { id: "n0", x: 0, y: 170, t: "Internet", s: "0.0.0.0/0", c: "var(--kind-org)" },
  { id: "n1", x: 175, y: 80, t: "shop.acme.io", s: "subdomain", c: "var(--kind-subdomain)" },
  { id: "n2", x: 350, y: 170, t: "nginx 1.18.0", s: "CVE-2021-23017", c: "var(--kind-service)", chip: "KEV" },
  { id: "n3", x: 525, y: 80, t: "api-gateway", s: "service · 8443", c: "var(--kind-technology)" },
  { id: "n4", x: 700, y: 170, t: "customers-db", s: "crown jewel", c: "var(--sev-crit)", chip: "PII" },
  { id: "d1", x: 175, y: 280, t: "blog.acme.io", s: "subdomain", c: "var(--text-3)", dim: true },
  { id: "d2", x: 350, y: 330, t: "cdn-edge", s: "service", c: "var(--text-3)", dim: true },
  { id: "d3", x: 525, y: 280, t: "redis-cache", s: "ipv4", c: "var(--text-3)", dim: true },
];
const NW = 150, NH = 58;
const PATH: [string, string][] = [["n0", "n1"], ["n1", "n2"], ["n2", "n3"], ["n3", "n4"]];
const DIM: [string, string][] = [["n0", "d1"], ["d1", "d2"], ["d2", "d3"]];
const by = (id: string) => NODES.find((n) => n.id === id)!;
function edge(a: string, b: string) {
  const A = by(a), B = by(b);
  const x1 = A.x + NW, y1 = A.y + NH / 2, x2 = B.x, y2 = B.y + NH / 2;
  const mx = (x1 + x2) / 2;
  return `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`;
}

export function PathWindow({ run }: { run: boolean }) {
  const full = PATH.map(([a, b]) => edge(a, b));
  return (
    <AppWindow url="paddock.acme.io / attack-paths / PATH-0147" active="Attack Paths" run={run} className="sc-front" h={560} rail={false}>
      <div className="sc-head">
        <div>
          <h4 className="sc-title">Internet to customer data in 4 hops</h4>
          <p className="sc-sub">PATH-0147 · blast radius 92 · first seen 2 days ago</p>
        </div>
        <span className="sc-pill crit">Critical</span>
      </div>
      <div className="sc-grid path">
        <div className="panel sc-graph">
          <svg className={`sc-svg${run ? " in" : ""}`} viewBox="-8 38 868 342">
            <defs>
              <linearGradient id="sc-edge" x1="0" x2="1">
                <stop offset="0" stopColor="#9fc2d8" />
                <stop offset="1" stopColor="#e67350" />
              </linearGradient>
              <filter id="sc-glow"><feGaussianBlur stdDeviation="3" /></filter>
            </defs>
            {DIM.map(([a, b], i) => <path key={i} d={edge(a, b)} className="sc-dim-edge" />)}
            {full.map((d, i) => (
              <g key={i}>
                <path d={d} className="sc-edge-glow" style={{ animationDelay: `${600 + i * 450}ms` }} pathLength={1} />
                <path d={d} className="sc-edge" style={{ animationDelay: `${600 + i * 450}ms` }} pathLength={1} />
              </g>
            ))}
            {run && (
              <circle r="4.5" fill="#ecdec4" filter="url(#sc-glow)">
                <animateMotion dur="4.2s" begin="2.8s" repeatCount="indefinite" path={full.join(" ").replace(/M/g, " M")} calcMode="linear" />
              </circle>
            )}
            {NODES.map((n, i) => (
              <g key={n.id} transform={`translate(${n.x} ${n.y})`}>
              <g className={`sc-node${n.dim ? " dim" : ""}`} style={{ animationDelay: `${(n.dim ? 300 : i * 450) + 200}ms` }}>
                <rect width={NW} height={NH} rx="12" className="sc-node-bg" />
                <rect x="0" y="12" width="3.5" height={NH - 24} rx="1.75" fill={n.c} />
                <text x="18" y="25" className="sc-node-t">{n.t}</text>
                <text x="18" y="43" className="sc-node-s">{n.s}</text>
                {n.chip && (
                  <g transform={`translate(${NW - 36} -9)`}>
                    <rect width="40" height="18" rx="9" fill={n.id === "n4" ? "var(--sev-crit)" : "var(--sev-high)"} />
                    <text x="20" y="12.5" textAnchor="middle" className="sc-chip-t">{n.chip}</text>
                  </g>
                )}
              </g>
              </g>
            ))}
          </svg>
        </div>
        <div className="panel sc-why">
          <div className="panel-h"><h2>Why it ranks first</h2></div>
          {[
            ["Exploited in the wild", "CISA KEV", "var(--sev-crit)"],
            ["Internet-facing", "no WAF in front", "var(--sev-high)"],
            ["Reaches PII", "4 hops · no segmentation", "var(--sev-med)"],
            ["Owner", "payments-platform", "var(--accent)"],
          ].map(([a, b, c], i) => (
            <div className="sc-why-row" key={a} style={{ transitionDelay: `${900 + i * 160}ms` }}>
              <i style={{ background: c }} />
              <div><b>{a}</b><span>{b}</span></div>
            </div>
          ))}
          <div className="sc-cta">Open fix in Jira <span>→</span></div>
        </div>
      </div>
    </AppWindow>
  );
}

export default function Showcase() {
  const [ref, seen] = useInView<HTMLElement>(0.18);
  return (
    <section className="lp-showcase" id="product" ref={ref}>
      <PixelField className="lp-showcase-px" cell={6} animate={false} originX={-0.1} />
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">The product</span>
        <h2>See the path before they do.</h2>
      </div>
      <div className={`sc-stage${seen ? " in" : ""}`}>
        <div className="sc-back"><OverviewWindow run={seen} /></div>
        <div className="sc-fore"><PathWindow run={seen} /></div>
      </div>
      <p className="sc-note mono">Mock data, real interface.</p>
    </section>
  );
}
