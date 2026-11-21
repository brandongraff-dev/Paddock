import { useMemo } from "react";
import { Link } from "react-router-dom";
import DigitHorse from "../brand/DigitHorse";
import HorseMark from "../brand/HorseMark";
import { useAuth } from "../state/auth";
import "../styles/landing.css";

/**
 * Public landing page. Old-plate photography meets an instrument panel:
 * a smoky sky that breaks into pixel blocks, a staggered serif headline,
 * and Muybridge's gallop redrawn as drifting digits.
 */

interface Agent {
  name: string;
  version: string;
  id: string;
  role: string;
  blurb: string;
  to: string;
  plate: number;
  tone: "sepia" | "ash" | "patina" | "ember";
}

const AGENTS: Agent[] = [
  {
    name: "Warden",
    version: "1.0",
    id: "AGENT-001 · v1.0.0",
    role: "Scope agent",
    blurb: "Enforces the allowlist on every packet; differential-fuzzed against real URL parsers",
    to: "/scope",
    plate: 6,
    tone: "sepia",
  },
  {
    name: "Outrider",
    version: "2.1",
    id: "AGENT-002 · v2.1.4",
    role: "Discovery agent",
    blurb: "Maps your surface from CT logs, DNS, ASN ranges and polite authorised probes",
    to: "/graph",
    plate: 3,
    tone: "ash",
  },
  {
    name: "Herald",
    version: "1.4",
    id: "AGENT-003 · v1.4.2",
    role: "Threat-intel agent",
    blurb: "Correlates NVD, EPSS, CISA KEV and your TAXII feeds against what you actually run",
    to: "/threat-intel",
    plate: 8,
    tone: "patina",
  },
  {
    name: "Farrier",
    version: "3.0",
    id: "AGENT-004 · v3.0.1",
    role: "Remediation agent",
    blurb: "Routes each attack path to its owner with the fix, the ticket and the deadline",
    to: "/remediation",
    plate: 0,
    tone: "ember",
  },
];

const RULES = [
  ["No exploitation", "Findings describe impact. They never carry a working payload."],
  ["No credential attacks", "Default-credential risk is fingerprinted, never tried."],
  ["No evasion", "The scanner names itself. No decoys, no spoofing, no WAF bypass."],
  ["No out-of-scope anything", "Checked at dispatch, per request and per redirect. Audited."],
];

/** Deterministic blocky "pixel mosaic" for the sky, as in a broken plate. */
function useSkyBlocks(n = 70) {
  return useMemo(() => {
    let s = 7;
    const rnd = () => ((s = (s * 16807) % 2147483647) / 2147483647);
    return Array.from({ length: n }, () => {
      const size = 3 + Math.floor(rnd() * 9);
      return {
        x: Math.floor(rnd() * 100),
        y: Math.floor(rnd() * 26),
        w: size * (1 + Math.floor(rnd() * 3)),
        h: size,
        o: 0.03 + rnd() * 0.09,
        l: rnd() > 0.5,
      };
    });
  }, [n]);
}

export default function Landing() {
  const token = useAuth((s) => s.token);
  const enter = token ? "/" : "/login";
  const blocks = useSkyBlocks();

  return (
    <div className="lp">
      <section className="lp-hero">
        <div className="lp-sky" aria-hidden="true">
          <svg className="lp-blocks" viewBox="0 0 100 60" preserveAspectRatio="none">
            {blocks.map((b, i) => (
              <rect
                key={i}
                x={b.x}
                y={b.y}
                width={b.w / 4}
                height={b.h / 4}
                fill={b.l ? "#d9d0c2" : "#2a2520"}
                opacity={b.o}
              />
            ))}
          </svg>
        </div>
        <div className="lp-grain" aria-hidden="true" />

        <nav className="lp-nav">
          <Link to="/welcome" className="lp-brand">
            <HorseMark size={30} />
            <span>Paddock</span>
          </Link>
          <div className="lp-links">
            <a href="#agents">Agents</a>
            <a href="#principles">Principles</a>
            <a href="https://github.com/brandongraff-dev/cybersec" target="_blank" rel="noreferrer">
              Source
            </a>
            <Link to={enter} className="lp-cta">
              {token ? "Open console" : "Sign in"} <span aria-hidden="true">→</span>
            </Link>
          </div>
        </nav>

        <h1 className="lp-headline">
          <span className="l1">Discover.</span>
          <span className="l2">Correlate.</span>
          <span className="l3">Defend.</span>
        </h1>

        <div className="lp-horse">
          <DigitHorse body={0.42} />
        </div>

        <footer className="lp-hero-foot">
          <p className="left">
            Mapping the paths
            <br />
            attackers would take
          </p>
          <HorseMark size={64} className="lp-seal" />
          <p className="right">
            and closing them
            <br />
            before they do
          </p>
        </footer>
      </section>

      <section className="lp-agents" id="agents">
        <div className="lp-section-head">
          <span className="lp-eyebrow mono">Defensive agents</span>
          <h2>Four agents. One invariant: only what you own.</h2>
        </div>
        <div className="lp-rail" role="list">
          {AGENTS.map((a) => (
            <article className={`lp-card tone-${a.tone}`} key={a.id} role="listitem">
              <div className="lp-card-img">
                <DigitHorse still={a.plate} strays={false} body={0.5} />
              </div>
              <div className="lp-card-body">
                <div className="lp-card-top">
                  <h3>
                    {a.name} {a.version}
                  </h3>
                  <span className="lp-tag">
                    <i aria-hidden="true" />
                    {a.role}
                  </span>
                </div>
                <div className="lp-card-info">
                  <span>Agent info</span>
                  <span className="mono">{a.id}</span>
                </div>
                <p>{a.blurb}</p>
                <Link to={token ? a.to : "/login"} className="lp-run">
                  <span aria-hidden="true">⟶</span> Run agent
                </Link>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="lp-principles" id="principles">
        <div className="lp-section-head">
          <span className="lp-eyebrow mono">Hard rules · enforced in code</span>
          <h2>A defender&apos;s instrument, by construction.</h2>
        </div>
        <div className="lp-rules">
          {RULES.map(([t, d]) => (
            <div className="lp-rule" key={t}>
              <h4>{t}</h4>
              <p>{d}</p>
            </div>
          ))}
        </div>
        <div className="lp-proof">
          <div>
            <b>10,000,000</b>
            <span>hostile targets fuzzed against WHATWG + RFC 3986 parsers</span>
          </div>
          <div>
            <b>0</b>
            <span>scope parser differentials after hardening (from 77,554 per million)</span>
          </div>
          <div>
            <b>SHA-256</b>
            <span>hash-chained, verifiable audit log of every decision</span>
          </div>
        </div>
      </section>

      <footer className="lp-foot">
        <span className="mono">paddock · AGPL-3.0 · self-hosted</span>
        <span>
          Horse after Eadweard Muybridge, <i>The Horse in Motion</i>, 1878 (public domain).
        </span>
      </footer>
    </div>
  );
}
