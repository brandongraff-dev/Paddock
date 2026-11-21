import { Link } from "react-router-dom";
import DigitHorse from "../brand/DigitHorse";
import HorseMark from "../brand/HorseMark";
import Wordmark, { WORDMARK_ASPECT } from "../brand/Wordmark";
import PixelField from "../brand/PixelField";
import GallopTrail from "../brand/GallopTrail";
import PlateStrip from "../brand/PlateStrip";
import DitherRule from "../brand/DitherRule";
import ShockRipple from "../brand/ShockRipple";
import { useAuth } from "../state/auth";
import Showcase from "./landing/Showcase";
import { useInView } from "./landing/hooks";
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

const WORKS_WITH = [
  "Jira", "ServiceNow", "Linear", "Slack", "Microsoft Teams", "PagerDuty", "Splunk", "Microsoft Sentinel",
  "Elastic", "CrowdStrike", "Microsoft Defender", "AWS", "UniFi", "Meraki", "SARIF", "OCSF 1.3",
  "STIX 2.1 / TAXII", "CycloneDX", "SPDX", "OIDC · SAML · SCIM", "Terraform",
];

const RULES = [
  ["No exploitation", "Findings describe impact. They never carry a working payload."],
  ["No credential attacks", "Default-credential risk is fingerprinted, never tried."],
  ["No evasion", "The scanner names itself. No decoys, no spoofing, no WAF bypass."],
  ["No out-of-scope anything", "Checked at dispatch, per request and per redirect. Audited."],
];

export default function Landing() {
  const token = useAuth((s) => s.token);
  const enter = token ? "/" : "/login";
  const [railRef, railIn] = useInView<HTMLDivElement>(0.15);
  const [megaRef, megaIn] = useInView<HTMLDivElement>(0.55);

  return (
    <div className="lp">
      <section className="lp-hero">
        <div className="lp-sky" aria-hidden="true">
          <PixelField className="lp-pixels" interactive wake={{ x: 0.43, y: 0.64 }} />
        </div>
        <div className="lp-grain" aria-hidden="true" />

        <nav className="lp-nav">
          <Link to="/welcome" className="lp-brand">
            <HorseMark size={30} />
            <Wordmark height={22} />
          </Link>
          <div className="lp-links">
            <a href="#agents">Agents</a>
            <a href="#product">Product</a>
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
          <GallopTrail className="lp-trail" />
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

      <div className="lp-film" aria-hidden="true">
        <PlateStrip className="lp-film-track" />
      </div>

      <section className="lp-agents" id="agents">
        <div className="lp-section-head">
          <span className="lp-eyebrow mono">Defensive agents</span>
          <h2>Four agents. One invariant: only what you own.</h2>
        </div>
        <div className={`lp-rail${railIn ? " in" : ""}`} role="list" ref={railRef}>
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

      <DitherRule className="lp-rule-dither" />
      <Showcase />

      <div className="lp-ticker" aria-label="Integrations and standards">
        <div className="lp-ticker-track">
          {[...WORKS_WITH, ...WORKS_WITH].map((w, i) => (
            <span key={i}><b aria-hidden="true" />{w}</span>
          ))}
        </div>
      </div>

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
      </section>


      <section className="lp-mega">
        <ShockRipple fire={megaIn} anchor={megaRef} className="lp-mega-ripple" />
        <div className="lp-mega-cta">
          <h2>Close the paths before they&apos;re walked.</h2>
          <div>
            <Link to={enter} className="lp-run lp-mega-btn">
              {token ? "Open console" : "Sign in"} <span aria-hidden="true">→</span>
            </Link>
            <a className="lp-mega-link" href="https://github.com/brandongraff-dev/cybersec" target="_blank" rel="noreferrer">
              Read the source ↗
            </a>
          </div>
        </div>
        <div ref={megaRef} className={`lp-mega-mark${megaIn ? " in" : ""}`} style={{ aspectRatio: `${WORDMARK_ASPECT / 0.73}` }} aria-hidden="true">
          <Wordmark fluid shimmer />
        </div>
      </section>
    </div>
  );
}
