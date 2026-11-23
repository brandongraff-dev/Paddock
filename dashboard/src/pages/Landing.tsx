import { Link } from "react-router-dom";
import DigitHorse from "../brand/DigitHorse";
import HorseMark from "../brand/HorseMark";
import Wordmark from "../brand/Wordmark";
import PixelField from "../brand/PixelField";
import FooterScene from "../brand/FooterScene";
import GitHubStars from "./landing/GitHubStars";
import CtaBox from "./landing/CtaBox";
import FlatArt from "./landing/FlatArt";
import PixelConstellation from "../brand/PixelConstellation";
import PixelSprite from "../brand/PixelSprite";
import type { SpriteName } from "../brand/spriteData";
import Faq from "./landing/Faq";
import { useAuth } from "../state/auth";
import Showcase from "./landing/Showcase";
import HowItWorks from "./landing/HowItWorks";
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
    role: "Scope",
    blurb: "Keeps every scan inside the scope you own.",
    to: "/scope",
    plate: 6,
    tone: "sepia",
  },
  {
    name: "Outrider",
    version: "2.1",
    id: "AGENT-002 · v2.1.4",
    role: "Discovery",
    blurb: "Finds everything you have exposed to the internet.",
    to: "/graph",
    plate: 3,
    tone: "ash",
  },
  {
    name: "Herald",
    version: "1.4",
    id: "AGENT-003 · v1.4.2",
    role: "Threat intel",
    blurb: "Flags the weaknesses attackers are using right now.",
    to: "/threat-intel",
    plate: 8,
    tone: "patina",
  },
  {
    name: "Farrier",
    version: "3.0",
    id: "AGENT-004 · v3.0.1",
    role: "Remediation",
    blurb: "Sends each fix to the team that owns it.",
    to: "/remediation",
    plate: 0,
    tone: "ember",
  },
];

const REPO = "https://github.com/brandongraff-dev/Paddock";
const FOOTER_LINKS: { title: string; links: [string, string][] }[] = [
  { title: "Product", links: [["Agents", "#agents"], ["See it work", "#product"], ["How it works", "#how"], ["Principles", "#principles"], ["FAQ", "#faq"], ["Console", "/login"]] },
  { title: "Project", links: [["Source", REPO], ["Documentation", "https://docs.openpaddock.dev"], ["Issues", `${REPO}/issues`], ["Contributing", `${REPO}/blob/main/CONTRIBUTING.md`]] },
  { title: "Security", links: [["Security policy", `${REPO}/blob/main/SECURITY.md`], ["Report a vulnerability", `${REPO}/security/advisories/new`], ["Code of conduct", `${REPO}/blob/main/CODE_OF_CONDUCT.md`]] },
];

const RULES = [
  ["No exploitation", "Findings describe impact. They never carry a working payload.", "anvil"],
  ["No credential attacks", "Default-credential risk is fingerprinted, never tried.", "key"],
  ["No evasion", "The scanner names itself. No decoys, no spoofing, no WAF bypass.", "lantern"],
  ["No out-of-scope anything", "Checked at dispatch, per request and per redirect. Audited.", "compass"],
];

export default function Landing() {
  const token = useAuth((s) => s.token);
  const enter = token ? "/" : "/login";
  const isPhone = typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(max-width: 720px)").matches;
  const [railRef, railIn] = useInView<HTMLDivElement>(0.15);
  const [megaRef, megaIn] = useInView<HTMLDivElement>(0.6);

  return (
    <div className="lp">
      <div className="lp-col">
      <section className="lp-hero">
        <div className="lp-sky" aria-hidden="true">
          <PixelField className="lp-pixels" cell={6} maxDpr={1} wake={isPhone ? { x: 0.4, y: 0.62 } : { x: 0.43, y: 0.64 }} />
        </div>

        <nav className="lp-nav">
          <Link to="/welcome" className="lp-brand">
            <HorseMark size={30} />
            <Wordmark height={22} />
          </Link>
          <div className="lp-links">
            <a href="#agents">Agents</a>
            <a href="#product">Product</a>
            <a href="#principles">Principles</a>
            <a href="https://docs.openpaddock.dev" target="_blank" rel="noreferrer">
              Docs
            </a>
            <GitHubStars />
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

      <section className="lp-cta-strip" aria-label="Get started">
        <CtaBox className="cta-strip" />
      </section>

      <section className="lp-agents" id="agents">
        <div className="lp-section-head">
          <span className="lp-eyebrow mono">Defensive agents</span>
          <h2>Four agents. One invariant: only what you own.</h2>
        </div>
        <div className={`lp-rail${railIn ? " in" : ""}`} role="list" ref={railRef}>
          {AGENTS.map((a) => (
            <article className={`lp-card tone-${a.tone}`} key={a.id} role="listitem">
              <div className="lp-card-img">
                <FlatArt name={a.name} />
              </div>
              <div className="lp-card-body">
                <span className="lp-tag">
                  <i aria-hidden="true" />
                  {a.role}
                </span>
                <h3>{a.name}</h3>
                <p>{a.blurb}</p>
                <Link to={token ? a.to : "/login"} className="lp-open">
                  Open <span aria-hidden="true">→</span>
                </Link>
              </div>
            </article>
          ))}
        </div>
      </section>

      <Showcase />
      <HowItWorks />


      <section className="lp-principles scene" id="principles">
        <PixelConstellation className="scene-bg" variant="rules" />
        <div className="lp-section-head">
          <span className="lp-eyebrow mono">Hard rules · enforced in code</span>
          <h2>A defender&rsquo;s instrument, by construction.</h2>
        </div>
        <ul className="rows rules in">
          {RULES.map(([t, d, icon], i) => (
            <li key={t}>
              <PixelSprite name={icon as SpriteName} size={72} />
              <h3><span className="mono">0{i + 1}</span>{t}</h3>
              <p>{d}</p>
            </li>
          ))}
        </ul>
      </section>


      <Faq />
      </div>

      <footer className="lp-footer">
        <FooterScene className="lp-footer-px" parallax />
        <div className="lp-footer-in">
          <div className="lp-footer-cta">
            <h2>Close the paths before they&rsquo;re walked.</h2>
            <CtaBox className="cta-footer" />
          </div>
          <div className="lp-footer-grid">
            <div className="lp-footer-brand" ref={megaRef}>
              <div className={`lp-footer-logo${megaIn ? " in" : ""}`}>
                <HorseMark size={34} />
                <Wordmark height={30} shimmer />
              </div>
              <p>Map the paths attackers would take, and close them before they do.</p>
            </div>
            {FOOTER_LINKS.map((col) => (
              <nav key={col.title} aria-label={col.title}>
                <h5>{col.title}</h5>
                {col.links.map(([label, href]) =>
                  href.startsWith("/") ? (
                    <Link key={label} to={href}>{label}</Link>
                  ) : (
                    <a key={label} href={href} {...(href.startsWith("http") ? { target: "_blank", rel: "noreferrer" } : {})}>{label}</a>
                  ),
                )}
              </nav>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
