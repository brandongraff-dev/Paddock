import PixelSprite from "../../brand/PixelSprite";
import type { SpriteName } from "../../brand/spriteData";
import { useInView } from "./hooks";
import "../../styles/how.css";

const STEPS: { icon: SpriteName; title: string; body: string }[] = [
  { icon: "spyglass", title: "Discover", body: "Finds your internet-facing assets from public sources and the ones you add." },
  { icon: "compass", title: "Correlate", body: "Matches them against vulnerability and threat feeds to see what is really exposed." },
  { icon: "lighthouse", title: "Prioritise", body: "Traces the paths an attacker would take and ranks them by what they reach." },
  { icon: "key", title: "Fix", body: "Sends each path to its owner with the fix and a deadline, then re-checks." },
];

/** "How it works": the whole idea as one funnel, then the four steps. */
export default function HowItWorks() {
  const [sRef, sIn] = useInView<HTMLDivElement>(0.2);
  return (
    <section className="lp-how" id="how">
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>From unknown to fixed in four steps.</h2>
      </div>

      <div className={`how-steps${sIn ? " in" : ""}`} ref={sRef}>
        <div className="how-line" aria-hidden="true" />
        {STEPS.map((s, i) => (
          <article key={s.title} style={{ transitionDelay: `${i * 160}ms` }}>
            <div className="how-ico"><PixelSprite name={s.icon} size={96} /></div>
            <span className="how-no mono">0{i + 1}</span>
            <h3>{s.title}</h3>
            <p>{s.body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
