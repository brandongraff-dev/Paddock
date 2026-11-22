import PixelConstellation from "../../brand/PixelConstellation";
import PixelSprite from "../../brand/PixelSprite";
import type { SpriteName } from "../../brand/spriteData";
import { useInView } from "./hooks";
import "../../styles/how.css";

const STEPS: [string, string, SpriteName][] = [
  ["Discover", "Finds your internet-facing assets from public sources and the ones you add.", "spyglass"],
  ["Correlate", "Matches them against vulnerability and threat feeds to see what is really exposed.", "compass"],
  ["Prioritise", "Traces the paths an attacker would take and ranks them by what they reach.", "lighthouse"],
  ["Fix", "Sends each path to its owner with the fix and a deadline, then re-checks.", "key"],
];

/** Plain editorial list: number, title, one line. Rows ink in as they scroll into view. */
export default function HowItWorks() {
  const [ref, seen] = useInView<HTMLOListElement>(0.2);
  return (
    <section className="lp-how scene" id="how">
      <PixelConstellation className="scene-bg" variant="path" />
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>From unknown to fixed in four steps.</h2>
      </div>
      <ol className={`rows${seen ? " in" : ""}`} ref={ref}>
        {STEPS.map(([t, d, icon], i) => (
          <li key={t} style={{ transitionDelay: `${i * 120}ms` }}>
            <PixelSprite name={icon} size={72} />
            <h3><span className="mono">0{i + 1}</span>{t}</h3>
            <p>{d}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
