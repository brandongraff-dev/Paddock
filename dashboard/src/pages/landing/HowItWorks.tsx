import { useInView } from "./hooks";
import "../../styles/how.css";

const STEPS: [string, string][] = [
  ["Discover", "Finds your internet-facing assets from public sources and the ones you add."],
  ["Correlate", "Matches them against vulnerability and threat feeds to see what is really exposed."],
  ["Prioritise", "Traces the paths an attacker would take and ranks them by what they reach."],
  ["Fix", "Sends each path to its owner with the fix and a deadline, then re-checks."],
];

/** Plain editorial list: number, title, one line. Rows ink in as they scroll into view. */
export default function HowItWorks() {
  const [ref, seen] = useInView<HTMLOListElement>(0.2);
  return (
    <section className="lp-how" id="how">
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>From unknown to fixed in four steps.</h2>
      </div>
      <ol className={`rows${seen ? " in" : ""}`} ref={ref}>
        {STEPS.map(([t, d], i) => (
          <li key={t} style={{ transitionDelay: `${i * 120}ms` }}>
            <span className="mono">0{i + 1}</span>
            <h3>{t}</h3>
            <p>{d}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
