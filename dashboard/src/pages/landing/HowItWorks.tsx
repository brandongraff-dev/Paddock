import PixelField from "../../brand/PixelField";
import StepIcon, { type StepIconName } from "./StepIcon";
import { useInView } from "./hooks";
import "../../styles/how.css";

const STEPS: [string, string, StepIconName][] = [
  ["Discover", "Finds your internet-facing assets from public sources and the ones you add.", "discover"],
  ["Correlate", "Matches them against vulnerability and threat feeds to see what is really exposed.", "correlate"],
  ["Prioritise", "Traces the paths an attacker would take and ranks them by what they reach.", "prioritise"],
  ["Fix", "Sends each path to its owner with the fix and a deadline, then re-checks.", "fix"],
];

/** One dashed line joins four stops and ends in a rust dot: the thing to fix first. */
export default function HowItWorks() {
  const [ref, seen] = useInView<HTMLOListElement>(0.2);
  return (
    <section className="lp-how scene" id="how">
      <PixelField className="scene-bg" cell={6} animate={false} maxDpr={1} originX={0.12} />
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>From unknown to fixed in four steps.</h2>
      </div>
      <ol className={`path${seen ? " in" : ""}`} ref={ref}>
        {STEPS.map(([t, d, icon], i) => (
          <li key={t} style={{ transitionDelay: `${i * 140}ms` }}>
            <div className="path-node"><StepIcon name={icon} /></div>
            <span className="path-no mono">0{i + 1}</span>
            <h3>{t}</h3>
            <p>{d}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
