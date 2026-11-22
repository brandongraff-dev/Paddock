import { useEffect, useState } from "react";
import PixelSprite from "../../brand/PixelSprite";
import PixelField from "../../brand/PixelField";
import type { SpriteName } from "../../brand/spriteData";
import { useScrollProgress } from "./hooks";
import PaintedJourney from "./PaintedJourney";
import "../../styles/how.css";

export const STEPS: { icon: SpriteName; title: string; body: string }[] = [
  { icon: "spyglass", title: "Discover", body: "Finds your internet-facing assets from public sources and the ones you add." },
  { icon: "compass", title: "Correlate", body: "Matches them against vulnerability and threat feeds to see what is really exposed." },
  { icon: "lighthouse", title: "Prioritise", body: "Traces the paths an attacker would take and ranks them by what they reach." },
  { icon: "key", title: "Fix", body: "Sends each path to its owner with the fix and a deadline, then re-checks." },
];

/** Glass journey: one wide panel, a line that draws as you scroll, and each step lighting up in turn. */
function GlassJourney() {
  const [ref, p] = useScrollProgress<HTMLDivElement>();
  // the section is in view from p≈0.2 to p≈0.8; map that to 0..1 of the journey
  const j = Math.min(1, Math.max(0, (p - 0.28) / 0.34));
  return (
    <section className="lp-how" id="how">
      <PixelField className="how-px" cell={6} animate={false} maxDpr={1} originX={0.05} />
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>From unknown to fixed in four steps.</h2>
      </div>
      <div className="how-panel" ref={ref} style={{ ["--j" as string]: j } as React.CSSProperties}>
        <div className="how-track" aria-hidden="true"><i /></div>
        <ol>
          {STEPS.map((s, i) => {
            const on = j >= i / (STEPS.length - 1) - 0.02;
            return (
              <li key={s.title} className={on ? "on" : ""}>
                <div className="how-ico"><PixelSprite name={s.icon} size={132} /></div>
                <span className="how-no mono">0{i + 1}</span>
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </li>
            );
          })}
        </ol>
      </div>
    </section>
  );
}

/** Use the painted, animated journey when the illustration exists; otherwise the glass panel. */
export default function HowItWorks() {
  const [painted, setPainted] = useState(false);
  useEffect(() => {
    let live = true;
    const im = new Image();
    im.onload = () => live && setPainted(true);
    im.src = "/journey.webp";
    return () => { live = false; };
  }, []);
  return painted ? <PaintedJourney /> : <GlassJourney />;
}
