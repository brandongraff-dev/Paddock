import { useEffect, useState } from "react";
import PixelSprite from "../../brand/PixelSprite";
import type { SpriteName } from "../../brand/spriteData";
import { useInView } from "./hooks";
import "../../styles/how.css";

function CountUp({ to, run, dur = 1500 }: { to: number; run: boolean; dur?: number }) {
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
  return <>{v.toLocaleString("en-US")}</>;
}

const TIERS: [number, string][] = [
  [1284, "assets discovered"],
  [82, "open findings after correlation"],
  [7, "attack paths worth your time"],
  [1, "fix to make first"],
];

const STEPS: { icon: SpriteName; title: string; body: string }[] = [
  { icon: "spyglass", title: "Discover", body: "Finds your internet-facing assets from public sources and the ones you add." },
  { icon: "compass", title: "Correlate", body: "Matches them against vulnerability and threat feeds to see what is really exposed." },
  { icon: "lighthouse", title: "Prioritise", body: "Traces the paths an attacker would take and ranks them by what they reach." },
  { icon: "key", title: "Fix", body: "Sends each path to its owner with the fix and a deadline, then re-checks." },
];

/** "How it works": the whole idea as one funnel, then the four steps. */
export default function HowItWorks() {
  const [fRef, fIn] = useInView<HTMLDivElement>(0.3);
  const [sRef, sIn] = useInView<HTMLDivElement>(0.2);
  return (
    <section className="lp-how" id="product">
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">How it works</span>
        <h2>Thousands of assets. One thing to fix first.</h2>
      </div>

      <div className={`how-fun${fIn ? " in" : ""}`} ref={fRef}>
        <div className="how-funnel" aria-hidden="true" />
        <ol className="how-tiers">
          {TIERS.map(([n, label], i) => (
            <li key={label} className={i === TIERS.length - 1 ? "hot" : ""} style={{ transitionDelay: `${250 + i * 220}ms` }}>
              <b><CountUp to={n} run={fIn} /></b>
              <span>{label}</span>
            </li>
          ))}
        </ol>
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
