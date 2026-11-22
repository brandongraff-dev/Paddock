import { useEffect, useRef, useState } from "react";
import { useStickyProgress } from "./hooks";
import PixelSprite from "../../brand/PixelSprite";
import { STEPS } from "./HowItWorks";
import "../../styles/journey.css";

/**
 * Painted scroll journey. One wide illustration is the world; as you scroll, the camera
 * travels along the path through four stops (one per step). The world warms and brightens as
 * you go, mist drifts across it, and a glowing marker walks the route.
 *
 * STOPS are positions in the image (fractions of its width/height). Retune them when the
 * illustration changes: they are the only thing tied to the artwork.
 */
const IMAGE = "/journey.webp";
const STOPS: { x: number; y: number }[] = [
  { x: 0.12, y: 0.74 },
  { x: 0.36, y: 0.62 },
  { x: 0.62, y: 0.46 },
  { x: 0.86, y: 0.28 },
];
const ZOOM = 1.55;

const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const ease = (t: number) => t * t * (3 - 2 * t);

function pointAt(t: number) {
  const n = STOPS.length - 1;
  const f = Math.min(n - 1e-6, Math.max(0, t * n));
  const i = Math.floor(f);
  const k = ease(f - i);
  return { x: lerp(STOPS[i].x, STOPS[i + 1].x, k), y: lerp(STOPS[i].y, STOPS[i + 1].y, k) };
}

export default function PaintedJourney() {
  const [ref, p] = useStickyProgress<HTMLElement>();
  const stage = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState({ w: 1440, h: 900 });
  const [ratio, setRatio] = useState(2.4);

  useEffect(() => {
    const im = new Image();
    im.onload = () => setRatio(im.naturalWidth / im.naturalHeight);
    im.src = IMAGE;
  }, []);
  useEffect(() => {
    const el = stage.current;
    if (!el) return;
    const fit = () => setBox({ w: el.clientWidth, h: el.clientHeight });
    fit();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // image is sized to cover the stage at ZOOM, then panned so the camera point sits just above centre
  const baseH = Math.max(box.h, box.w / ratio);
  const imgH = baseH * ZOOM, imgW = imgH * ratio;
  const cam = pointAt(p);
  const tx = Math.min(0, Math.max(box.w - imgW, box.w * 0.5 - cam.x * imgW));
  const ty = Math.min(0, Math.max(box.h - imgH, box.h * 0.42 - cam.y * imgH));
  const active = Math.min(STEPS.length - 1, Math.round(p * (STEPS.length - 1)));
  const dark = 0.5 * (1 - ease(Math.min(1, p * 1.2)));            // the world brightens as you travel

  return (
    <section className="jr" id="how" ref={ref} aria-label="How it works">
      <div className="jr-stage" ref={stage}>
        <div className="jr-world" style={{ width: imgW, height: imgH, transform: `translate3d(${tx}px, ${ty}px, 0)` }}>
          <img src={IMAGE} alt="" decoding="async" draggable={false} />
          <div className="jr-mist m1" />
          <div className="jr-mist m2" />
          {STOPS.map((s, i) => (
            <div key={i} className={`jr-pin${i <= active ? " on" : ""}${i === active ? " now" : ""}`} style={{ left: `${s.x * 100}%`, top: `${s.y * 100}%` }}>
              <b>{i + 1}</b>
            </div>
          ))}
          <div className="jr-walker" style={{ left: `${cam.x * 100}%`, top: `${cam.y * 100}%` }} />
        </div>
        <div className="jr-shade" style={{ opacity: dark }} />
        <div className="jr-vignette" />

        <div className="jr-head">
          <span className="lp-eyebrow mono">How it works</span>
          <h2>From unknown to fixed in four steps.</h2>
        </div>

        <div className="jr-card" key={active}>
          <PixelSprite name={STEPS[active].icon} size={84} />
          <div>
            <span className="mono">0{active + 1} / 0{STEPS.length}</span>
            <h3>{STEPS[active].title}</h3>
            <p>{STEPS[active].body}</p>
          </div>
        </div>
        <ol className="jr-dots" aria-hidden="true">
          {STEPS.map((_, i) => <li key={i} className={i <= active ? "on" : ""} />)}
        </ol>
      </div>
    </section>
  );
}
