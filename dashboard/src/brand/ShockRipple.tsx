import { useEffect, useRef, type RefObject } from "react";
import { hash, ramp } from "./PixelField";

/**
 * Shockwaves through the pixel field. When `fire` flips true, rings of dither
 * dots expand from the wordmark's "o" at each landing (timed to wm-drop in
 * landing.css), cooling from ember to patina blue as they travel and fade.
 */
const IMPACTS = [
  { at: 1.54, power: 1, speed: 1250 },
  { at: 2.09, power: 0.6, speed: 950 },
];
const CELL = 6;

export default function ShockRipple({ fire, anchor, className }: { fire: boolean; anchor: RefObject<HTMLElement>; className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (!fire) return;
    const canvas = ref.current;
    const host = canvas?.parentElement;
    if (!canvas || !host) return;
    const reduce = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const size = () => {
      canvas.width = Math.round(host.clientWidth * dpr);
      canvas.height = Math.round(host.clientHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    size();

    const waves: { t0: number; cx: number; cy: number; power: number; speed: number }[] = [];
    const timers = IMPACTS.map((im) =>
      window.setTimeout(() => {
        const o = anchor.current?.querySelector(".wm-o")?.getBoundingClientRect();
        const hr = host.getBoundingClientRect();
        if (!o) return;
        waves.push({ t0: performance.now(), cx: o.left + o.width / 2 - hr.left, cy: o.top + o.height / 2 - hr.top, power: im.power, speed: im.speed });
      }, (im.at + 0.45) * 1000 - 450), // +0.45 css delay, measured from the mark entering view
    );

    let raf = 0;
    const DUR = 1.5;
    const frame = (now: number) => {
      const w = host.clientWidth, h = host.clientHeight;
      ctx.clearRect(0, 0, w, h);
      for (let k = waves.length - 1; k >= 0; k--) {
        const wv = waves[k];
        const age = (now - wv.t0) / 1000;
        if (age > DUR) { waves.splice(k, 1); continue; }
        const r = age * wv.speed;
        const thick = 46 + age * 70;
        const fade = Math.pow(1 - age / DUR, 1.6) * wv.power;
        const x0 = Math.max(0, Math.floor((wv.cx - r - thick) / CELL)), x1 = Math.min(Math.ceil(w / CELL), Math.ceil((wv.cx + r + thick) / CELL));
        const y0 = Math.max(0, Math.floor((wv.cy - r - thick) / CELL)), y1 = Math.min(Math.ceil(h / CELL), Math.ceil((wv.cy + r + thick) / CELL));
        for (let j = y0; j < y1; j++) {
          for (let i = x0; i < x1; i++) {
            const px = i * CELL + CELL / 2, py = j * CELL + CELL / 2;
            const d = Math.hypot(px - wv.cx, py - wv.cy);
            const off = Math.abs(d - r);
            if (off > thick) continue;
            const prof = 1 - off / thick;
            if (prof * fade * 1.5 < hash(i, j)) continue; // dither
            const tcol = 0.8 - Math.min(1, r / 900) * 0.65; // ember near the impact, blue far out
            const [cr, cg, cb] = ramp(tcol);
            ctx.fillStyle = `rgba(${cr | 0},${cg | 0},${cb | 0},${Math.min(1, prof * fade * 1.4)})`;
            ctx.fillRect(i * CELL, j * CELL, CELL - 1.4, CELL - 1.4);
          }
        }
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    window.addEventListener("resize", size);
    return () => {
      timers.forEach(clearTimeout);
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", size);
    };
  }, [fire, anchor]);
  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
