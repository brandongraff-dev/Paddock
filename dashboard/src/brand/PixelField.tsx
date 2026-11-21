import { useEffect, useRef } from "react";

/**
 * PixelField — a dithered dot-matrix aurora.
 *
 * A diagonal band of light (patina blue → pale cream → ember → sepia black)
 * is sampled on a coarse grid; every cell is quantised through an ordered
 * (Bayer) threshold plus per-cell noise, so the gradient dissolves into
 * speckled pixels, the way a halftone plate breaks at its edges. Colours come
 * from the Daguerreotype tokens, not neon.
 */

const BAYER8 = [
  [0, 32, 8, 40, 2, 34, 10, 42],
  [48, 16, 56, 24, 50, 18, 58, 26],
  [12, 44, 4, 36, 14, 46, 6, 38],
  [60, 28, 52, 20, 62, 30, 54, 22],
  [3, 35, 11, 43, 1, 33, 9, 41],
  [51, 19, 59, 27, 49, 17, 57, 25],
  [15, 47, 7, 39, 13, 45, 5, 37],
  [63, 31, 55, 23, 61, 29, 53, 21],
];

type RGB = [number, number, number];

/** Colour ramp across the band: position 0 (blue edge) … 1 (ember edge). */
const RAMP: { at: number; c: RGB }[] = [
  { at: 0.0, c: [18, 16, 14] },
  { at: 0.18, c: [48, 82, 108] },
  { at: 0.34, c: [95, 135, 160] },
  { at: 0.46, c: [182, 211, 227] },
  { at: 0.54, c: [236, 222, 196] },
  { at: 0.64, c: [233, 160, 110] },
  { at: 0.78, c: [213, 73, 60] },
  { at: 0.92, c: [92, 28, 22] },
  { at: 1.0, c: [18, 16, 14] },
];

export function ramp(t: number): RGB {
  if (t <= 0) return RAMP[0].c;
  for (let i = 1; i < RAMP.length; i++) {
    if (t <= RAMP[i].at) {
      const a = RAMP[i - 1];
      const b = RAMP[i];
      const k = (t - a.at) / (b.at - a.at);
      return [
        a.c[0] + (b.c[0] - a.c[0]) * k,
        a.c[1] + (b.c[1] - a.c[1]) * k,
        a.c[2] + (b.c[2] - a.c[2]) * k,
      ];
    }
  }
  return RAMP[RAMP.length - 1].c;
}

/** Cheap deterministic hash → [0,1). */
export function hash(x: number, y: number): number {
  let h = (x * 374761393 + y * 668265263) | 0;
  h = (h ^ (h >>> 13)) * 1274126177;
  return (((h ^ (h >>> 16)) >>> 0) % 100000) / 100000;
}

/** Smooth value noise for warping the band. */
function vnoise(x: number, y: number): number {
  const xi = Math.floor(x);
  const yi = Math.floor(y);
  const xf = x - xi;
  const yf = y - yi;
  const u = xf * xf * (3 - 2 * xf);
  const v = yf * yf * (3 - 2 * yf);
  const a = hash(xi, yi);
  const b = hash(xi + 1, yi);
  const c = hash(xi, yi + 1);
  const d = hash(xi + 1, yi + 1);
  return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
}

interface Props {
  /** Grid cell in CSS px (dot pitch). */
  cell?: number;
  /** Animate a slow drift. Ignored under prefers-reduced-motion. */
  animate?: boolean;
  /** Slide the band horizontally (fraction of width; negative = rightwards). */
  originX?: number;
  /** Lean toward the pointer and light up the dots around it. */
  interactive?: boolean;
  /** Render as a streaming wake pouring out leftwards from this point (0..1 canvas space). */
  wake?: { x: number; y: number };
  className?: string;
}

export default function PixelField({ cell = 5, animate = true, originX = 0, interactive = false, wake, className }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / no canvas: the CSS fallback gradient shows instead

    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let last = 0;
    let t0 = 0;
    // pointer in 0..1 canvas space (smoothed), plus presence 0..1
    const ptr = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5, on: 0, ton: 0 };

    const paint = (time: number) => {
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (!w || !h) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = "#0e0c0a";
      ctx.fillRect(0, 0, w, h);

      const cols = Math.ceil(w / cell);
      const rows = Math.ceil(h / cell);
      const drift = time * 0.00004;
      const lean = interactive ? (ptr.x - 0.5) * 0.12 : 0;
      const lift = interactive ? (ptr.y - 0.5) * 0.08 : 0;
      const aspect = w / h;
      const dot = Math.max(1, cell - 1.4);

      for (let j = 0; j < rows; j++) {
        for (let i = 0; i < cols; i++) {
          if (wake) {
            const rx = i / cols;
            const ry = j / rows;
            const dx = wake.x - rx;
            let envW = 0;
            let ttW = 0.5;
            if (dx > -0.05) {
              const dxc = Math.max(0, dx);
              const sway = (vnoise(dxc * 3.2 - time * 0.0006, 7.3) - 0.5) * 0.09;
              const center = wake.y - dxc * 0.32 + sway + lift * 0.5;
              const hw = 0.045 + 0.30 * Math.pow(dxc, 0.66);
              const off = (ry - center) / hw;
              if (Math.abs(off) < 1.5) {
                const core = Math.exp(-off * off * 1.5);
                const head = Math.min(1, (dx + 0.05) / 0.07);
                const sp = 0.6 + hash(j, 5) * 1.3;
                const streak = vnoise(i * 0.035 + time * 0.0011 * sp, j * 0.33);
                envW = core * Math.exp(-dxc * 0.85) * head * (0.45 + 1.1 * streak);
                ttW = Math.min(0.82, Math.max(0.12, 0.8 - dxc * 0.95 + off * 0.05));
              }
            }
            let litW = envW * 1.7 - (BAYER8[j & 7][i & 7] / 64 * 0.55 + hash(i, j) * 0.45) * 0.55;
            if (interactive && ptr.on > 0.01) {
              const ddx = (rx - ptr.x) * aspect;
              const ddy = ry - ptr.y;
              const d = Math.sqrt(ddx * ddx + ddy * ddy) / 0.22;
              if (d < 1) { litW += (1 - d) * (1 - d) * 0.8 * ptr.on; if (envW === 0) ttW = 0.5 + (rx - ptr.x) * 0.9; }
            }
            if (litW <= 0.02) continue;
            const [wr, wg, wb] = ramp(ttW);
            const wk = Math.min(1, litW * 1.5);
            ctx.fillStyle = `rgb(${(wr * wk) | 0},${(wg * wk) | 0},${(wb * wk) | 0})`;
            ctx.fillRect(i * cell, j * cell, dot, dot);
            continue;
          }
          const nx = i / cols - originX - lean;
          const ny = j / rows;
          // Band axis runs from upper-left to lower-right, ~28° off horizontal.
          const along = nx * 0.88 + ny * 1.1;
          const across = nx * -0.5 + ny * 1.0 - 0.18 - lift;
          const warp = (vnoise(i * 0.045 + drift * 90, j * 0.06) - 0.5) * 0.22;
          // Band centre line fades as it travels; width tapers toward the right.
          const profile = across + warp - 0.12 * Math.sin(along * 2.4 + drift * 60);
          const tt = 0.5 + profile * 1.9;
          const inBand = tt > 0 && tt < 1;
          if (!inBand && !(interactive && ptr.on > 0.01)) continue;
          // Brightness envelope: strong on the left, dying out to the right.
          const fade = Math.max(0, 1 - along * 0.62);
          const env = inBand ? Math.sin(tt * Math.PI) * fade : 0;
          // Ordered dither + noise decides whether this dot lights at all.
          const thr =
            (BAYER8[j & 7][i & 7] / 64) * 0.55 + hash(i, j) * 0.45;
          let lit = env * 1.25 - thr * 0.55;
          if (interactive && ptr.on > 0.01) {
            // a soft lens: dots near the pointer brighten and ignite even off-band
            const dx = (i / cols - ptr.x) * aspect;
            const dy = j / rows - ptr.y;
            const d = Math.sqrt(dx * dx + dy * dy) / 0.22;
            if (d < 1) lit += (1 - d) * (1 - d) * 0.9 * ptr.on * (0.5 + 0.5 * env + 0.3);
          }
          if (lit <= 0.02) continue;
          const [r, g, b] = ramp(inBand ? tt : 0.5 + ((i / cols - ptr.x) * 0.9));
          const k = Math.min(1, lit * 1.5);
          ctx.fillStyle = `rgb(${(r * k) | 0},${(g * k) | 0},${(b * k) | 0})`;
          ctx.fillRect(i * cell, j * cell, dot, dot);
        }
      }
    };

    const loop = (now: number) => {
      if (!t0) t0 = now;
      ptr.x += (ptr.tx - ptr.x) * 0.12;
      ptr.y += (ptr.ty - ptr.y) * 0.12;
      ptr.on += (ptr.ton - ptr.on) * 0.1;
      if (now - last > (interactive || wake ? 40 : 66)) {
        paint(now - t0);
        last = now;
      }
      raf = requestAnimationFrame(loop);
    };

    paint(0);
    const onResize = () => paint(last ? last - t0 : 0);
    window.addEventListener("resize", onResize);
    const onMove = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width;
      const y = (e.clientY - r.top) / r.height;
      const inside = x >= -0.05 && x <= 1.05 && y >= -0.05 && y <= 1.05;
      ptr.tx = Math.min(1, Math.max(0, x));
      ptr.ty = Math.min(1, Math.max(0, y));
      ptr.ton = inside ? 1 : 0;
    };
    const onLeave = () => { ptr.ton = 0; };
    if (interactive && !reduce) {
      window.addEventListener("pointermove", onMove, { passive: true });
      document.addEventListener("pointerleave", onLeave);
    }
    if ((animate || interactive || wake) && !reduce) raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
    };
  }, [cell, animate, originX, interactive, wake?.x, wake?.y]);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
