import { useEffect, useRef } from "react";
import { HORSE_COLS, HORSE_FRAMES, HORSE_ROWS, decodeFrame } from "./horseFrames";
import { ramp } from "./PixelField";

/**
 * A strip of film: Muybridge's eleven plates as dot-matrix silhouettes in
 * sprocketed frames, each tinted along the patina-to-ember ramp, scrolling
 * slowly. Drawn once to a canvas (twice the strip, for a seamless loop).
 */
const FRAMES = HORSE_FRAMES.map(decodeFrame);
const PW = 300; // plate width, css px
const PH = 190;
const GAP = 14;
const BAND = 26; // film border top/bottom

export default function PlateStrip({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const unit = PW + GAP;
    const total = unit * FRAMES.length;
    const W = total * 2;
    const H = PH + BAND * 2;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // film base
    ctx.fillStyle = "#0a0807";
    ctx.fillRect(0, 0, W, H);

    const cell = PW / HORSE_COLS;
    for (let rep = 0; rep < 2; rep++) {
      FRAMES.forEach((f, idx) => {
        const x0 = rep * total + idx * unit;
        const y0 = BAND;
        // plate paper: sepia radial
        const g = ctx.createRadialGradient(x0 + PW * 0.6, y0 + PH * 0.3, 10, x0 + PW / 2, y0 + PH / 2, PW * 0.75);
        const k = idx / (FRAMES.length - 1);
        const [r, gg, b] = ramp(0.2 + k * 0.6);
        g.addColorStop(0, `rgba(${(r * 0.55) | 0},${(gg * 0.5) | 0},${(b * 0.45) | 0},1)`);
        g.addColorStop(1, "#14100d");
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.roundRect(x0, y0, PW, PH, 6);
        ctx.fill();
        // horse as dots
        const oy = y0 + (PH - HORSE_ROWS * cell * 1.2) / 2;
        for (let j = 0; j < HORSE_ROWS; j++) {
          for (let i = 0; i < HORSE_COLS; i++) {
            if (!f[j * HORSE_COLS + i]) continue;
            ctx.fillStyle = "rgba(236,226,208,0.9)";
            ctx.fillRect(x0 + i * cell, oy + j * cell * 1.2, Math.max(1, cell - 0.5), Math.max(1, cell * 1.2 - 0.5));
          }
        }
        // plate label
        ctx.font = "10px 'JetBrains Mono', ui-monospace, monospace";
        ctx.fillStyle = "rgba(236,226,208,0.55)";
        ctx.fillText(`PLATE ${String(idx + 1).padStart(2, "0")}`, x0 + 12, y0 + PH - 12);
        ctx.fillText("1878", x0 + PW - 40, y0 + PH - 12);
        // sprocket holes
        ctx.fillStyle = "#1d1814";
        for (let sx = x0 + 6; sx < x0 + PW; sx += 24) {
          ctx.beginPath();
          ctx.roundRect(sx, 7, 12, 11, 2);
          ctx.roundRect(sx, H - 18, 12, 11, 2);
          ctx.fill();
        }
      });
    }
  }, []);
  return (
    <div className={className} aria-hidden="true">
      <canvas ref={ref} className="lp-film-canvas" />
    </div>
  );
}
