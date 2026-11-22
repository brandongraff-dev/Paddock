import { useEffect, useRef } from "react";
import { hash, ramp } from "./PixelField";

/**
 * Footer scene: a rider on horseback at the edge of a cliff, looking out over a
 * calm sea at a low sun. Painted once, in pixel cells and Paddock's blue-to-ember
 * palette, as a dark silhouette against a dithered glow.
 */
const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];
const LUT = (() => {
  const t = new Uint8Array(256 * 3);
  for (let i = 0; i < 256; i++) {
    const [r, g, b] = ramp(i / 255);
    t[i * 3] = r; t[i * 3 + 1] = g; t[i * 3 + 2] = b;
  }
  return t;
})();

function vnoise(x: number, y: number): number {
  const xi = Math.floor(x), yi = Math.floor(y);
  const xf = x - xi, yf = y - yi;
  const u = xf * xf * (3 - 2 * xf), v = yf * yf * (3 - 2 * yf);
  const a = hash(xi, yi), b = hash(xi + 1, yi), c = hash(xi, yi + 1), d = hash(xi + 1, yi + 1);
  return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
}

export default function FooterScene({ className, cell = 5, phoneHorizon = 0.58, parallax = false }: { className?: string; cell?: number; phoneHorizon?: number; parallax?: boolean }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const cliffRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const riderImg = useRef<HTMLImageElement | null>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const paint = () => {
      const w = canvas.clientWidth, h = canvas.clientHeight;
      if (!w || !h) return;
      const phone = w < 720;
      const cs = phone ? 3 : cell;
      wrapRef.current?.style.setProperty("--cs", `${cs}px`);
      const cols = Math.ceil(w / cs), rows = Math.ceil(h / cs);
      const small = document.createElement("canvas");
      small.width = cols; small.height = rows;
      const sctx = small.getContext("2d");
      if (!sctx) return;
      const img = sctx.createImageData(cols, rows);
      const px = img.data;
      const put = (i: number, j: number, r: number, g: number, b: number, a = 1) => {
        if (i < 0 || j < 0 || i >= cols || j >= rows) return;
        const o = (j * cols + i) * 4;
        if (a >= 1) { px[o] = r; px[o + 1] = g; px[o + 2] = b; px[o + 3] = 255; return; }
        const pa = px[o + 3] / 255;
        px[o] = px[o] * pa * (1 - a) + r * a; px[o + 1] = px[o + 1] * pa * (1 - a) + g * a; px[o + 2] = px[o + 2] * pa * (1 - a) + b * a; px[o + 3] = 255;
      };
      // background
      for (let o = 0; o < px.length; o += 4) { px[o] = 14; px[o + 1] = 12; px[o + 2] = 10; px[o + 3] = 255; }

      // illustration geometry (shared by the glow and the drawing): ledge sits near the horizon,
      // so the dark horse stands in front of the brightest part of the sky
      const rih = h * (phone ? 1.35 : 1.6);
      const riw = (rih * 783) / 1200;
      const rix = phone ? w * 0.62 - 0.4 * riw : w - riw * 0.78;
      const riy = h * (phone ? phoneHorizon + 0.02 : 0.62) - 0.19 * rih;
      const horseCol = Math.round((rix + riw * 0.24) / cs);
      const hy = Math.round(rows * (phone ? phoneHorizon : 0.66));        // horizon row
      const cliffX = Math.round(cols * (phone ? 0.44 : 0.63));    // cliff face start (at ledge)
      const ledge = hy - Math.round(rows * 0.035);                // ledge row
      const orbX = Math.round(cols * (phone ? 0.3 : 0.5));
      const orbY = Math.round(hy - rows * (phone ? 0.2 : 0.36));
      const orbR = phone ? 5 : 6;

      // sky glow: strongest at the horizon, dithered upward, blue on the left to ember on the right
      for (let j = 0; j < hy; j++) {
        const dep = (hy - j) / hy;
        const g = Math.exp(-dep * 3.4);
        for (let i = 0; i < cols; i++) {
          const x = i / cols;
          const near = Math.max(Math.exp(-Math.pow((i - orbX) / (cols * 0.3), 2)), Math.exp(-Math.pow((i - horseCol) / (cols * 0.14), 2)) * 1.25);
          const lit = (g * (0.5 + 0.75 * near) * 2.2) - (BAYER[(j & 3) * 4 + (i & 3)] / 16 * 0.55 + hash(i, j) * 0.45) * 0.5;
          if (lit <= 0.02) continue;
          const li = ((0.12 + 0.74 * x) * 255) | 0;
          const k = Math.min(1, lit * 1.5);
          put(i, j, LUT[li * 3] * k, LUT[li * 3 + 1] * k, LUT[li * 3 + 2] * k);
        }
      }
      // sun: cream disc with a dithered halo
      for (let j = orbY - orbR * 3; j <= orbY + orbR * 3; j++) {
        for (let i = orbX - orbR * 3; i <= orbX + orbR * 3; i++) {
          const dd = Math.hypot(i - orbX, (j - orbY) * 1.0);
          if (dd <= orbR) {
            const t = dd / orbR;
            put(i, j, 255 - t * 20, 238 - t * 62, 205 - t * 100);
          } else if (dd < orbR * 3) {
            const f = 1 - (dd - orbR) / (orbR * 2);
            if (f * 0.9 > BAYER[(j & 3) * 4 + (i & 3)] / 16 * 0.8 + hash(i, j) * 0.3) put(i, j, 232, 160, 110, 0.55 * f);
          }
        }
      }
      // sea
      for (let j = hy; j < rows; j++) {
        const dep = (j - hy) / Math.max(1, rows - hy);
        for (let i = 0; i < cols; i++) {
          const x = i / cols;
          const streak = vnoise(i * 0.045 + j * 5.1, j * 0.9);
          const lit = (1 - dep * 0.85) * (streak - 0.42) * 2.4 - (BAYER[(j & 3) * 4 + (i & 3)] / 16) * 0.35;
          if (lit > 0.03) {
            const li = ((0.14 + 0.72 * x) * 255) | 0;
            const k = Math.min(1, lit) * 0.46;
            put(i, j, LUT[li * 3] * k, LUT[li * 3 + 1] * k, LUT[li * 3 + 2] * k);
          }
          // the sun's reflection: a column of short bright dashes
          const rd = Math.abs(i - orbX);
          if (rd < 2 + dep * 7 && streak > 0.5 && ((j + (i >> 1)) & 1) === 0 && hash(i, j) > dep * 0.9) put(i, j, 240, 190, 140, 0.5 * (1 - dep));
        }
      }
      for (let i = 0; i < cols; i++) put(i, hy, 230, 190, 150, 0.55);          // horizon line

      ctx.imageSmoothingEnabled = false;
      canvas.width = Math.round(w);
      canvas.height = Math.round(h);
      sctx.putImageData(img, 0, 0);
      ctx.drawImage(small, 0, 0, cols * cs, rows * cs);
      // carve the dot gaps so it reads as the same pixel language as the rest of the site
      ctx.globalCompositeOperation = "destination-out";
      for (let i = 1; i <= cols; i++) ctx.fillRect(i * cs - 1, 0, 1, rows * cs);
      for (let j = 1; j <= rows; j++) ctx.fillRect(0, j * cs - 1, cols * cs, 1);
      ctx.globalCompositeOperation = "destination-over";
      ctx.fillStyle = "#0e0c0a";
      ctx.fillRect(0, 0, w, h);
      ctx.globalCompositeOperation = "source-over";

      // ---- solid art: a tall generated cliff with a rider, anchored right at full height ----
      const cc = cliffRef.current;
      const cctx = cc ? cc.getContext("2d") : null;
      if (cc && cctx) { cc.width = Math.round(w); cc.height = Math.round(h) + 40; cctx.clearRect(0, 0, cc.width, cc.height); }
      const ri = riderImg.current;
      if (cctx && ri && ri.complete && ri.naturalWidth) {
        // cropped in: the rider is large, the ruins and bottom of the cliff run off the frame
        const ih = rih, iw = riw, ix = rix, iy = riy;
        // tone the illustration down on its own layer so it sits in the scene
        const layer = document.createElement("canvas");
        layer.width = Math.ceil(iw); layer.height = Math.ceil(ih);
        const lc = layer.getContext("2d");
        if (lc) {
          lc.drawImage(ri, 0, 0, layer.width, layer.height);
          lc.globalCompositeOperation = "source-atop";
          lc.fillStyle = "rgba(10, 7, 5, 0.34)"; lc.fillRect(0, 0, layer.width, layer.height);       // overall dim
          const fade = lc.createLinearGradient(0, 0, 0, layer.height);
          fade.addColorStop(0, "rgba(10,7,5,0)"); fade.addColorStop(1, "rgba(8,6,5,0.5)");           // deeper toward the base
          lc.fillStyle = fade; lc.fillRect(0, 0, layer.width, layer.height);
          lc.fillStyle = "rgba(60, 30, 16, 0.10)"; lc.fillRect(0, 0, layer.width, layer.height);     // warm the shadows a touch
          cctx.drawImage(layer, ix, iy);
        } else cctx.drawImage(ri, ix, iy, iw, ih);
      }
    };
    const im = new Image();
    im.onload = () => paint();
    im.src = "/cliff-final.webp";
    riderImg.current = im;
    paint();
    let t = 0;
    const on = () => { window.clearTimeout(t); t = window.setTimeout(paint, 120); };
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("resize", on); window.clearTimeout(t); };
  }, [cell, phoneHorizon]);

  // scroll-tied depth: the cliff rises into place and the sky brightens as the footer arrives
  useEffect(() => {
    if (!parallax) return;
    const reduce = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const wrap = wrapRef.current, sky = ref.current, cliff = cliffRef.current;
    if (!wrap || !sky || !cliff || reduce) return;
    let raf = 0;
    const apply = () => {
      raf = 0;
      const r = wrap.getBoundingClientRect();
      const vh = window.innerHeight;
      const p = Math.min(1, Math.max(0, (vh - r.top) / (Math.min(r.height, vh) * 0.9)));
      const e = 1 - Math.pow(1 - p, 3);
      cliff.style.transform = `translate3d(0, ${((1 - e) * 36).toFixed(1)}px, 0)`;
      sky.style.opacity = (0.55 + 0.45 * e).toFixed(3);
    };
    const on = () => { if (!raf) raf = requestAnimationFrame(apply); };
    apply();
    window.addEventListener("scroll", on, { passive: true });
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("scroll", on); window.removeEventListener("resize", on); if (raf) cancelAnimationFrame(raf); };
  }, [parallax]);

  return (
    <div ref={wrapRef} className={className} aria-hidden="true" style={{ overflow: "hidden" }}>
      <canvas ref={ref} className="scene-sky" />
      <canvas ref={cliffRef} className="scene-cliff" />
      <div className="scene-grid" />
    </div>
  );
}
