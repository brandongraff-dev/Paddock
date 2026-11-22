import { useEffect, useRef } from "react";
import { hash, ramp } from "./PixelField";
import { RIDER_H, RIDER_RUNS, RIDER_W } from "./riderData";

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

export default function FooterScene({ className, cell = 5 }: { className?: string; cell?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

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

      const hy = Math.round(rows * (phone ? 0.58 : 0.66));        // horizon row
      const cliffX = Math.round(cols * (phone ? 0.5 : 0.66));    // cliff face start (at ledge)
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
          const near = Math.max(Math.exp(-Math.pow((i - orbX) / (cols * 0.3), 2)), Math.exp(-Math.pow((i - (cliffX + 14)) / (cols * 0.22), 2)));
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

      // cliff: stepped, jagged face; rock is dark with fine blocks and a lit left edge
      const edge = (j: number) => cliffX + Math.round((j - ledge) * 0.32 + (vnoise(j * 0.35, 3.7) - 0.5) * 5 - (j > hy + 6 ? (j - hy - 6) * 0.1 : 0));
      for (let j = ledge; j < rows; j++) {
        const e = edge(j);
        for (let i = Math.max(0, e); i < cols; i++) {
          const course = Math.floor((j - ledge) / 5);
          const joint = hash(Math.floor(i / 7) + course * 13, course) > 0.5 ? 3 : 0;
          const seam = (j - ledge) % 5 === 0 || ((i + joint) % 7 === 0 && (j - ledge) % 5 < 4);
          const tone = 20 + hash(i >> 1, j >> 1) * 12 + (seam ? -8 : 0);
          put(i, j, tone + 4, tone, tone - 4);
          const d = i - e;
          if (d >= 0 && d < 2) put(i, j, 150, 82, 56, 0.55 - d * 0.25);       // rim lit by the glow
        }
        if (j === ledge) for (let i = Math.max(0, e - 1); i < cols; i++) put(i, j, 120, 90, 70, 0.5);
      }
      // ruined columns on the cliff (far right), fluted, of different heights
      const colTop = (n: number) => ledge - [26, 17, 21][n];
      [0, 1, 2].forEach((n) => {
        const cx = Math.round(cols * (phone ? 0.86 + n * 0.045 : 0.82 + n * 0.065));
        const wcol = phone ? 3 : 5;
        for (let j = colTop(n); j < ledge; j++) {
          for (let i = cx; i < cx + wcol; i++) {
            const fl = (i - cx) % 2 === 0 ? 0 : 6;
            const t = 34 + fl + hash(i, j >> 1) * 8 - (j - colTop(n)) * 0.12;
            put(i, j, t + 6, t, t - 6);
          }
          put(cx, j, 120, 72, 52, 0.35);
        }
        for (let i = cx - 1; i < cx + wcol + 1; i++) { put(i, colTop(n), 52, 46, 40); put(i, colTop(n) - 1, 44, 38, 32); } // capital
        for (let i = cx - 1; i < cx + wcol + 1; i++) put(i, ledge - 1, 48, 42, 36);                                         // base
      });

      // rider: dark silhouette on the ledge, facing the sea, rim-lit on the sun side
      const rs = phone ? 1 : 1;
      const rw = Math.round(RIDER_W * rs), rh = Math.round(RIDER_H * rs);
      const rx0 = cliffX + 2, ry0 = ledge - rh + 1;
      const solid = new Set<number>();
      for (const [y, x, len] of RIDER_RUNS) {
        for (let k = 0; k < len; k++) {
          const sx = Math.round((x + k) * rs), sy = Math.round(y * rs);
          solid.add(sy * rw + sx);
        }
      }
      for (const key of solid) {
        const sy = Math.floor(key / rw), sx = key % rw;
        const i = rx0 + sx, j = ry0 + sy;
        const left = !solid.has(key - 1), top = !solid.has(key - rw);
        if (left || top) put(i, j, 8, 7, 6), put(i, j, 255, 190, 140, left ? 0.7 : 0.5);
        else put(i, j, 8, 7, 6);
      }

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
    };
    paint();
    let t = 0;
    const on = () => { window.clearTimeout(t); t = window.setTimeout(paint, 120); };
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("resize", on); window.clearTimeout(t); };
  }, [cell]);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
