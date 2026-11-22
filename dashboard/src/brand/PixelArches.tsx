import { useEffect, useRef } from "react";
import { hash, ramp } from "./PixelField";

/**
 * A pixel-art ruined arcade at dusk, painted once in 6px cells: a dithered sky glowing from the
 * horizon (blue to ember), a low sun, two receding rows of arches with broken tops and a lit left
 * edge, a flagstone floor, rubble, and a few birds. Variants move the arches and the sun.
 */
const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];
const LUT = (() => {
  const t = new Uint8Array(256 * 3);
  for (let i = 0; i < 256; i++) { const [r, g, b] = ramp(i / 255); t[i * 3] = r; t[i * 3 + 1] = g; t[i * 3 + 2] = b; }
  return t;
})();

export type ArchVariant = "dusk" | "dawn";

interface Row { n: number; span: number; pier: number; height: number; x0: number; tone: number; seed: number; ruin: number }

export default function PixelArches({ className, variant = "dusk", cell = 6 }: { className?: string; variant?: ArchVariant; cell?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const paint = () => {
      const w = canvas.clientWidth, h = canvas.clientHeight;
      if (!w || !h) return;
      const phone = w < 720;
      const cs = phone ? 5 : cell;
      const cols = Math.ceil(w / cs), rows = Math.ceil(h / cs);
      const small = document.createElement("canvas");
      small.width = cols; small.height = rows;
      const sctx = small.getContext("2d");
      const ctx = canvas.getContext("2d");
      if (!sctx || !ctx) return;
      const img = sctx.createImageData(cols, rows);
      const px = img.data;
      const put = (i: number, j: number, r: number, g: number, b: number) => {
        if (i < 0 || j < 0 || i >= cols || j >= rows) return;
        const o = (j * cols + i) * 4; px[o] = r; px[o + 1] = g; px[o + 2] = b; px[o + 3] = 255;
      };
      const mirror = false;
      const dawn = variant === "dawn";
      const X = (i: number) => (mirror ? cols - 1 - i : i);

      const floor = Math.round(rows * 0.84);
      const hy = Math.round(rows * 0.62);
      const sunX = Math.round(cols * (dawn ? 0.74 : 0.7)), sunY = hy - Math.round(rows * (dawn ? 0.2 : 0.14)), sunR = phone ? 4 : 6;

      // background
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) put(i, j, 14, 12, 10);
      // sky glow
      for (let j = 0; j < hy; j++) {
        const dep = (hy - j) / hy, g = Math.exp(-dep * 1.9);
        for (let i = 0; i < cols; i++) {
          const x = i / cols, near = Math.exp(-Math.pow((i - sunX) / (cols * 0.34), 2));
          const lit = g * (0.6 + 0.7 * near) * 2.2 - (BAYER[(j & 3) * 4 + (i & 3)] / 16 * 0.55 + hash(i, j) * 0.45) * 0.5;
          if (lit <= 0.03) continue;
          const ti = Math.round((mirror ? 0.12 + 0.74 * (1 - x) : 0.12 + 0.74 * x) * 255);
          const k = Math.min(1, lit * 1.4);
          put(i, j, LUT[ti * 3] * k, LUT[ti * 3 + 1] * k, LUT[ti * 3 + 2] * k);
        }
      }
      // sun
      for (let j = sunY - sunR * 3; j <= sunY + sunR * 3; j++) for (let i = sunX - sunR * 3; i <= sunX + sunR * 3; i++) {
        const d = Math.hypot(i - sunX, j - sunY);
        if (d <= sunR) put(i, j, 252, 232 - d * 4, 196 - d * 9);
        else if (d < sunR * 3 && (1 - (d - sunR) / (sunR * 2)) * 0.9 > BAYER[(j & 3) * 4 + (i & 3)] / 16 * 0.8 + hash(i, j) * 0.3) put(i, j, 236, 170, 120);
      }
      // sea band between horizon and floor
      for (let j = hy; j < floor; j++) for (let i = 0; i < cols; i++) {
        const dep = (j - hy) / Math.max(1, floor - hy);
        const streak = hash(Math.floor(i / 5) + j * 7, j) ;
        if (streak > 0.78 - dep * 0.1) { const ti = Math.round((0.15 + 0.7 * (mirror ? 1 - i / cols : i / cols)) * 255); const k = 0.22 * (1 - dep * 0.6); put(i, j, LUT[ti * 3] * k, LUT[ti * 3 + 1] * k, LUT[ti * 3 + 2] * k); }
        if (j === hy) put(i, j, 150, 120, 96);
      }
      // arcades: far row (hazy, blue-grey) then near row (dark, ember-rimmed)
      const rowsDef: Row[] = [
        { n: 8, span: phone ? 8 : 11, pier: 3, height: Math.round(rows * 0.5), x0: cols * (dawn ? 0.5 : 0.52), tone: 0, seed: 3, ruin: 0.3 },
        { n: phone ? 3 : 3, span: phone ? 11 : 15, pier: phone ? 5 : 6, height: Math.round(rows * (dawn ? 0.62 : 0.68)), x0: cols * (dawn ? 0.6 : (phone ? 0.42 : 0.64)), tone: 1, seed: dawn ? 21 : 11, ruin: dawn ? 0.4 : 0.5 },
      ];
      const solid = new Uint8Array(cols * rows);
      for (const R of rowsDef) {
        const m = new Uint8Array(cols * rows);
        const unit = R.span + R.pier;
        for (let k = 0; k < R.n; k++) {
          const px0 = Math.round(R.x0 + k * unit), cx = px0 + R.pier + R.span / 2, r = R.span / 2;
          const spring = floor - R.height + Math.round(r) + 3, top = spring - Math.round(r) - 3;
          // ruin: each pier loses its top below a jagged break line
          const broken = hash(k, R.seed) < R.ruin;
          const cut = broken ? top + Math.round((0.15 + hash(k, R.seed + 5) * 0.55) * R.height) : top;
          for (let j = top; j < floor; j++) for (let ii = px0; ii < px0 + unit; ii++) {
            let on: boolean;
            if (ii < px0 + R.pier) on = true;                                   // pier
            else {
              const dx = ii + 0.5 - cx;
              const archY = j >= spring ? Infinity : spring - Math.sqrt(Math.max(0, r * r - dx * dx));
              on = j < archY - (j < spring ? 0 : 0) && j < spring && j < archY;   // wall above the arch curve
              if (j < top + 3) on = true;                                         // entablature
              if (j >= spring) on = false;                                        // the opening
            }
            if (!on) continue;
            if (broken && j < cut + (ii % 3 === 0 ? 2 : 0) + Math.round(hash(ii, R.seed) * 3)) continue;
            m[j * cols + ii] = 1;
          }
          // fallen blocks on the floor
          for (let n = 0; n < 4; n++) { const bx = px0 + Math.round(hash(k * 9 + n, R.seed + 2) * unit), by = floor - 1 - Math.round(hash(n, k + R.seed) * 2); if (bx >= 0 && bx < cols) { m[by * cols + bx] = 1; m[by * cols + bx + 1] = 1; } }
        }
        for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
          if (!m[j * cols + i] || (R.tone === 0 && solid[j * cols + i])) continue;
          const left = i > 0 && !m[j * cols + i - 1], top = j > 0 && !m[(j - 1) * cols + i];
          const n = hash(i >> 1, j >> 1);
          if (R.tone === 0) {
            const v = 34 + n * 10, k2 = j / rows;
            put(i, j, v + 8 - k2 * 8, v + 16 - k2 * 6, v + 26 - k2 * 4);        // far: cool haze
            if (left) put(i, j, 90, 80, 78);
          } else {
            const course = (j % 6 === 0) || ((i + (Math.floor(j / 6) % 2) * 3) % 7 === 0 && j % 6 < 5);
            const v = 14 + n * 10 - (course ? 6 : 0);
            put(i, j, v + 4, v + 1, v - 3);                                       // near: warm black stone
            if (left) put(i, j, 210, 112, 76);                                    // lit left edge
            else if (top) put(i, j, 150, 84, 58);                                 // lit top edge
            else if (i > 0 && !m[j * cols + i - 1 + 0] ) put(i, j, 90, 52, 36);
          }
          solid[j * cols + i] = 1;
        }
      }
      // floor: flagstones with a lit edge
      for (let j = floor; j < rows; j++) for (let i = 0; i < cols; i++) {
        const row = j - floor, flag = row % 4 === 0 || (i + (Math.floor(row / 4) % 2) * 5) % 10 === 0;
        const v = 16 + hash(i >> 1, j) * 8 - (flag ? 7 : 0) - row * 0.5;
        put(i, j, Math.max(6, v + 4), Math.max(5, v), Math.max(4, v - 3));
        if (row === 0) put(i, j, 170, 96, 66);
      }

      // draw: mirror by flipping horizontally if needed (done via X when painting would be heavy), so flip the buffer
      sctx.putImageData(img, 0, 0);
      canvas.width = Math.round(w); canvas.height = Math.round(h);
      ctx.imageSmoothingEnabled = false;
      ctx.save();
      if (mirror) { ctx.translate(w, 0); ctx.scale(-1, 1); }
      ctx.drawImage(small, 0, 0, cols * cs, rows * cs);
      ctx.restore();
      ctx.globalCompositeOperation = "destination-out";
      for (let i = 1; i <= cols; i++) ctx.fillRect(i * cs - 1, 0, 1, rows * cs);
      for (let j = 1; j <= rows; j++) ctx.fillRect(0, j * cs - 1, cols * cs, 1);
      ctx.globalCompositeOperation = "destination-over";
      ctx.fillStyle = "#0e0c0a"; ctx.fillRect(0, 0, w, h);
      ctx.globalCompositeOperation = "source-over";
      void X;
    };
    paint();
    let t = 0;
    const on = () => { window.clearTimeout(t); t = window.setTimeout(paint, 140); };
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("resize", on); window.clearTimeout(t); };
  }, [variant, cell]);
  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
