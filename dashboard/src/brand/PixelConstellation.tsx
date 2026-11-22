import { useEffect, useRef } from "react";
import { hash } from "./PixelField";

/**
 * A pixel star field with a soft blue haze and a path of linked nodes ending in one ember point
 * (the thing to fix first). Painted once, in 6px cells. Variants change the haze and the path.
 */
const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];
const BL: [number, number, number][] = [[18, 34, 52], [40, 86, 120], [96, 152, 186], [190, 218, 232], [244, 239, 227]];
function ramp(t: number): [number, number, number] {
  const k = Math.max(0, Math.min(1, t)) * (BL.length - 1);
  const i = Math.min(BL.length - 2, Math.floor(k)), f = k - i;
  return [BL[i][0] + (BL[i + 1][0] - BL[i][0]) * f, BL[i][1] + (BL[i + 1][1] - BL[i][1]) * f, BL[i][2] + (BL[i + 1][2] - BL[i][2]) * f];
}
function vn(x: number, y: number) {
  const xi = Math.floor(x), yi = Math.floor(y), xf = x - xi, yf = y - yi;
  const u = xf * xf * (3 - 2 * xf), v = yf * yf * (3 - 2 * yf);
  const a = hash(xi, yi), b = hash(xi + 1, yi), c = hash(xi, yi + 1), d = hash(xi + 1, yi + 1);
  return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
}
const fbm = (x: number, y: number) => vn(x, y) * 0.55 + vn(x * 2.1, y * 2.1) * 0.3 + vn(x * 4.3, y * 4.3) * 0.15;

export type ConstellationVariant = "path" | "rules" | "card";
const VARIANTS = {
  path: { haze: [0.72, 0.5], seed: 4, nodes: [[0.5, 0.8], [0.64, 0.55], [0.78, 0.66], [0.9, 0.3]] },
  rules: { haze: [0.78, 0.46], seed: 17, nodes: [[0.56, 0.3], [0.7, 0.52], [0.62, 0.76], [0.86, 0.7], [0.93, 0.34]] },
  card: { haze: [0.5, 0.5], seed: 9, nodes: [] },
} as const;

export default function PixelConstellation({ className, variant = "path", cell = 6 }: { className?: string; variant?: ConstellationVariant; cell?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const paint = () => {
      const w = canvas.clientWidth, h = canvas.clientHeight;
      if (!w || !h) return;
      const cs = w < 720 ? 5 : cell;
      const cols = Math.ceil(w / cs), rows = Math.ceil(h / cs);
      canvas.width = Math.round(w); canvas.height = Math.round(h);
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.clearRect(0, 0, w, h);
      const V = VARIANTS[variant];
      const px = (i: number, j: number, r: number, g: number, b: number, a = 1) => {
        if (i < 0 || j < 0 || i >= cols || j >= rows) return;
        ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${a})`;
        ctx.fillRect(i * cs, j * cs, cs - 1, cs - 1);
      };
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
        const x = i / cols, y = j / rows;
        const neb = fbm(i * 0.03 + V.seed, j * 0.05 + V.seed * 0.4) * Math.exp(-Math.pow((x - V.haze[0]) / (variant === "card" ? 0.5 : 0.34), 2)) * Math.exp(-Math.pow((y - V.haze[1]) / 0.5, 2));
        if (neb > 0.12 && neb * 2.2 > (BAYER[(j & 3) * 4 + (i & 3)] / 16) * 0.6 + hash(i, j) * 0.5) { const [r, g, b] = ramp(0.1 + neb * 1.3); px(i, j, r, g, b, 0.55); }
        if (hash(i * 3 + 1, j * 7 + 2) > 0.992) {
          const br = hash(i, j * 5), [r, g, b] = ramp(0.5 + br * 0.6);
          px(i, j, r, g, b, 0.8);
          if (br > 0.8) { px(i + 1, j, r, g, b, 0.4); px(i - 1, j, r, g, b, 0.4); px(i, j + 1, r, g, b, 0.4); px(i, j - 1, r, g, b, 0.4); }
        }
      }
      const P = (V.nodes as readonly (readonly number[])[]).map(([x, y]) => [Math.round(x * cols), Math.round(y * rows)] as const);
      for (let n = 0; n < P.length - 1; n++) {
        const [a, b] = P[n], [c, d] = P[n + 1], L = Math.hypot(c - a, d - b);
        for (let t = 0; t <= L; t++) if (t % 3 < 2) px(Math.round(a + ((c - a) * t) / L), Math.round(b + ((d - b) * t) / L), 150, 190, 215, 0.8);
      }
      P.forEach(([i, j], n) => {
        const last = n === P.length - 1, col: [number, number, number] = last ? [232, 105, 74] : [244, 239, 227];
        for (let dj = -2; dj <= 2; dj++) for (let di = -2; di <= 2; di++) if (Math.abs(di) + Math.abs(dj) <= 2) px(i + di, j + dj, ...col);
      });
    };
    paint();
    let t = 0;
    const on = () => { window.clearTimeout(t); t = window.setTimeout(paint, 140); };
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("resize", on); window.clearTimeout(t); };
  }, [variant, cell]);
  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
