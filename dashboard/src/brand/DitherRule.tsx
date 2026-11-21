import { useEffect, useRef } from "react";
import { hash, ramp } from "./PixelField";

const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];

/** A thin horizontal band of dithered dots, blue to ember, fading top to bottom. */
export default function DitherRule({ className, rows = 9, cell = 5 }: { className?: string; rows?: number; cell?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const draw = () => {
      const w = canvas.clientWidth;
      if (!w) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const h = rows * cell;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const cols = Math.ceil(w / cell);
      for (let j = 0; j < rows; j++) {
        const density = 1 - j / rows; // dense at the top edge, dissolving downward
        for (let i = 0; i < cols; i++) {
          const x = i / cols;
          const wave = 0.5 + 0.5 * Math.sin(x * 9 + hash(i >> 3, 3) * 2);
          const thr = BAYER[(j & 3) * 4 + (i & 3)] / 16 * 0.6 + hash(i, j) * 0.4;
          if (density * (0.55 + 0.45 * wave) <= thr) continue;
          const [r, g, b] = ramp(0.12 + x * 0.7);
          ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${0.85 - j * 0.07})`;
          ctx.fillRect(i * cell, j * cell, cell - 1.3, cell - 1.3);
        }
      }
    };
    draw();
    window.addEventListener("resize", draw);
    return () => window.removeEventListener("resize", draw);
  }, [rows, cell]);
  return <canvas ref={ref} className={className} style={{ width: "100%", height: rows * cell, display: "block" }} aria-hidden="true" />;
}
