import { useEffect, useRef } from "react";
import { HORSE_COLS, HORSE_ROWS } from "./horseFrames";
import { ramp } from "./PixelField";

/**
 * The ground the horse runs on: three parallax rows of pixel dashes streaming
 * past, and dust kicked up at the hooves that cools from ember to patina blue
 * as it drifts back. Sits under <DigitHorse/> in the same box, using the same
 * grid fit so the ground line meets the hooves.
 */
export default function GallopTrail({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce =
      typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let w = 0, h = 0, dpr = 1, cw = 1, ch = 1, ox = 0, groundY = 0, raf = 0, last = 0;
    const parts: { x: number; y: number; vx: number; vy: number; life: number; ttl: number; s: number }[] = [];

    const layout = () => {
      const r = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = Math.max(1, r.width);
      h = Math.max(1, r.height);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // identical fit to DigitHorse so the hooves line up
      cw = Math.min(w / HORSE_COLS, h / (HORSE_ROWS * 1.61));
      ch = cw * 1.61;
      ox = (w - cw * HORSE_COLS) / 2;
      const oy = (h - ch * HORSE_ROWS) / 2;
      groundY = oy + ch * (HORSE_ROWS - 0.5);
    };

    const LAYERS = [
      { dy: -3, speed: 560, dash: 30, gap: 40, a: 0.75, s: 3 },
      { dy: 2, speed: 340, dash: 16, gap: 56, a: 0.4, s: 2.4 },
    ];

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
      last = now;
      ctx.clearRect(0, 0, w, h);
      const t = now / 1000;

      // ground dashes
      for (const L of LAYERS) {
        const period = L.dash + L.gap;
        const off = reduce ? 0 : (t * L.speed) % period;
        const y = groundY + L.dy;
        if (y > h) continue;
        for (let x = -off; x < w; x += period) {
          const k = x / w;
          const [r, g, b] = ramp(0.1 + k * 0.8);
          ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${L.a * (0.35 + 0.65 * Math.sin(Math.PI * Math.min(1, Math.max(0, k))))})`;
          for (let d = 0; d < L.dash; d += L.s * 1.6) ctx.fillRect(x + d, y, L.s, L.s);
        }
      }

      if (!reduce) {
        // dust from the hooves: spawn along the stride zone, then drift back
        const n = Math.random() < dt * 38 ? 1 : 0;
        for (let i = 0; i < n; i++) {
          parts.push({
            x: ox + cw * HORSE_COLS * (0.3 + Math.random() * 0.45),
            y: groundY - Math.random() * ch * 1.5,
            vx: -(120 + Math.random() * 260),
            vy: -(10 + Math.random() * 60),
            life: 0,
            ttl: 0.7 + Math.random() * 1.0,
            s: 2 + Math.random() * 3.2,
          });
        }
        for (let i = parts.length - 1; i >= 0; i--) {
          const p = parts[i];
          p.life += dt;
          if (p.life > p.ttl) { parts.splice(i, 1); continue; }
          p.x += p.vx * dt;
          p.y += p.vy * dt;
          p.vy += 40 * dt;
          const k = p.life / p.ttl;
          const [r, g, b] = ramp(0.78 - k * 0.6); // ember -> cream -> patina
          const snap = Math.max(2, Math.round(p.s));
          ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${(1 - k) * 0.75})`;
          ctx.fillRect(Math.round(p.x / snap) * snap, Math.round(p.y / snap) * snap, snap, snap);
        }
        if (parts.length > 260) parts.splice(0, parts.length - 260);
      }
      raf = requestAnimationFrame(frame);
    };

    layout();
    window.addEventListener("resize", layout);
    let vis = true;
    const io = typeof IntersectionObserver !== "undefined"
      ? new IntersectionObserver(([e]) => {
          vis = e.isIntersecting;
          cancelAnimationFrame(raf);
          if (vis) { last = performance.now(); raf = requestAnimationFrame(frame); }
        })
      : null;
    io?.observe(canvas);
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      io?.disconnect();
      window.removeEventListener("resize", layout);
    };
  }, []);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}

