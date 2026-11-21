import { useEffect, useRef } from "react";
import { HORSE_COLS, HORSE_FRAMES, HORSE_ROWS, decodeFrame } from "./horseFrames";

/**
 * A galloping horse rendered as columns of drifting digits.
 *
 * The silhouette is Muybridge's 1878 gallop (see horseFrames.ts); each lit
 * cell is a glyph whose digit scrolls down its column at a per-column speed,
 * over a soft luminous underpainting. Digits shed off the trailing edge and
 * drift away behind the horse. Canvas 2D, DPR-aware, paused when hidden or
 * off-screen, and frozen on a single frame under prefers-reduced-motion.
 */

interface Props {
  className?: string;
  /** Gallop speed in plates per second (Muybridge shot ~25/s). */
  fps?: number;
  /** Ink colour as "r,g,b". */
  ink?: string;
  /** Opacity of the painted body under the digits (0..1). */
  body?: number;
  /** Show digits shedding off the horse. */
  strays?: boolean;
  /** Freeze on this plate (0..10) instead of galloping. */
  still?: number;
}

const DIGITS = "0123456789";
const FRAMES = HORSE_FRAMES.map(decodeFrame);
// Plates 2 and 3 of the original are motion-blurred (legs smear into a blob);
// skipping them is invisible at gallop speed and keeps every frame legible.
const GALLOP = [0, 3, 4, 5, 6, 7, 8, 9, 10];

// Deterministic per-column jitter so the texture is stable between renders.
function hash(n: number): number {
  let x = (n * 374761393) ^ 0x5bd1e995;
  x = Math.imul(x ^ (x >>> 13), 1274126177);
  return ((x ^ (x >>> 16)) >>> 0) / 4294967295;
}
const COL_SPEED = Array.from({ length: HORSE_COLS }, (_, c) => 2 + hash(c + 11) * 7);
const COL_PHASE = Array.from({ length: HORSE_COLS }, (_, c) => Math.floor(hash(c + 97) * 10));
const COL_GAIN = Array.from({ length: HORSE_COLS }, (_, c) => 0.55 + hash(c + 5) * 0.45);

interface Stray {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  ttl: number;
  d: string;
}

export default function DigitHorse({
  className,
  fps = 13,
  ink = "236,230,218",
  body = 0.22,
  strays = true,
  still,
}: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = canvas.getContext("2d");
    } catch {
      ctx = null;
    }
    if (!ctx) return; // jsdom / no canvas: render nothing, never throw

    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const frozen = still != null || reduce;

    // Blurred body per plate, painted at 1/4 resolution and cached: blurring
    // a full-res canvas 13x a second is far too slow on CPU rasterisers.
    const BODY_SCALE = 0.25;
    let bodies: (HTMLCanvasElement | null)[] = FRAMES.map(() => null);

    let w = 0;
    let h = 0;
    let cw = 0;
    let ch = 0;
    let ox = 0;
    let oy = 0;
    let dpr = 1;

    const layout = () => {
      const r = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = Math.max(1, r.width);
      h = Math.max(1, r.height);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      // Cells are 1 : 1.61 (glyph aspect). Fit the grid inside the box.
      cw = Math.min(w / HORSE_COLS, h / (HORSE_ROWS * 1.61));
      ch = cw * 1.61;
      ox = (w - cw * HORSE_COLS) / 2;
      oy = (h - ch * HORSE_ROWS) / 2;
      bodies = FRAMES.map(() => null);
      buildAtlas();
    };

    const pool: Stray[] = [];
    let plate = still ?? 6;
    let lastPlate = -1;
    let lastT = 0;
    let lastDraw = -1e9;
    let raf = 0;
    let running = true;

    // Glyph atlas: 10 digits x LEVELS alpha steps, rendered once per layout.
    // Blitting from it is ~10x cheaper than fillText per cell per frame.
    const LEVELS = 10;
    let atlas: HTMLCanvasElement | null = null;
    let gw = 1;
    let gh = 1;
    const buildAtlas = () => {
      gw = Math.max(1, Math.ceil(cw * dpr));
      gh = Math.max(1, Math.ceil(ch * dpr));
      const a = document.createElement("canvas");
      a.width = gw * 10;
      a.height = gh * LEVELS;
      const g = a.getContext("2d");
      if (!g) {
        atlas = null;
        return;
      }
      g.font = `500 ${gh * 0.86}px "JetBrains Mono", ui-monospace, monospace`;
      g.textAlign = "center";
      g.textBaseline = "middle";
      for (let l = 0; l < LEVELS; l++) {
        g.fillStyle = `rgba(${ink},${((l + 1) / LEVELS).toFixed(2)})`;
        for (let d = 0; d < 10; d++) g.fillText(DIGITS[d], d * gw + gw / 2, l * gh + gh / 2);
      }
      atlas = a;
    };
    const blit = (digit: number, alpha: number, x: number, y: number, scale = 1) => {
      if (!atlas || !ctx) return;
      const l = Math.max(0, Math.min(LEVELS - 1, Math.round(alpha * LEVELS) - 1));
      if (alpha <= 0.04) return;
      ctx.drawImage(atlas, digit * gw, l * gh, gw, gh, x, y, cw * scale, ch * scale);
    };

    const bodyFor = (idx: number): HTMLCanvasElement | null => {
      const hit = bodies[idx];
      if (hit) return hit;
      const c = document.createElement("canvas");
      c.width = Math.max(1, Math.ceil(w * BODY_SCALE));
      c.height = Math.max(1, Math.ceil(h * BODY_SCALE));
      const b = c.getContext("2d");
      if (!b) return null;
      const cells = FRAMES[idx];
      b.scale(BODY_SCALE, BODY_SCALE);
      // A softly-edged painted body...
      b.filter = `blur(${Math.max(0.6, cw * 0.45 * BODY_SCALE)}px)`;
      b.fillStyle = `rgba(${ink},1)`;
      for (let r = 0; r < HORSE_ROWS; r++) {
        for (let col = 0; col < HORSE_COLS; col++) {
          if (cells[r * HORSE_COLS + col]) b.fillRect(ox + col * cw, oy + r * ch, cw + 0.5, ch + 0.5);
        }
      }
      b.filter = "none";
      // ...lit from above like the plate: bright back, shadowed belly and legs.
      b.globalCompositeOperation = "source-atop";
      const shade = b.createLinearGradient(0, oy, 0, oy + HORSE_ROWS * ch);
      shade.addColorStop(0, "rgba(255,250,240,0.95)");
      shade.addColorStop(0.45, "rgba(214,204,188,0.9)");
      shade.addColorStop(1, "rgba(92,82,72,0.85)");
      b.fillStyle = shade;
      b.fillRect(0, 0, w, h);
      b.globalCompositeOperation = "source-over";
      bodies[idx] = c;
      return c;
    };

    const draw = (t: number) => {
      if (!ctx) return;
      const cells = FRAMES[plate];
      if (plate !== lastPlate) {
        lastPlate = plate;
        // Shed digits from the trailing (left) edge of the new plate.
        if (strays && !frozen) {
          for (let k = 0; k < 7; k++) {
            const r = Math.floor(Math.random() * HORSE_ROWS);
            for (let c = 0; c < HORSE_COLS; c++) {
              if (cells[r * HORSE_COLS + c]) {
                pool.push({
                  x: ox + c * cw,
                  y: oy + r * ch,
                  vx: -(18 + Math.random() * 60),
                  vy: -6 + Math.random() * 12,
                  life: 0,
                  ttl: 0.9 + Math.random() * 1.6,
                  d: DIGITS[Math.floor(Math.random() * 10)],
                });
                break;
              }
            }
          }
          if (pool.length > 140) pool.splice(0, pool.length - 140);
        }
      }

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const bodyImg = body > 0 ? bodyFor(plate) : null;
      if (bodyImg) {
        ctx.globalAlpha = body;
        ctx.imageSmoothingEnabled = true;
        ctx.drawImage(bodyImg, 0, 0, w, h);
        ctx.globalAlpha = 1;
      }

      const tick = frozen ? 0 : t / 1000;

      for (let c = 0; c < HORSE_COLS; c++) {
        const scroll = Math.floor(tick * COL_SPEED[c]);
        const gain = COL_GAIN[c];
        const x = ox + c * cw;
        for (let r = 0; r < HORSE_ROWS; r++) {
          const i = r * HORSE_COLS + c;
          if (!cells[i]) continue;
          // Edge cells (any unlit 4-neighbour) are dimmer: soft silhouette.
          const edge =
            !cells[i - 1] || !cells[i + 1] || !cells[i - HORSE_COLS] || !cells[i + HORSE_COLS];
          // A bright "head" travels down each column, trailing off above it.
          const head = (scroll + COL_PHASE[c] * 3) % (HORSE_ROWS + 12);
          const dist = (head - r + HORSE_ROWS + 12) % (HORSE_ROWS + 12);
          const trail = dist < 10 ? 1 - dist / 12 : 0.28;
          const a = Math.min(1, (edge ? 0.55 : 1) * (0.5 + 0.5 * gain) * (0.5 + 0.6 * trail));
          blit((r + scroll + COL_PHASE[c]) % 10, a, x, oy + r * ch);
        }
      }

      if (strays && pool.length) {
        for (const s of pool) {
          const k = 1 - s.life / s.ttl;
          if (k > 0) blit(DIGITS.indexOf(s.d), k * 0.7, s.x, s.y - ch / 2, 0.9);
        }
      }
    };

    const loop = (t: number) => {
      if (!running) return;
      const dt = lastT ? Math.min(0.05, (t - lastT) / 1000) : 0;
      lastT = t;
      if (!frozen) plate = GALLOP[Math.floor((t / 1000) * fps) % GALLOP.length];
      for (const s of pool) {
        s.life += dt;
        s.x += s.vx * dt;
        s.y += s.vy * dt;
      }
      for (let i = pool.length - 1; i >= 0; i--) if (pool[i].life >= pool[i].ttl) pool.splice(i, 1);
      // Cap at ~30fps: the digits are the texture, not the motion.
      if (t - lastDraw >= 32) {
        lastDraw = t;
        draw(t);
      }
      raf = requestAnimationFrame(loop);
    };

    layout();
    if (frozen) {
      draw(0);
    } else {
      raf = requestAnimationFrame(loop);
    }

    const ro = typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(() => {
          layout();
          lastPlate = -1;
          if (frozen) draw(0);
        })
      : null;
    ro?.observe(canvas);

    // Pause off-screen / in background tabs.
    const io = typeof IntersectionObserver !== "undefined" && !frozen
      ? new IntersectionObserver(([e]) => {
          const vis = e?.isIntersecting ?? true;
          if (vis && !running) {
            running = true;
            lastT = 0;
            raf = requestAnimationFrame(loop);
          } else if (!vis) {
            running = false;
            cancelAnimationFrame(raf);
          }
        })
      : null;
    io?.observe(canvas);

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      ro?.disconnect();
      io?.disconnect();
    };
  }, [fps, ink, body, strays, still]);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
