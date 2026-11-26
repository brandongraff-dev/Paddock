# Paddock: notes for agents working in this repo

## UI design baseline (owner sign-off is no longer required)

The repo owner hand-tuned the dashboard and landing UI (PR #2,
`claude/optimistic-volta-khlk4c`, merged to `main`). The owner has given
standing approval for UI work: you do **not** need to ask before adding,
changing or restyling UI. Treat what follows as the current design baseline:
build new UI in the same visual language, and keep the performance rules and
the deliberately-removed list below unless you have a concrete reason, which you
state in the PR or commit message. Don't regress it by accident:

**Console (dashboard)**
- **Pixel aurora** (`src/brand/PixelField.tsx`): a dithered Bayer dot-matrix
  band in the Daguerreotype palette (patina blue → cream → ember → sepia), no
  neon. It sits behind the content sheet only (`.canvas-pixels`, static,
  `animate={false}`) and also behind login and setup. The rail stays flat
  chrome.
- **Layered premium glass** on every card, panel, stat tile, overlay, login and
  setup (theme.css "Pixel aurora + liquid glass"): a clear blurred slab with
  refracted edge fringes carrying a more solid frosted plate. Panel headers are
  the plate and bodies stay clear, so charts sit over the aurora. No 3D rim, no
  drop shadow, no hover glow.
- **Calm topbar**: the classification indicator is a quiet pill
  (`ClassificationBanner` → `.class-pill`, sentence case, "public" in
  `--text-2`) inside the topbar. Don't bring back the full-width banner.
- **Wordmark** (`src/brand/Wordmark.tsx`, `wordmarkData.ts`): serif outlines
  with a pixel-ring "o". Used in the sidebar, landing nav and README; SVGs are
  in `docs/assets/paddock-wordmark*.svg`.

**Landing**
- The hero aurora is the horse's wake, streaming left from its tail, with a
  ground track and hoof dust under the gallop (`GallopTrail.tsx`).
- Glass agent cards overlap their plates and **don't** brighten on hover.
- An animated product showcase (`pages/landing/Showcase.tsx`, mock data).
- A framed column between hairlines, and a dither divider (`DitherRule.tsx`).
- Footer: a muted **paper** tone with grain and mottling, a hard edge with a
  pixel bar on the seam (no gradient), and a giant cropped wordmark whose "o"
  drops in spinning, bounces twice, and sends a shockwave through the pixels
  when the page bottom is reached.
- **Deliberately removed. Don't re-add:** the film strip, the integrations
  ticker, the "o" ripple, the hero cursor lens, the proof-stats row, and the
  license/credit footer.
- Performance rules: the ImageData aurora uses lookup tables and pauses when
  hidden; no backdrop blur or float inside product windows; an overlay rather
  than a mask on the hero; a capped dust canvas.

**Deploy:** `dashboard/vercel.json` (vite build, SPA rewrite); `.vercel` and
`.env*` are ignored.

Changing any of this no longer needs the owner's sign-off. If you change a baseline
decision on purpose, update this section in the same change so it stays accurate.

## Working rules

- Generated files: after changing API routes, run
  `python scripts/export_openapi.py && python sdk/python/codegen.py && node sdk/typescript/scripts/codegen.mjs`
  (CI runs the same commands with `--check`).
- Status, gaps and the roadmap are in `docs/READINESS.md` and `docs/VISION.md`.
