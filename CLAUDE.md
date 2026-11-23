# Working agreements for this repo

Notes for Claude Code (and any contributor) working on the Paddock site and dashboard.

## Deploying to Vercel: batch it

The Vercel free plan allows **100 deployments per rolling 24 hours** per account. A long
design session burned through that and blocked every deploy for a day.

- **Do not deploy after every small tweak.** Commit and push as often as you like; that is free.
- Iterate locally: `npm run build && npx vite preview --port 4173` in `dashboard/`, and look
  at screenshots (desktop and a ~390px phone) before calling anything done.
- **Deploy once, when the owner says the result looks right.** Ask first if unsure.
- A single deploy covers one project. Deploy the docs site only when `docs/` or `mkdocs.yml` changed.
- If a deploy is refused with `api-deployments-free-per-day`, stop. Do not retry in a loop.
  Report it, and say that the owner can wait or upgrade to Vercel Pro.

### How the two sites deploy

| Site | Project | Source | Command |
|---|---|---|---|
| Landing page and console | `paddock` (`www.openpaddock.dev`) | `dashboard/` | `cd dashboard && vercel deploy --prod --yes` |
| Docs | `paddock-docs` (`paddock-docs.vercel.app`) | `site/`, built by `mkdocs build --strict` | `mkdocs build --strict && cd site && vercel deploy --prod --yes` |

`site/` and `dashboard/.vercel` are git-ignored build/link output. Never commit tokens or `.env*` files.

## Before you call a change finished

1. `cd dashboard && npx tsc -b` has no errors.
2. `npx vitest run` passes. Run it twice: the console is code-split, so a slow first load can
   make a smoke test flaky.
3. Screenshot desktop (1440px) **and** phone (390px). Confirm there is no horizontal scroll
   (`document.documentElement.scrollWidth === 390`).
4. Do not claim something is live unless a deploy actually succeeded.

## Design guidance (what the owner has asked for)

The look is "Daguerreotype": warm sepia blacks, cream ink, serif headlines, quiet sans body.

- **Restraint.** If something looks "AI" or "too much", simplify it. The owner has rejected, in order:
  busy glass cards, photographic or rendered art, the pixel arch scenery, gradient dividers,
  and decorative effects without a job to do. Prefer plain type, hairlines and flat shapes.
- **Palette.** Near-black `#0e0c0a`, cream `#ece6da`, muted grey `#b0aea5`. Accents are used
  sparingly: rust `#b4573b`, ochre `#c8a35a`, patina blue `#9fc2d8`. No neon.
- **Type.** Newsreader (serif) for headlines, Inter for body, JetBrains Mono for small labels.
  Use curly apostrophes. Balance headlines (`text-wrap: balance`).
- **Cards.** Small radius (about 10px), a thin ~10% white border, no blur, glow or inner shadow.
- **Illustration.** Flat, solid, drawn in code (SVG), one consistent style across a set. Do not
  mix a painted or traced image with hand-built shapes.
- **Pixel motif.** The dithered pixel field is the brand texture (hero wake, constellation
  backgrounds, faint card fields). Keep it faint behind content.
- **Performance.** Paint canvases once where possible, pause animation off-screen, respect
  `prefers-reduced-motion`. The landing JavaScript should stay small: the signed-in console is lazy-loaded.
- **Content.** No fake logos, testimonials or numbers. Mock figures must be obviously illustrative.
- **Safety copy.** Paddock is defensive-only. Never write copy or prompts that encourage scanning
  things the user does not own.

## Names and links

- Repo: `https://github.com/brandongraff-dev/Paddock` (renamed from `cybersec`).
- Site: `https://www.openpaddock.dev`. Docs: `https://docs.openpaddock.dev` (a CNAME `docs` at name.com
  pointing to Vercel; the same docs are also reachable at `paddock-docs.vercel.app`).
- Keep the canonical URL, Open Graph tags, `robots.txt` and `sitemap.xml` in `dashboard/` in step with the site address.
