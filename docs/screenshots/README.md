# Screenshots

The images referenced from the root [`README.md`](../../README.md) live in this
directory. They are **tracked in git** (unlike runtime screenshots captured by
the active worker, which land in a gitignored root-level `screenshots/`).

> **Note:** the four JPEGs the root README uses are checked in here (kept
> small — JPEG q84, ~2400px wide). Retake them with the steps below and keep
> the same filenames. Do not commit screenshots of a real target's
> surface — use the bundled demo graph.

## Expected files

| File | Route | What to show |
|------|-------|--------------|
| `graph.jpg`        | `/graph`        | The hero shot — the live asset graph with 2–3 high/critical nodes highlighted. |
| `overview.png`     | `/`             | Overview with all panels populated. |
| `findings.jpg`     | `/findings`     | Findings table, a filter active, cursor on a KEV row. |
| `chains.jpg`       | `/chains`       | At least one correlation chain card expanded. |
| `attack-paths.jpg` | `/attack-paths` | An attack path from an internet-facing asset to a crown jewel. |
| `timeline.png`     | `/timeline`     | 7–14 days of surface history. |
| `scope.png`        | `/scope`        | A scope row expanded, showing its audit trail. |

## How to capture (reproducible)

```bash
make quickstart          # brings the stack up + seeds the acme-demo graph
# open http://localhost:3000, resize the window to 1600x1000
```

Then capture each route (Playwright is not a project dependency — install it
ad hoc only if you want automated captures):

```bash
npx playwright screenshot --viewport-size=1600,1000 \
  http://localhost:3000/graph docs/screenshots/graph.jpg
# repeat per route in the table above
```

See [`../DASHBOARD_NOTES.md`](../DASHBOARD_NOTES.md) ("Screenshot plan") for the
visual-tuning details (node layout, which asset kinds to enable for the hero).
