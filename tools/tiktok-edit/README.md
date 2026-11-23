# Paddock TikTok edit generator

A canvas-based generator for short vertical (1080×1920, 30 fps) edits in the Paddock "terminal / SOC" style,
cut to a song: **one new screen on every beat**.

```bash
./build.sh path/to/song.mp3            # video length = song end (or pass seconds as 2nd arg)
# -> out/tiktok-with-song.mp4  out/tiktok-NO-AUDIO.mp4
```

Needs `node` + `playwright`, `python3` + `numpy`, `ffmpeg`. `inputs/memes/*.png` and `inputs/shots/*.png` are
git-ignored (third-party images, kept local): see `edit.html` (`SCREENS`) for the names it loads.

## How it works
- `analyze_song.py` finds the drum hits and the beat grid (`build/onsets.json`, `build/config.json`: beat period, first beat, end).
- `edit.html` is a pure function `render(t)`; `render.js` screenshots it frame by frame; `ffmpeg` muxes the song.
- `prepare.py` builds the horse frames (from `dashboard/src/brand/horseFrames.ts`) and the code wall (from the SDK source).
- Screens live in the `SCREENS` array (index = beat). The three big song drops get a zoom hit (`HITS`): Python triangle,
  Kali triangle, then the Paddock triangle, each shrinking into a corner badge.

## Variants and music
`edit.html?v=main|a|b` selects a screen set: `main` (original), `a` (product tour: real dashboard screenshots, services, git log, tests),
`b` (attacker vs defender split screens + memes). `render.js ... <port> <variant>` renders one; `analyze_song.py ... --variant a`
writes its beat grid. `music/phonk.py drift|funk out.wav` makes original rights-free phonk tracks laid out on the grid the screens expect
(drop on beat 8, denser on 16, final hit on beat 32).

The style rules (and what not to do) are in `.claude/skills/paddock-tiktok-edit/SKILL.md`.

## Licensing notes
Logos in `assets/logos` come from [Simple Icons](https://simpleicons.org) (CC0 files). The marks themselves belong to their
owners and appear only as context. Newsreader is OFL. Do not commit songs, memes or screenshots of other people's pages.
