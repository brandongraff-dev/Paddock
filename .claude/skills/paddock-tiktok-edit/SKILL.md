---
name: paddock-tiktok-edit
description: Make a short vertical TikTok/Reels/Shorts edit for Paddock in the saved "terminal / SOC, new screen every beat" style, cut to a given song. Use when the user asks for a Paddock TikTok, short video, launch edit or "more like the last one".
---

# Paddock TikTok edit (saved style)

Generator: `tools/tiktok-edit/` (see its README). Run `tools/tiktok-edit/build.sh <song>`; edit the `SCREENS` array in
`tools/tiktok-edit/edit.html` for new content. Deliver BOTH `tiktok-with-song.mp4` and `tiktok-NO-AUDIO.mp4`
(the user should post the silent one and add the sound in TikTok). Send the file in chat; artifact pages cannot offer
downloads and cap each file at 15 MB.

## The style (from the user's feedback; keep all of it)
- 1080×1920, 30 fps, ~17 s, ends on the song's last hit. **A different screen on every beat**; never repeat a layout.
  Hard cuts with a 2-frame glitch, small zoom punch, light flash on the cut, tick on the half-beat.
- Zoom-in logo hits on the song's big drops (kick enters, dense section, final hit), like the reference TikTok:
  white triangle with title on top, mark in the middle, side labels, bottom label. Python (`pyw`/`pyi`/`py`) first,
  then Kali, then the Paddock horse triangle. After a hit it shrinks to a corner badge with a small `openpaddock.dev`.
- Professional cybersecurity feel, **clutter**, no big text stamps (no BREACH/CRITICAL/HIGH stamps): SOC alert cards, a thin
  monitor HUD (corner brackets, `PADDOCK // SURFACE MONITOR`, LIVE, status line), terminal windows, packet table, port list,
  radar, hex, attack-path graph, logo cards, logo wall with the Paddock horse in it, kinetic type kept plain.
- **No strong glow** on logos, text or cards. Add film grain (animated), light scanlines, vignette.
- Feature Kali, Linux (Tux), Python, Docker, Git/GitHub, bash, OpenSSL, Wireshark, OWASP, Burp, Claude/Anthropic and other
  open-source/security logos, but emphasise Paddock, open source and terminals.
- Real content only: real `paddockctl` / `paddock_sdk` commands, demo org `acme-demo.example`, RFC 5737 IPs, mock demo data.
  Real screenshots of public pages (CISA KEV, NVD, MITRE ATT&CK, nmap.org, wireshark.org, kali.org, the repo page) taken with
  Playwright, never copyrighted stock.
- Ending: the Paddock horse assembles from code and gallops, then types `openpaddock.dev` + `OPEN SOURCE · AGPL-3.0`.
  Use the **URL, not the GitHub link**. No long end card, no slogan: it should not feel like an ad.
- Stick-figure coder / red attacker figures are fine in small doses; keep text short (0.45 s per beat).

## Rules
- Meme images the user supplies (e.g. "evil AI" logos) go in `inputs/memes/` and are used as given; do not invent them or
  alter real companies' logos on your own. Keep artist watermarks. Do not commit memes, screenshots or songs.
- Do not put exploit code in frames; attacker lines stay fictional (`find_open()`).
- Check frames before sending (contact sheet), then confirm frame count and audio length with `ffprobe`.
- TikTok safe zones: keep key content out of the top ~120 px, the bottom ~400 px and the right ~120 px.
